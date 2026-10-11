package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/ratelimit"
	pc "github.com/PrivateCaptcha/private-captcha-go"
	"github.com/golang-jwt/jwt/v5"
	"github.com/justinas/alice"
	"golang.org/x/net/idna"
)

var (
	errUnknownKey    = errors.New("unknown edge token key")
	errInvalidHeader = errors.New("invalid edge token header")
	errInvalidHost   = errors.New("invalid hostname")
)

type edgeClaims struct {
	Version int    `json:"v"`
	Host    string `json:"host"`
	jwt.RegisteredClaims
}

type Authorizer struct {
	s               Settings
	keys            *KeyCache
	parser          *jwt.Parser
	limitedComplete http.Handler
	gates           *gateCache
	verifier        *pc.Client
}

func NewAuthorizer(s Settings, keys *KeyCache) (*Authorizer, error) {
	client := *keys.client
	client.Transport = verificationTransport{
		RoundTripper: keys.client.Transport,
	}
	verifier, err := pc.NewClient(pc.Configuration{
		Domain: s.apiBaseURL,
		APIKey: s.apiKey,
		Client: &client,
	})
	if err != nil {
		return nil, err
	}
	a := &Authorizer{
		s:        s,
		keys:     keys,
		verifier: verifier,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{keyAlgorithm}),
			jwt.WithIssuer(s.issuer),
			jwt.WithAudience(s.sitekey),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithStrictDecoding(),
		),
	}
	limiter := ratelimit.NewIPAddrRateLimiter(common.HeaderClientIP, ratelimit.NewIPAddrBuckets(10_000, 10, 6*time.Second))
	a.limitedComplete = limiter.RateLimit(http.HandlerFunc(a.completeSolution))
	a.gates = &gateCache{
		url:    s.apiBaseURL + gatePath + "?" + common.ParamSiteKey + "=" + url.QueryEscape(s.sitekey),
		client: keys.client,
		now:    time.Now,
	}
	return a, nil
}

func (a *Authorizer) Setup(router *http.ServeMux) {
	chain := alice.New(common.ServiceMiddleware(ServiceName), common.Recovered(nil), common.SoftTimeoutHandler(requestTimeout))
	router.Handle(http.MethodGet+" "+healthPath, common.HttpStatus(http.StatusNoContent))
	router.Handle(http.MethodGet+" "+authPath, chain.ThenFunc(a.auth))
	router.Handle(http.MethodPost+" "+completePath, http.MaxBytesHandler(chain.ThenFunc(a.complete), maxFormBytes))
}

func (a *Authorizer) auth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(common.HeaderCacheControl, cacheNoStore)
	ctx := r.Context()
	if reason := a.validate(r); reason != "" {
		level := slog.LevelWarn
		if reason == reasonMissing || reason == reasonExpired {
			level = slog.LevelDebug
		}
		slog.Log(ctx, level, "Edge authorization denied", "reason", reason, "status", http.StatusUnauthorized, "endpoint", authPath)
		if reason != reasonBadForwarded && reason != reasonMalformedRequest && browserNavigation(r) {
			if page, err := a.gates.get(ctx); err == nil {
				common.WriteHeaders(w, page.headers)
				w.WriteHeader(http.StatusUnauthorized)
				if _, err := w.Write(page.body); err != nil {
					slog.DebugContext(ctx, "Failed to send gate response")
				}
				return
			}
			slog.ErrorContext(ctx, "Hosted gate is unavailable", "endpoint", authPath)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Authorizer) validate(r *http.Request) denialReason {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.RequestURI) > maxRequestURI {
		return reasonMalformedRequest
	}
	host, err := a.s.requestHost(r)
	if err != nil {
		return reasonBadForwarded
	}
	cookieCount := 0
	for _, header := range r.Header.Values(HeaderCookie) {
		for part := range strings.SplitSeq(header, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == edgeCookieName {
				cookieCount++
			}
		}
	}
	if cookieCount == 0 {
		return reasonMissing
	}
	cookies := r.CookiesNamed(edgeCookieName)
	if cookieCount != 1 || len(cookies) != 1 || len(cookies[0].Value) == 0 || len(cookies[0].Value) > maxTokenBytes {
		return reasonMalformed
	}
	_, reason := a.verify(r.Context(), cookies[0].Value, host)
	return reason
}

func (a *Authorizer) verify(ctx context.Context, raw, host string) (*edgeClaims, denialReason) {
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		return nil, reasonMalformed
	}
	claims := &edgeClaims{}
	token, err := a.parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["typ"] != edgeTokenType {
			return nil, errInvalidHeader
		}
		for _, name := range []string{"jku", "x5u", "jwk", "crit", "b64"} {
			if _, present := token.Header[name]; present {
				return nil, errInvalidHeader
			}
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > maxKeyIDBytes {
			return nil, errInvalidHeader
		}
		return a.keys.lookup(ctx, kid)
	})
	if err != nil {
		switch {
		case errors.Is(err, errUnknownKey):
			return nil, reasonUnknownKey
		case errors.Is(err, errInvalidHeader):
			return nil, reasonMalformed
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, reasonBadSignature
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, reasonExpired
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, reasonBadAudience
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, reasonBadIssuer
		default:
			return nil, reasonMalformed
		}
	}
	if !token.Valid || claims.Version != 1 || claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, reasonBadClaims
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime < time.Second || lifetime > maxTokenTTL {
		return nil, reasonBadClaims
	}
	signedHost, err := normalizeHostname(claims.Host)
	if err != nil || signedHost != host {
		return nil, reasonBadHost
	}
	return claims, ""
}

func normalizeHostname(host string) (string, error) {
	if host == "" || len(host) > 1024 || strings.ContainsAny(host, ":/@?#\\ \t\r\n") {
		return "", errInvalidHost
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", errInvalidHost
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", errInvalidHost
	}
	if common.IsIPAddress(ascii) {
		return "", errInvalidHost
	}
	for label := range strings.SplitSeq(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errInvalidHost
		}
		if strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return "", errInvalidHost
		}
	}
	return ascii, nil
}

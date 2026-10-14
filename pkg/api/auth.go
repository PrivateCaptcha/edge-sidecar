package api

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/monitoring"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/ratelimit"
	pc "github.com/PrivateCaptcha/private-captcha-go"
	"github.com/golang-jwt/jwt/v5"
	"github.com/justinas/alice"
	"github.com/maypok86/otter/v2"
	"golang.org/x/crypto/blake2b"
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
	rateLimiter     ratelimit.HTTPRateLimiter
	gates           *gateCache
	verifier        *pc.Client
	completionLimit *completionLimiter
	cookieUses      *otter.Cache[int64, *int64]
}

func NewAuthorizer(s Settings, keys *KeyCache) (*Authorizer, error) {
	return newAuthorizer(s, keys, nil, nil, nil)
}

func newAuthorizer(s Settings, keys *KeyCache, completionLimit *completionLimiter, rateLimiter ratelimit.HTTPRateLimiter, cookieUses *otter.Cache[int64, *int64]) (*Authorizer, error) {
	s.proxyDNS = &proxyDNSCache{
		entries: make(map[string]proxyDNSResult, len(s.trustedProxyHosts)),
		now:     time.Now,
	}
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
	if completionLimit == nil {
		completionLimit = &completionLimiter{
			limit: s.maxConcurrentCompletions,
		}
	}
	if rateLimiter == nil {
		rateLimiter = ratelimit.NewIPAddrRateLimiter(common.HeaderClientIP, ratelimit.NewIPAddrBuckets(10_000, 10, 6*time.Second))
	}
	if cookieUses == nil {
		cookieUses = otter.Must(&otter.Options[int64, *int64]{
			MaximumSize:      100_000,
			InitialCapacity:  1_000,
			ExpiryCalculator: otter.ExpiryCreating[int64, *int64](maxTokenTTL + 2*tokenLeeway),
		})
	}
	a := &Authorizer{
		s:               s,
		keys:            keys,
		verifier:        verifier,
		completionLimit: completionLimit,
		rateLimiter:     rateLimiter,
		cookieUses:      cookieUses,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{keyAlgorithm}),
			jwt.WithIssuer(s.issuer),
			jwt.WithAudience(s.sitekey),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(tokenLeeway),
			jwt.WithStrictDecoding(),
		),
	}
	a.limitedComplete = a.rateLimiter.RateLimit(http.HandlerFunc(a.completeSolution))
	a.gates = &gateCache{
		url:    s.apiBaseURL + gatePath + "?" + common.ParamSiteKey + "=" + url.QueryEscape(s.sitekey),
		client: keys.client,
		now:    time.Now,
	}
	slog.Debug("Configured edge authorizer", "protected_origin", s.protectedOrigin,
		"trusted_proxy_cidrs", s.trustedProxies, "trusted_proxy_hosts", s.trustedProxyHosts,
		"max_concurrent_completions", s.maxConcurrentCompletions, "max_cookie_uses", s.maxCookieUses)
	return a, nil
}

// Reconfigure builds a replacement while retaining admission limits for in-flight requests.
func (a *Authorizer) Reconfigure(s Settings, keys *KeyCache) (*Authorizer, error) {
	next, err := newAuthorizer(s, keys, a.completionLimit, a.rateLimiter, a.cookieUses)
	if err != nil {
		return nil, err
	}
	next.completionLimit.setLimit(s.maxConcurrentCompletions)
	return next, nil
}

func (a *Authorizer) Setup(router *http.ServeMux) {
	chain := alice.New(common.ServiceMiddleware(ServiceName), monitoring.Logged, common.Recovered(nil), common.SoftTimeoutHandler(requestTimeout))
	router.Handle(http.MethodGet+" "+healthPath, common.HttpStatus(http.StatusNoContent))
	router.Handle(http.MethodGet+" "+authPath, chain.ThenFunc(a.auth))
	router.Handle(http.MethodPost+" "+completePath, http.MaxBytesHandler(chain.ThenFunc(a.complete), maxFormBytes))
}

func (a *Authorizer) auth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(common.HeaderCacheControl, cacheNoStore)
	ctx := r.Context()
	if reason := a.validate(r); reason != "" {
		level := slog.LevelWarn
		if reason == reasonMissing || reason == reasonExpired || reason == reasonCookieUseLimit {
			level = slog.LevelDebug
		}
		navigation := browserNavigation(r)
		slog.Log(ctx, level, "Edge authorization denied", "reason", reason, "status", http.StatusUnauthorized,
			"endpoint", authPath, "browser_navigation", navigation)
		if reason != reasonBadForwarded && reason != reasonMalformedRequest && navigation {
			slog.DebugContext(ctx, "Preparing hosted captcha challenge", "endpoint", authPath)
			if page, err := a.gates.get(ctx); err == nil {
				common.WriteHeaders(w, page.headers)
				w.WriteHeader(http.StatusUnauthorized)
				if sent, err := w.Write(page.body); err != nil {
					slog.DebugContext(ctx, "Failed to send gate response", "endpoint", authPath, "bytes", sent, common.ErrAttr(err))
				} else {
					slog.DebugContext(ctx, "Sent hosted captcha challenge", "endpoint", authPath, "status", http.StatusUnauthorized, "bytes", sent)
				}
				return
			} else {
				slog.ErrorContext(ctx, "Hosted gate is unavailable", "endpoint", authPath, common.ErrAttr(err))
			}
		}
		slog.DebugContext(ctx, "Returning authorization denial without a challenge", "endpoint", authPath,
			"reason", reason, "browser_navigation", navigation)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	slog.Log(ctx, common.LevelTrace, "Edge authorization succeeded", "endpoint", authPath, "status", http.StatusNoContent)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Authorizer) validate(r *http.Request) denialReason {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.RequestURI) > maxRequestURI {
		slog.WarnContext(r.Context(), "Malformed authorization request", "endpoint", authPath,
			"content_length", r.ContentLength, "transfer_encodings", len(r.TransferEncoding), "uri_length", len(r.RequestURI))
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
		slog.DebugContext(r.Context(), "Edge authorization cookie is missing", "endpoint", authPath, "cookie_name", edgeCookieName)
		return reasonMissing
	}
	cookies := r.CookiesNamed(edgeCookieName)
	if cookieCount != 1 || len(cookies) != 1 || len(cookies[0].Value) == 0 || len(cookies[0].Value) > maxTokenBytes {
		slog.DebugContext(r.Context(), "Edge authorization cookie is malformed", "endpoint", authPath,
			"cookie_count", cookieCount, "parsed_cookie_count", len(cookies))
		return reasonMalformed
	}
	slog.Log(r.Context(), common.LevelTrace, "Checking edge authorization cookie", "endpoint", authPath)
	_, reason := a.verify(r.Context(), cookies[0].Value, host)
	if reason != "" {
		return reason
	}
	digest := blake2b.Sum256([]byte(cookies[0].Value))
	key := int64(binary.LittleEndian.Uint64(digest[:8]))
	counter, _ := a.cookieUses.ComputeIfAbsent(key, func() (*int64, bool) {
		return new(int64), false
	})
	if count := atomic.AddInt64(counter, 1); count > a.s.maxCookieUses {
		atomic.AddInt64(counter, -1)
		slog.DebugContext(r.Context(), "Edge authorization cookie usage limit exceeded", "endpoint", authPath,
			"cookie_uses", count-1, "max_cookie_uses", a.s.maxCookieUses)
		return reasonCookieUseLimit
	}
	return ""
}

func (a *Authorizer) verify(ctx context.Context, raw, host string) (*edgeClaims, denialReason) {
	slog.Log(ctx, common.LevelTrace, "Validating edge token", "host", host)
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
		case errors.Is(err, jwt.ErrTokenUsedBeforeIssued), errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, reasonNotYetValid
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
	slog.Log(ctx, common.LevelTrace, "Edge token validated", "host", host, "expires_at", claims.ExpiresAt.UTC())
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

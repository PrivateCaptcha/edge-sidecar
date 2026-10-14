package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	if err := RegisterConfig(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type edgeFixture struct {
	s         Settings
	key       *ecdsa.PrivateKey
	keys      *KeyCache
	a         *Authorizer
	jwksCalls atomic.Int32
}

func testEnv() map[string]string {
	return map[string]string{
		"PC_SITEKEY":             "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"PC_API_KEY":             "fixture-api-key",
		"PC_PROTECTED_ORIGIN":    "https://example.com",
		"PC_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
	}
}

func newEdgeFixture(t *testing.T) *edgeFixture {
	return newEdgeFixtureWithEnv(t, nil)
}

func newEdgeFixtureWithEnv(t *testing.T, overrides map[string]string) *edgeFixture {
	t.Helper()
	f := &edgeFixture{}
	var err error
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := f.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	key := jwk{
		Kty: "EC",
		Crv: "P-256",
		Alg: keyAlgorithm,
		Use: "sig",
		Kid: "fixture-key",
		X:   base64.RawURLEncoding.EncodeToString(point[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(point[33:]),
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.jwksCalls.Add(1)
		if r.URL.Path != "/.well-known/jwks.json" {
			t.Errorf("unexpected key URL: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []jwk{key}})
	}))
	t.Cleanup(upstream.Close)
	env := testEnv()
	for name, value := range overrides {
		env[name] = value
	}
	env["PC_JWKS_URL"] = upstream.URL + "/.well-known/jwks.json"
	f.s, err = LoadSettings(config.NewEnvConfig(func(name string) string { return env[name] }))
	if err != nil {
		t.Fatal(err)
	}
	f.keys = NewKeyCache(f.s)
	t.Cleanup(f.keys.CloseIdleConnections)
	if err := f.keys.RunOnce(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	f.a, err = NewAuthorizer(f.s, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *edgeFixture) token(t *testing.T, changes jwt.MapClaims, headers map[string]any) string {
	t.Helper()
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"v":    1,
		"iss":  f.s.issuer,
		"aud":  f.s.sitekey,
		"host": "example.com",
		"iat":  now,
		"exp":  now + 3600,
	}
	for name, value := range changes {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = edgeTokenType
	token.Header["kid"] = "fixture-key"
	for name, value := range headers {
		if value == nil {
			delete(token.Header, name)
		} else {
			token.Header[name] = value
		}
	}
	signed, err := token.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func authRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://sidecar/auth", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set(HeaderForwardedHost, "example.com")
	r.Header.Set(HeaderForwardedProto, "https")
	r.Header.Set(HeaderForwardedMethod, http.MethodGet)
	r.Header.Set(HeaderForwardedURI, "/private?x=1")
	r.Header.Set(common.HeaderClientIP, "192.0.2.1")
	if token != "" {
		r.AddCookie(&http.Cookie{
			Name:  edgeCookieName,
			Value: token,
		})
	}
	return r
}

func TestEdgeSidecarProxy(t *testing.T) {
	f := newEdgeFixture(t)
	token := f.token(t, nil, nil)
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"Trusted", func(*http.Request) {}, 204},
		{"Untrusted", func(r *http.Request) { r.RemoteAddr = "192.0.2.10:8080" }, 401},
		{"WrongPort", func(r *http.Request) { r.Header.Set(HeaderForwardedHost, "example.com:8443") }, 401},
		{"HTTP", func(r *http.Request) { r.Header.Set(HeaderForwardedProto, "http") }, 401},
		{"DefaultPort", func(r *http.Request) { r.Header.Set(HeaderForwardedHost, "EXAMPLE.COM.:443") }, 204},
		{"DuplicateHost", func(r *http.Request) { r.Header.Add(HeaderForwardedHost, "evil.com") }, 401},
		{"HostURL", func(r *http.Request) { r.Header.Set(HeaderForwardedHost, "https://example.com") }, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := authRequest(token)
			tc.edit(r)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != tc.want || w.Body.Len() != 0 || w.Header().Get(common.HeaderCacheControl) != cacheNoStore {
				t.Fatalf("status=%d body=%q headers=%v", w.Code, w.Body.String(), w.Header())
			}
		})
	}
	if f.jwksCalls.Load() != 1 {
		t.Fatal("normal authorization contacted JWKS")
	}
}

func TestEdgeSidecarCookieUses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		limit int
	}{
		{
			name:  "Default",
			limit: 100,
		},
		{
			name:  "Configured",
			value: "2",
			limit: 2,
		},
		{
			name:  "SingleUse",
			value: "1",
			limit: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": tc.value})
			token := f.token(t, nil, nil)
			for i := 0; i < tc.limit+2; i++ {
				w := httptest.NewRecorder()
				f.a.auth(w, authRequest(token))
				want := http.StatusNoContent
				if i >= tc.limit {
					want = http.StatusUnauthorized
				}
				if w.Code != want || w.Body.Len() != 0 || w.Header().Get(common.HeaderCacheControl) != cacheNoStore {
					t.Fatalf("request %d: status=%d want=%d body=%q headers=%v", i+1, w.Code, want, w.Body.String(), w.Header())
				}
			}
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(f.token(t, jwt.MapClaims{"jti": "renewed"}, nil)))
			if w.Code != http.StatusNoContent {
				t.Fatalf("new cookie did not receive its own allowance: status=%d", w.Code)
			}
			if f.jwksCalls.Load() != 1 {
				t.Fatal("cookie usage checks contacted JWKS")
			}
		})
	}
}

func TestEdgeSidecarCookieUsesConcurrent(t *testing.T) {
	const limit = 17
	const requests = 64
	f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "17"})
	token := f.token(t, nil, nil)
	var allowed atomic.Int64
	var denied atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(token))
			switch w.Code {
			case http.StatusNoContent:
				allowed.Add(1)
			case http.StatusUnauthorized:
				denied.Add(1)
			default:
				t.Errorf("unexpected authorization status=%d", w.Code)
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed.Load() != limit || denied.Load() != requests-limit {
		t.Fatalf("allowed=%d denied=%d want=%d/%d", allowed.Load(), denied.Load(), limit, requests-limit)
	}
}

func TestEdgeSidecarCookieUsesDeniedRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
	}{
		{
			name: "UntrustedProxy",
			edit: func(r *http.Request) { r.RemoteAddr = "192.0.2.10:8080" },
		},
		{
			name: "WrongOrigin",
			edit: func(r *http.Request) { r.Header.Set(HeaderForwardedHost, "other.example") },
		},
		{
			name: "MalformedRequest",
			edit: func(r *http.Request) { r.ContentLength = 1 },
		},
		{
			name: "DuplicateCookie",
			edit: func(r *http.Request) { r.Header.Add(HeaderCookie, r.Header.Get(HeaderCookie)) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "1"})
			token := f.token(t, nil, nil)
			r := authRequest(token)
			tc.edit(r)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("invalid request returned status=%d", w.Code)
			}
			if reason := f.a.validate(authRequest(token)); reason != "" {
				t.Fatalf("denied request consumed a cookie use: reason=%q", reason)
			}
			if reason := f.a.validate(authRequest(token)); reason != reasonCookieUseLimit {
				t.Fatalf("cookie allowance was not exhausted: reason=%q", reason)
			}
		})
	}
}

func TestEdgeSidecarCookieUsesVerification(t *testing.T) {
	f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "1"})
	token := f.token(t, nil, nil)
	for i := 0; i < 2; i++ {
		if _, reason := f.a.verify(t.Context(), token, "example.com"); reason != "" {
			t.Fatalf("token verification failed: reason=%q", reason)
		}
	}
	if reason := f.a.validate(authRequest(token)); reason != "" {
		t.Fatalf("token verification consumed a cookie use: reason=%q", reason)
	}
	if reason := f.a.validate(authRequest(token)); reason != reasonCookieUseLimit {
		t.Fatalf("cookie allowance was not exhausted: reason=%q", reason)
	}
	if _, reason := f.a.verify(t.Context(), token, "example.com"); reason != "" {
		t.Fatalf("cookie usage affected token verification: reason=%q", reason)
	}
}

func TestEdgeSidecarCookieUsesReconfigure(t *testing.T) {
	f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "3"})
	token := f.token(t, nil, nil)
	for i := 0; i < 2; i++ {
		if reason := f.a.validate(authRequest(token)); reason != "" {
			t.Fatalf("request %d denied: reason=%q", i+1, reason)
		}
	}
	updated := f.s
	updated.maxCookieUses = 4
	reconfigured, err := f.a.Reconfigure(updated, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if reason := reconfigured.validate(authRequest(token)); reason != "" {
			t.Fatalf("reload did not apply the increased limit: reason=%q", reason)
		}
	}
	if reason := reconfigured.validate(authRequest(token)); reason != reasonCookieUseLimit {
		t.Fatalf("reload reset cookie uses: reason=%q", reason)
	}
	if reason := f.a.validate(authRequest(token)); reason != reasonCookieUseLimit {
		t.Fatalf("old authorizer did not share cookie uses with the replacement: reason=%q", reason)
	}
	updated.maxCookieUses = 5
	reconfigured, err = reconfigured.Reconfigure(updated, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if reason := reconfigured.validate(authRequest(token)); reason != "" {
		t.Fatalf("denied requests consumed cookie uses: reason=%q", reason)
	}
	if reason := reconfigured.validate(authRequest(token)); reason != reasonCookieUseLimit {
		t.Fatalf("cookie allowance was not exhausted after reload: reason=%q", reason)
	}
}

func TestEdgeSidecarJWT(t *testing.T) {
	f := newEdgeFixture(t)
	for name, change := range map[string]jwt.MapClaims{
		"Valid":          {},
		"WrongSitekey":   {"aud": "wrong"},
		"OriginAudience": {"aud": "https://example.com"},
		"WrongHost":      {"host": "other.example"},
		"WrongIssuer":    {"iss": "https://other.example"},
		"Expired":        {"exp": time.Now().Add(-time.Minute).Unix()},
		"Future":         {"iat": time.Now().Add(time.Minute).Unix()},
		"MissingExpiry":  {"exp": nil},
		"MissingIssued":  {"iat": nil},
		"Version":        {"v": 2},
		"TooLong":        {"exp": time.Now().Add(25 * time.Hour).Unix()},
		"NotBefore":      {"nbf": time.Now().Add(time.Minute).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(f.token(t, change, nil)))
			want := http.StatusUnauthorized
			if name == "Valid" {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("got %d, want %d", w.Code, want)
			}
		})
	}
	for name, value := range map[string]any{"typ": "JWT", "kid": nil, "jku": "https://evil.example/key", "x5u": "https://evil.example/key", "jwk": map[string]any{}, "crit": []string{"b64"}} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(f.token(t, nil, map[string]any{name: value})))
			if w.Code != 401 {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
	parts := strings.Split(f.token(t, nil, nil), ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	for _, raw := range []string{strings.Join(parts, "."), "malformed", ""} {
		w := httptest.NewRecorder()
		f.a.auth(w, authRequest(raw))
		if w.Code != 401 {
			t.Fatalf("invalid token returned %d", w.Code)
		}
	}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{})
	raw, _ := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	w := httptest.NewRecorder()
	f.a.auth(w, authRequest(raw))
	if w.Code != 401 {
		t.Fatal("unsigned token accepted")
	}
}

func TestEdgeSidecarIssuerNormalization(t *testing.T) {
	const canonical = "https://api.privatecaptcha.com"
	for _, tc := range []struct {
		name  string
		issue string
	}{
		{"TrailingSlash", "https://api.privatecaptcha.com/"},
		{"UppercaseScheme", "HTTPS://api.privatecaptcha.com"},
		{"MissingScheme", "api.privatecaptcha.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEdgeFixtureWithEnv(t, map[string]string{"PC_ISSUER": tc.issue})
			if f.s.issuer != canonical {
				t.Fatalf("configured issuer not normalized: got %q want %q", f.s.issuer, canonical)
			}
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(f.token(t, jwt.MapClaims{"iss": canonical}, nil)))
			if w.Code != http.StatusNoContent {
				t.Fatalf("canonical issuer token rejected with non-canonical PC_ISSUER=%q: status=%d body=%q", tc.issue, w.Code, w.Body.String())
			}
			w = httptest.NewRecorder()
			f.a.auth(w, authRequest(f.token(t, jwt.MapClaims{"iss": tc.issue}, nil)))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("raw (non-canonical) issuer token should be rejected after normalization: status=%d", w.Code)
			}
		})
	}
}

func TestEdgeSidecarIssuedAtLeeway(t *testing.T) {
	f := newEdgeFixture(t)
	ctx := context.Background()
	leeway := int64(tokenLeeway / time.Second)
	now := time.Now().Unix()
	for _, tc := range []struct {
		name string
		iat  int64
		want denialReason
	}{
		{"Current", now, ""},
		{"WithinLeeway", now + leeway, ""},
		{"JustWithinLeeway", now + leeway - 1, ""},
		{"BeyondLeeway", now + leeway + 10, reasonNotYetValid},
		{"FarFuture", now + 60, reasonNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, reason := f.a.verify(ctx, f.token(t, jwt.MapClaims{"iat": tc.iat}, nil), "example.com")
			if reason != tc.want {
				t.Fatalf("got reason %q, want %q", reason, tc.want)
			}
		})
	}
}

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/api"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"golang.org/x/net/html"
)

func hostedGate(t *testing.T, sitekey string) ([]byte, string) {
	t.Helper()
	var out bytes.Buffer
	if err := api.GatePageTemplate.Execute(&out, struct {
		Sitekey      string
		ScriptURL    string
		PuzzleURL    string
		StartMode    string
		Domain       string
		CompletePath string
	}{
		Sitekey:      sitekey,
		ScriptURL:    "//cdn.privatecaptcha.com/widget/js/privatecaptcha.js",
		PuzzleURL:    "//api.privatecaptcha.com/puzzle",
		StartMode:    "click",
		Domain:       "example.com",
		CompletePath: api.GateCompletePath,
	}); err != nil {
		t.Fatal(err)
	}
	z := html.NewTokenizer(bytes.NewReader(out.Bytes()))
	inline := false
	var script []byte
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				t.Fatal(z.Err())
			}
			if len(script) == 0 {
				t.Fatal("hosted gate has no inline script")
			}
			hash := sha256.Sum256(script)
			return out.Bytes(), "default-src 'none'; base-uri 'none'; object-src 'none'; form-action 'self'; script-src https://cdn.privatecaptcha.com 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "' 'wasm-unsafe-eval'; connect-src 'self' https://api.privatecaptcha.com; worker-src blob:; style-src 'unsafe-inline'; img-src data: https://cdn.privatecaptcha.com; frame-ancestors 'none'"
		case html.StartTagToken:
			token := z.Token()
			inline = token.Data == "script"
			for _, attr := range token.Attr {
				if attr.Key == "src" {
					inline = false
				}
			}
		case html.TextToken:
			if inline {
				script = append(script, z.Raw()...)
			}
		case html.EndTagToken:
			inline = false
		}
	}
}

func navigationRequest(token string) *http.Request {
	r := authRequest(token)
	r.Header.Set(HeaderAccept, "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	r.Header.Set(HeaderSecFetchMode, "navigate")
	r.Header.Set(HeaderSecFetchDest, "document")
	return r
}

func TestEdgeSidecarGateChallenge(t *testing.T) {
	f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "1"})
	body, csp := hostedGate(t, f.s.sitekey)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != gatePath || r.URL.Query().Get(common.ParamSiteKey) != f.s.sitekey ||
			r.Header.Get(common.HeaderAPIKey) != "" || r.Header.Get(HeaderCookie) != "" {
			t.Error("gate fetch escaped its configured public endpoint")
		}
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "public, max-age=300")
		w.Header().Set(HeaderSetCookie, "upstream=not-for-browser")
		w.Header().Set(common.HeaderETag, `"gate-v1"`)
		w.Write(body)
	}))
	for _, token := range []string{"", "invalid-token"} {
		w := httptest.NewRecorder()
		r := navigationRequest(token)
		r.AddCookie(&http.Cookie{
			Name:  "unrelated",
			Value: "browser-secret",
		})
		f.a.auth(w, r)
		if w.Code != 401 || !bytes.Contains(w.Body.Bytes(), []byte(`id="gate-form"`)) ||
			w.Header().Get(common.HeaderCacheControl) != cacheNoStore || w.Header().Get(HeaderSetCookie) != "" ||
			w.Header().Get(common.HeaderETag) != "" || w.Header().Get(common.HeaderXContentTypeOptions) != "nosniff" ||
			w.Header().Get(common.HeaderReferrerPolicy) != "no-referrer" || w.Header().Get(HeaderXFrameOptions) != "DENY" ||
			w.Header().Get(common.HeaderContentSecurityPolicy) != csp || !bytes.Equal(w.Body.Bytes(), body) {
			t.Fatalf("challenge status=%d headers=%v size=%d", w.Code, w.Header(), w.Body.Len())
		}
	}
	w := httptest.NewRecorder()
	token := f.token(t, nil, nil)
	f.a.auth(w, navigationRequest(token))
	if w.Code != 204 || calls.Load() != 1 {
		t.Fatal("valid cookie fetched challenge or challenge cache was not reused")
	}
	w = httptest.NewRecorder()
	f.a.auth(w, navigationRequest(token))
	if w.Code != http.StatusUnauthorized || !bytes.Equal(w.Body.Bytes(), body) ||
		w.Header().Get(common.HeaderCacheControl) != cacheNoStore || calls.Load() != 1 {
		t.Fatal("exhausted cookie did not receive the cached challenge")
	}
}

func TestEdgeSidecarGateNavigation(t *testing.T) {
	f := newEdgeFixture(t)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
	}{
		{"Fetch", func(r *http.Request) { r.Header.Set(HeaderSecFetchMode, "cors") }},
		{"Asset", func(r *http.Request) { r.Header.Set(HeaderSecFetchDest, "script") }},
		{"POST", func(r *http.Request) { r.Header.Set(HeaderForwardedMethod, http.MethodPost) }},
		{"HEAD", func(r *http.Request) { r.Header.Set(HeaderForwardedMethod, http.MethodHead) }},
		{"Untrusted", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:12345" }},
		{"WrongOrigin", func(r *http.Request) { r.Header.Set(HeaderForwardedHost, "other.example") }},
		{"NoHTML", func(r *http.Request) { r.Header.Set(HeaderAccept, "*/*") }},
		{"HTMLForbidden", func(r *http.Request) { r.Header.Set(HeaderAccept, "text/html;q=0") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := navigationRequest("")
			tc.edit(r)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != 401 || w.Body.Len() != 0 {
				t.Fatal("non-navigation did not get a simple denial")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("non-navigation fetched gate")
	}
}

func TestEdgeSidecarGateCache(t *testing.T) {
	for _, tc := range []struct {
		name string
		cc   string
		age  string
	}{
		{"Fresh", "max-age=300", "290"},
		{"SharedFresh", "max-age=1, s-maxage=300", "290"},
		{"NoStore", "no-store", ""},
		{"NoCache", "no-cache, max-age=300", ""},
		{"Private", "private, max-age=300", ""},
		{"Expires", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEdgeFixture(t)
			body, csp := hostedGate(t, f.s.sitekey)
			now := time.Now().UTC().Truncate(time.Second)
			date := now
			var calls atomic.Int32
			f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
				w.Header().Set(common.HeaderContentSecurityPolicy, csp)
				w.Header().Set(HeaderDate, date.Format(http.TimeFormat))
				w.Header().Set(HeaderAge, tc.age)
				w.Header().Set(common.HeaderCacheControl, tc.cc)
				if tc.name == "Expires" {
					w.Header().Set(HeaderExpires, date.Add(10*time.Second).Format(http.TimeFormat))
				}
				w.Write(body)
			}))
			f.a.gates.now = func() time.Time { return now }
			for i := 0; i < 2; i++ {
				w := httptest.NewRecorder()
				f.a.auth(w, navigationRequest(""))
				if w.Code != 401 || w.Body.Len() == 0 {
					t.Fatal("gate not returned")
				}
			}
			want := int32(1)
			if strings.HasPrefix(tc.cc, "no-") || strings.HasPrefix(tc.cc, "private") {
				want = 2
			}
			if calls.Load() != want {
				t.Fatalf("calls=%d want=%d", calls.Load(), want)
			}
			now = now.Add(11 * time.Second)
			f.a.auth(httptest.NewRecorder(), navigationRequest(""))
			if calls.Load() != want+1 {
				t.Fatal("expired gate did not refresh")
			}
		})
	}
}

func TestEdgeSidecarGateRevalidation(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	now := time.Now().UTC().Truncate(time.Second)
	date := now
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderDate, date.Format(http.TimeFormat))
		if calls.Add(1) == 1 {
			w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
			w.Header().Set(common.HeaderContentSecurityPolicy, csp)
			w.Header().Set(common.HeaderCacheControl, "max-age=1")
			w.Header().Set(common.HeaderETag, `"gate-v1"`)
			w.Write(body)
		} else {
			if r.Header.Get(common.HeaderIfNoneMatch) != `"gate-v1"` {
				t.Error("missing cache validator")
			}
			w.Header().Set(common.HeaderCacheControl, "max-age=300")
			w.WriteHeader(304)
		}
	}))
	f.a.gates.now = func() time.Time { return now }
	f.a.auth(httptest.NewRecorder(), navigationRequest(""))
	now = now.Add(2 * time.Second)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		f.a.auth(w, navigationRequest(""))
		if w.Body.Len() == 0 {
			t.Fatal("revalidated body missing")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("304 did not refresh cached freshness")
	}
}

func TestEdgeSidecarGateFailure(t *testing.T) {
	f := newEdgeFixture(t)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		csp    string
	}{
		{"Upstream", 503, "unavailable", ""},
		{"Redirect", 302, "", ""},
		{"MissingPolicy", 200, "upstream page", ""},
		{"Oversized", 200, strings.Repeat("a", 1024*1024+1), "default-src 'none'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
				w.Header().Set(common.HeaderContentSecurityPolicy, tc.csp)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			w := httptest.NewRecorder()
			f.a.auth(w, navigationRequest(""))
			if w.Code != 401 || w.Body.Len() != 0 {
				t.Fatal("bad gate did not fail closed")
			}
		})
	}
}

func TestEdgeSidecarGateConcurrent(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "max-age=300")
		w.Write(body)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			f.a.auth(w, navigationRequest(""))
			if w.Code != 401 || w.Body.Len() == 0 {
				t.Error("concurrent navigation lost its gate")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("gate requests were not coalesced")
	}
}

func TestEdgeSidecarGateCanceledCaller(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	entered := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	defer close(release)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
			return
		case <-release:
		}
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "max-age=300")
		w.Write(body)
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.a.gates.get(ctx)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled caller returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller waited for the shared fetch")
	}
	healthyDone := make(chan error, 1)
	go func() {
		page, err := f.a.gates.get(t.Context())
		if err == nil && !bytes.Equal(page.body, body) {
			err = errors.New("shared fetch returned an incorrect body")
		}
		healthyDone <- err
	}()
	release <- struct{}{}
	if err := <-healthyDone; err != nil {
		t.Fatalf("healthy caller lost its challenge: %v", err)
	}
	if _, err := f.a.gates.get(t.Context()); err != nil || calls.Load() != 1 {
		t.Fatalf("canceled caller poisoned the cache: calls=%d error=%v", calls.Load(), err)
	}
}

func TestEdgeSidecarGateExpiredFailure(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	var calls atomic.Int32
	var failed atomic.Bool
	now := time.Now().UTC().Truncate(time.Second)
	date := now
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "max-age=1")
		w.Header().Set(HeaderDate, date.Format(http.TimeFormat))
		w.Write(body)
	}))
	f.a.gates.now = func() time.Time { return now }
	f.a.auth(httptest.NewRecorder(), navigationRequest(""))
	failed.Store(true)
	now = now.Add(2 * time.Second)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		f.a.auth(w, navigationRequest(""))
		if w.Code != 401 || w.Body.Len() != 0 {
			t.Fatal("expired HTML was served after failed refresh")
		}
	}
	w := httptest.NewRecorder()
	f.a.auth(w, navigationRequest(f.token(t, nil, nil)))
	if w.Code != 204 || calls.Load() != 1+fetchAttempts {
		t.Fatal("gate failure affected cached token authorization or was not throttled")
	}
}

func TestEdgeSidecarLongQueryStringAuth(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	var gateCalls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gateCalls.Add(1)
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "public, max-age=300")
		w.Write(body)
	}))
	token := f.token(t, nil, nil)
	// A query that pushes r.RequestURI past maxRequestURI, simulating Caddy
	// forward_auth preserving the original query on the auth subrequest
	// (uri /auth without a trailing ? to clear the query string).
	longQuery := strings.Repeat("q", maxRequestURI)
	withLongQuery := func(r *http.Request) *http.Request {
		r.URL.RawQuery = longQuery
		r.RequestURI = r.URL.Path + "?" + longQuery
		if len(r.RequestURI) <= maxRequestURI {
			t.Fatalf("request URI not long enough: %d", len(r.RequestURI))
		}
		return r
	}

	// The length check must evaluate the auth path, not the echoed query string.
	// Validate should reach the cookie check and return "missing", not
	// "malformed_request".
	if reason := f.a.validate(withLongQuery(authRequest(""))); reason != reasonMissing {
		t.Fatalf("long-query no-cookie validate: got %q want %q", reason, reasonMissing)
	}

	// Unauthenticated browser navigation with a long query should receive the
	// hosted captcha challenge, not a bare empty 401.
	w := httptest.NewRecorder()
	f.a.auth(w, withLongQuery(navigationRequest("")))
	if w.Code != 401 || !bytes.Contains(w.Body.Bytes(), []byte(`id="gate-form"`)) {
		t.Fatalf("long-query navigation should get hosted challenge: status=%d body=%d bytes", w.Code, w.Body.Len())
	}
	if gateCalls.Load() != 1 {
		t.Fatal("long-query navigation did not fetch the gate")
	}

	// A valid edge cookie with a long query should authorize the request (204);
	// the length check no longer fires before the cookie is evaluated.
	w = httptest.NewRecorder()
	f.a.auth(w, withLongQuery(authRequest(token)))
	if w.Code != 204 {
		t.Fatalf("long-query with valid cookie should authorize: status=%d body=%q", w.Code, w.Body.String())
	}
	if gateCalls.Load() != 1 {
		t.Fatal("authorized request should not fetch the gate")
	}

	// Non-navigation with a long query and no cookie should get a bare 401
	// (no challenge), but the reason is "missing" rather than "malformed_request".
	w = httptest.NewRecorder()
	r := withLongQuery(authRequest(""))
	r.Header.Set(HeaderSecFetchMode, "cors")
	f.a.auth(w, r)
	if w.Code != 401 || w.Body.Len() != 0 {
		t.Fatalf("non-navigation long-query should get bare 401: status=%d body=%d bytes", w.Code, w.Body.Len())
	}

	// A body on the auth subrequest still triggers malformed_request; the
	// challenge is not served even for browser navigation.
	w = httptest.NewRecorder()
	r = navigationRequest("")
	r.ContentLength = 1
	f.a.auth(w, r)
	if w.Code != 401 || w.Body.Len() != 0 {
		t.Fatalf("bodied request should get bare 401: status=%d body=%d bytes", w.Code, w.Body.Len())
	}
	if gateCalls.Load() != 1 {
		t.Fatal("bodied request should not fetch the gate")
	}

	// The path-length limit still applies to the path itself: a path exceeding
	// maxRequestURI triggers malformed_request; a path of exactly maxRequestURI
	// does not.
	pathRequest := func(path string) *http.Request {
		pr := authRequest("")
		pr.URL.Path = path
		pr.RequestURI = path
		return pr
	}
	if reason := f.a.validate(pathRequest("/" + strings.Repeat("a", maxRequestURI))); reason != reasonMalformedRequest {
		t.Fatalf("oversized path should trigger malformed_request: got %q", reason)
	}
	if reason := f.a.validate(pathRequest("/" + strings.Repeat("a", maxRequestURI-1))); reason == reasonMalformedRequest {
		t.Fatal("path of exactly maxRequestURI should not be rejected")
	}
}

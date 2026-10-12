package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/golang-jwt/jwt/v5"
)

const fixtureProof = "AAAA.AAAA.AAAA"

func (f *edgeFixture) useAPI(t *testing.T, handler http.Handler) {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	f.keys.client.CloseIdleConnections()
	f.keys.client.Transport = upstream.Client().Transport
	f.s.apiBaseURL = upstream.URL
	var err error
	f.a, err = NewAuthorizer(f.s, f.keys)
	if err != nil {
		t.Fatal(err)
	}
}

func completionRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://sidecar/__privatecaptcha/complete", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header = authRequest("").Header.Clone()
	r.Header.Set(common.HeaderOrigin, "https://example.com")
	r.Header.Set(common.HeaderContentType, common.ContentTypeURLEncoded)
	r.Header.Set(HeaderSecFetchSite, "same-origin")
	return r
}

func proofForm(proof string) string {
	return url.Values{common.ParamPrivateCaptchaSolution: {proof}}.Encode()
}

func TestEdgeSidecarCompletionCookie(t *testing.T) {
	f := newEdgeFixture(t)
	token := f.token(t, nil, nil)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "edge_token": token})
	}))
	r := completionRequest(proofForm(fixtureProof))
	r.Header.Set(common.HeaderAPIKey, "attacker-key")
	r.Header.Set(common.HeaderSitekey, "attacker-sitekey")
	r.Header.Set(common.HeaderAuthorization, "attacker")
	r.Header.Set(HeaderCookie, "arbitrary=attacker")
	w := httptest.NewRecorder()
	f.a.complete(w, r)
	if w.Code != 204 || w.Body.Len() != 0 || w.Header().Get(common.HeaderCacheControl) != cacheNoStore {
		t.Fatalf("completion status=%d body=%q", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != edgeCookieName || cookie.Value != token || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" ||
		cookie.MaxAge <= 0 || cookie.MaxAge > 3600 || cookie.Expires.After(time.Now().Add(time.Hour)) {
		t.Fatal("cookie attributes or lifetime are incorrect")
	}
	if cookie.Expires.Sub(time.Now())+time.Second < time.Duration(cookie.MaxAge)*time.Second {
		t.Fatal("cookie Max-Age exceeds token expiry")
	}
	allowed := httptest.NewRecorder()
	f.a.auth(allowed, authRequest(cookie.Value))
	if allowed.Code != 204 || calls.Load() != 1 || f.jwksCalls.Load() != 1 {
		t.Fatal("cookie did not authorize locally")
	}
}

func TestEdgeSidecarCompletionBoundary(t *testing.T) {
	f := newEdgeFixture(t)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
		body string
		want int
	}{
		{"Untrusted", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:9000" }, "", 403},
		{"CrossOrigin", func(r *http.Request) { r.Header.Set(common.HeaderOrigin, "https://evil.example") }, "", 403},
		{"MissingOrigin", func(r *http.Request) { r.Header.Del(common.HeaderOrigin) }, "", 403},
		{"NullOrigin", func(r *http.Request) { r.Header.Set(common.HeaderOrigin, "null") }, "", 403},
		{"DuplicateOrigin", func(r *http.Request) { r.Header.Add(common.HeaderOrigin, "https://example.com") }, "", 403},
		{"CrossSite", func(r *http.Request) { r.Header.Set(HeaderSecFetchSite, "cross-site") }, "", 403},
		{"InvalidIP", func(r *http.Request) { r.Header.Set(common.HeaderClientIP, "192.0.2.1,192.0.2.2") }, "", 403},
		{"ContentType", func(r *http.Request) { r.Header.Set(common.HeaderContentType, common.ContentTypeJSON) }, "", 415},
		{"Empty", nil, "private-captcha-solution=", 400},
		{"MalformedForm", nil, "private-captcha-solution=%ZZ", 400},
		{"DuplicateProof", nil, proofForm(fixtureProof) + "&" + proofForm(fixtureProof), 400},
		{"ExtraField", nil, proofForm(fixtureProof) + "&sitekey=attacker", 400},
		{"Oversized", nil, strings.Repeat("a", 1024*1024+1), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if body == "" {
				body = proofForm(fixtureProof)
			}
			r := completionRequest(body)
			if tc.edit != nil {
				tc.edit(r)
			}
			w := httptest.NewRecorder()
			f.a.complete(w, r)
			if w.Code != tc.want || len(w.Result().Cookies()) != 0 || w.Header().Get(common.HeaderCacheControl) != cacheNoStore {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached verification API")
	}
}

func TestEdgeSidecarCompletionFailures(t *testing.T) {
	f := newEdgeFixture(t)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"Unsuccessful", 200, `{"success":false}`, 401},
		{"MissingToken", 200, `{"success":true}`, 401},
		{"InvalidToken", 200, `{"success":true,"edge_token":"invalid"}`, 401},
		{"ExpiredToken", 200, `{"success":true,"edge_token":"` + f.token(t, jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}, nil) + `"}`, 401},
		{"WrongAudience", 200, `{"success":true,"edge_token":"` + f.token(t, jwt.MapClaims{"aud": "wrong"}, nil) + `"}`, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			w := httptest.NewRecorder()
			f.a.complete(w, completionRequest(proofForm(fixtureProof)))
			if w.Code != tc.want || len(w.Result().Cookies()) != 0 {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestEdgeSidecarCompletionRateLimit(t *testing.T) {
	f := newEdgeFixture(t)
	var calls atomic.Int32
	token := f.token(t, nil, nil)
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "edge_token": token})
	}))
	for i := 0; i < 11; i++ {
		w := httptest.NewRecorder()
		f.a.complete(w, completionRequest(proofForm(fixtureProof)))
		if i < 10 && w.Code != 204 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
		if i == 10 && (w.Code != 429 || w.Header().Get(HeaderRetryAfter) == "" || len(w.Result().Cookies()) != 0) {
			t.Fatal("rate limit did not reject before cookie issuance")
		}
	}
	if calls.Load() != 10 {
		t.Fatal("rate-limited request reached API")
	}
	reconfigured, err := f.a.Reconfigure(f.s, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	reconfigured.complete(w, completionRequest(proofForm(fixtureProof)))
	if w.Code != http.StatusTooManyRequests || calls.Load() != 10 {
		t.Fatal("configuration reload reset the per-IP rate limit")
	}
}

func TestEdgeSidecarCompletionConcurrency(t *testing.T) {
	f := newEdgeFixture(t)
	f.s.maxConcurrentCompletions = 2
	entered := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	defer close(release)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
		io.WriteString(w, `{"success":false}`)
	}))
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		r := completionRequest(proofForm(fixtureProof))
		r.Header.Set(common.HeaderClientIP, fmt.Sprintf("2001:db8::%d", i+1))
		go func() {
			w := httptest.NewRecorder()
			f.a.complete(w, r)
			done <- w
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("completion did not reach the verification API")
		}
	}
	updated := f.s
	updated.maxConcurrentCompletions = 1
	reconfigured, err := f.a.Reconfigure(updated, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := completionRequest("")
	r.Header.Set(common.HeaderClientIP, "2001:db8::3")
	reconfigured.complete(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get(HeaderRetryAfter) == "" || len(w.Result().Cookies()) != 0 || calls.Load() != 2 {
		t.Fatalf("excess completion was not rejected before reading its form: status=%d calls=%d", w.Code, calls.Load())
	}
	allowed := httptest.NewRecorder()
	f.a.auth(allowed, authRequest(f.token(t, nil, nil)))
	if allowed.Code != http.StatusNoContent {
		t.Fatal("completion saturation blocked local authorization")
	}
	for i := 0; i < 2; i++ {
		release <- struct{}{}
		if result := <-done; result.Code != http.StatusUnauthorized {
			t.Fatalf("verification failure returned %d", result.Code)
		}
		if i == 0 {
			blocked := httptest.NewRecorder()
			reconfigured.complete(blocked, completionRequest(""))
			if blocked.Code != http.StatusTooManyRequests {
				t.Fatal("reload did not account for completions still using the old configuration")
			}
		}
	}
	release <- struct{}{}
	recovered := httptest.NewRecorder()
	reconfigured.complete(recovered, completionRequest(proofForm(fixtureProof)))
	if recovered.Code != http.StatusUnauthorized || calls.Load() != 3 {
		t.Fatal("finished completions did not release their concurrency slots")
	}
}

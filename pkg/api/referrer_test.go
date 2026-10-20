package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/maypok86/otter/v2"
)

func referralFixture(t *testing.T) *edgeFixture {
	t.Helper()
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
		w.Header().Set(common.HeaderContentSecurityPolicy, csp)
		w.Header().Set(common.HeaderCacheControl, "max-age=300")
		w.Write(body)
	}))
	return f
}

func captureReferral(t *testing.T, f *edgeFixture, uri, referer string) *http.Cookie {
	t.Helper()
	r := navigationRequest("")
	r.Header.Set(HeaderForwardedURI, uri)
	r.Header.Set(common.HeaderReferer, referer)
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusUnauthorized || w.Body.Len() == 0 {
		t.Fatalf("expected challenge, status=%d body bytes=%d", w.Code, w.Body.Len())
	}
	for _, cookie := range w.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "__Host-privatecaptcha-ref-") {
			return cookie
		}
	}
	t.Fatal("challenge did not set a referral-context cookie")
	return nil
}

func TestEdgeSidecarReferrerRestoration(t *testing.T) {
	f := referralFixture(t)
	const uri = "/private?utm_source=newsletter&tag=a&tag=b&return=%2Faccount"
	const referer = "https://referrer.example/news?campaign=original"
	cookie := captureReferral(t, f, uri, referer)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 300 {
		t.Fatalf("unexpected referral cookie attributes: %s", cookie.String())
	}
	if strings.Contains(cookie.Value, "referrer") || strings.Contains(cookie.Value, "campaign") {
		t.Fatal("referral cookie exposed referral data")
	}
	entry, found := f.a.referrals.GetEntry(cookie.Value)
	if !found || entry.ExpiresAfter() <= 0 || entry.ExpiresAfter() > 5*time.Minute {
		t.Fatal("referral context did not have a bounded lifetime")
	}
	unauthorized := navigationRequest("")
	unauthorized.Header.Set(HeaderForwardedURI, uri)
	unauthorized.AddCookie(cookie)
	denied := httptest.NewRecorder()
	f.a.auth(denied, unauthorized)
	if denied.Code != http.StatusUnauthorized || denied.Header().Get(HeaderAuthReferer) != "" {
		t.Fatal("referral context authorized an otherwise unauthorized request")
	}
	r := navigationRequest(f.token(t, nil, nil))
	r.Header.Set(HeaderForwardedURI, uri)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("X-PC-Referer") != referer {
		t.Fatalf("referrer was not restored: status=%d referer=%q", w.Code, w.Header().Get("X-PC-Referer"))
	}
	w = httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("X-PC-Referer") != "" {
		t.Fatal("referral context was reused")
	}
}

func TestEdgeSidecarReferrerIsolation(t *testing.T) {
	f := referralFixture(t)
	const firstURI = "/private?utm_source=first"
	const secondURI = "/private?utm_source=second"
	first := captureReferral(t, f, firstURI, "https://first.example/")
	second := captureReferral(t, f, secondURI, "https://second.example/")
	if first.Name == second.Name || first.Value == second.Value {
		t.Fatal("different URLs shared a referral-context cookie")
	}
	for _, tc := range []struct {
		uri     string
		referer string
	}{
		{
			uri:     secondURI,
			referer: "https://second.example/",
		},
		{
			uri:     firstURI,
			referer: "https://first.example/",
		},
	} {
		r := navigationRequest(f.token(t, nil, nil))
		r.Header.Set(HeaderForwardedURI, tc.uri)
		r.Header.Del(HeaderAccept)
		r.AddCookie(first)
		r.AddCookie(second)
		w := httptest.NewRecorder()
		f.a.auth(w, r)
		if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != tc.referer {
			t.Fatalf("nginx auth did not restore the matching URL's referrer: status=%d referer=%q", w.Code, w.Header().Get(HeaderAuthReferer))
		}
	}
}

func TestEdgeSidecarReferrerConsumption(t *testing.T) {
	for name, edit := range map[string]func(*http.Request){
		"OtherPath":  func(r *http.Request) { r.Header.Set(HeaderForwardedURI, "/other") },
		"OtherQuery": func(r *http.Request) { r.Header.Set(HeaderForwardedURI, "/private?x=2") },
		"MissingURI": func(r *http.Request) { r.Header.Del(HeaderForwardedURI) },
		"POST":       func(r *http.Request) { r.Header.Set(HeaderForwardedMethod, http.MethodPost) },
		"Fetch":      func(r *http.Request) { r.Header.Set(HeaderSecFetchMode, "cors") },
		"Asset":      func(r *http.Request) { r.Header.Set(HeaderSecFetchDest, "script") },
		"XHR":        func(r *http.Request) { r.Header.Set(HeaderXRequestedWith, "XMLHttpRequest") },
		"HTMX":       func(r *http.Request) { r.Header.Set(common.HeaderHtmxRequest, "true") },
		"LegacyFetch": func(r *http.Request) {
			r.Header.Del(HeaderSecFetchMode)
			r.Header.Del(HeaderSecFetchDest)
			r.Header.Set(HeaderAccept, "application/json")
		},
		"DuplicateCookie": func(r *http.Request) { r.Header.Add(HeaderCookie, r.Header.Get(HeaderCookie)) },
		"InvalidAuthorization": func(r *http.Request) {
			r.Header.Set(HeaderCookie, strings.ReplaceAll(r.Header.Get(HeaderCookie), edgeCookieName+"=", edgeCookieName+"=invalid"))
		},
		"Untrusted": func(r *http.Request) { r.RemoteAddr = "192.0.2.1:12345" },
	} {
		t.Run(name, func(t *testing.T) {
			f := referralFixture(t)
			const referer = "https://referrer.example/"
			cookie := captureReferral(t, f, "/private?x=1", referer)
			r := navigationRequest(f.token(t, nil, nil))
			r.AddCookie(cookie)
			edit(r)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Header().Get(HeaderAuthReferer) != "" {
				t.Fatal("nonmatching request restored the referrer")
			}
			r = navigationRequest(f.token(t, nil, nil))
			r.AddCookie(cookie)
			w = httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != referer {
				t.Fatal("nonmatching request consumed the referral context")
			}
		})
	}
}

func TestEdgeSidecarReferrerCurrentNavigation(t *testing.T) {
	f := referralFixture(t)
	cookie := captureReferral(t, f, "/private?x=1", "https://referrer.example/old")
	r := navigationRequest(f.token(t, nil, nil))
	r.AddCookie(cookie)
	const referer = "https://referrer.example/new"
	r.Header.Set(common.HeaderReferer, referer)
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != referer {
		t.Fatal("pending referral context overwrote a genuine incoming referrer")
	}
}

func TestEdgeSidecarReferrerTargetBinding(t *testing.T) {
	f := referralFixture(t)
	cookie := captureReferral(t, f, "/private?x=1", "https://referrer.example/")
	for _, origin := range []string{f.s.protectedOrigin, "https://example.com:8443"} {
		s := f.s
		s.protectedOrigin = origin
		a, err := f.a.Reconfigure(s, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		r := navigationRequest(f.token(t, nil, nil))
		if origin == f.s.protectedOrigin {
			r.Header.Set(HeaderForwardedURI, "/other")
		} else {
			r.Header.Set(HeaderForwardedHost, "example.com:8443")
		}
		target, ok := a.referralTarget(r)
		if !ok {
			t.Fatal("invalid test target")
		}
		forged := *cookie
		forged.Name = referralCookieName(target)
		r.AddCookie(&forged)
		w := httptest.NewRecorder()
		a.auth(w, r)
		if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != "" {
			t.Fatal("renaming a cookie restored another target's referrer")
		}
	}
	r := navigationRequest(f.token(t, nil, nil))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Header().Get(HeaderAuthReferer) != "https://referrer.example/" {
		t.Fatal("mismatched target consumed the original context")
	}
}

func TestEdgeSidecarReferrerChallengeReload(t *testing.T) {
	f := referralFixture(t)
	const referer = "https://referrer.example/"
	cookie := captureReferral(t, f, "/private?x=1", referer)
	for _, current := range []string{referer, ""} {
		r := navigationRequest("")
		r.AddCookie(cookie)
		if current != "" {
			r.Header.Set(common.HeaderReferer, current)
		}
		w := httptest.NewRecorder()
		f.a.auth(w, r)
		if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
			t.Fatal("challenge reload replaced the existing referral context")
		}
	}
	r := navigationRequest(f.token(t, nil, nil))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Header().Get(HeaderAuthReferer) != referer {
		t.Fatal("challenge reload lost the original referrer")
	}
}

func TestEdgeSidecarReferrerConcurrent(t *testing.T) {
	f := referralFixture(t)
	cookie := captureReferral(t, f, "/private?x=1", "https://referrer.example/")
	token := f.token(t, nil, nil)
	var restored atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := navigationRequest(token)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != http.StatusNoContent {
				t.Errorf("authorized navigation returned %d", w.Code)
			}
			if w.Header().Get(HeaderAuthReferer) != "" {
				restored.Add(1)
			}
		}()
	}
	wg.Wait()
	if restored.Load() != 1 {
		t.Fatalf("referral context was restored %d times, want 1", restored.Load())
	}
}

func TestEdgeSidecarReferrerCaptureBoundaries(t *testing.T) {
	f := referralFixture(t)
	for name, edit := range map[string]func(*http.Request){
		"Missing":   func(r *http.Request) { r.Header.Del(common.HeaderReferer) },
		"Oversized": func(r *http.Request) { r.Header.Set(common.HeaderReferer, strings.Repeat("a", maxRefererBytes+1)) },
		"Newline": func(r *http.Request) {
			r.Header.Set(common.HeaderReferer, "https://referrer.example/\r\nInjected: yes")
		},
		"Control":       func(r *http.Request) { r.Header.Set(common.HeaderReferer, "https://referrer.example/\x00") },
		"Duplicate":     func(r *http.Request) { r.Header.Add(common.HeaderReferer, "https://other.example/") },
		"OversizedURI":  func(r *http.Request) { r.Header.Set(HeaderForwardedURI, "/"+strings.Repeat("a", maxReferralURI)) },
		"MissingURI":    func(r *http.Request) { r.Header.Del(HeaderForwardedURI) },
		"DuplicateURI":  func(r *http.Request) { r.Header.Add(HeaderForwardedURI, "/other") },
		"NonNavigation": func(r *http.Request) { r.Header.Set(HeaderSecFetchMode, "cors") },
		"AuthOnly":      func(r *http.Request) { r.Header.Del(HeaderAccept) },
		"Untrusted":     func(r *http.Request) { r.RemoteAddr = "192.0.2.1:12345" },
	} {
		t.Run(name, func(t *testing.T) {
			r := navigationRequest("")
			r.Header.Set(common.HeaderReferer, "https://referrer.example/")
			edit(r)
			w := httptest.NewRecorder()
			f.a.auth(w, r)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatalf("invalid capture set a cookie: status=%d cookies=%d", w.Code, len(w.Result().Cookies()))
			}
		})
	}
}

type referralTestClock struct {
	now atomic.Int64
}

func (c *referralTestClock) NowNano() int64                      { return c.now.Load() }
func (c *referralTestClock) Tick(time.Duration) <-chan time.Time { return nil }

func TestEdgeSidecarReferrerCacheMiss(t *testing.T) {
	for _, expired := range []bool{false, true} {
		f := referralFixture(t)
		clock := &referralTestClock{}
		clock.now.Store(time.Now().UnixNano())
		f.a.referrals = otter.Must(&otter.Options[string, referral]{
			MaximumSize:      10,
			ExpiryCalculator: otter.ExpiryCreating[string, referral](referralTTL),
			Clock:            clock,
		})
		cookie := captureReferral(t, f, "/private?x=1", "https://referrer.example/")
		if expired {
			clock.now.Add(int64(referralTTL + time.Second))
		} else {
			f.a.referrals.InvalidateAll()
		}
		r := navigationRequest(f.token(t, nil, nil))
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.a.auth(w, r)
		if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != "" {
			t.Fatalf("cache miss affected forwarding: expired=%t status=%d referer=%q", expired, w.Code, w.Header().Get(HeaderAuthReferer))
		}
	}
}

func TestEdgeSidecarReferrerReload(t *testing.T) {
	f := referralFixture(t)
	const referer = "https://referrer.example/"
	cookie := captureReferral(t, f, "/private?x=1", referer)
	next, err := f.a.Reconfigure(f.s, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := navigationRequest(f.token(t, nil, nil))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	next.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != referer {
		t.Fatal("configuration reload lost the referral context")
	}
	w = httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get(HeaderAuthReferer) != "" {
		t.Fatal("configuration reload allowed referral context reuse")
	}
}

func TestEdgeSidecarReferrerForwarding(t *testing.T) {
	f := newEdgeFixture(t)
	r := authRequest(f.token(t, nil, nil))
	const referer = "https://referrer.example/current?source=ordinary"
	r.Header.Set(common.HeaderReferer, referer)
	r.Header.Set("X-PC-Referer", "https://attacker.example/")
	w := httptest.NewRecorder()
	f.a.auth(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("X-PC-Referer") != referer {
		t.Fatalf("ordinary referrer was not retained: status=%d referer=%q", w.Code, w.Header().Get("X-PC-Referer"))
	}
}

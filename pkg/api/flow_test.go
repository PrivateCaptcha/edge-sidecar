package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

func TestEdgeSidecarFlow(t *testing.T) {
	f := newEdgeFixture(t)
	body, csp := hostedGate(t, f.s.sitekey)
	token := f.token(t, nil, nil)
	var gateCalls, verifyCalls, appCalls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gate/page":
			gateCalls.Add(1)
			w.Header().Set(common.HeaderContentType, common.ContentTypeHTML)
			w.Header().Set(common.HeaderContentSecurityPolicy, csp)
			w.Header().Set(common.HeaderCacheControl, "max-age=300")
			w.Write(body)
		case "/verify":
			verifyCalls.Add(1)
			proof, _ := io.ReadAll(r.Body)
			if string(proof) != fixtureProof || r.Header.Get(common.HeaderAPIKey) != f.s.apiKey || r.Header.Get(common.HeaderSitekey) != f.s.sitekey {
				t.Error("verification contract mismatch")
			}
			w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
			json.NewEncoder(w).Encode(map[string]any{"success": true, "edge_token": token})
		default:
			t.Errorf("unexpected upstream endpoint: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	router := http.NewServeMux()
	f.a.Setup(router)
	// Model Caddy's bodyless pre-check and completion bypass using the real routes.
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(HeaderForwardedHost, "example.com")
		r.Header.Set(HeaderForwardedProto, "https")
		r.Header.Set(common.HeaderClientIP, "192.0.2.1")
		if r.URL.Path == completePath {
			router.ServeHTTP(w, r)
			return
		}
		auth := httptest.NewRequest(http.MethodGet, "http://sidecar/auth", nil)
		auth.RemoteAddr = r.RemoteAddr
		auth.Header = r.Header.Clone()
		auth.Header.Del(common.HeaderContentLength)
		auth.Header.Set(HeaderForwardedMethod, r.Method)
		auth.Header.Set(HeaderForwardedURI, r.URL.RequestURI())
		check := httptest.NewRecorder()
		router.ServeHTTP(check, auth)
		if check.Code == 204 {
			r.Header.Set(common.HeaderReferer, check.Header().Get(HeaderAuthReferer))
			appCalls.Add(1)
			w.Header().Set("X-Demo-Referer", r.Referer())
			io.WriteString(w, "application reached")
			return
		}
		for name, values := range check.Header() {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.WriteHeader(check.Code)
		w.Write(check.Body.Bytes())
	}))
	t.Cleanup(gateway.Close)
	client := gateway.Client()
	client.Jar, _ = cookiejar.New(nil)
	navigate := func(referer string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, gateway.URL+"/private?demo=1", nil)
		r.Host = "example.com"
		r.Header = navigationRequest("").Header.Clone()
		r.Header.Set(HeaderForwardedHost, "attacker.example")
		if referer != "" {
			r.Header.Set(common.HeaderReferer, referer)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	const referer = "https://referrer.example/"
	response := navigate(referer)
	challenge, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 401 || string(challenge) != string(body) || appCalls.Load() != 0 || verifyCalls.Load() != 0 {
		t.Fatal("no-cookie request did not stop at hosted challenge")
	}
	r, _ := http.NewRequest(http.MethodPost, gateway.URL+completePath, strings.NewReader(proofForm(fixtureProof)))
	r.Host = "example.com"
	r.Header = completionRequest("").Header.Clone()
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || len(response.Cookies()) != 1 || appCalls.Load() != 0 {
		t.Fatal("completion did not bypass auth and issue cookie")
	}
	response = navigate("")
	allowed, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(allowed) != "application reached" || appCalls.Load() != 1 || gateCalls.Load() != 1 || verifyCalls.Load() != 1 || f.jwksCalls.Load() != 1 {
		t.Fatal("cookie did not permit application access with local verification")
	}
	if response.Header.Get("X-Demo-Referer") != referer {
		t.Fatal("challenge completion lost the original referrer")
	}
	response = navigate("")
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Demo-Referer") != "" {
		t.Fatal("later navigation reused the original referral context")
	}
}

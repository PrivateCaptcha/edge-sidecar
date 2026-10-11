package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

func TestEdgeSidecarProxyServiceName(t *testing.T) {
	f := newEdgeFixture(t)
	f.a.s.trustedProxies = nil
	f.a.s.trustedProxyHosts = []string{"caddy"}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	var lookupErr error
	f.a.s.lookupProxy = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "caddy" {
			t.Fatal("proxy lookup did not use the fixed configured service name")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("proxy lookup is not time bounded")
		}
		return addresses, lookupErr
	}
	token := f.token(t, nil, nil)
	authorize := func(peer string, want int) {
		t.Helper()
		r := authRequest(token)
		r.RemoteAddr = peer
		w := httptest.NewRecorder()
		f.a.auth(w, r)
		if w.Code != want {
			t.Fatalf("peer %s returned %d, want %d", peer, w.Code, want)
		}
	}
	authorize("192.0.2.10:8080", 204)
	authorize("[2001:db8::10]:8080", 204)
	authorize("192.0.2.11:8080", 401)

	addresses = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	authorize("192.0.2.20:8080", 204)
	authorize("192.0.2.10:8080", 401)
	lookupErr = errors.New("DNS unavailable")
	authorize("192.0.2.20:8080", 401)
	lookupErr = nil
	addresses = nil
	authorize("192.0.2.20:8080", 401)
}

func TestEdgeSidecarProxyServiceNameCompletion(t *testing.T) {
	f := newEdgeFixture(t)
	token := f.token(t, nil, nil)
	var calls atomic.Int32
	f.useAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(common.HeaderContentType, common.ContentTypeJSON)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "edge_token": token})
	}))
	f.a.s.trustedProxies = nil
	f.a.s.trustedProxyHosts = []string{"caddy"}
	f.a.s.lookupProxy = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	r := completionRequest(proofForm(fixtureProof))
	r.RemoteAddr = "192.0.2.11:8080"
	w := httptest.NewRecorder()
	f.a.complete(w, r)
	if w.Code != 403 || len(w.Result().Cookies()) != 0 || calls.Load() != 0 {
		t.Fatal("completion trusted a peer not belonging to Caddy")
	}
	r = completionRequest(proofForm(fixtureProof))
	r.RemoteAddr = "192.0.2.10:8080"
	w = httptest.NewRecorder()
	f.a.complete(w, r)
	if w.Code != 204 || len(w.Result().Cookies()) != 1 || calls.Load() != 1 {
		t.Fatal("completion through the discovered Caddy peer did not issue a cookie")
	}
}

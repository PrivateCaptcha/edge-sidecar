package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

func TestEdgeSidecarProxyServiceName(t *testing.T) {
	f := newEdgeFixtureWithEnv(t, map[string]string{"PC_MAX_COOKIE_USES": "200"})
	f.a.s.trustedProxies = nil
	f.a.s.trustedProxyHosts = []string{"caddy"}
	now := time.Now()
	f.a.s.proxyDNS.now = func() time.Time { return now }
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	var lookupErr error
	var lookups atomic.Int32
	f.a.s.lookupProxy = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups.Add(1)
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
	for i := 0; i < 100; i++ {
		authorize("192.0.2.10:8080", 204)
	}
	if lookups.Load() != 1 {
		t.Fatalf("warm authorization performed %d DNS lookups", lookups.Load())
	}

	addresses = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	authorize("192.0.2.10:8080", 204)
	authorize("192.0.2.20:8080", 401)
	now = now.Add(proxyDNSTTL)
	authorize("192.0.2.20:8080", 204)
	authorize("192.0.2.10:8080", 401)
	lookupErr = errors.New("DNS unavailable")
	now = now.Add(proxyDNSTTL)
	authorize("192.0.2.20:8080", 401)
	authorize("192.0.2.20:8080", 401)
	if lookups.Load() != 3 {
		t.Fatal("DNS errors were not briefly cached")
	}
	lookupErr = nil
	now = now.Add(proxyTimeout)
	authorize("192.0.2.20:8080", 204)
	addresses = nil
	now = now.Add(proxyDNSTTL)
	authorize("192.0.2.20:8080", 401)
}

func TestEdgeSidecarProxyCanceledLookup(t *testing.T) {
	f := newEdgeFixture(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	defer close(release)
	var calls atomic.Int32
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	f.a.s.lookupProxy = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		return addresses, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.a.s.proxyDNS.lookup(ctx, "caddy", f.a.s.lookupProxy)
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
		t.Fatal("canceled caller waited for the shared lookup")
	}
	healthyDone := make(chan error, 1)
	go func() {
		addrs, err := f.a.s.proxyDNS.lookup(t.Context(), "caddy", f.a.s.lookupProxy)
		if err != nil || len(addrs) != 1 || addrs[0] != addresses[0] {
			err = errors.New("shared lookup returned an incorrect result")
		}
		healthyDone <- err
	}()
	release <- struct{}{}
	if err := <-healthyDone; err != nil {
		t.Fatalf("healthy caller lost its result: %v", err)
	}
	if _, err := f.a.s.proxyDNS.lookup(t.Context(), "caddy", f.a.s.lookupProxy); err != nil || calls.Load() != 1 {
		t.Fatalf("canceled caller poisoned the cache: calls=%d error=%v", calls.Load(), err)
	}
}

func TestEdgeSidecarProxyDNSParallel(t *testing.T) {
	f := newEdgeFixture(t)
	const n = 10
	const latency = 80 * time.Millisecond
	var calls atomic.Int32
	f.a.s.lookupProxy = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		calls.Add(1)
		select {
		case <-time.After(latency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "host" + strconv.Itoa(i)
			if _, err := f.a.s.proxyDNS.lookup(t.Context(), host, f.a.s.lookupProxy); err != nil {
				t.Errorf("lookup %s failed: %v", host, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if calls.Load() != n {
		t.Fatalf("expected %d lookups, got %d", n, calls.Load())
	}
	if elapsed >= time.Duration(n)*latency/2 {
		t.Fatalf("lookups serialized: %d lookups took %v (expected ~%v)", n, elapsed, latency)
	}
}

func TestEdgeSidecarProxyDNSSingleFlight(t *testing.T) {
	f := newEdgeFixture(t)
	const n = 20
	entered := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	defer close(release)
	var calls atomic.Int32
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	f.a.s.lookupProxy = func(context.Context, string, string) ([]netip.Addr, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return addresses, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := f.a.s.proxyDNS.lookup(t.Context(), "caddy", f.a.s.lookupProxy)
			if err != nil || len(addrs) != 1 || addrs[0] != addresses[0] {
				t.Errorf("coalesced lookup returned %v (err %v)", addrs, err)
			}
		}()
	}
	<-entered
	release <- struct{}{}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected a single coalesced lookup, got %d", calls.Load())
	}
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

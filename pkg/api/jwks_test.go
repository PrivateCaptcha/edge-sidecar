package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testJWK(t *testing.T, key *ecdsa.PrivateKey, kid string) jwk {
	t.Helper()
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return jwk{
		Kty: "EC",
		Crv: "P-256",
		Alg: keyAlgorithm,
		Use: "sig",
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(point[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(point[33:]),
	}
}

func TestEdgeSidecarJWKSWaitingDeadline(t *testing.T) {
	f := newEdgeFixture(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	key := testJWK(t, f.key, "fixture-key")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		json.NewEncoder(w).Encode(map[string]any{"keys": []jwk{key}})
	}))
	t.Cleanup(upstream.Close)
	f.keys.url = upstream.URL
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		f.keys.RunOnce(t.Context(), nil)
	}()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	lookupDone := make(chan struct{})
	go func() {
		defer close(lookupDone)
		f.keys.lookup(ctx, "unknown")
	}()
	select {
	case <-lookupDone:
	case <-time.After(100 * time.Millisecond):
		t.Error("canceled request waited for an unrelated refresh")
	}
	close(release)
	<-refreshDone
	<-lookupDone
}

func TestEdgeSidecarJWKSRotationAndFailure(t *testing.T) {
	f := newEdgeFixture(t)
	rotated := newEdgeFixture(t)
	var calls atomic.Int32
	var failed atomic.Bool
	var malformed atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/.well-known/jwks.json" {
			t.Error("JWKS escaped fixed URL")
		}
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		keys := []jwk{testJWK(t, f.key, "fixture-key"), testJWK(t, rotated.key, "rotated-key")}
		if malformed.Load() {
			keys = nil
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(upstream.Close)
	f.keys.url = upstream.URL + "/.well-known/jwks.json"
	token := rotated.token(t, nil, map[string]any{"kid": "rotated-key"})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(token))
			if w.Code != 204 {
				t.Error("rotated token not authorized")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("unknown-kid requests did not share a refresh")
	}
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		f.a.auth(w, authRequest(f.token(t, nil, map[string]any{"kid": "unknown"})))
		if w.Code != 401 {
			t.Fatal("unknown key accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unknown key caused refresh flooding")
	}
	for _, failure := range []bool{true, false} {
		failed.Store(failure)
		malformed.Store(!failure)
		if err := f.keys.RunOnce(t.Context(), nil); err == nil {
			t.Fatal("invalid refresh succeeded")
		}
		for _, raw := range []string{token, f.token(t, nil, nil)} {
			w := httptest.NewRecorder()
			f.a.auth(w, authRequest(raw))
			if w.Code != 204 {
				t.Fatal("refresh failure discarded cached keys")
			}
		}
	}
}

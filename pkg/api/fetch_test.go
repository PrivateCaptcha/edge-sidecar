package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestEdgeSidecarFetchRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		calls  int32
	}{
		{"Unavailable", http.StatusServiceUnavailable, 2},
		{"RateLimited", http.StatusTooManyRequests, 2},
		{"Forbidden", http.StatusForbidden, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(tc.status)
					return
				}
				io.WriteString(w, "fresh response")
			}))
			t.Cleanup(upstream.Close)
			req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
			response, err := fetch(t.Context(), upstream.Client(), req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || calls.Load() != tc.calls {
				t.Fatalf("calls=%d error=%v", calls.Load(), err)
			}
			if tc.calls > 1 && (response.StatusCode != http.StatusOK || string(body) != "fresh response") {
				t.Fatal("retry did not recover or returned a canceled response body")
			}
		})
	}
}

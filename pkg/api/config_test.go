package api

import (
	"testing"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
)

func TestEdgeSidecarConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"PC_API_KEY", ""},
		{"PC_API_KEY", "secret\r\nInjected: yes"},
		{"PC_PROTECTED_ORIGIN", ""},
		{"PC_PROTECTED_ORIGIN", "http://example.com"},
		{"PC_PROTECTED_ORIGIN", "https://example.com/path"},
		{"PC_TRUSTED_PROXY_CIDRS", ""},
		{"PC_TRUSTED_PROXY_CIDRS", "not-an-IP"},
		{"PC_API_BASE_URL", "http://example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testEnv()
			env[tc.name] = tc.value
			if _, err := LoadSettings(config.NewEnvConfig(func(name string) string { return env[name] })); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestEdgeSidecarConfigProxyServiceName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names string
		valid bool
	}{
		{"Single", "caddy", true},
		{"Multiple", "caddy, caddy-secondary.internal", true},
		{"Missing", "", false},
		{"URL", "https://caddy", false},
		{"Port", "caddy:8080", false},
		{"Wildcard", "*", false},
		{"EmptyEntry", "caddy,,other", false},
		{"IP", "192.0.2.10", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testEnv()
			delete(env, "PC_TRUSTED_PROXY_CIDRS")
			env["PC_TRUSTED_PROXY_HOSTS"] = tc.names
			s, err := LoadSettings(config.NewEnvConfig(func(name string) string { return env[name] }))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && (len(s.trustedProxies) != 0 || len(s.trustedProxyHosts) == 0) {
				t.Fatal("hostname-only proxy trust was not configured")
			}
		})
	}
}

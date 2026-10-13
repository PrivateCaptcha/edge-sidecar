package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
)

const (
	jwksURLKey common.ConfigKey = common.COMMON_CONFIG_KEYS_COUNT + iota
	issuerKey
	sitekeyKey
	jwksRefreshIntervalKey
	apiKeyKey
	protectedOriginKey
	trustedProxiesKey
	trustedProxyHostsKey
	maxConcurrentCompletionsKey
)

type Settings struct {
	Address                  string
	jwksURL                  string
	issuer                   string
	sitekey                  string
	refreshInterval          time.Duration
	apiBaseURL               string
	apiKey                   string
	protectedOrigin          string
	trustedProxies           []netip.Prefix
	trustedProxyHosts        []string
	lookupProxy              func(context.Context, string, string) ([]netip.Addr, error)
	maxConcurrentCompletions int
	proxyDNS                 *proxyDNSCache
}

func RegisterConfig() error {
	for key, name := range map[common.ConfigKey]string{
		jwksURLKey:                  "PC_JWKS_URL",
		issuerKey:                   "PC_ISSUER",
		sitekeyKey:                  "PC_SITEKEY",
		jwksRefreshIntervalKey:      "PC_JWKS_REFRESH_INTERVAL",
		apiKeyKey:                   "PC_API_KEY",
		protectedOriginKey:          "PC_PROTECTED_ORIGIN",
		trustedProxiesKey:           "PC_TRUSTED_PROXY_CIDRS",
		trustedProxyHostsKey:        "PC_TRUSTED_PROXY_HOSTS",
		maxConcurrentCompletionsKey: "PC_MAX_CONCURRENT_COMPLETIONS",
	} {
		if err := config.RegisterEnvNameForConfigKey(key, name); err != nil {
			return err
		}
	}
	return nil
}

func LoadSettings(cfg common.ConfigStore) (Settings, error) {
	value := func(key common.ConfigKey, fallback string) string {
		if s := cfg.Get(key).Value(); s != "" {
			return s
		}
		return fallback
	}
	port := value(common.PortKey, "8080")
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Settings{}, errors.New("PC_PORT must be a port between 1 and 65535")
	}
	maxCompletions, err := strconv.Atoi(value(maxConcurrentCompletionsKey, "512"))
	if err != nil || maxCompletions < 1 {
		return Settings{}, errors.New("PC_MAX_CONCURRENT_COMPLETIONS must be a positive integer")
	}
	s := Settings{
		Address:                  net.JoinHostPort(value(common.HostKey, "localhost"), port),
		jwksURL:                  value(jwksURLKey, "https://api.privatecaptcha.com"+jwksPath),
		issuer:                   value(issuerKey, "https://api.privatecaptcha.com"),
		sitekey:                  value(sitekeyKey, ""),
		refreshInterval:          5 * time.Minute,
		apiBaseURL:               strings.TrimRight(value(common.APIBaseURLKey, "https://api.privatecaptcha.com"), "/"),
		apiKey:                   value(apiKeyKey, ""),
		lookupProxy:              net.DefaultResolver.LookupNetIP,
		maxConcurrentCompletions: maxCompletions,
	}
	if s.sitekey == "" || len(s.sitekey) > 128 || strings.ContainsAny(s.sitekey, " \t\r\n") {
		return Settings{}, errors.New("PC_SITEKEY must be a nonempty sitekey")
	}
	for key, item := range map[common.ConfigKey]struct{ raw, name string }{
		jwksURLKey:           {raw: s.jwksURL, name: "PC_JWKS_URL"},
		issuerKey:            {raw: s.issuer, name: "PC_ISSUER"},
		common.APIBaseURLKey: {raw: s.apiBaseURL, name: "PC_API_BASE_URL"},
	} {
		parsed, err := upstreamURL(key, item.raw)
		if err != nil {
			return Settings{}, fmt.Errorf("invalid upstream URL configuration for %s: %w", item.name, err)
		}
		switch key {
		case jwksURLKey:
			s.jwksURL = parsed
		case issuerKey:
			s.issuer = parsed
		case common.APIBaseURLKey:
			s.apiBaseURL = parsed
		}
	}
	if !strings.HasPrefix(s.apiBaseURL, "https://") {
		return Settings{}, errors.New("PC_API_BASE_URL must use HTTPS for the official verification client")
	}
	if raw := cfg.Get(jwksRefreshIntervalKey).Value(); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil || interval < time.Second || interval > 24*time.Hour {
			return Settings{}, errors.New("PC_JWKS_REFRESH_INTERVAL must be between 1s and 24h")
		}
		s.refreshInterval = interval
	}
	if s.apiKey == "" || len(s.apiKey) > 4096 || strings.TrimSpace(s.apiKey) != s.apiKey || strings.ContainsAny(s.apiKey, "\r\n") {
		return Settings{}, errors.New("PC_API_KEY must be a nonempty valid API key")
	}
	s.protectedOrigin, _, err = normalizeOrigin(value(protectedOriginKey, ""))
	if err != nil {
		return Settings{}, errors.New("PC_PROTECTED_ORIGIN must be an HTTPS origin without a path, query, or fragment")
	}
	if raw := value(trustedProxiesKey, ""); raw != "" {
		for entry := range strings.SplitSeq(raw, ",") {
			entry = strings.TrimSpace(entry)
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				ip, iperr := netip.ParseAddr(entry)
				if iperr != nil {
					return Settings{}, errors.New("PC_TRUSTED_PROXY_CIDRS must contain valid proxy IPs or CIDRs")
				}
				prefix = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
			}
			if prefix.Bits() == 0 || len(s.trustedProxies) >= 256 {
				return Settings{}, errors.New("PC_TRUSTED_PROXY_CIDRS must contain bounded, specific proxy networks")
			}
			s.trustedProxies = append(s.trustedProxies, prefix.Masked())
		}
	}
	if raw := value(trustedProxyHostsKey, ""); raw != "" {
		for entry := range strings.SplitSeq(raw, ",") {
			host, err := normalizeHostname(strings.TrimSpace(entry))
			if err != nil || len(s.trustedProxyHosts) >= 16 {
				return Settings{}, errors.New("PC_TRUSTED_PROXY_HOSTS must contain up to 16 valid proxy hostnames without ports")
			}
			s.trustedProxyHosts = append(s.trustedProxyHosts, host)
		}
	}
	if len(s.trustedProxies) == 0 && len(s.trustedProxyHosts) == 0 {
		return Settings{}, errors.New("PC_TRUSTED_PROXY_CIDRS or PC_TRUSTED_PROXY_HOSTS is required")
	}
	return s, nil
}

func upstreamURL(key common.ConfigKey, raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + strings.TrimPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("must be a URL without credentials, query, or fragment")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid URL port")
		}
	}
	address := config.AsURL(context.Background(), config.NewStaticValue(key, u.Host+u.EscapedPath()))
	if u.Scheme == "https" || (u.Scheme == "http" && common.IsLocalhost(address.Domain())) {
		return u.Scheme + ":" + address.URL(), nil
	}
	return "", errors.New("must use HTTPS (HTTP is allowed only on localhost for local development)")
}

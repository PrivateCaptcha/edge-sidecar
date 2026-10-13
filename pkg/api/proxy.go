package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
	realclientip "github.com/realclientip/realclientip-go"
)

type proxyDNSResult struct {
	addresses []netip.Addr
	err       error
	expiresAt time.Time
}

type proxyDNSFlight struct {
	done      chan struct{}
	addresses []netip.Addr
	err       error
}

type proxyDNSCache struct {
	mu      sync.Mutex
	entries map[string]proxyDNSResult
	flights map[string]*proxyDNSFlight
	now     func() time.Time
}

func (c *proxyDNSCache) lookup(ctx context.Context, host string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	c.mu.Lock()
	if result, found := c.entries[host]; found && c.now().Before(result.expiresAt) {
		c.mu.Unlock()
		return result.addresses, result.err
	}
	flight := c.flights[host]
	if flight == nil {
		flight = &proxyDNSFlight{done: make(chan struct{})}
		if c.flights == nil {
			c.flights = make(map[string]*proxyDNSFlight)
		}
		c.flights[host] = flight
		go c.fetch(context.WithoutCancel(ctx), host, lookup, flight)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-flight.done:
		return flight.addresses, flight.err
	}
}

func (c *proxyDNSCache) fetch(ctx context.Context, host string, lookup func(context.Context, string, string) ([]netip.Addr, error), flight *proxyDNSFlight) {
	ctx, cancel := context.WithTimeout(ctx, proxyTimeout)
	defer cancel()
	addresses, err := lookup(ctx, "ip", host)
	c.mu.Lock()
	if ctx.Err() != context.Canceled {
		ttl := proxyDNSTTL
		if err != nil || len(addresses) == 0 {
			ttl = proxyTimeout
		}
		c.entries[host] = proxyDNSResult{
			addresses: addresses,
			err:       err,
			expiresAt: c.now().Add(ttl),
		}
	}
	delete(c.flights, host)
	flight.addresses, flight.err = addresses, err
	close(flight.done)
	c.mu.Unlock()
}

func singleHeader(r *http.Request, name string) (string, error) {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], " ,\t\r\n") {
		return "", errInvalidHost
	}
	return values[0], nil
}

func normalizeOrigin(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", errInvalidHost
	}
	host, err := normalizeHostname(u.Hostname())
	if err != nil {
		return "", "", err
	}
	authority := host
	if strings.Contains(u.Host, ":") {
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil || port == "" || strings.Trim(port, "0123456789") != "" {
			return "", "", errInvalidHost
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", errInvalidHost
		}
		if n != 443 {
			authority = net.JoinHostPort(host, strconv.Itoa(n))
		}
	}
	address := config.AsURL(context.Background(), config.NewStaticValue(protectedOriginKey, authority))
	return "https:" + address.URL(), address.Domain(), nil
}

func (s Settings) requestHost(r *http.Request) (string, error) {
	peer := (realclientip.RemoteAddrStrategy{}).ClientIP(r.Header, r.RemoteAddr)
	ip, err := netip.ParseAddr(peer)
	if err != nil {
		slog.WarnContext(r.Context(), "Proxy peer address is invalid", "endpoint", r.URL.Path)
		return "", errInvalidHost
	}
	trusted := false
	for _, prefix := range s.trustedProxies {
		trusted = trusted || prefix.Contains(ip.Unmap())
	}
	if !trusted && len(s.trustedProxyHosts) != 0 {
		ctx, cancel := context.WithTimeout(r.Context(), proxyTimeout)
		defer cancel()
		for _, host := range s.trustedProxyHosts {
			addresses, err := s.proxyDNS.lookup(ctx, host, s.lookupProxy)
			if err != nil {
				slog.WarnContext(ctx, "Trusted proxy hostname lookup failed", "endpoint", r.URL.Path,
					"proxy_host", host, common.ErrAttr(err))
				continue
			}
			for _, address := range addresses {
				trusted = trusted || address.Unmap() == ip.Unmap()
			}
			if trusted {
				break
			}
		}
	}
	if !trusted {
		slog.WarnContext(r.Context(), "Request peer is not a trusted proxy", "endpoint", r.URL.Path, "proxy_peer", peer)
		return "", errInvalidHost
	}
	host, err := singleHeader(r, HeaderForwardedHost)
	if err != nil {
		slog.WarnContext(r.Context(), "Forwarded header is missing or malformed", "endpoint", r.URL.Path,
			"header", HeaderForwardedHost, "header_count", len(r.Header.Values(HeaderForwardedHost)))
		return "", err
	}
	proto, err := singleHeader(r, HeaderForwardedProto)
	if err != nil {
		slog.WarnContext(r.Context(), "Forwarded header is missing or malformed", "endpoint", r.URL.Path,
			"header", HeaderForwardedProto, "header_count", len(r.Header.Values(HeaderForwardedProto)))
		return "", err
	}
	origin, hostname, err := normalizeOrigin(proto + "://" + host)
	if err != nil {
		slog.WarnContext(r.Context(), "Forwarded origin is invalid", "endpoint", r.URL.Path,
			"expected_origin", s.protectedOrigin, "https", proto == "https")
		return "", errInvalidHost
	}
	if origin != s.protectedOrigin {
		slog.WarnContext(r.Context(), "Forwarded origin does not match protected origin", "endpoint", r.URL.Path,
			"origin", origin, "expected_origin", s.protectedOrigin)
		return "", errInvalidHost
	}
	slog.Log(r.Context(), common.LevelTrace, "Validated proxy request", "endpoint", r.URL.Path,
		"proxy_peer", peer, "origin", origin)
	return hostname, nil
}

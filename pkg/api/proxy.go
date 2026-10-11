package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
	realclientip "github.com/realclientip/realclientip-go"
)

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
			addresses, err := s.lookupProxy(ctx, "ip", host)
			if err != nil {
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
		return "", errInvalidHost
	}
	host, err := singleHeader(r, HeaderForwardedHost)
	if err != nil {
		return "", err
	}
	proto, err := singleHeader(r, HeaderForwardedProto)
	if err != nil {
		return "", err
	}
	origin, hostname, err := normalizeOrigin(proto + "://" + host)
	if err != nil || origin != s.protectedOrigin {
		return "", errInvalidHost
	}
	return hostname, nil
}

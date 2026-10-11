package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

const (
	unknownKeyRefreshGap = 10 * time.Second
	maxJWKSBytes         = 1024 * 1024
	maxJWKSKeys          = 64
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type KeyCache struct {
	common.StubPeriodicJob
	url                string
	interval           time.Duration
	client             *http.Client
	mu                 sync.RWMutex
	keys               map[string]*ecdsa.PublicKey
	refreshGate        chan struct{}
	lastUnknownRefresh time.Time
}

func NewKeyCache(s Settings) *KeyCache {
	return &KeyCache{
		StubPeriodicJob: "refresh_edge_jwks",
		url:             s.jwksURL,
		interval:        s.refreshInterval,
		refreshGate:     make(chan struct{}, 1),
		client: &http.Client{
			Timeout: fetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy:                  http.ProxyFromEnvironment,
				DialContext:            (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				TLSHandshakeTimeout:    3 * time.Second,
				ResponseHeaderTimeout:  3 * time.Second,
				IdleConnTimeout:        60 * time.Second,
				MaxIdleConnsPerHost:    1,
				MaxResponseHeaderBytes: 16 * 1024,
			},
		},
	}
}

func (c *KeyCache) CloseIdleConnections() { c.client.CloseIdleConnections() }

func (c *KeyCache) Interval() time.Duration { return c.interval }
func (*KeyCache) Timeout() time.Duration    { return fetchTimeout }

func (c *KeyCache) RunOnce(ctx context.Context, _ any) error {
	return c.refresh(ctx, false)
}

func (c *KeyCache) cached(kid string) *ecdsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

func (c *KeyCache) lookup(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if key := c.cached(kid); key != nil {
		return key, nil
	}
	if err := c.refresh(ctx, true); err != nil {
		return nil, errUnknownKey
	}
	if key := c.cached(kid); key != nil {
		return key, nil
	}
	return nil, errUnknownKey
}

func (c *KeyCache) refresh(ctx context.Context, unknown bool) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.refreshGate <- struct{}{}:
	}
	defer func() { <-c.refreshGate }()
	if unknown {
		if time.Since(c.lastUnknownRefresh) < unknownKeyRefreshGap {
			return nil
		}
		c.lastUnknownRefresh = time.Now()
	}
	keys, err := c.fetch(ctx)
	if err != nil {
		slog.WarnContext(ctx, "JWKS refresh failed; keeping cached keys", common.ErrAttr(err))
		return err
	}
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	slog.InfoContext(ctx, "Refreshed JWKS", "keys", len(keys))
	return nil
}

func (c *KeyCache) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderAccept, common.ContentTypeJSON)
	response, err := fetch(ctx, c.client, req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("JWKS response is too large")
	}
	var document struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, errors.New("malformed JWKS response")
	}
	if len(document.Keys) == 0 || len(document.Keys) > maxJWKSKeys {
		return nil, errors.New("JWKS has an invalid key count")
	}
	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))
	for _, entry := range document.Keys {
		if entry.Kty != keyType || entry.Crv != keyCurve || entry.Alg != keyAlgorithm || entry.Use != keyUse || entry.Kid == "" || len(entry.Kid) > maxKeyIDBytes {
			return nil, errors.New("JWKS contains an unsupported key")
		}
		if _, duplicate := keys[entry.Kid]; duplicate {
			return nil, errors.New("JWKS contains a duplicate key ID")
		}
		x, xerr := base64.RawURLEncoding.Strict().DecodeString(entry.X)
		y, yerr := base64.RawURLEncoding.Strict().DecodeString(entry.Y)
		if xerr != nil || yerr != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("JWKS contains invalid coordinates")
		}
		point := append([]byte{4}, x...)
		point = append(point, y...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, errors.New("JWKS contains an invalid public key")
		}
		keys[entry.Kid] = key
	}
	return keys, nil
}

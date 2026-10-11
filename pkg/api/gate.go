package api

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

var errGateUnavailable = errors.New("gate unavailable")

type gatePage struct {
	body      []byte
	headers   http.Header
	upstream  http.Header
	expiresAt time.Time
	cacheable bool
}

type gateFlight struct {
	done chan struct{}
	page *gatePage
	err  error
}

type gateCache struct {
	url        string
	client     *http.Client
	now        func() time.Time
	mu         sync.Mutex
	entry      *gatePage
	flight     *gateFlight
	retryAfter time.Time
}

func (c *gateCache) get(ctx context.Context) (*gatePage, error) {
	c.mu.Lock()
	now := c.now()
	if c.entry != nil && now.Before(c.entry.expiresAt) {
		page := c.entry
		c.mu.Unlock()
		return page, nil
	}
	if flight := c.flight; flight != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-flight.done:
			return flight.page, flight.err
		}
	}
	if now.Before(c.retryAfter) {
		c.mu.Unlock()
		return nil, errGateUnavailable
	}
	flight := &gateFlight{
		done: make(chan struct{}),
	}
	c.flight = flight
	previous := c.entry
	c.mu.Unlock()

	page, err := c.fetch(ctx, previous)
	c.mu.Lock()
	if err != nil {
		c.retryAfter = c.now().Add(gateRetryGap)
	} else {
		c.entry = nil
		if page.cacheable {
			c.entry = page
		}
		c.retryAfter = time.Time{}
	}
	flight.page, flight.err = page, err
	c.flight = nil
	close(flight.done)
	c.mu.Unlock()
	return page, err
}

func (c *gateCache) fetch(ctx context.Context, previous *gatePage) (*gatePage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, errGateUnavailable
	}
	req.Header.Set(HeaderAccept, "text/html")
	if previous != nil {
		if etag := previous.upstream.Get(common.HeaderETag); etag != "" {
			req.Header.Set(common.HeaderIfNoneMatch, etag)
		}
		if modified := previous.upstream.Get(HeaderLastModified); modified != "" {
			req.Header.Set(HeaderIfModifiedSince, modified)
		}
	}
	started := c.now()
	response, err := fetch(ctx, c.client, req)
	if err != nil {
		return nil, errGateUnavailable
	}
	defer response.Body.Close()
	upstream := response.Header.Clone()
	var body []byte
	switch response.StatusCode {
	case http.StatusOK:
		mediaType, _, err := mime.ParseMediaType(upstream.Get(common.HeaderContentType))
		if err != nil || mediaType != "text/html" {
			return nil, errGateUnavailable
		}
		body, err = io.ReadAll(response.Body)
		if err != nil || len(body) == 0 {
			return nil, errGateUnavailable
		}
	case http.StatusNotModified:
		if previous == nil || (req.Header.Get(common.HeaderIfNoneMatch) == "" && req.Header.Get(HeaderIfModifiedSince) == "") {
			return nil, errGateUnavailable
		}
		merged := previous.upstream.Clone()
		merged.Del(HeaderAge)
		for name, values := range upstream {
			merged[name] = append([]string(nil), values...)
		}
		upstream = merged
		body = previous.body
	default:
		return nil, errGateUnavailable
	}
	policies := upstream.Values(common.HeaderContentSecurityPolicy)
	if len(policies) == 0 || policies[0] == "" {
		return nil, errGateUnavailable
	}
	headers := http.Header(common.SecurityHeaders).Clone()
	headers.Set(common.HeaderContentType, common.ContentTypeHTML)
	headers.Set(common.HeaderCacheControl, cacheNoStore)
	headers[common.HeaderContentSecurityPolicy] = append([]string(nil), policies...)
	headers.Set(common.HeaderReferrerPolicy, "no-referrer")
	headers.Set(common.HeaderXRobotsTag, "noindex, nofollow")
	now := c.now()
	expiresAt, cacheable := gateFreshness(upstream, now, now.Sub(started))
	return &gatePage{
		body:      body,
		headers:   headers,
		upstream:  upstream,
		expiresAt: expiresAt,
		cacheable: cacheable,
	}, nil
}

func gateFreshness(h http.Header, now time.Time, delay time.Duration) (time.Time, bool) {
	maxAge, sharedAge := int64(-1), int64(-1)
	revalidate := false
	for part := range strings.SplitSeq(strings.Join(h.Values(common.HeaderCacheControl), ","), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(name) {
		case "no-store", "private":
			return now, false
		case "no-cache":
			revalidate = true
		case "max-age", "s-maxage":
			seconds, err := strconv.ParseInt(strings.Trim(value, "\""), 10, 64)
			if err != nil || seconds < 0 || seconds > int64(maxGateTTL/time.Second) {
				revalidate = true
			} else if strings.EqualFold(name, "s-maxage") {
				sharedAge = seconds
			} else {
				maxAge = seconds
			}
		}
	}
	if sharedAge >= 0 {
		maxAge = sharedAge
	}
	date, dateErr := http.ParseTime(h.Get(HeaderDate))
	if maxAge < 0 {
		expires, err := http.ParseTime(h.Get(HeaderExpires))
		if err != nil {
			return now, true
		}
		base := now
		if dateErr == nil {
			base = date
		}
		maxAge = int64(expires.Sub(base) / time.Second)
	}
	if revalidate || maxAge <= 0 {
		return now, true
	}
	age := time.Duration(0)
	if dateErr == nil {
		age = max(age, now.Sub(date))
	}
	if raw := h.Get(HeaderAge); raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || seconds < 0 || seconds > int64(maxGateTTL/time.Second) {
			return now, true
		}
		age = max(age, time.Duration(seconds)*time.Second+delay)
	}
	maxAge = min(maxAge, int64(maxGateTTL/time.Second))
	return now.Add(time.Duration(maxAge)*time.Second - age), true
}

func browserNavigation(r *http.Request) bool {
	method, err := singleHeader(r, HeaderForwardedMethod)
	if err != nil || method != http.MethodGet || r.Header.Get(HeaderXRequestedWith) != "" || r.Header.Get(common.HeaderHtmxRequest) != "" {
		return false
	}
	mode, dest := r.Header.Values(HeaderSecFetchMode), r.Header.Values(HeaderSecFetchDest)
	if (len(mode) != 0 || len(dest) != 0) && (len(mode) != 1 || len(dest) != 1 || mode[0] != "navigate" || dest[0] != "document") {
		return false
	}
	for part := range strings.SplitSeq(strings.Join(r.Header.Values(HeaderAccept), ","), ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || mediaType != "text/html" {
			continue
		}
		if q, present := params["q"]; present {
			quality, err := strconv.ParseFloat(q, 64)
			if err == nil && quality > 0 && quality <= 1 {
				return true
			}
			continue
		}
		return true
	}
	return false
}

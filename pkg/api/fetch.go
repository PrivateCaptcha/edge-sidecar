package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/jpillora/backoff"
)

func fetch(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	b := &backoff.Backoff{
		Min:    100 * time.Millisecond,
		Max:    time.Second,
		Factor: 2,
		Jitter: true,
	}
	var response *http.Response
	var err error
	for attempt := 0; attempt < fetchAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(b.Duration()):
			}
		}
		response, err = doFetch(client, req.Clone(ctx))
		var retryable common.RetriableError
		if err == nil || !errors.As(err, &retryable) {
			break
		}
		err = retryable.Unwrap()
		slog.WarnContext(ctx, "Upstream fetch failed", "attempt", attempt+1, common.ErrAttr(err))
	}
	return response, err
}

func doFetch(client *http.Client, req *http.Request) (*http.Response, error) {
	response, err := client.Do(req)
	if err != nil {
		return nil, common.NewRetriableError(err)
	}
	status := response.StatusCode
	if status >= http.StatusInternalServerError || status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status == http.StatusTooEarly {
		response.Body.Close()
		return nil, common.NewRetriableError(fmt.Errorf("upstream HTTP status %d", status))
	}
	if err := bufferResponse(response, maxGateBytes); err != nil {
		return nil, err
	}
	return response, nil
}

type verificationTransport struct {
	http.RoundTripper
}

func (t verificationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if err := bufferResponse(response, maxVerifyBytes); err != nil {
		return nil, err
	}
	return response, nil
}

func bufferResponse(response *http.Response, limit int64) error {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return common.NewRetriableError(err)
	}
	if int64(len(data)) > limit {
		return errors.New("upstream response is too large")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	return nil
}

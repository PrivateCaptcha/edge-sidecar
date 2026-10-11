package privatecaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jpillora/backoff"
)

var (
	headerApiKey      = http.CanonicalHeaderKey("X-Api-Key")
	headerTraceID     = http.CanonicalHeaderKey("X-Trace-ID")
	headerUserAgent   = http.CanonicalHeaderKey("User-Agent")
	headerRetryAfter  = http.CanonicalHeaderKey("Retry-After")
	headerRateLimit   = http.CanonicalHeaderKey("X-RateLimit-Limit")
	headerContentType = http.CanonicalHeaderKey("Content-Type")
	headerSitekey     = http.CanonicalHeaderKey("X-PC-Sitekey")
	errEmptyAPIKey    = errors.New("privatecaptcha: API key is empty")
	errEmtpySolution  = errors.New("privatecaptcha: solution is empty")
)

const (
	GlobalDomain     = "api.privatecaptcha.com"
	EUDomain         = "api.eu.privatecaptcha.com"
	DefaultFormField = "private-captcha-solution"
	Version          = "0.0.6"
	minBackoffMillis = 500
	userAgent        = "private-captcha-go/" + Version
)

// HTTPError represents an error with an associated HTTP status code
type HTTPError struct {
	TraceID    string
	StatusCode int
	Seconds    int
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("privatecaptcha: HTTP error %d", e.StatusCode)
}

// GetStatusCode returns the HTTP status code if the error is an HTTPError
func GetStatusCode(err error) (int, bool) {
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode, true
	}
	return 0, false
}

type Configuration struct {
	// (optional) Domain name when used with self-hosted version of Private Captcha
	Domain string
	// (required) API key created in Private Captcha account settings
	APIKey string
	// (optional) Custom form field to read puzzle solution from (only used for VerifyRequest helper)
	FormField string
	// (optional) Custom http.Client to use with requests
	Client *http.Client
	// (optional) http status to return for failed verifications (defaults to http.StatusForbidden)
	FailedStatusCode int
}

type Client struct {
	endpoint         string
	apiKey           string
	formField        string
	failedStatusCode int
	client           *http.Client
}

// NewClient creates a new instance of Private Captcha API client
func NewClient(cfg Configuration) (*Client, error) {
	if len(cfg.APIKey) == 0 {
		return nil, errEmptyAPIKey
	}

	if len(cfg.Domain) == 0 {
		cfg.Domain = GlobalDomain
	} else if strings.HasPrefix(cfg.Domain, "http") {
		cfg.Domain = strings.TrimPrefix(cfg.Domain, "https://")
		cfg.Domain = strings.TrimPrefix(cfg.Domain, "http://")
	}

	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}

	if len(cfg.FormField) == 0 {
		cfg.FormField = DefaultFormField
	}

	if cfg.FailedStatusCode == 0 {
		cfg.FailedStatusCode = http.StatusForbidden
	}

	return &Client{
		endpoint:         fmt.Sprintf("https://%s/verify", strings.Trim(cfg.Domain, "/")),
		apiKey:           cfg.APIKey,
		client:           cfg.Client,
		formField:        cfg.FormField,
		failedStatusCode: cfg.FailedStatusCode,
	}, nil
}

// retriableError is a wrapper for errors that should be retried.
type retriableError struct {
	err error
}

func (e retriableError) Error() string {
	return e.err.Error()
}

func (e retriableError) Unwrap() error {
	return e.err
}

func (c *Client) doVerify(ctx context.Context, solution, sitekey string, headers []string) (*VerifyOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(solution))
	if err != nil {
		slog.Log(ctx, levelTrace, "Failed to create HTTP request", errAttr(err))
		return nil, err
	}

	req.Header.Set(headerApiKey, c.apiKey)
	req.Header.Set(headerUserAgent, userAgent)
	req.Header.Set(headerContentType, "text/plain")
	if len(sitekey) > 0 {
		req.Header.Set(headerSitekey, sitekey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Log(ctx, levelTrace, "Failed to send HTTP request", "path", req.URL.Path, "method", req.Method, errAttr(err))
		return nil, retriableError{err}
	}
	defer resp.Body.Close()

	traceID := resp.Header.Get(headerTraceID)

	slog.Log(ctx, levelTrace, "HTTP request finished", "path", req.URL.Path, "status", resp.StatusCode, "traceID", traceID)

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		httpErr := HTTPError{StatusCode: resp.StatusCode, TraceID: traceID}
		if retryAfter := resp.Header.Get(headerRetryAfter); len(retryAfter) > 0 {
			slog.Log(ctx, levelTrace, "Rate limited", "retryAfter", retryAfter, "rateLimit", resp.Header.Get(headerRateLimit))
			if value, aerr := strconv.Atoi(retryAfter); aerr == nil {
				httpErr.Seconds = value
			} else {
				slog.Log(ctx, levelTrace, "Failed to parse Retry-After header", "retryAfter", retryAfter, errAttr(aerr))
			}
		}

		return nil, retriableError{httpErr}
	case http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusBadGateway,
		http.StatusGatewayTimeout,
		http.StatusRequestTimeout,
		http.StatusTooEarly:
		return nil, retriableError{HTTPError{StatusCode: resp.StatusCode, TraceID: traceID}}
	}

	if resp.StatusCode >= 300 {
		return nil, HTTPError{StatusCode: resp.StatusCode, TraceID: traceID}
	}

	metadata := make(map[string]string)
	for _, header := range headers {
		metadata[header] = resp.Header.Get(header)
	}

	response := &VerifyOutput{requestID: traceID, metadata: metadata}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return response, retriableError{err}
	}

	return response, nil
}

type VerifyInput struct {
	Solution          string
	MaxBackoffSeconds int
	Attempts          int
	Headers           []string
	Sitekey           string
}

// Verify will verify CAPTCHA solution obtained from the client-side. Solution usually comes as part of the form.
// In case of errors, can use VerificationResponse.RequestID() for tracing.
func (c *Client) Verify(ctx context.Context, input VerifyInput) (*VerifyOutput, error) {
	if len(input.Solution) == 0 {
		return nil, errEmtpySolution
	}

	attempts := 5
	if input.Attempts > 0 {
		attempts = input.Attempts
	}

	maxBackoffSeconds := 20
	if input.MaxBackoffSeconds > 0 {
		maxBackoffSeconds = input.MaxBackoffSeconds
	}

	b := &backoff.Backoff{
		Min:    minBackoffMillis * time.Millisecond,
		Max:    time.Duration(maxBackoffSeconds) * time.Second,
		Factor: 2,
		Jitter: true,
	}

	var response *VerifyOutput
	var err error
	var i int

	slog.Log(ctx, levelTrace, "About to start verifying solution", "maxAttempts", attempts, "maxBackoff", maxBackoffSeconds, "solution", len(input.Solution))

	for i = 0; i < attempts; i++ {
		if i > 0 {
			backoffDuration := b.Duration()
			var httpErr HTTPError
			if (err != nil) && errors.As(err, &httpErr) {
				if int64(httpErr.Seconds)*1000 > backoffDuration.Milliseconds() {
					backoffDuration = time.Duration(min(httpErr.Seconds, maxBackoffSeconds)) * time.Second
				}
			}
			slog.Log(ctx, levelTrace, "Failed to send verify request", "attempt", i, "backoff", backoffDuration.String(), errAttr(err))
			select {
			case <-ctx.Done():
				if response == nil {
					response = &VerifyOutput{Success: false, Code: VERIFY_CODES_COUNT}
				}
				return response, ctx.Err()
			case <-time.After(backoffDuration):
			}
		}

		response, err = c.doVerify(ctx, input.Solution, input.Sitekey, input.Headers)
		var rerr retriableError
		if (err != nil) && errors.As(err, &rerr) {
			err = rerr.Unwrap()
		} else {
			break
		}
	}

	slog.Log(ctx, levelTrace, "Finished verifying solution", "attempts", i, "success", (err == nil))

	if response == nil {
		response = &VerifyOutput{Success: false, Code: VERIFY_CODES_COUNT}
	}
	response.attempt = i

	return response, err
}

// VerifyRequest fetches puzzle solution from HTTP form field configured on creation and calls Verify() with defaults
func (c *Client) VerifyRequest(ctx context.Context, r *http.Request) error {
	solution := r.FormValue(c.formField)

	output, err := c.Verify(ctx, VerifyInput{Solution: solution})
	if err != nil {
		return err
	}

	if !output.OK() {
		return fmt.Errorf("captcha verification failed: %v", output.Error())
	}

	return nil
}

// VerifyFunc is a basic http middleware that verifies captcha solution sent via form
func (c *Client) VerifyFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.VerifyRequest(r.Context(), r); err != nil {
			http.Error(w, http.StatusText(c.failedStatusCode), c.failedStatusCode)
			return
		}

		next.ServeHTTP(w, r)
	})
}

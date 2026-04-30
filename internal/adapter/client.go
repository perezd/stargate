// Package adapter provides the HTTP client used by agent hook adapters
// to communicate with the stargate classification server.
package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ClientConfig holds HTTP client settings resolved from flags/env.
type ClientConfig struct {
	URL         string        // resolved from --url / STARGATE_URL / default
	Timeout     time.Duration // provided by caller
	AllowRemote bool          // --allow-remote flag
	Verbose     bool          // --verbose flag
}

// ClassifyRequest is the adapter's view of the classify request.
// Matches the server's expected JSON but defined locally to avoid
// importing the classifier package in the thin hook client.
type ClassifyRequest struct {
	Command string         `json:"command"`
	CWD     string         `json:"cwd,omitempty"`
	Context map[string]any `json:"context,omitempty"`
}

// ClassifyResponse is the adapter's view of the classify response.
// Only the fields the adapter needs — not the full server response.
type ClassifyResponse struct {
	Decision      string  `json:"decision"`
	Action        string  `json:"action"`
	Reason        string  `json:"reason"`
	Guidance      string  `json:"guidance,omitempty"`
	StargateTrID  string  `json:"stargate_trace_id"`
	FeedbackToken *string `json:"feedback_token"`
}

// FeedbackRequest is the POST /feedback body.
type FeedbackRequest struct {
	StargateTrID  string         `json:"stargate_trace_id"`
	ToolUseID     string         `json:"tool_use_id"`
	FeedbackToken string         `json:"feedback_token"`
	Outcome       string         `json:"outcome"`
	Context       map[string]any `json:"context,omitempty"`
}

// ValidateURL checks that the URL is well-formed and uses http or https.
// Unless AllowRemote is set, the host must also be a literal loopback address
// (127.0.0.1 or ::1). "localhost" is explicitly rejected because DNS
// resolution could point elsewhere.
func (c ClientConfig) ValidateURL() error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("adapter: invalid URL %q: %w", c.URL, err)
	}

	// Validate scheme and host are present.
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("adapter: URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("adapter: URL %q has no host", c.URL)
	}

	if c.AllowRemote {
		return nil
	}

	// Extract the hostname without port. url.Hostname() handles both
	// "host:port" and bare "host" forms, including IPv6 bracket notation.
	hostname := u.Hostname()

	// Reject the string "localhost" — DNS could resolve it to a non-loopback addr.
	if strings.EqualFold(hostname, "localhost") {
		return fmt.Errorf("adapter: URL host %q is not a literal loopback address (use 127.0.0.1 or ::1)", hostname)
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		return fmt.Errorf("adapter: URL host %q is not a loopback address (use 127.0.0.1 or ::1)", hostname)
	}

	if !ip.IsLoopback() {
		return fmt.Errorf("adapter: URL host %q is not a loopback address (use 127.0.0.1 or ::1)", hostname)
	}

	return nil
}

// Classify sends POST /classify and returns the parsed response.
// Retries exactly once on connection refused after a 100ms delay.
func Classify(ctx context.Context, cfg ClientConfig, req ClassifyRequest) (*ClassifyResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("adapter: marshal classify request: %w", err)
	}

	endpoint := strings.TrimRight(cfg.URL, "/") + "/classify"
	resp, err := doPostWithRetry(ctx, cfg, endpoint, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var result ClassifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("adapter: decode classify response: %w", err)
	}

	return &result, nil
}

// SendFeedback sends POST /feedback. Returns error on failure.
// Caller decides whether to log/ignore the error (fire-and-forget).
func SendFeedback(ctx context.Context, cfg ClientConfig, req FeedbackRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("adapter: marshal feedback request: %w", err)
	}

	endpoint := strings.TrimRight(cfg.URL, "/") + "/feedback"
	resp, err := doPostWithRetry(ctx, cfg, endpoint, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return readErrorResponse(resp)
	}

	return nil
}

// doPostWithRetry performs a POST request and retries exactly once on
// connection refused, waiting 100ms between attempts.
func doPostWithRetry(ctx context.Context, cfg ClientConfig, url string, body []byte) (*http.Response, error) {
	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	do := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("adapter: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		return client.Do(req)
	}

	resp, err := do()
	if err != nil && isConnectionRefused(err) {
		// Close the response body from the failed attempt if present.
		if resp != nil {
			resp.Body.Close() //nolint:errcheck
		}
		// Retry exactly once after a short delay.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		resp, err = do()
	}

	if err != nil && resp != nil {
		resp.Body.Close() //nolint:errcheck
	}

	return resp, err
}

// isConnectionRefused returns true when the error represents a TCP
// connection-refused condition. It checks both the stdlib sentinel and the
// error message for robustness across platforms and wrapping depths.
func isConnectionRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(err.Error(), "connection refused")
}

// IsServerUnavailable returns true when the error indicates the stargate
// server could not be reached — timeout, connection refused, or DNS failure.
// Callers use this to fall back to prompting the user instead of failing hard.
func IsServerUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if isConnectionRefused(err) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// readErrorResponse reads the response body (truncated to 200 chars) and
// returns a descriptive error containing the HTTP status code and body.
func readErrorResponse(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 201))
	body := string(data)
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	return fmt.Errorf("adapter: server returned %d: %s", resp.StatusCode, strings.TrimSpace(body))
}

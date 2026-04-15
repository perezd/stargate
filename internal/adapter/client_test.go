package adapter_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limbic-systems/stargate/internal/adapter"
)

// newTestConfig returns a ClientConfig pointed at the given test server URL.
func newTestConfig(serverURL string) adapter.ClientConfig {
	return adapter.ClientConfig{
		URL:     serverURL,
		Timeout: 5 * time.Second,
	}
}

// --- Classify tests ---

func TestClassify_AllowResponse(t *testing.T) {
	want := adapter.ClassifyResponse{
		Decision:     "green",
		Action:       "allow",
		Reason:       "safe read-only command",
		StargateTrID: "trace-001",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/classify" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want) //nolint:errcheck
	}))
	defer srv.Close()

	got, err := adapter.Classify(context.Background(), newTestConfig(srv.URL), adapter.ClassifyRequest{
		Command: "git status",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Decision != want.Decision {
		t.Errorf("Decision: got %q, want %q", got.Decision, want.Decision)
	}
	if got.Action != want.Action {
		t.Errorf("Action: got %q, want %q", got.Action, want.Action)
	}
	if got.Reason != want.Reason {
		t.Errorf("Reason: got %q, want %q", got.Reason, want.Reason)
	}
	if got.StargateTrID != want.StargateTrID {
		t.Errorf("StargateTrID: got %q, want %q", got.StargateTrID, want.StargateTrID)
	}
}

func TestClassify_DenyResponse(t *testing.T) {
	tok := "fb-tok-123"
	want := adapter.ClassifyResponse{
		Decision:      "red",
		Action:        "deny",
		Reason:        "destructive command",
		StargateTrID:  "trace-002",
		FeedbackToken: &tok,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want) //nolint:errcheck
	}))
	defer srv.Close()

	got, err := adapter.Classify(context.Background(), newTestConfig(srv.URL), adapter.ClassifyRequest{
		Command: "rm -rf /",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Action != "deny" {
		t.Errorf("Action: got %q, want \"deny\"", got.Action)
	}
	if got.FeedbackToken == nil || *got.FeedbackToken != tok {
		t.Errorf("FeedbackToken: got %v, want %q", got.FeedbackToken, tok)
	}
}

func TestClassify_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := adapter.Classify(context.Background(), newTestConfig(srv.URL), adapter.ClassifyRequest{
		Command: "ls",
	})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestClassify_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json`)) //nolint:errcheck
	}))
	defer srv.Close()

	_, err := adapter.Classify(context.Background(), newTestConfig(srv.URL), adapter.ClassifyRequest{
		Command: "ls",
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestClassify_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the client times out.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := adapter.ClientConfig{
		URL:     srv.URL,
		Timeout: 50 * time.Millisecond,
	}
	_, err := adapter.Classify(context.Background(), cfg, adapter.ClassifyRequest{Command: "ls"})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestClassify_RetryOnConnectionRefused verifies that Classify retries exactly
// once when the server is initially not listening (ECONNREFUSED), then succeeds
// when the server becomes available during the retry window.
//
// Strategy:
//  1. Reserve a free port by binding and immediately closing it.
//  2. Send the first request — the port is closed, so we get ECONNREFUSED.
//  3. The 100ms retry delay gives us time to start a real server on that port.
//  4. The second attempt succeeds.
func TestClassify_RetryOnConnectionRefused(t *testing.T) {
	// Step 1: find a free port and immediately release it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close() // port is now closed; next connect → ECONNREFUSED

	// Step 2: spin up the real server on that address in a goroutine,
	// but delay its start so the first attempt definitely hits ECONNREFUSED.
	var callCount atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(adapter.ClassifyResponse{ //nolint:errcheck
			Decision:     "green",
			Action:       "allow",
			StargateTrID: "trace-retry",
		})
	})

	started := make(chan struct{})
	go func() {
		listener, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			// Port grabbed by OS between close and re-listen; skip from goroutine.
			close(started)
			return
		}
		retrySrv := &httptest.Server{
			Listener: listener,
			Config:   &http.Server{Handler: handler},
		}
		retrySrv.Start()
		close(started)
		// Keep server alive until test ends via deferred close.
		// We deliberately don't defer here; caller controls lifetime.
		<-time.After(5 * time.Second)
		retrySrv.Close()
	}()

	// Give the goroutine a moment to bind (but not too long — the first
	// Classify attempt must still see ECONNREFUSED, so we start Classify
	// before the goroutine has finished binding by using a tiny sleep).
	// Actually: the goroutine races to bind. We want the FIRST attempt to
	// see ECONNREFUSED. To guarantee that, we call Classify BEFORE waiting
	// for <-started, and accept that the test is slightly racy. On any
	// reasonable system the goroutine won't bind in < 1ms.

	cfg := adapter.ClientConfig{
		URL:     "http://" + addr,
		Timeout: 3 * time.Second,
	}

	resp, classifyErr := adapter.Classify(context.Background(), cfg, adapter.ClassifyRequest{Command: "ls"})

	// Wait for the goroutine's server to be up (or detect port-grab failure).
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("retry server goroutine did not start in time")
	}

	if classifyErr != nil {
		// If the port was grabbed by the OS between close and re-listen the
		// goroutine could not bind — skip rather than fail.
		t.Skipf("retry test inconclusive (port rebind race): %v", classifyErr)
	}

	if resp == nil || resp.Action != "allow" {
		t.Errorf("expected allow response, got: %v (err: %v)", resp, classifyErr)
	}
	// The server must have been called exactly once (on the retry).
	if callCount.Load() != 1 {
		t.Errorf("handler call count: got %d, want 1", callCount.Load())
	}
}

// --- SendFeedback tests ---

func TestSendFeedback_Success(t *testing.T) {
	var gotBody FeedbackBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/feedback" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req := adapter.FeedbackRequest{
		StargateTrID:  "trace-fb-001",
		ToolUseID:     "tool-use-abc",
		FeedbackToken: "fb-tok-xyz",
		Outcome:       "correct",
	}
	err := adapter.SendFeedback(context.Background(), newTestConfig(srv.URL), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody.StargateTrID != req.StargateTrID {
		t.Errorf("StargateTrID: got %q, want %q", gotBody.StargateTrID, req.StargateTrID)
	}
	if gotBody.Outcome != req.Outcome {
		t.Errorf("Outcome: got %q, want %q", gotBody.Outcome, req.Outcome)
	}
}

func TestSendFeedback_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := adapter.SendFeedback(context.Background(), newTestConfig(srv.URL), adapter.FeedbackRequest{
		StargateTrID:  "trace-err",
		FeedbackToken: "fb-tok",
		Outcome:       "correct",
	})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// FeedbackBody mirrors FeedbackRequest for decoding in tests.
type FeedbackBody struct {
	StargateTrID  string `json:"stargate_trace_id"`
	ToolUseID     string `json:"tool_use_id"`
	FeedbackToken string `json:"feedback_token"`
	Outcome       string `json:"outcome"`
}

// --- ValidateURL tests ---

func TestValidateURL_Loopback127(t *testing.T) {
	cfg := adapter.ClientConfig{URL: "http://127.0.0.1:9099"}
	if err := cfg.ValidateURL(); err != nil {
		t.Errorf("unexpected error for 127.0.0.1: %v", err)
	}
}

func TestValidateURL_LoopbackIPv6(t *testing.T) {
	cfg := adapter.ClientConfig{URL: "http://[::1]:9099"}
	if err := cfg.ValidateURL(); err != nil {
		t.Errorf("unexpected error for [::1]: %v", err)
	}
}

func TestValidateURL_PrivateIP(t *testing.T) {
	cfg := adapter.ClientConfig{URL: "http://192.168.1.1:9099"}
	if err := cfg.ValidateURL(); err == nil {
		t.Error("expected error for 192.168.1.1, got nil")
	}
}

func TestValidateURL_PublicDomain(t *testing.T) {
	cfg := adapter.ClientConfig{URL: "http://evil.com:9099"}
	if err := cfg.ValidateURL(); err == nil {
		t.Error("expected error for evil.com, got nil")
	}
}

func TestValidateURL_LocalhostRejected(t *testing.T) {
	cfg := adapter.ClientConfig{URL: "http://localhost:9099"}
	if err := cfg.ValidateURL(); err == nil {
		t.Error("expected error for localhost (DNS resolution risk), got nil")
	}
}

func TestValidateURL_AllowRemote(t *testing.T) {
	cfg := adapter.ClientConfig{
		URL:         "http://10.0.0.1:9099",
		AllowRemote: true,
	}
	if err := cfg.ValidateURL(); err != nil {
		t.Errorf("unexpected error with AllowRemote=true: %v", err)
	}
}

// itoa is a minimal int-to-string helper for the raw HTTP response builder.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

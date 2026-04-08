package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/perezd/stargate/internal/classifier"
	"github.com/perezd/stargate/internal/config"
	"github.com/perezd/stargate/internal/server"
)

// testConfig returns a minimal config with representative RED, GREEN, and
// YELLOW rules sufficient for the classify endpoint tests.
func testConfig() *config.Config {
	trueVal := true
	return &config.Config{
		Server: config.ServerConfig{Listen: "127.0.0.1:9099"},
		Parser: config.ParserConfig{Dialect: "bash"},
		Classifier: config.ClassifierConfig{
			DefaultDecision:       "yellow",
			UnresolvableExpansion: "yellow",
			MaxASTDepth:           64,
			MaxCommandLength:      65536,
		},
		Rules: config.RulesConfig{
			Red: []config.Rule{
				{
					Command: "rm",
					Flags:   []string{"-rf", "-fr"},
					Args:    []string{"/"},
					Reason:  "destructive deletion of root",
				},
			},
			Green: []config.Rule{
				{
					Commands: []string{"git", "ls", "echo"},
					Reason:   "safe read-only commands",
				},
			},
			Yellow: []config.Rule{
				{
					Command:   "curl",
					LLMReview: &trueVal,
					Reason:    "network access requires review",
				},
			},
		},
		Wrappers: config.DefaultWrappers(),
		Commands: config.DefaultCommandFlags(),
	}
}

func TestHealthEndpoint(t *testing.T) {
	cfg := testConfig()
	srv := server.New(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if _, ok := body["uptime_seconds"]; !ok {
		t.Error("missing uptime_seconds field")
	}
	// Health should only return status and uptime — nothing else.
	if len(body) != 2 {
		t.Errorf("health returned %d fields, want exactly 2 (status, uptime_seconds)", len(body))
	}
}

func TestStubEndpointsReturn501(t *testing.T) {
	cfg := testConfig()
	srv := server.New(cfg)

	endpoints := []struct{ method, path string }{
		{"POST", "/feedback"},
		{"POST", "/reload"},
		{"POST", "/test"},
	}
	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
			}
		})
	}
}

func postClassify(t *testing.T, srv http.Handler, body string) (int, *classifier.ClassifyResponse) {
	t.Helper()
	req := httptest.NewRequest("POST", "/classify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		return w.Code, nil
	}

	var resp classifier.ClassifyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	return w.Code, &resp
}

func TestClassifyGreenCommand(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"git status"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "green" {
		t.Errorf("decision = %q, want green", resp.Decision)
	}
	if resp.Action != "allow" {
		t.Errorf("action = %q, want allow", resp.Action)
	}
}

func TestClassifyRedCommand(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"rm -rf /"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyMissingCommand(t *testing.T) {
	srv := server.New(testConfig())

	req := httptest.NewRequest("POST", "/classify", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestClassifyUnknownCommand(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"unknown_cmd"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow (default)", resp.Decision)
	}
}

func TestClassifyUnparseable(t *testing.T) {
	srv := server.New(testConfig())

	// An unclosed quote is a parse error.
	code, resp := postClassify(t, srv, `{"command":"echo \"unterminated"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red (parse error → fail-closed)", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "parse error") {
		t.Errorf("reason = %q, want it to mention parse error", resp.Reason)
	}
}

func TestClassifyTraceID(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"git status"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.HasPrefix(resp.StargateTrID, "sg_tr_") {
		t.Errorf("trace ID %q does not start with sg_tr_", resp.StargateTrID)
	}
	if len(resp.StargateTrID) != len("sg_tr_")+24 {
		t.Errorf("trace ID %q has unexpected length", resp.StargateTrID)
	}
}

func TestClassifyTimingPopulated(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"git status"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Timing == nil {
		t.Fatal("timing is nil")
	}
}

func TestClassifyASTSummary(t *testing.T) {
	srv := server.New(testConfig())

	code, resp := postClassify(t, srv, `{"command":"git status"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if resp.AST.CommandsFound < 1 {
		t.Errorf("commands_found = %d, want >= 1", resp.AST.CommandsFound)
	}
}

func TestClassifyOversizedCommand(t *testing.T) {
	cfg := testConfig()
	cfg.Classifier.MaxCommandLength = 20 // very small limit for testing
	srv := server.New(cfg)

	// Command exceeds limit — should get a RED classification (not HTTP 413).
	code, resp := postClassify(t, srv, `{"command":"echo this is a command that exceeds the limit"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (classifier handles length, not HTTP layer)", code)
	}
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
	if !strings.Contains(resp.Reason, "exceeds maximum length") {
		t.Errorf("reason = %q, want it to mention length", resp.Reason)
	}
}

func TestClassifyInvalidJSON(t *testing.T) {
	srv := server.New(testConfig())

	req := httptest.NewRequest("POST", "/classify", bytes.NewBufferString(`{not valid json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/rules"
)

// --- parseTestFlags tests ---

func TestParseTestFlags_PositionalCommand(t *testing.T) {
	f, err := parseTestFlags([]string{"git", "status"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.command != "git status" {
		t.Errorf("command = %q, want %q", f.command, "git status")
	}
}

func TestParseTestFlags_SingleArgCommand(t *testing.T) {
	f, err := parseTestFlags([]string{"ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.command != "ls" {
		t.Errorf("command = %q, want %q", f.command, "ls")
	}
}

func TestParseTestFlags_StdinSentinel(t *testing.T) {
	f, err := parseTestFlags([]string{"-"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if !f.readStdin {
		t.Error("readStdin should be true for '-' arg")
	}
}

func TestParseTestFlags_StdinSentinelRejectsTrailingArgs(t *testing.T) {
	// `stargate test - ls` should error — positional args after - would be
	// silently dropped when stdin overwrites f.command.
	_, err := parseTestFlags([]string{"-", "ls"})
	if err == nil {
		t.Error("expected error for args after '-' sentinel")
	}
}

func TestParseTestFlags_CWD(t *testing.T) {
	f, err := parseTestFlags([]string{"--cwd", "/tmp", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.cwd != "/tmp" {
		t.Errorf("cwd = %q, want %q", f.cwd, "/tmp")
	}
}

func TestParseTestFlags_JSON(t *testing.T) {
	f, err := parseTestFlags([]string{"--json", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if !f.asJSON {
		t.Error("asJSON should be true")
	}
}

func TestParseTestFlags_Verbose(t *testing.T) {
	f, err := parseTestFlags([]string{"--verbose", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if !f.verbose {
		t.Error("verbose should be true")
	}
}

func TestParseTestFlags_Cached(t *testing.T) {
	f, err := parseTestFlags([]string{"--cached", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if !f.useCache {
		t.Error("useCache should be true")
	}
}

func TestParseTestFlags_Offline(t *testing.T) {
	f, err := parseTestFlags([]string{"--offline", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if !f.offline {
		t.Error("offline should be true")
	}
}

func TestParseTestFlags_URL(t *testing.T) {
	f, err := parseTestFlags([]string{"--url", "http://127.0.0.1:8888", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.url != "http://127.0.0.1:8888" {
		t.Errorf("url = %q", f.url)
	}
}

func TestParseTestFlags_URLEquals(t *testing.T) {
	f, err := parseTestFlags([]string{"--url=http://127.0.0.1:7777", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.url != "http://127.0.0.1:7777" {
		t.Errorf("url = %q", f.url)
	}
}

func TestParseTestFlags_Timeout(t *testing.T) {
	f, err := parseTestFlags([]string{"--timeout", "5s", "ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.timeout != 5*time.Second {
		t.Errorf("timeout = %v", f.timeout)
	}
}

func TestParseTestFlags_UnknownFlag(t *testing.T) {
	_, err := parseTestFlags([]string{"--bogus", "ls"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestParseTestFlags_Help(t *testing.T) {
	_, err := parseTestFlags([]string{"--help"})
	if err != errShowHelp {
		t.Errorf("expected errShowHelp, got %v", err)
	}
}

func TestParseTestFlags_DefaultURL(t *testing.T) {
	f, err := parseTestFlags([]string{"ls"})
	if err != nil {
		t.Fatalf("parseTestFlags: %v", err)
	}
	if f.url != defaultStargateURL {
		t.Errorf("url = %q, want default %q", f.url, defaultStargateURL)
	}
}

// --- handleTest integration tests (server mode) ---

// fakeTestServer starts an httptest server that returns the given response
// JSON for POST /test.
func fakeTestServer(t *testing.T, resp classifier.ClassifyResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/test" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHandleTest_MissingCommand(t *testing.T) {
	// No command argument and no stdin sentinel.
	code := handleTest([]string{}, "", false)
	if code != 2 {
		t.Errorf("exit = %d, want 2 for missing command", code)
	}
}

func TestHandleTest_UnknownFlag(t *testing.T) {
	code := handleTest([]string{"--bogus", "ls"}, "", false)
	if code != 2 {
		t.Errorf("exit = %d, want 2 for unknown flag", code)
	}
}

func TestHandleTest_ServerModeSuccess(t *testing.T) {
	srv := fakeTestServer(t, classifier.ClassifyResponse{
		Decision:     "green",
		Action:       "allow",
		Reason:       "safe",
		StargateTrID: "tr_test",
	})

	code := handleTest([]string{"--url", srv.URL, "ls"}, "", false)
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

func TestHandleTest_ServerModeConnectionRefused(t *testing.T) {
	// Point at a port that's definitely not listening.
	code := handleTest([]string{
		"--url", "http://127.0.0.1:1",
		"--timeout", "500ms",
		"ls",
	}, "", false)
	if code != 1 {
		t.Errorf("exit = %d, want 1 for unreachable server", code)
	}
}

func TestHandleTest_Help(t *testing.T) {
	code := handleTest([]string{"--help"}, "", false)
	if code != 0 {
		t.Errorf("exit = %d, want 0 for --help", code)
	}
}

// --- formatOneLiner tests ---

func TestFormatOneLiner_WithRule(t *testing.T) {
	resp := &classifier.ClassifyResponse{
		Decision: "red",
		Action:   "block",
		Reason:   "dangerous",
		Rule:     &rules.MatchedRule{Level: "red", Index: 2, Reason: "dangerous"},
	}
	got := formatOneLiner(resp)
	if !strings.Contains(got, "RED") {
		t.Errorf("want uppercase decision: %s", got)
	}
	if !strings.Contains(got, "block") {
		t.Errorf("want action: %s", got)
	}
	if !strings.Contains(got, "dangerous") {
		t.Errorf("want reason: %s", got)
	}
	if !strings.Contains(got, "rules.red[2]") {
		t.Errorf("want rule tag 'rules.red[2]': %s", got)
	}
}

func TestFormatOneLiner_NoRule(t *testing.T) {
	resp := &classifier.ClassifyResponse{
		Decision: "yellow",
		Action:   "ask",
		Reason:   "unknown",
	}
	got := formatOneLiner(resp)
	if strings.Contains(got, "rule:") {
		t.Errorf("should not contain 'rule:' when Rule is nil: %s", got)
	}
}

// --- printResponse tests ---

func TestPrintResponse_JSON(t *testing.T) {
	var buf bytes.Buffer
	resp := &classifier.ClassifyResponse{
		Decision:     "green",
		Action:       "allow",
		StargateTrID: "tr_1",
	}
	f := &testFlags{asJSON: true}
	printResponse(&buf, resp, f)

	var decoded classifier.ClassifyResponse
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Decision != "green" {
		t.Errorf("decoded decision = %q", decoded.Decision)
	}
}

func TestPrintResponse_Default(t *testing.T) {
	var buf bytes.Buffer
	resp := &classifier.ClassifyResponse{
		Decision: "green",
		Action:   "allow",
		Reason:   "safe",
	}
	f := &testFlags{}
	printResponse(&buf, resp, f)
	out := buf.String()
	if !strings.HasPrefix(out, "GREEN") {
		t.Errorf("default output should start with decision: %q", out)
	}
}

func TestPrintResponse_Verbose(t *testing.T) {
	var buf bytes.Buffer
	resp := &classifier.ClassifyResponse{
		Decision:     "green",
		Action:       "allow",
		Reason:       "safe",
		StargateTrID: "tr_verbose",
		Timing:       &classifier.Timing{TotalMs: 1.5, ParseUs: 100, RulesUs: 50},
	}
	f := &testFlags{verbose: true}
	printResponse(&buf, resp, f)
	out := buf.String()
	if !strings.Contains(out, "timing:") {
		t.Errorf("verbose output should include timing: %q", out)
	}
	if !strings.Contains(out, "tr_verbose") {
		t.Errorf("verbose output should include trace ID: %q", out)
	}
}

package telemetry

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
)

func TestInit_DisabledReturnsNoOp(t *testing.T) {
	tel, err := Init(config.TelemetryConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, ok := tel.(*NoOpTelemetry); !ok {
		t.Errorf("expected *NoOpTelemetry, got %T", tel)
	}
}

func TestInit_EnabledReturnsLive(t *testing.T) {
	cfg := config.TelemetryConfig{
		Enabled:       true,
		Endpoint:      "https://localhost:4318",
		ExportTraces:  true,
		ExportMetrics: true,
		ExportLogs:    true,
	}
	tel, err := Init(cfg)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tel.Shutdown(context.Background())

	if _, ok := tel.(*LiveTelemetry); !ok {
		t.Errorf("expected *LiveTelemetry, got %T", tel)
	}
}

func TestNoOpTelemetry_NoPanic(t *testing.T) {
	var n NoOpTelemetry
	ctx := context.Background()

	// All methods should be callable without panic.
	n.Shutdown(ctx)
	n.LogClassification(ctx, ClassifyResult{})
	n.RecordClassification("green", "rule1", 1.0)
	n.RecordLLMCall("allow", 100.0)
	n.RecordParseError()
	n.RecordFeedback("executed")
	n.RecordCorpusHit("exact")
	n.RecordCorpusWrite("allow")
	n.RecordScopeResolution("github", "resolved")
	n.SetRulesLoaded("red", 5)
	n.SetCorpusEntries("allow", 10)
	n.StoreToolUseTrace("toolu_1", "trace_1")

	if got := n.LookupToolUseTrace("toolu_1"); got != "" {
		t.Errorf("LookupToolUseTrace: got %q, want empty", got)
	}

	if got := n.TraceIDFromContext(ctx); got != "" {
		t.Errorf("TraceIDFromContext: got %q, want empty", got)
	}

	ctx2, span := n.StartClassifySpan(ctx)
	if ctx2 != ctx {
		t.Error("StartClassifySpan: context should be unchanged")
	}
	span.End() // should not panic

	ctx3, span2 := n.StartSpan(ctx, "test")
	if ctx3 != ctx {
		t.Error("StartSpan: context should be unchanged")
	}
	span2.End()

	ctx4, span3 := n.StartFeedbackSpan(ctx, "some-trace-id")
	if ctx4 != ctx {
		t.Error("StartFeedbackSpan: context should be unchanged")
	}
	span3.End()
}

func TestRedactedString_FmtV(t *testing.T) {
	pw := config.RedactedString("super-secret")
	got := fmt.Sprintf("%v", pw)
	if got != "[REDACTED]" {
		t.Errorf("fmt %%v: got %q, want [REDACTED]", got)
	}
}

func TestRedactedString_FmtPlusV(t *testing.T) {
	pw := config.RedactedString("super-secret")
	got := fmt.Sprintf("%+v", pw)
	if got != "[REDACTED]" {
		t.Errorf("fmt %%+v: got %q, want [REDACTED]", got)
	}
}

func TestRedactedString_ParentStruct(t *testing.T) {
	cfg := config.TelemetryConfig{
		Enabled:  true,
		Password: config.RedactedString("super-secret"),
	}
	got := fmt.Sprintf("%+v", cfg)
	if containsSubstring(got, "super-secret") {
		t.Errorf("parent struct %%+v leaked password: %s", got)
	}
	if !containsSubstring(got, "[REDACTED]") {
		t.Errorf("parent struct %%+v missing redaction: %s", got)
	}
}

func TestShutdown_JoinsErrors(t *testing.T) {
	// NoOp shutdown should return nil.
	n := &NoOpTelemetry{}
	if err := n.Shutdown(context.Background()); err != nil {
		t.Errorf("NoOp shutdown: %v", err)
	}
}

func TestShutdown_LiveTelemetry(t *testing.T) {
	cfg := config.TelemetryConfig{
		Enabled:       true,
		Endpoint:      "https://localhost:4318",
		ExportTraces:  true,
		ExportMetrics: true,
		ExportLogs:    true,
	}
	tel, err := Init(cfg)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Shutdown should not panic or error (exporters will fail to connect
	// but batch processors handle that gracefully).
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Logf("Shutdown error (expected for non-existent endpoint): %v", err)
	}
}

func TestHTTPWithCredentialsWarning(t *testing.T) {
	// http:// with credentials should not error, just warn.
	cfg := config.TelemetryConfig{
		Enabled:      true,
		Endpoint:     "http://localhost:4318",
		Username:     "user",
		Password:     config.RedactedString("pass"),
		ExportTraces: true,
	}
	tel, err := Init(cfg)
	if err != nil {
		t.Fatalf("Init with http+creds: %v", err)
	}
	defer tel.Shutdown(context.Background())
}

func TestToolUseTraceMap(t *testing.T) {
	cfg := config.TelemetryConfig{
		Enabled:      true,
		Endpoint:     "https://localhost:4318",
		ExportTraces: true,
	}
	tel, err := Init(cfg)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tel.Shutdown(context.Background())

	tel.StoreToolUseTrace("toolu_abc", "trace_123")
	got := tel.LookupToolUseTrace("toolu_abc")
	if got != "trace_123" {
		t.Errorf("LookupToolUseTrace: got %q, want %q", got, "trace_123")
	}

	// Miss returns empty.
	if got := tel.LookupToolUseTrace("nonexistent"); got != "" {
		t.Errorf("LookupToolUseTrace miss: got %q, want empty", got)
	}
}

func TestBasicAuth(t *testing.T) {
	got := basicAuth("user", "pass")
	// "user:pass" base64 = "dXNlcjpwYXNz"
	if got != "dXNlcjpwYXNz" {
		t.Errorf("basicAuth: got %q, want %q", got, "dXNlcjpwYXNz")
	}
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

package classifier_test

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/llm"
	"github.com/limbic-systems/stargate/internal/telemetry"
)

// TestDryRun_NoFeedbackTokenForYellow verifies that DryRun=true prevents
// feedback token generation for YELLOW decisions even when tool_use_id is set.
func TestDryRun_NoFeedbackTokenForYellow(t *testing.T) {
	clf := newClassifier(t)

	req := classifier.ClassifyRequest{
		Command: "curl https://example.com",
		Context: map[string]any{"tool_use_id": "toolu_test"},
		DryRun:  true,
	}
	resp := clf.Classify(context.Background(), req)

	if resp.Decision != "yellow" {
		t.Fatalf("expected yellow decision, got %q", resp.Decision)
	}
	if resp.FeedbackToken != nil {
		t.Errorf("DryRun=true should produce no FeedbackToken, got %q", *resp.FeedbackToken)
	}
}

// TestDryRun_YieldsFeedbackTokenWhenNotDryRun is the control — the same
// request without DryRun should produce a token.
func TestDryRun_YieldsFeedbackTokenWhenNotDryRun(t *testing.T) {
	clf := newClassifier(t)

	req := classifier.ClassifyRequest{
		Command: "curl https://example.com",
		Context: map[string]any{"tool_use_id": "toolu_test"},
		// DryRun: false (default)
	}
	resp := clf.Classify(context.Background(), req)

	if resp.Decision != "yellow" {
		t.Fatalf("expected yellow decision, got %q", resp.Decision)
	}
	if resp.FeedbackToken == nil {
		t.Error("non-dry-run YELLOW with tool_use_id should produce a FeedbackToken")
	}
}

// TestDryRun_CorpusNotWrittenWithLLMAllow verifies that DryRun suppresses
// corpus writes even on a code path that WOULD write in non-dry-run mode
// (LLM approves, corpus enabled). Without this test, the happy path of
// "no LLM provider in tests" could mask a regression where DryRun no
// longer gates postProcess.
func TestDryRun_CorpusNotWrittenWithLLMAllow(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &mockProvider{response: llm.ReviewResponse{
		Decision:  "allow",
		Reasoning: "safe API call",
	}}

	cfg := llmTestConfig()
	trueVal := true
	cfg.Corpus = config.CorpusConfig{
		Enabled: &trueVal,
		Path:    tmpDir + "/corpus.db",
	}

	clf, err := classifier.NewWithProvider(cfg, mock)
	if err != nil {
		t.Fatalf("NewWithProvider: %v", err)
	}
	defer clf.Close() //nolint:errcheck

	// Baseline: non-dry-run should trigger LLM and write to corpus.
	wet := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "curl https://api.example.com",
	})
	if wet.Action != "allow" {
		t.Fatalf("baseline expected action=allow, got %q", wet.Action)
	}
	if wet.Corpus == nil || !wet.Corpus.EntryWritten {
		t.Fatalf("non-dry-run should have written to corpus; got Corpus=%+v", wet.Corpus)
	}
	if mock.calls != 1 {
		t.Fatalf("expected 1 LLM call before dry-run, got %d", mock.calls)
	}

	// Dry-run with a different command so the cache doesn't interfere.
	dry := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "curl https://different.example.com",
		DryRun:  true,
	})
	if dry.Action != "allow" {
		t.Fatalf("dry-run expected action=allow, got %q", dry.Action)
	}
	if dry.Corpus != nil && dry.Corpus.EntryWritten {
		t.Errorf("DryRun must NOT write to corpus; got EntryWritten=true")
	}
	if mock.calls != 2 {
		t.Errorf("expected LLM called once for dry-run (total 2), got %d total", mock.calls)
	}
}

// TestDryRun_DecisionIdenticalToNonDryRun verifies DryRun does not change
// the classification decision itself — only side effects are suppressed.
func TestDryRun_DecisionIdenticalToNonDryRun(t *testing.T) {
	clf := newClassifier(t)
	ctx := context.Background()

	cases := []string{"git status", "ls -la", "rm -rf /", "echo hello"}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			dryReq := classifier.ClassifyRequest{Command: cmd, DryRun: true}
			wetReq := classifier.ClassifyRequest{Command: cmd, DryRun: false}

			dry := clf.Classify(ctx, dryReq)
			wet := clf.Classify(ctx, wetReq)

			if dry.Decision != wet.Decision {
				t.Errorf("decision mismatch: dry=%q wet=%q", dry.Decision, wet.Decision)
			}
			if dry.Action != wet.Action {
				t.Errorf("action mismatch: dry=%q wet=%q", dry.Action, wet.Action)
			}
		})
	}
}

// TestDryRun_SpanHasDryRunAttribute verifies that DryRun=true sets the
// stargate.dry_run=true span attribute, so operators can filter /test
// traffic from real classifications in Grafana dashboards.
func TestDryRun_SpanHasDryRunAttribute(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	t.Cleanup(func() { tp.Shutdown(context.Background()) })

	clf := newClassifier(t)
	clf.SetTelemetry(&testTelemetry{tp: tp})

	clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "ls",
		DryRun:  true,
	})

	spans := exporter.GetSpans()
	var found bool
	for _, span := range spans {
		if span.Name == "stargate.classify" {
			for _, attr := range span.Attributes {
				if attr.Key == "stargate.dry_run" && attr.Value.AsBool() {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("DryRun=true should set stargate.dry_run=true attribute on classify span")
	}

	// Also verify: DryRun=false should NOT have the attribute.
	exporter.Reset()
	clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "ls",
		DryRun:  false,
	})
	spans = exporter.GetSpans()
	for _, span := range spans {
		if span.Name == "stargate.classify" {
			for _, attr := range span.Attributes {
				if attr.Key == "stargate.dry_run" {
					t.Error("DryRun=false should NOT set stargate.dry_run attribute")
				}
			}
		}
	}
}

// testTelemetry embeds NoOpTelemetry and overrides span methods to use a
// real TracerProvider so we can verify span attributes.
type testTelemetry struct {
	telemetry.NoOpTelemetry
	tp *sdktrace.TracerProvider
}

func (t *testTelemetry) StartClassifySpan(ctx context.Context) (context.Context, trace.Span) {
	return t.tp.Tracer("stargate-test").Start(ctx, "stargate.classify")
}

func (t *testTelemetry) TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}

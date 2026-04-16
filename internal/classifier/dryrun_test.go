package classifier_test

import (
	"context"
	"testing"

	"github.com/limbic-systems/stargate/internal/classifier"
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

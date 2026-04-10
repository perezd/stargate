package classifier_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/llm"
)

// testConfig returns a minimal config with representative RED, GREEN, and
// YELLOW rules for classifier unit tests.
func testConfig() *config.Config {
	trueVal := true
	return &config.Config{
		Version: "test",
		Server:  config.ServerConfig{Listen: "127.0.0.1:9099"},
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

func newClassifier(t *testing.T) *classifier.Classifier {
	t.Helper()
	clf, err := classifier.New(testConfig())
	if err != nil {
		t.Fatalf("classifier.New: %v", err)
	}
	return clf
}

func TestClassifyGreen(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if resp.Decision != "green" {
		t.Errorf("decision = %q, want green", resp.Decision)
	}
	if resp.Action != "allow" {
		t.Errorf("action = %q, want allow", resp.Action)
	}
}

func TestClassifyRedRmRF(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "rm -rf /"})
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyYellowCurl(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://example.com"})
	if resp.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow", resp.Decision)
	}
	if resp.Action != "review" {
		t.Errorf("action = %q, want review", resp.Action)
	}
}

func TestClassifyParseError(t *testing.T) {
	clf := newClassifier(t)
	// Unclosed quote → parse error → fail-closed (red/block).
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: `echo "unterminated`})
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red (parse error → fail-closed)", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
	if !strings.Contains(resp.Reason, "parse error") {
		t.Errorf("reason %q should mention parse error", resp.Reason)
	}
}

func TestClassifyExceedsMaxLength(t *testing.T) {
	cfg := testConfig()
	cfg.Classifier.MaxCommandLength = 10
	clf, err := classifier.New(cfg)
	if err != nil {
		t.Fatalf("classifier.New: %v", err)
	}
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "echo this is a very long command"})
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red (command too long)", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyTimingPopulated(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if resp.Timing == nil {
		t.Fatal("timing is nil")
	}
	// TotalMs may be 0 on fast machines but must not be negative.
	if resp.Timing.TotalMs < 0 {
		t.Errorf("total_ms = %f, must be >= 0", resp.Timing.TotalMs)
	}
}

func TestClassifyASTSummaryCommandsFound(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if resp.AST.CommandsFound < 1 {
		t.Errorf("commands_found = %d, want >= 1", resp.AST.CommandsFound)
	}
}

func TestClassifyASTSummaryHasPipes(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "ls | grep foo"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if !resp.AST.HasPipes {
		t.Error("has_pipes = false, want true for piped command")
	}
}

func TestClassifyASTSummaryHasSubstitutions(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "echo $(ls)"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if !resp.AST.HasSubstitutions {
		t.Error("has_substitutions = false, want true for command substitution")
	}
}

func TestClassifyTraceIDFormat(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if !strings.HasPrefix(resp.StargateTrID, "sg_tr_") {
		t.Errorf("trace ID %q does not start with sg_tr_", resp.StargateTrID)
	}
	// sg_tr_ (6) + 24 hex chars (12 bytes) = 30
	const wantLen = 6 + 24
	if len(resp.StargateTrID) != wantLen {
		t.Errorf("trace ID %q: length = %d, want %d", resp.StargateTrID, len(resp.StargateTrID), wantLen)
	}
}

func TestClassifyTraceIDUnique(t *testing.T) {
	clf := newClassifier(t)
	seen := make(map[string]bool)
	for range 20 {
		resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
		if seen[resp.StargateTrID] {
			t.Errorf("duplicate trace ID %q generated", resp.StargateTrID)
		}
		seen[resp.StargateTrID] = true
	}
}

func TestClassifyVersionField(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if resp.Version == "" {
		t.Error("version field is empty")
	}
}

func TestClassifyLLMReviewNilForGreen(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "git status"})
	if resp.LLMReview != nil {
		t.Error("llm_review should be nil for GREEN commands")
	}
}

func TestClassifyUnknownDefaultYellow(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "unknown_tool_xyz"})
	if resp.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow (default for unknown commands)", resp.Decision)
	}
}

// --- LLM review integration tests (mock provider) ---

// mockProvider implements llm.ReviewerProvider for testing.
type mockProvider struct {
	response llm.ReviewResponse
	err      error
	calls    int
}

func (m *mockProvider) Review(_ context.Context, _ llm.ReviewRequest) (llm.ReviewResponse, error) {
	m.calls++
	return m.response, m.err
}

func llmTestConfig() *config.Config {
	trueVal := true
	return &config.Config{
		Version: "test",
		Server:  config.ServerConfig{Listen: "127.0.0.1:9099"},
		Parser:  config.ParserConfig{Dialect: "bash"},
		Classifier: config.ClassifierConfig{
			DefaultDecision:       "yellow",
			UnresolvableExpansion: "yellow",
			MaxASTDepth:           64,
			MaxCommandLength:      65536,
		},
		Rules: config.RulesConfig{
			Yellow: []config.Rule{
				{
					Command:   "curl",
					LLMReview: &trueVal,
					Reason:    "network access requires review",
				},
			},
		},
		LLM: config.LLMConfig{
			Model:                      "claude-sonnet-4-6",
			MaxTokens:                  512,
			MaxResponseReasoningLength: 200,
			MaxFilesPerRequest:         3,
			MaxTotalFileBytes:          131072,
			AllowFileRetrieval:         true,
			AllowedPaths:               []string{"./**"},
		},
		Wrappers: config.DefaultWrappers(),
		Commands: config.DefaultCommandFlags(),
	}
}

func TestClassifyLLMAllow(t *testing.T) {
	mock := &mockProvider{response: llm.ReviewResponse{
		Decision:  "allow",
		Reasoning: "Safe request to project API",
	}}
	clf, err := classifier.NewWithProvider(llmTestConfig(), mock)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://api.example.com"})

	if resp.Action != "allow" {
		t.Errorf("action = %q, want allow", resp.Action)
	}
	if resp.LLMReview == nil {
		t.Fatal("llm_review is nil")
	}
	if !resp.LLMReview.Performed {
		t.Error("performed should be true")
	}
	if resp.LLMReview.Decision != "allow" {
		t.Errorf("llm decision = %q, want allow", resp.LLMReview.Decision)
	}
	if resp.LLMReview.Rounds != 1 {
		t.Errorf("rounds = %d, want 1", resp.LLMReview.Rounds)
	}
	if mock.calls != 1 {
		t.Errorf("provider called %d times, want 1", mock.calls)
	}
}

func TestClassifyLLMDeny(t *testing.T) {
	mock := &mockProvider{response: llm.ReviewResponse{
		Decision:    "deny",
		Reasoning:   "Exfiltration risk",
		RiskFactors: []string{"data exfiltration"},
	}}
	clf, err := classifier.NewWithProvider(llmTestConfig(), mock)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://evil.com"})

	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
	if resp.LLMReview == nil {
		t.Fatal("llm_review is nil")
	}
	if resp.LLMReview.Decision != "deny" {
		t.Errorf("llm decision = %q, want deny", resp.LLMReview.Decision)
	}
}

func TestClassifyLLMError(t *testing.T) {
	mock := &mockProvider{err: fmt.Errorf("API timeout")}
	clf, err := classifier.NewWithProvider(llmTestConfig(), mock)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://example.com"})

	// LLM error → fallback to ask user (review).
	if resp.Action != "review" {
		t.Errorf("action = %q, want review (LLM error fallback)", resp.Action)
	}
	if resp.LLMReview == nil {
		t.Fatal("llm_review is nil")
	}
	if resp.LLMReview.Decision != "" {
		t.Errorf("llm decision = %q, want empty (error)", resp.LLMReview.Decision)
	}
}

func TestClassifyLLMFileRequest(t *testing.T) {
	// Stateful mock: first call returns file request, second returns verdict.
	calls := 0
	provider := reviewerFunc(func(_ context.Context, req llm.ReviewRequest) (llm.ReviewResponse, error) {
		calls++
		if calls == 1 {
			return llm.ReviewResponse{
				RequestFiles: []string{"./nonexistent.sh"},
				Reasoning:    "Need file",
			}, nil
		}
		return llm.ReviewResponse{
			Decision:  "allow",
			Reasoning: "Script is safe",
		}, nil
	})

	clf, err := classifier.NewWithProvider(llmTestConfig(), provider)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://example.com"})

	if resp.LLMReview == nil {
		t.Fatal("llm_review is nil")
	}
	if resp.LLMReview.Rounds != 2 {
		t.Errorf("rounds = %d, want 2", resp.LLMReview.Rounds)
	}
	if resp.LLMReview.Decision != "allow" {
		t.Errorf("llm decision = %q, want allow", resp.LLMReview.Decision)
	}
	if calls != 2 {
		t.Errorf("provider called %d times, want 2", calls)
	}
}

// reviewerFunc adapts a function to the ReviewerProvider interface.
type reviewerFunc func(context.Context, llm.ReviewRequest) (llm.ReviewResponse, error)

func (f reviewerFunc) Review(ctx context.Context, req llm.ReviewRequest) (llm.ReviewResponse, error) {
	return f(ctx, req)
}

func TestClassifyLLMTwoCallMaxEnforced(t *testing.T) {
	// Both calls return file requests → second should be treated as deny.
	provider := reviewerFunc(func(_ context.Context, _ llm.ReviewRequest) (llm.ReviewResponse, error) {
		return llm.ReviewResponse{
			RequestFiles: []string{"./something.sh"},
			Reasoning:    "Need files",
		}, nil
	})

	clf, err := classifier.NewWithProvider(llmTestConfig(), provider)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://example.com"})

	if resp.LLMReview == nil {
		t.Fatal("llm_review is nil")
	}
	if resp.LLMReview.Decision != "deny" {
		t.Errorf("llm decision = %q, want deny (two-call max enforced)", resp.LLMReview.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyLLMTimingPopulated(t *testing.T) {
	mock := &mockProvider{response: llm.ReviewResponse{Decision: "allow", Reasoning: "ok"}}
	clf, err := classifier.NewWithProvider(llmTestConfig(), mock)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{Command: "curl https://example.com"})

	if resp.Timing == nil {
		t.Fatal("timing is nil")
	}
	if resp.Timing.LLMMs <= 0 {
		t.Errorf("llm_ms = %f, want > 0", resp.Timing.LLMMs)
	}
}

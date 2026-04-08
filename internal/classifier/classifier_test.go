package classifier_test

import (
	"strings"
	"testing"

	"github.com/perezd/stargate/internal/classifier"
	"github.com/perezd/stargate/internal/config"
)

// testConfig returns a minimal config with representative RED, GREEN, and
// YELLOW rules for classifier unit tests.
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
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
	if resp.Decision != "green" {
		t.Errorf("decision = %q, want green", resp.Decision)
	}
	if resp.Action != "allow" {
		t.Errorf("action = %q, want allow", resp.Action)
	}
}

func TestClassifyRedRmRF(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "rm -rf /"})
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyYellowCurl(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "curl https://example.com"})
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
	resp := clf.Classify(classifier.ClassifyRequest{Command: `echo "unterminated`})
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
	resp := clf.Classify(classifier.ClassifyRequest{Command: "echo this is a very long command"})
	if resp.Decision != "red" {
		t.Errorf("decision = %q, want red (command too long)", resp.Decision)
	}
	if resp.Action != "block" {
		t.Errorf("action = %q, want block", resp.Action)
	}
}

func TestClassifyTimingPopulated(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
	if resp.Timing == nil {
		t.Fatal("timing is nil")
	}
	// TotalMs may be 0 on fast machines but must not be negative.
	if resp.Timing.TotalMs < 0 {
		t.Errorf("total_ms = %d, must be >= 0", resp.Timing.TotalMs)
	}
}

func TestClassifyASTSummaryCommandsFound(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if resp.AST.CommandsFound < 1 {
		t.Errorf("commands_found = %d, want >= 1", resp.AST.CommandsFound)
	}
}

func TestClassifyASTSummaryHasPipes(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "ls | grep foo"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if !resp.AST.HasPipes {
		t.Error("has_pipes = false, want true for piped command")
	}
}

func TestClassifyASTSummaryHasSubstitutions(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "echo $(ls)"})
	if resp.AST == nil {
		t.Fatal("ast is nil")
	}
	if !resp.AST.HasSubstitutions {
		t.Error("has_substitutions = false, want true for command substitution")
	}
}

func TestClassifyTraceIDFormat(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
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
		resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
		if seen[resp.StargateTrID] {
			t.Errorf("duplicate trace ID %q generated", resp.StargateTrID)
		}
		seen[resp.StargateTrID] = true
	}
}

func TestClassifyVersionField(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
	if resp.Version == "" {
		t.Error("version field is empty")
	}
}

func TestClassifyLLMReviewNilInM2(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "git status"})
	if resp.LLMReview != nil {
		t.Error("llm_review should be nil in M2")
	}
}

func TestClassifyUnknownDefaultYellow(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(classifier.ClassifyRequest{Command: "unknown_tool_xyz"})
	if resp.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow (default for unknown commands)", resp.Decision)
	}
}

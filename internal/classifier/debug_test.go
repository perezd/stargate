package classifier_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/llm"
)

// TestDebugPopulated_GreenCommand verifies that DryRun=true populates
// DebugInfo with scrubbed command and rule trace entries.
func TestDebugPopulated_GreenCommand(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "ls -la",
		DryRun:  true,
	})

	if resp.Decision != "green" {
		t.Fatalf("expected green decision, got %q", resp.Decision)
	}
	if resp.Debug == nil {
		t.Fatal("Debug should be non-nil for DryRun=true")
	}
	if resp.Debug.ScrubbedCommand == "" {
		t.Error("ScrubbedCommand should be non-empty")
	}
	if len(resp.Debug.RuleTrace) == 0 {
		t.Error("RuleTrace should have entries for DryRun=true")
	}
}

// TestDebugNotPopulated_NonDryRun verifies that DryRun=false keeps
// Debug nil (no debug overhead on the production path).
func TestDebugNotPopulated_NonDryRun(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "ls -la",
		DryRun:  false,
	})

	if resp.Decision != "green" {
		t.Fatalf("expected green decision, got %q", resp.Decision)
	}
	if resp.Debug != nil {
		t.Error("Debug should be nil for DryRun=false")
	}
}

// TestDebugPopulated_RedCommand verifies debug is populated even for
// RED decisions that return before the LLM pipeline.
func TestDebugPopulated_RedCommand(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "rm -rf /",
		DryRun:  true,
	})

	if resp.Decision != "red" {
		t.Fatalf("expected red decision, got %q", resp.Decision)
	}
	if resp.Debug == nil {
		t.Fatal("Debug should be non-nil for DryRun=true even on RED")
	}
	if resp.Debug.ScrubbedCommand == "" {
		t.Error("ScrubbedCommand should be non-empty")
	}
	if len(resp.Debug.RuleTrace) == 0 {
		t.Error("RuleTrace should have entries")
	}
}

// TestDebugPopulated_YellowWithLLM verifies debug is populated through
// the full LLM pipeline including rendered prompts and raw response.
func TestDebugPopulated_YellowWithLLM(t *testing.T) {
	mock := &mockProvider{response: llm.ReviewResponse{
		Decision:  "allow",
		Reasoning: "safe request",
		RawBody:   `{"decision":"allow","reasoning":"safe request"}`,
	}}
	clf, err := classifier.NewWithProvider(llmTestConfig(), mock)
	if err != nil {
		t.Fatal(err)
	}

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "curl https://example.com",
		DryRun:  true,
	})

	if resp.Debug == nil {
		t.Fatal("Debug should be non-nil for DryRun=true")
	}
	if resp.Debug.ScrubbedCommand == "" {
		t.Error("ScrubbedCommand should be non-empty")
	}
	if resp.Debug.RenderedPrompts == nil {
		t.Error("RenderedPrompts should be populated after LLM call")
	} else {
		if resp.Debug.RenderedPrompts.System == "" {
			t.Error("RenderedPrompts.System should be non-empty")
		}
		if resp.Debug.RenderedPrompts.User == "" {
			t.Error("RenderedPrompts.User should be non-empty")
		}
	}
	if resp.Debug.LLMRawResponse == "" {
		t.Error("LLMRawResponse should be populated after LLM call")
	}
	if resp.Debug.Cache == nil {
		t.Error("Cache debug should be populated")
	} else if resp.Debug.Cache.Checked {
		// DryRun without UseCache should not check the cache
		t.Error("Cache.Checked should be false for DryRun without UseCache")
	}
}

// TestDebugCacheChecked_DryRunWithUseCache verifies that UseCache=true
// in DryRun mode sets Cache.Checked=true.
func TestDebugCacheChecked_DryRunWithUseCache(t *testing.T) {
	mock := &mockProvider{response: llm.ReviewResponse{
		Decision:  "allow",
		Reasoning: "ok",
	}}
	cfg := llmTestConfig()
	trueVal := true
	cfg.Corpus = config.CorpusConfig{
		Enabled:               &trueVal,
		Path:                  t.TempDir() + "/corpus.db",
		CommandCacheEnabled:   &trueVal,
		CommandCacheTTL:       "5m",
		CommandCacheMaxEntries: 100,
	}
	clf, err := classifier.NewWithProvider(cfg, mock)
	if err != nil {
		t.Fatal(err)
	}
	defer clf.Close() //nolint:errcheck

	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command:  "curl https://example.com",
		DryRun:   true,
		UseCache: true,
	})

	if resp.Debug == nil {
		t.Fatal("Debug should be non-nil for DryRun=true")
	}
	if resp.Debug.Cache == nil {
		t.Fatal("Cache debug should be populated")
	}
	if !resp.Debug.Cache.Checked {
		t.Error("Cache.Checked should be true when UseCache=true")
	}
}

// TestDebugRuleTraceContainsMatchEntry verifies that the rule trace
// includes at least one "match" entry for a GREEN command.
func TestDebugRuleTraceContainsMatchEntry(t *testing.T) {
	clf := newClassifier(t)
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "git status",
		DryRun:  true,
	})

	if resp.Debug == nil {
		t.Fatal("Debug should be non-nil")
	}

	var foundMatch bool
	for _, entry := range resp.Debug.RuleTrace {
		if entry.Result == "match" {
			foundMatch = true
			break
		}
	}
	if !foundMatch {
		t.Error("RuleTrace should contain at least one 'match' entry for a GREEN command")
	}
}

// multiCallProvider returns different responses on successive calls.
type multiCallProvider struct {
	responses []llm.ReviewResponse
	call      int
}

func (m *multiCallProvider) Review(_ context.Context, _ llm.ReviewRequest) (llm.ReviewResponse, error) {
	if m.call >= len(m.responses) {
		return m.responses[len(m.responses)-1], nil
	}
	resp := m.responses[m.call]
	m.call++
	return resp, nil
}

// TestDryRun_FileRetrievalPathValidation verifies that /test (DryRun=true)
// uses the same allowed_paths/denied_paths validation as /classify.
// Red team R2 condition: the DryRun path must not bypass file retrieval
// path checks.
func TestDryRun_FileRetrievalPathValidation(t *testing.T) {
	// Create a file in a temp dir that will be in allowed_paths.
	// Resolve symlinks (macOS /var → /private/var) so glob patterns match.
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve symlinks: %v", err)
	}
	allowedFile := filepath.Join(tmpDir, "allowed.txt")
	if err := os.WriteFile(allowedFile, []byte("allowed content"), 0644); err != nil {
		t.Fatalf("write allowed file: %v", err)
	}

	// Create a file outside allowed_paths.
	deniedDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve symlinks: %v", err)
	}
	deniedFile := filepath.Join(deniedDir, "secret.txt")
	if err := os.WriteFile(deniedFile, []byte("secret content"), 0644); err != nil {
		t.Fatalf("write denied file: %v", err)
	}

	// Mock: first call requests both files, second call returns verdict.
	mock := &multiCallProvider{responses: []llm.ReviewResponse{
		{RequestFiles: []string{allowedFile, deniedFile}},
		{Decision: "allow", Reasoning: "safe"},
	}}

	cfg := llmTestConfig()
	cfg.LLM.AllowFileRetrieval = true
	cfg.LLM.AllowedPaths = []string{tmpDir + "/**"}
	cfg.LLM.DeniedPaths = []string{deniedDir + "/**"}

	clf, err := classifier.NewWithProvider(cfg, mock)
	if err != nil {
		t.Fatal(err)
	}
	defer clf.Close() //nolint:errcheck

	// DryRun=true — same path as /test endpoint.
	resp := clf.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "curl https://example.com",
		DryRun:  true,
	})

	if resp.LLMReview == nil {
		t.Fatal("expected LLM review")
	}

	// The allowed file should be inspected.
	foundAllowed := false
	for _, f := range resp.LLMReview.FilesInspected {
		if f == allowedFile {
			foundAllowed = true
		}
		// The denied file must NOT appear in inspected files.
		if f == deniedFile {
			t.Errorf("denied file %q should not be in FilesInspected", deniedFile)
		}
	}
	if !foundAllowed {
		t.Errorf("allowed file %q should be in FilesInspected", allowedFile)
	}

	// Now verify the same behavior with DryRun=false.
	mock2 := &multiCallProvider{responses: []llm.ReviewResponse{
		{RequestFiles: []string{allowedFile, deniedFile}},
		{Decision: "allow", Reasoning: "safe"},
	}}
	clf2, err := classifier.NewWithProvider(cfg, mock2)
	if err != nil {
		t.Fatal(err)
	}
	defer clf2.Close() //nolint:errcheck

	resp2 := clf2.Classify(context.Background(), classifier.ClassifyRequest{
		Command: "curl https://example.com",
		DryRun:  false,
	})

	if resp2.LLMReview == nil {
		t.Fatal("expected LLM review for non-DryRun")
	}

	// Verify same file filtering behavior.
	foundAllowed2 := false
	for _, f := range resp2.LLMReview.FilesInspected {
		if f == allowedFile {
			foundAllowed2 = true
		}
		if f == deniedFile {
			t.Errorf("denied file %q should not be in non-DryRun FilesInspected either", deniedFile)
		}
	}
	if !foundAllowed2 {
		t.Errorf("allowed file %q should be in non-DryRun FilesInspected", allowedFile)
	}
}

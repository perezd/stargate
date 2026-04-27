package rules

import (
	"context"
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
)

func TestSnapshotFromRule(t *testing.T) {
	trueVal := true
	r := config.Rule{
		Command:   "curl",
		Flags:     []string{"-o"},
		Resolve:   &config.ResolveConfig{Resolver: "url_domain", Scope: "allowed_domains"},
		LLMReview: &trueVal,
		Reason:    "network access",
	}
	snap := snapshotFromRule(r)
	if snap.Command != "curl" {
		t.Errorf("command = %q, want curl", snap.Command)
	}
	if snap.Resolve == nil || snap.Resolve.Resolver != "url_domain" {
		t.Error("resolve not captured")
	}
	if snap.LLMReview == nil || !*snap.LLMReview {
		t.Error("llm_review not captured")
	}
	if snap.Reason != "network access" {
		t.Errorf("reason = %q, want 'network access'", snap.Reason)
	}
	if len(snap.Flags) != 1 || snap.Flags[0] != "-o" {
		t.Errorf("flags = %v, want [-o]", snap.Flags)
	}
}

func TestSnapshotFromRule_NilResolve(t *testing.T) {
	r := config.Rule{
		Command: "ls",
		Reason:  "safe",
	}
	snap := snapshotFromRule(r)
	if snap.Resolve != nil {
		t.Error("resolve should be nil when rule has no resolve config")
	}
}

func TestSnapshotFromRule_Commands(t *testing.T) {
	r := config.Rule{
		Commands: []string{"git", "svn"},
		Reason:   "vcs",
	}
	snap := snapshotFromRule(r)
	if len(snap.Commands) != 2 {
		t.Errorf("commands = %v, want [git svn]", snap.Commands)
	}
}

func TestEvaluateWithTrace_RedMatch(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{Command: "rm", Flags: []string{"-rf"}, Reason: "recursive force delete"}},
		[]config.Rule{{Command: "ls", Reason: "safe list"}},
		nil, "",
	)
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	result := engine.EvaluateWithTrace(context.Background(),
		[]CommandInfo{{Name: "rm", Flags: []string{"-rf"}, Args: []string{"/"}},},
		"rm -rf /", "",
	)

	if result.Decision != "red" {
		t.Fatalf("expected red decision, got %s", result.Decision)
	}
	if result.Trace == nil {
		t.Fatal("expected non-nil trace from EvaluateWithTrace")
	}

	// Find the match entry.
	var found bool
	for _, entry := range result.Trace {
		if entry.Result == "match" {
			found = true
			if entry.Level != "red" {
				t.Errorf("match entry level = %q, want red", entry.Level)
			}
			if entry.Index != 0 {
				t.Errorf("match entry index = %d, want 0", entry.Index)
			}
			if entry.CommandTested != "rm" {
				t.Errorf("match entry command = %q, want rm", entry.CommandTested)
			}
			break
		}
	}
	if !found {
		t.Errorf("no match entry found in trace; entries: %+v", result.Trace)
	}
}

func TestEvaluateWithTrace_SkipDetail(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{Command: "rm", Flags: []string{"-rf"}, Reason: "recursive force delete"}},
		[]config.Rule{{Command: "ls", Reason: "safe list"}},
		nil, "",
	)
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	result := engine.EvaluateWithTrace(context.Background(),
		[]CommandInfo{{Name: "ls"}},
		"ls", "",
	)

	if result.Decision != "green" {
		t.Fatalf("expected green decision, got %s", result.Decision)
	}
	if result.Trace == nil {
		t.Fatal("expected non-nil trace from EvaluateWithTrace")
	}

	// The RED rule for "rm" should have a skip entry with failedStep="command"
	// because "ls" != "rm".
	var foundSkip bool
	for _, entry := range result.Trace {
		if entry.Result == "skip" && entry.Level == "red" && entry.FailedStep == "command" {
			foundSkip = true
			if entry.Detail == "" {
				t.Error("skip entry should have non-empty detail")
			}
			break
		}
	}
	if !foundSkip {
		t.Errorf("no red skip entry with failedStep=command found in trace; entries: %+v", result.Trace)
	}
}

func TestEvaluate_NoTraceAllocations(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{Command: "rm", Reason: "dangerous"}},
		[]config.Rule{{Command: "ls", Reason: "safe"}},
		nil, "",
	)
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Evaluate via Evaluate (not EvaluateWithTrace) — result.Trace must be nil.
	result := engine.Evaluate(context.Background(),
		[]CommandInfo{{Name: "ls"}},
		"ls", "",
	)

	if result.Trace != nil {
		t.Errorf("expected nil Trace from Evaluate, got %d entries", len(result.Trace))
	}
}

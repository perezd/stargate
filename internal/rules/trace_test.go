package rules

import (
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

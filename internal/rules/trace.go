package rules

import (
	"fmt"

	"github.com/limbic-systems/stargate/internal/config"
)

// RuleTraceEntry records the result of matching one rule against one command.
type RuleTraceEntry struct {
	Level         string        `json:"level"`
	Index         int           `json:"index"`
	Rule          RuleSnapshot  `json:"rule"`
	CommandTested string        `json:"command_tested"`
	Result        string        `json:"result"` // "match" or "skip"
	FailedStep    string        `json:"failed_step,omitempty"`
	Detail        string        `json:"detail,omitempty"`
	ResolveDetail *ResolveDebug `json:"resolve_detail,omitempty"`
}

// RuleSnapshot is a JSON-safe copy of a rule definition for debug output.
type RuleSnapshot struct {
	Command     string       `json:"command,omitempty"`
	Commands    []string     `json:"commands,omitempty"`
	Subcommands []string     `json:"subcommands,omitempty"`
	Flags       []string     `json:"flags,omitempty"`
	Args        []string     `json:"args,omitempty"`
	Pattern     string       `json:"pattern,omitempty"`
	Scope       string       `json:"scope,omitempty"`
	Context     string       `json:"context,omitempty"`
	Resolve     *ResolveSnap `json:"resolve,omitempty"`
	LLMReview   *bool        `json:"llm_review,omitempty"`
	Reason      string       `json:"reason"`
}

// ResolveSnap is a JSON-safe snapshot of a rule's resolve configuration.
type ResolveSnap struct {
	Resolver string `json:"resolver"`
	Scope    string `json:"scope"`
}

// ResolveDebug holds the runtime outcome of a resolve step for debug output.
type ResolveDebug struct {
	Resolver      string   `json:"resolver"`
	ResolvedValue string   `json:"resolved_value,omitempty"`
	Resolved      bool     `json:"resolved"`
	Error         string   `json:"error,omitempty"`
	Scope         string   `json:"scope"`
	ScopePatterns []string `json:"scope_patterns,omitempty"`
	Matched       bool     `json:"matched"`
}

// snapshotFromRule builds a JSON-safe RuleSnapshot from a config.Rule.
func snapshotFromRule(r config.Rule) RuleSnapshot {
	snap := RuleSnapshot{
		Command:     r.Command,
		Commands:    r.Commands,
		Subcommands: r.Subcommands,
		Flags:       r.Flags,
		Args:        r.Args,
		Pattern:     r.Pattern,
		Scope:       r.Scope,
		Context:     r.Context,
		LLMReview:   r.LLMReview,
		Reason:      r.Reason,
	}
	if r.Resolve != nil {
		snap.Resolve = &ResolveSnap{
			Resolver: r.Resolve.Resolver,
			Scope:    r.Resolve.Scope,
		}
	}
	return snap
}

// evalContext carries per-invocation trace state. It is stack-local and never
// stored on the shared Engine struct, so concurrent requests are safe.
type evalContext struct {
	trace        bool
	entries      []RuleTraceEntry
	currentLevel string
	currentIndex int
}

// appendSkipf records a rule that was skipped because a match step failed.
// The format string and args are only evaluated when tracing is active,
// avoiding fmt.Sprintf allocations on the /classify hot path.
// No-op when ec is nil or tracing is disabled.
func (ec *evalContext) appendSkipf(cr *compiledRule, cmdName, failedStep, format string, args ...any) {
	if ec == nil || !ec.trace {
		return
	}
	ec.entries = append(ec.entries, RuleTraceEntry{
		Level:         ec.currentLevel,
		Index:         ec.currentIndex,
		Rule:          snapshotFromRule(cr.rule),
		CommandTested: cmdName,
		Result:        "skip",
		FailedStep:    failedStep,
		Detail:        fmt.Sprintf(format, args...),
	})
}

// appendMatch records a rule that successfully matched.
// No-op when ec is nil or tracing is disabled.
func (ec *evalContext) appendMatch(cr *compiledRule, cmdName string) {
	if ec == nil || !ec.trace {
		return
	}
	ec.entries = append(ec.entries, RuleTraceEntry{
		Level:         ec.currentLevel,
		Index:         ec.currentIndex,
		Rule:          snapshotFromRule(cr.rule),
		CommandTested: cmdName,
		Result:        "match",
	})
}

// appendResolveSkip records a rule skip caused by a resolve step failure,
// including full resolver debug details.
// No-op when ec is nil or tracing is disabled.
func (ec *evalContext) appendResolveSkip(cr *compiledRule, cmdName string, rd ResolveDebug) {
	if ec == nil || !ec.trace {
		return
	}
	detail := fmt.Sprintf("resolver=%s resolved=%t matched=%t", rd.Resolver, rd.Resolved, rd.Matched)
	if rd.Error != "" {
		detail += fmt.Sprintf(" error=%s", rd.Error)
	}
	ec.entries = append(ec.entries, RuleTraceEntry{
		Level:         ec.currentLevel,
		Index:         ec.currentIndex,
		Rule:          snapshotFromRule(cr.rule),
		CommandTested: cmdName,
		Result:        "skip",
		FailedStep:    "resolve",
		Detail:        detail,
		ResolveDetail: &rd,
	})
}

// scopePatternGetter is an optional interface for ScopeMatchers that can
// return their configured patterns. Used to populate ResolveDebug.
type scopePatternGetter interface {
	Scopes() map[string][]string
}

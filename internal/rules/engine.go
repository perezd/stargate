// Package rules defines the command classification types and rule engine.
package rules

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/limbic-systems/stargate/internal/config"
)

// ScopeMatcher matches resolved values against operator-defined scopes.
// Implemented by *scopes.Registry.
type ScopeMatcher interface {
	Match(scopeName, value string) bool
	Has(scopeName string) bool
}

// ResolverFunc extracts a target value from a command for scope matching.
// This mirrors scopes.Resolver but is defined here to avoid a circular import.
type ResolverFunc func(ctx context.Context, cmd CommandInfo, cwd string) (value string, ok bool, err error)

// ResolverProvider looks up named resolvers.
// Implemented by adapter wrapping *scopes.ResolverRegistry.
type ResolverProvider interface {
	Get(name string) (ResolverFunc, bool)
}

// Engine evaluates commands against compiled classification rules.
type Engine struct {
	red              []compiledRule
	green            []compiledRule
	yellow           []compiledRule
	defaultDecision  string
	scopeMatcher     ScopeMatcher
	resolverProvider ResolverProvider
}

// compiledRule holds a config rule with pre-compiled fields.
type compiledRule struct {
	rule            config.Rule
	index           int
	pattern         *regexp.Regexp
	normalizedScope string // cleaned and /-suffixed scope, computed at compile time
}

// Result holds the outcome of rule evaluation.
type Result struct {
	Decision       string       // "red", "yellow", "green"
	Action         string       // "block", "review", "allow"
	Reason         string
	Rule           *MatchedRule // nil if default decision
	LLMReview      bool
	MatchedCommand *CommandInfo // which command triggered (for RED)
}

// MatchedRule identifies which rule matched.
type MatchedRule struct {
	Level  string
	Reason string
	Index  int
}

// NewEngine compiles rules from config and returns an Engine.
// The optional scopeMatcher and resolverProvider enable contextual trust
// resolution for rules with a resolve field. If nil, rules with resolve
// will not match (fail-closed).
// Returns an error if any rule has both command and commands set,
// if a regex pattern fails to compile, or if a rule references an
// undefined scope or resolver.
func NewEngine(cfg *config.Config, scopeMatcher ScopeMatcher, resolverProvider ResolverProvider) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rules: config must not be nil")
	}
	defDecision := cfg.Classifier.DefaultDecision
	if defDecision == "" {
		defDecision = "yellow" // fail-closed default
	}
	validDecisions := map[string]bool{"red": true, "yellow": true, "green": true}
	if !validDecisions[defDecision] {
		return nil, fmt.Errorf("rules: invalid default_decision %q", defDecision)
	}
	e := &Engine{
		defaultDecision:  defDecision,
		scopeMatcher:     scopeMatcher,
		resolverProvider: resolverProvider,
	}

	var err error
	if e.red, err = compileRules(cfg.Rules.Red, "red"); err != nil {
		return nil, err
	}
	if e.green, err = compileRules(cfg.Rules.Green, "green"); err != nil {
		return nil, err
	}
	if e.yellow, err = compileRules(cfg.Rules.Yellow, "yellow"); err != nil {
		return nil, err
	}

	// Validate that all rules with resolve reference defined scopes and resolvers.
	allRules := []struct {
		level string
		rules []compiledRule
	}{
		{"red", e.red}, {"green", e.green}, {"yellow", e.yellow},
	}
	for _, group := range allRules {
		for _, cr := range group.rules {
			if cr.rule.Resolve == nil {
				continue
			}
			if scopeMatcher == nil || resolverProvider == nil {
				return nil, fmt.Errorf("rules.%s[%d]: rule has resolve but no scope matcher or resolver provider configured", group.level, cr.index)
			}
			if !scopeMatcher.Has(cr.rule.Resolve.Scope) {
				return nil, fmt.Errorf("rules.%s[%d]: resolve references undefined scope %q", group.level, cr.index, cr.rule.Resolve.Scope)
			}
			if _, ok := resolverProvider.Get(cr.rule.Resolve.Resolver); !ok {
				return nil, fmt.Errorf("rules.%s[%d]: resolve references undefined resolver %q", group.level, cr.index, cr.rule.Resolve.Resolver)
			}
		}
	}

	return e, nil
}

// compileRules validates and compiles a slice of config rules.
func compileRules(rules []config.Rule, level string) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, r := range rules {
		if r.Command != "" && len(r.Commands) > 0 {
			return nil, fmt.Errorf("rules.%s[%d]: cannot set both command and commands", level, i)
		}
		var pat *regexp.Regexp
		if r.Pattern != "" {
			var err error
			pat, err = regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rules.%s[%d]: invalid pattern %q: %w", level, i, r.Pattern, err)
			}
		}
		// Normalize scope at compile time: clean path and ensure trailing /.
		// Reject relative scopes — they can never match absolute path arguments.
		var normScope string
		if r.Scope != "" {
			normScope = path.Clean(r.Scope)
			if !path.IsAbs(normScope) {
				return nil, fmt.Errorf("rules.%s[%d]: scope %q must be an absolute path", level, i, r.Scope)
			}
			if normScope != "/" && !strings.HasSuffix(normScope, "/") {
				normScope += "/"
			}
		}

		// Validate context value at compile time.
		if r.Context != "" {
			validContexts := map[string]bool{
				"any": true, "pipeline_sink": true, "pipeline_source": true,
				"pipeline": true, "subshell": true, "substitution": true,
				"condition": true, "function": true, "redirect": true,
				"background": true, // reserved — accepted in config, returns false in matching
			}
			if !validContexts[r.Context] {
				return nil, fmt.Errorf("rules.%s[%d]: invalid context %q", level, i, r.Context)
			}
		}

		// Validate args glob patterns at compile time.
		for _, argPat := range r.Args {
			if !doublestar.ValidatePattern(argPat) {
				return nil, fmt.Errorf("rules.%s[%d]: invalid glob pattern %q", level, i, argPat)
			}
		}

		compiled = append(compiled, compiledRule{
			rule:            r,
			index:           i,
			pattern:         pat,
			normalizedScope: normScope,
		})
	}
	return compiled, nil
}

// Evaluate runs the RED/GREEN/YELLOW pipeline and returns a classification.
func (e *Engine) Evaluate(cmds []CommandInfo, rawCommand string, cwd string) *Result {
	// Phase 1: RED — any match returns immediately.
	for i := range cmds {
		for j := range e.red {
			if e.matchRule(&e.red[j], &cmds[i], rawCommand, cwd) {
				return &Result{
					Decision: "red",
					Action:   "block",
					Reason:   e.red[j].rule.Reason,
					Rule: &MatchedRule{
						Level:  "red",
						Reason: e.red[j].rule.Reason,
						Index:  e.red[j].index,
					},
					MatchedCommand: &cmds[i],
				}
			}
		}
	}

	// Phase 2: GREEN — all commands must match some green rule.
	greenMatched := make([]bool, len(cmds))
	if len(cmds) > 0 && len(e.green) > 0 {
		allGreen := true
		for i := range cmds {
			for j := range e.green {
				if e.matchRule(&e.green[j], &cmds[i], rawCommand, cwd) {
					greenMatched[i] = true
					break
				}
			}
			if !greenMatched[i] {
				allGreen = false
			}
		}
		if allGreen {
			return &Result{
				Decision: "green",
				Action:   "allow",
				Reason:   "all commands matched green rules",
				Rule: &MatchedRule{
					Level:  "green",
					Reason: "all commands matched green rules",
					Index:  -1, // composite match — no single rule
				},
			}
		}
	}

	// Phase 3: YELLOW — first match for any command that didn't match GREEN.
	for i := range cmds {
		if greenMatched[i] {
			continue
		}
		for j := range e.yellow {
			if e.matchRule(&e.yellow[j], &cmds[i], rawCommand, cwd) {
				llmReview := false
				if e.yellow[j].rule.LLMReview != nil {
					llmReview = *e.yellow[j].rule.LLMReview
				}
				return &Result{
					Decision:  "yellow",
					Action:    "review",
					Reason:    e.yellow[j].rule.Reason,
					LLMReview: llmReview,
					Rule: &MatchedRule{
						Level:  "yellow",
						Reason: e.yellow[j].rule.Reason,
						Index:  e.yellow[j].index,
					},
					MatchedCommand: &cmds[i],
				}
			}
		}
	}

	// Phase 4: Default decision.
	return &Result{
		Decision: e.defaultDecision,
		Action:   decisionToAction(e.defaultDecision),
		Reason:   "no rule matched; applied default classification",
	}
}

// decisionToAction maps a decision string to its action.
func decisionToAction(decision string) string {
	switch decision {
	case "red":
		return "block"
	case "green":
		return "allow"
	default:
		return "review"
	}
}

// matchRule checks whether a compiled rule matches a command.
// All specified fields must match (conjunction). Unspecified fields are wildcards.
func (e *Engine) matchRule(cr *compiledRule, cmd *CommandInfo, rawCommand string, cwd string) bool {
	r := &cr.rule

	// 1. command/commands
	if r.Command != "" {
		if cmd.Name == "" || cmd.Name != r.Command {
			return false
		}
	}
	if len(r.Commands) > 0 {
		if cmd.Name == "" {
			return false
		}
		if !slices.Contains(r.Commands, cmd.Name) {
			return false
		}
	}

	// 2. subcommands
	if len(r.Subcommands) > 0 {
		if cmd.Subcommand == "" {
			return false
		}
		if !slices.Contains(r.Subcommands, cmd.Subcommand) {
			return false
		}
	}

	// 3. flags (two-phase matching)
	if len(r.Flags) > 0 {
		if !matchFlags(r.Flags, cmd.Flags) {
			return false
		}
	}

	// 4. args (glob matching)
	if len(r.Args) > 0 {
		if !matchArgs(r.Args, cmd.Args) {
			return false
		}
	}

	// 5. scope
	if cr.normalizedScope != "" {
		if !matchScope(cr.normalizedScope, cmd.Args) {
			return false
		}
	}

	// 6. context
	if r.Context != "" {
		if !matchContext(r.Context, cmd) {
			return false
		}
	}

	// 7. resolve — contextual trust check via scope-bound resolver.
	if r.Resolve != nil {
		if e.resolverProvider == nil || e.scopeMatcher == nil {
			return false // no resolver/scope support, fail-closed
		}
		resolver, ok := e.resolverProvider.Get(r.Resolve.Resolver)
		if !ok {
			return false // unknown resolver, fail-closed
		}
		value, resolved, err := resolver(context.Background(), *cmd, cwd)
		if err != nil || !resolved {
			return false // unresolvable, fail-closed
		}
		if !e.scopeMatcher.Match(r.Resolve.Scope, value) {
			return false // value not in scope
		}
	}

	// 8. pattern
	if cr.pattern != nil {
		if !cr.pattern.MatchString(rawCommand) {
			return false
		}
	}

	return true
}

// isDecomposable returns true if the flag is a combined short flag: starts with
// single '-' (not '--'), and ALL characters after the '-' are ASCII letters.
// Callers must strip any '=value' suffix via stripFlagValue before calling.
func isDecomposable(flag string) bool {
	if strings.HasPrefix(flag, "--") {
		return false
	}
	if !strings.HasPrefix(flag, "-") || len(flag) < 2 {
		return false
	}
	body := flag[1:]
	for _, ch := range body {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			return false
		}
	}
	return true
}

// stripFlagValue removes the =value suffix from a flag.
func stripFlagValue(flag string) string {
	if name, _, ok := strings.Cut(flag, "="); ok {
		return name
	}
	return flag
}

// matchFlags implements two-phase flag matching.
// Phase 1: Build the command's character set from decomposable short flags
// and a literal set from other flags.
// Phase 2: Check if ANY rule flag matches.
func matchFlags(ruleFlags, cmdFlags []string) bool {
	// Phase 1: Build command's flag sets.
	charSet := make(map[byte]bool)
	literalSet := make(map[string]bool)

	for _, f := range cmdFlags {
		f = stripFlagValue(f)
		if isDecomposable(f) {
			// Add each character to the char set.
			for i := 1; i < len(f); i++ {
				charSet[f[i]] = true
			}
		} else {
			literalSet[f] = true
		}
	}

	// Phase 2: Check rule flags.
	for _, rf := range ruleFlags {
		rf = stripFlagValue(rf)
		if isDecomposable(rf) {
			// All constituent chars must be in the char set.
			allPresent := true
			for i := 1; i < len(rf); i++ {
				if !charSet[rf[i]] {
					allPresent = false
					break
				}
			}
			if allPresent {
				return true
			}
		} else {
			if literalSet[rf] {
				return true
			}
		}
	}

	return false
}

// matchArgs checks if at least one cmd arg matches any rule arg pattern using doublestar.
func matchArgs(ruleArgs, cmdArgs []string) bool {
	for _, ca := range cmdArgs {
		for _, ra := range ruleArgs {
			matched, err := doublestar.Match(ra, ca)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

// matchScope checks if any absolute path in cmd args falls within the scope.
// Uses path (POSIX) semantics, not filepath (OS-specific), since stargate
// classifies bash commands with POSIX paths.
func matchScope(normalizedScope string, cmdArgs []string) bool {
	for _, arg := range cmdArgs {
		if !path.IsAbs(arg) {
			continue
		}
		cleaned := path.Clean(arg)
		if normalizedScope == "/" {
			return true
		}
		if strings.HasPrefix(cleaned+"/", normalizedScope) {
			return true
		}
	}
	return false
}

// matchContext checks if the command's context matches the rule's context requirement.
func matchContext(ctx string, cmd *CommandInfo) bool {
	switch ctx {
	case "any", "":
		return true
	case "pipeline_sink":
		return cmd.Context.PipelinePosition >= 2
	case "pipeline_source":
		return cmd.Context.PipelinePosition == 1
	case "pipeline":
		return cmd.Context.PipelinePosition >= 1
	case "subshell":
		return cmd.Context.SubshellDepth > 0
	case "substitution":
		return cmd.Context.InSubstitution
	case "condition":
		return cmd.Context.InCondition
	case "function":
		return cmd.Context.InFunction != ""
	case "redirect":
		return len(cmd.Redirects) > 0
	default:
		return false
	}
}

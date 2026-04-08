// Package rules defines the command classification types and rule engine.
package rules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/perezd/stargate/internal/config"
)

// Engine evaluates commands against compiled classification rules.
type Engine struct {
	red             []compiledRule
	green           []compiledRule
	yellow          []compiledRule
	defaultDecision string
}

// compiledRule holds a config rule with its pre-compiled regex pattern.
type compiledRule struct {
	rule    config.Rule
	index   int
	pattern *regexp.Regexp
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
// Returns an error if any rule has both command and commands set,
// or if a regex pattern fails to compile.
func NewEngine(cfg *config.Config) (*Engine, error) {
	e := &Engine{
		defaultDecision: cfg.Classifier.DefaultDecision,
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
		compiled = append(compiled, compiledRule{
			rule:    r,
			index:   i,
			pattern: pat,
		})
	}
	return compiled, nil
}

// Evaluate runs the RED/GREEN/YELLOW pipeline and returns a classification.
func (e *Engine) Evaluate(cmds []CommandInfo, rawCommand string) *Result {
	// Phase 1: RED — any match returns immediately.
	for i := range cmds {
		for j := range e.red {
			if matchRule(&e.red[j], &cmds[i], rawCommand) {
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
	if len(cmds) > 0 && len(e.green) > 0 {
		allGreen := true
		for i := range cmds {
			matched := false
			for j := range e.green {
				if matchRule(&e.green[j], &cmds[i], rawCommand) {
					matched = true
					break
				}
			}
			if !matched {
				allGreen = false
				break
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

	// Phase 3: YELLOW — first match for any unmatched command.
	for i := range cmds {
		for j := range e.yellow {
			if matchRule(&e.yellow[j], &cmds[i], rawCommand) {
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
func matchRule(cr *compiledRule, cmd *CommandInfo, rawCommand string) bool {
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
	if r.Scope != "" {
		if !matchScope(r.Scope, cmd.Args) {
			return false
		}
	}

	// 6. context
	if r.Context != "" {
		if !matchContext(r.Context, cmd) {
			return false
		}
	}

	// 7. resolve — not implemented until M3. Rules with a resolve field
	// do NOT match until resolvers are available. This prevents false-GREEN
	// classifications for scope-gated rules (e.g., curl/gh) during M2.
	if r.Resolve != nil {
		return false
	}

	// 8. pattern
	if cr.pattern != nil {
		if !cr.pattern.MatchString(rawCommand) {
			return false
		}
	}

	return true
}

// isDecomposable returns true if the flag (after stripping leading '-' and any '=value')
// is a combined short flag: starts with single '-' (not '--'), and ALL characters
// after the '-' are ASCII letters.
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

// matchScope checks if any absolute path in cmd args falls within the rule's scope.
func matchScope(scope string, cmdArgs []string) bool {
	// Normalize scope: append "/" if not present and not already "/".
	normalizedScope := scope
	if normalizedScope != "/" && !strings.HasSuffix(normalizedScope, "/") {
		normalizedScope += "/"
	}

	for _, arg := range cmdArgs {
		// Skip non-absolute paths.
		if !filepath.IsAbs(arg) {
			continue
		}
		cleaned := filepath.Clean(arg)
		// For root scope "/", all absolute paths match.
		if normalizedScope == "/" {
			return true
		}
		// Check prefix: cleaned path must start with the normalized scope,
		// or be exactly the scope directory (without trailing slash).
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

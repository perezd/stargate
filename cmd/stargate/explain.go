package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/rules"
)

const explainUsage = `Usage: stargate explain [flags] <command>

Pretty-print the full debug trace from /test. Requires a running server.

Flags:
  --server string   Stargate server URL (default: $STARGATE_URL or http://127.0.0.1:9099)
  --verbose         Show all rule trace entries and full prompts
  --json            Pretty-print the raw JSON response
`

func handleExplain(args []string, _ string, globalVerbose bool) int {
	f, err := parseExplainFlags(args, globalVerbose)
	if err != nil {
		if err == errShowHelp {
			fmt.Print(explainUsage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "explain: %v\n", err)
		return 2
	}

	if f.command == "" {
		fmt.Fprintln(os.Stderr, "explain: command is required")
		fmt.Fprint(os.Stderr, explainUsage)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	rawBody, result, err := fetchExplain(ctx, f.server, f.command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "explain: %v\n", err)
		return 1
	}

	if f.asJSON {
		var buf bytes.Buffer
		if err := json.Indent(&buf, rawBody, "", "  "); err != nil {
			// fallback: print raw
			os.Stdout.Write(rawBody) //nolint:errcheck
		} else {
			fmt.Println(buf.String())
		}
		return 0
	}

	printExplain(os.Stdout, result, f.verbose)
	return 0
}

// explainFlags holds parsed flags for the explain subcommand.
type explainFlags struct {
	server  string
	verbose bool
	asJSON  bool
	command string
}

// explainResult is the full JSON response from /test including the debug field.
type explainResult struct {
	classifier.ClassifyResponse
	Debug *classifier.DebugInfo `json:"debug"`
}

// fetchExplain POSTs to {server}/test and returns the raw body and parsed result.
func fetchExplain(ctx context.Context, server, command string) ([]byte, *explainResult, error) {
	payload := map[string]string{"command": command}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(server, "/") + "/test"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer httpResp.Body.Close() //nolint:errcheck

	rawBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("server returned %d: %s", httpResp.StatusCode, strings.TrimSpace(string(rawBody)))
	}

	var result explainResult
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return rawBody, nil, fmt.Errorf("decode response: %w", err)
	}
	return rawBody, &result, nil
}

const sectionWidth = 50

func sectionHeader(title string) string {
	dashes := sectionWidth - len(title) - 4 // "-- " prefix + " " suffix
	if dashes < 2 {
		dashes = 2
	}
	return fmt.Sprintf("\n-- %s %s", title, strings.Repeat("-", dashes))
}

// printExplain writes the pretty-printed explain output to w.
func printExplain(w io.Writer, r *explainResult, verbose bool) {
	// Header block.
	fmt.Fprintf(w, "DECISION: %s → %s (%s)\n", r.Decision, r.Action, r.Reason)
	fmt.Fprintf(w, "TRACE ID: %s\n", r.StargateTrID)
	fmt.Fprintf(w, "COMMAND:  %s\n", r.ClassifyResponse.Context["command_tested"])

	scrubbed := ""
	if r.Debug != nil {
		scrubbed = r.Debug.ScrubbedCommand
	}
	if scrubbed != "" {
		fmt.Fprintf(w, "SCRUBBED: %s\n", scrubbed)
	}

	// Rule Evaluation section.
	if r.Debug != nil && len(r.Debug.RuleTrace) > 0 {
		fmt.Fprintln(w, sectionHeader("Rule Evaluation"))
		entries := r.Debug.RuleTrace
		if !verbose {
			entries = filterRuleTrace(entries)
		}
		for _, e := range entries {
			printRuleTraceEntry(w, e)
		}
	}

	// Cache section.
	if r.Debug != nil && r.Debug.Cache != nil {
		fmt.Fprintln(w, sectionHeader("Cache"))
		c := r.Debug.Cache
		hitStr := "no"
		if c.Hit {
			hitStr = "yes"
		}
		checkedStr := "no"
		if c.Checked {
			checkedStr = "yes"
		}
		fmt.Fprintf(w, "  checked: %s, hit: %s\n", checkedStr, hitStr)
		if c.Entry != nil {
			fmt.Fprintf(w, "  cached decision: %s  action: %s\n", c.Entry.Decision, c.Entry.Action)
		}
	}

	// Corpus Precedents section.
	if r.Debug != nil && len(r.Debug.PrecedentsInjected) > 0 {
		fmt.Fprintf(w, "%s\n", sectionHeader(fmt.Sprintf("Corpus Precedents (%d injected)", len(r.Debug.PrecedentsInjected))))
		for i, p := range r.Debug.PrecedentsInjected {
			age := time.Duration(p.AgeSeconds) * time.Second
			cmdStr := strings.Join(p.CommandNames, " ")
			if len(p.Flags) > 0 {
				cmdStr += " [" + strings.Join(p.Flags, ",") + "]"
			}
			fmt.Fprintf(w, "  #%d  %-12s  sim=%.2f  %-30s  %s\n",
				i+1, p.Decision, p.Similarity, cmdStr, formatAge(age))
		}
	}

	// LLM Prompt section.
	if r.Debug != nil && r.Debug.RenderedPrompts != nil {
		fmt.Fprintln(w, sectionHeader("LLM Prompt"))
		systemPrompt := r.Debug.RenderedPrompts.System
		userContent := r.Debug.RenderedPrompts.User
		if !verbose {
			systemPrompt = truncate(systemPrompt, 200)
			userContent = truncate(userContent, 500)
		}
		if systemPrompt != "" {
			fmt.Fprintf(w, "  [system] %s\n", systemPrompt)
		}
		if userContent != "" {
			fmt.Fprintf(w, "  [user]   %s\n", userContent)
		}
	}

	// LLM Response section.
	if r.LLMReview != nil && r.LLMReview.Performed {
		fmt.Fprintln(w, sectionHeader("LLM Response"))
		fmt.Fprintf(w, "  Decision:  %s\n", r.LLMReview.Decision)
		if r.LLMReview.Reasoning != "" {
			fmt.Fprintf(w, "  Reasoning: %s\n", r.LLMReview.Reasoning)
		}
		if r.Debug != nil && r.Debug.LLMRawResponse != "" {
			raw := r.Debug.LLMRawResponse
			if !verbose {
				raw = truncate(raw, 300)
			}
			fmt.Fprintf(w, "  Raw:       %s\n", raw)
		}
	}

	// Timing section.
	if r.Timing != nil {
		fmt.Fprintln(w, sectionHeader("Timing"))
		fmt.Fprintf(w, "  parse: %.2fms  rules: %.2fms  llm: %.2fms  total: %.2fms\n",
			float64(r.Timing.ParseUs)/1000,
			float64(r.Timing.RulesUs)/1000,
			r.Timing.LLMMs,
			r.Timing.TotalMs,
		)
	}
}

// printRuleTraceEntry writes a single rule trace entry line.
func printRuleTraceEntry(w io.Writer, e rules.RuleTraceEntry) {
	levelTag := formatLevelTag(e.Level)
	resultStr := "→ skip"
	detail := ""

	if e.Result == "match" {
		resultStr = "→ MATCH"
	}

	// Build a compact rule summary.
	ruleSummary := buildRuleSummary(e.Rule)

	if e.FailedStep != "" && e.Detail != "" {
		detail = fmt.Sprintf(" (%s: %s)", e.FailedStep, truncate(e.Detail, 60))
	} else if e.FailedStep != "" {
		detail = fmt.Sprintf(" (%s)", e.FailedStep)
	} else if e.Detail != "" {
		detail = fmt.Sprintf(" (%s)", truncate(e.Detail, 60))
	}

	fmt.Fprintf(w, "  %s  #%-3d  %-30s  %s%s\n",
		levelTag, e.Index, ruleSummary, resultStr, detail)
}

// buildRuleSummary produces a compact one-line representation of a rule.
func buildRuleSummary(r rules.RuleSnapshot) string {
	cmd := r.Command
	if cmd == "" && len(r.Commands) > 0 {
		cmd = strings.Join(r.Commands, "|")
	}
	if cmd == "" && r.Pattern != "" {
		return fmt.Sprintf("pattern:%s", truncate(r.Pattern, 25))
	}

	parts := []string{}
	if len(r.Subcommands) > 0 {
		parts = append(parts, strings.Join(r.Subcommands, "|"))
	}
	if r.Resolve != nil {
		parts = append(parts, fmt.Sprintf("resolve:%s", r.Resolve.Resolver))
	} else if len(r.Flags) > 0 {
		parts = append(parts, "["+strings.Join(r.Flags, ",")+"]")
	}

	if len(parts) > 0 {
		return fmt.Sprintf("%s %s", cmd, strings.Join(parts, " "))
	}
	return cmd
}

// formatLevelTag returns a fixed-width colored-like label for a rule level.
func formatLevelTag(level string) string {
	switch strings.ToLower(level) {
	case "red":
		return "RED"
	case "green":
		return "GRN"
	case "yellow":
		return "YLW"
	default:
		return strings.ToUpper(level)
	}
}

// filterRuleTrace returns only the "relevant" entries per the task spec:
// - result == "match" (always show the winning rule)
// - command/commands contains the command_tested name
// - no command/commands field (applies to all commands)
// - has a pattern field
func filterRuleTrace(entries []rules.RuleTraceEntry) []rules.RuleTraceEntry {
	var out []rules.RuleTraceEntry
	for _, e := range entries {
		if isRelevantEntry(e) {
			out = append(out, e)
		}
	}
	return out
}

func isRelevantEntry(e rules.RuleTraceEntry) bool {
	// Always show the winning rule.
	if e.Result == "match" {
		return true
	}
	// Show pattern-only rules (no command binding).
	if e.Rule.Pattern != "" {
		return true
	}
	// Show rules with no command/commands field (applies-to-all).
	if e.Rule.Command == "" && len(e.Rule.Commands) == 0 {
		return true
	}
	// Show rules where command_tested appears in the command/commands list.
	cmdTested := strings.ToLower(e.CommandTested)
	if strings.ToLower(e.Rule.Command) == cmdTested {
		return true
	}
	for _, c := range e.Rule.Commands {
		if strings.ToLower(c) == cmdTested {
			return true
		}
	}
	return false
}

// resolveExplainURL returns the server URL from flag, env, or default.
func resolveExplainURL(flagURL string) string {
	if flagURL != "" {
		return flagURL
	}
	if env := os.Getenv("STARGATE_URL"); env != "" {
		return env
	}
	return defaultStargateURL
}

// parseExplainFlags parses flags for the explain subcommand.
func parseExplainFlags(args []string, globalVerbose bool) (*explainFlags, error) {
	f := &explainFlags{
		verbose: globalVerbose,
	}

	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			return nil, errShowHelp

		case arg == "--server":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--server requires a value")
			}
			f.server = args[i]
		case strings.HasPrefix(arg, "--server="):
			f.server = strings.TrimPrefix(arg, "--server=")

		case arg == "--verbose" || arg == "-v":
			f.verbose = true

		case arg == "--json":
			f.asJSON = true

		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown flag %q", arg)
			}
			// Remaining positional args form the command string.
			f.command = strings.Join(args[i:], " ")
			i = len(args)
		}
		i++
	}

	f.server = resolveExplainURL(f.server)
	return f, nil
}

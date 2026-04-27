package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/corpus"
	"github.com/limbic-systems/stargate/internal/parser"
)

const corpusUsage = `Usage: stargate corpus <action> [flags]

Inspect, search, and manage the precedent corpus.

Actions:
  stats                Print corpus statistics
  recent               List recent corpus entries
  search <command>     Search precedents by command string
  inspect <id>         Show full details of an entry
  invalidate <id>      Remove an entry by ID
  clear --confirm      Remove all entries
  export               Export as JSON to stdout
  import <file>        Import entries from a previous export
`

func handleCorpus(args []string, configPath string, verbose bool) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Print(corpusUsage)
		return 0
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, corpusUsage)
		return 1
	}

	switch args[0] {
	case "stats":
		return handleCorpusStats(args[1:], configPath, verbose)
	case "recent":
		return handleCorpusRecent(args[1:], configPath, verbose)
	case "search":
		return handleCorpusSearch(args[1:], configPath, verbose)
	case "inspect":
		return handleCorpusInspect(args[1:], configPath, verbose)
	case "invalidate":
		return handleCorpusInvalidate(args[1:], configPath, verbose)
	case "clear":
		return handleCorpusClear(args[1:], configPath, verbose)
	case "export":
		return handleCorpusExport(args[1:], configPath, verbose)
	case "import":
		return handleCorpusImport(args[1:], configPath, verbose)
	default:
		fmt.Fprintf(os.Stderr, "corpus: unknown subcommand %q\n", args[0])
		return 1
	}
}

// openCorpusDB loads config and opens the corpus database.
// Returns the corpus and the loaded config, or an error on failure.
func openCorpusDB(configPath string) (*corpus.Corpus, *config.Config, error) {
	if configPath == "" {
		return nil, nil, fmt.Errorf("no config file found; pass --config or set STARGATE_CONFIG")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}
	if !cfg.Corpus.IsEnabled() {
		return nil, nil, fmt.Errorf("corpus is disabled in config (corpus.enabled = false)")
	}
	if cfg.Corpus.Path == "" {
		return nil, nil, fmt.Errorf("corpus.path is not set in config")
	}
	c, err := corpus.Open(context.Background(), cfg.Corpus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open corpus: %w", err)
	}
	return c, cfg, nil
}

func handleCorpusStats(args []string, configPath string, _ bool) int {
	c, cfg, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus stats: %v\n", err)
		return 1
	}
	defer c.Close()

	stats, err := c.Stats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus stats: %v\n", err)
		return 1
	}

	fmt.Printf("Total entries: %d\n", stats.TotalEntries)

	// Decisions in deterministic order.
	for _, decision := range []string{"allow", "deny", "user_approved"} {
		count := stats.ByDecision[decision]
		fmt.Printf("  %s: %d\n", decision, count)
	}
	// Print any unexpected decisions too.
	for decision, count := range stats.ByDecision {
		if decision != "allow" && decision != "deny" && decision != "user_approved" {
			fmt.Printf("  %s: %d\n", decision, count)
		}
	}

	if stats.HasEntries {
		fmt.Printf("Oldest entry: %s\n", stats.OldestEntry.Format(time.RFC3339))
		fmt.Printf("Newest entry: %s\n", stats.NewestEntry.Format(time.RFC3339))
	} else {
		fmt.Println("Oldest entry: (none)")
		fmt.Println("Newest entry: (none)")
	}

	// DB file size: resolve path from config (already loaded by openCorpusDB).
	dbPath := cfg.Corpus.Path
	if len(dbPath) > 1 && dbPath[:2] == "~/" {
		if home, err := os.UserHomeDir(); err == nil {
			dbPath = filepath.Join(home, dbPath[2:])
		}
	}
	if info, err := os.Stat(dbPath); err == nil {
		fmt.Printf("DB file size: %d bytes\n", info.Size())
	}

	return 0
}

func handleCorpusSearch(args []string, configPath string, _ bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate corpus search <command>")
		return 1
	}

	command := strings.Join(args, " ")

	c, cfg, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus search: %v\n", err)
		return 1
	}
	defer c.Close()

	// Parse and walk the command to get CommandInfo.
	walkerCfg := parser.NewWalkerConfig(cfg.Wrappers, cfg.Commands)
	cmds, err := parser.ParseAndWalk(command, cfg.Parser.Dialect, walkerCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus search: parse command: %v\n", err)
		return 1
	}

	signature, _ := corpus.ComputeSignature(cmds)
	cmdNames := corpus.CommandNames(cmds)

	// Build lookup config from corpus config defaults.
	maxAge := 90 * 24 * time.Hour
	if parsed, err := config.ParseMaxAge(cfg.Corpus.MaxAge); err == nil && parsed > 0 {
		maxAge = parsed
	}


	lookupCfg := corpus.LookupConfig{
		MinSimilarity:  cfg.Corpus.MinSimilarity,
		MaxPrecedents:  cfg.Corpus.MaxPrecedents,
		MaxPerPolarity: cfg.Corpus.MaxPrecedentsPerPolarity,
		MaxAge:         maxAge,
	}

	results, err := c.LookupSimilar(cmdNames, signature, lookupCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus search: lookup: %v\n", err)
		return 1
	}

	if len(results) == 0 {
		fmt.Println("No similar precedents found.")
		return 0
	}

	for _, r := range results {
		age := time.Since(r.CreatedAt)
		ageStr := formatAge(age)
		reasoning := r.Reasoning
		if len(reasoning) > 80 {
			reasoning = reasoning[:77] + "..."
		}
		rawCmd := r.RawCommand
		if rawCmd == "" {
			rawCmd = "(no raw command stored)"
		}
		fmt.Printf("ID: %d  decision: %-12s  similarity: %.2f  age: %s\n",
			r.ID, r.Decision, r.Similarity, ageStr)
		fmt.Printf("  command:   %s\n", rawCmd)
		if reasoning != "" {
			fmt.Printf("  reasoning: %s\n", reasoning)
		}
		fmt.Println()
	}

	return 0
}

func handleCorpusInspect(args []string, configPath string, _ bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate corpus inspect <id>")
		return 1
	}

	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus inspect: invalid id %q: %v\n", args[0], err)
		return 1
	}

	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus inspect: %v\n", err)
		return 1
	}
	defer c.Close()

	entry, err := c.GetByID(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus inspect: %v\n", err)
		return 1
	}

	fmt.Printf("ID:            %d\n", id)
	fmt.Printf("Decision:      %s\n", entry.Decision)
	fmt.Printf("Raw command:   %s\n", entry.RawCommand)
	fmt.Printf("Command names: %s\n", strings.Join(entry.CommandNames, ", "))
	fmt.Printf("Flags:         %s\n", strings.Join(entry.Flags, " "))
	fmt.Printf("Signature:     %s\n", entry.Signature)
	fmt.Printf("Sig hash:      %s\n", entry.SignatureHash)
	if entry.ASTSummary != "" {
		fmt.Printf("AST summary:   %s\n", entry.ASTSummary)
	}
	if entry.CWD != "" {
		fmt.Printf("CWD:           %s\n", entry.CWD)
	}
	if entry.Reasoning != "" {
		fmt.Printf("Reasoning:     %s\n", entry.Reasoning)
	}
	if len(entry.RiskFactors) > 0 {
		fmt.Printf("Risk factors:  %s\n", strings.Join(entry.RiskFactors, ", "))
	}
	if entry.MatchedRule != "" {
		fmt.Printf("Matched rule:  %s\n", entry.MatchedRule)
	}
	if len(entry.ScopesInPlay) > 0 {
		fmt.Printf("Scopes:        %s\n", strings.Join(entry.ScopesInPlay, ", "))
	}
	if entry.TraceID != "" {
		fmt.Printf("Trace ID:      %s\n", entry.TraceID)
	}
	if entry.SessionID != "" {
		fmt.Printf("Session ID:    %s\n", entry.SessionID)
	}
	if entry.Agent != "" {
		fmt.Printf("Agent:         %s\n", entry.Agent)
	}
	fmt.Printf("Created at:    %s\n", entry.CreatedAt.Format(time.RFC3339))
	if entry.LastHitAt != nil {
		fmt.Printf("Last hit at:   %s\n", entry.LastHitAt.Format(time.RFC3339))
	}
	fmt.Printf("Hit count:     %d\n", entry.HitCount)

	return 0
}

func handleCorpusInvalidate(args []string, configPath string, _ bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate corpus invalidate <id>")
		return 1
	}

	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus invalidate: invalid id %q: %v\n", args[0], err)
		return 1
	}

	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus invalidate: %v\n", err)
		return 1
	}
	defer c.Close()

	n, err := c.DeleteByID(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus invalidate: %v\n", err)
		return 1
	}

	if n == 0 {
		fmt.Fprintf(os.Stderr, "corpus invalidate: no entry found with id %d\n", id)
		return 1
	}

	fmt.Fprintf(os.Stderr, "corpus: invalidated precedent %d\n", id)
	fmt.Printf("Invalidated precedent %d.\n", id)
	return 0
}

func handleCorpusClear(args []string, configPath string, _ bool) int {
	confirmed := false
	for _, arg := range args {
		if arg == "--confirm" {
			confirmed = true
		}
	}

	if !confirmed {
		fmt.Fprintln(os.Stderr, "corpus clear: requires --confirm flag to delete all entries")
		return 1
	}

	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus clear: %v\n", err)
		return 1
	}
	defer c.Close()

	n, err := c.DeleteAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus clear: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "corpus: cleared all precedents\n")
	fmt.Printf("Cleared %d entries.\n", n)
	return 0
}

func handleCorpusExport(args []string, configPath string, _ bool) int {
	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus export: %v\n", err)
		return 1
	}
	defer c.Close()

	entries, err := c.ExportAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus export: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		fmt.Fprintf(os.Stderr, "corpus export: encode json: %v\n", err)
		return 1
	}

	return 0
}

func handleCorpusImport(args []string, configPath string, _ bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate corpus import <file>")
		return 1
	}

	filePath := args[0]

	// Check file size before reading — reject files over 100MB to prevent OOM.
	info, err := os.Stat(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus import: stat file: %v\n", err)
		return 1
	}
	const maxImportSize = 100 << 20 // 100MB
	if info.Size() > maxImportSize {
		fmt.Fprintf(os.Stderr, "corpus import: file too large (%d bytes, max %d)\n", info.Size(), maxImportSize)
		return 1
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus import: read file: %v\n", err)
		return 1
	}

	var entries []corpus.PrecedentEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		fmt.Fprintf(os.Stderr, "corpus import: parse JSON: %v\n", err)
		return 1
	}

	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus import: %v\n", err)
		return 1
	}
	defer c.Close()

	imported := 0
	for i, entry := range entries {
		if err := c.ImportEntry(entry); err != nil {
			fmt.Fprintf(os.Stderr, "corpus import: entry %d: %v\n", i, err)
			// Continue importing remaining entries.
			continue
		}
		imported++
	}

	fmt.Printf("Imported %d entries.\n", imported)
	return 0
}

func handleCorpusRecent(args []string, configPath string, _ bool) int {
	fs := flag.NewFlagSet("corpus recent", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "maximum number of entries to return")
	decision := fs.String("decision", "", "filter by decision (allow, deny, user_approved)")
	since := fs.String("since", "", "only show entries newer than this duration (e.g. 1h, 24h, 168h)")
	asJSON := fs.Bool("json", false, "output as JSON array")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "corpus recent: %v\n", err)
		return 1
	}

	filter := corpus.RecentFilter{
		Limit:    *limit,
		Decision: *decision,
	}

	if *since != "" {
		d, err := time.ParseDuration(*since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "corpus recent: invalid --since value %q: %v\n", *since, err)
			return 1
		}
		filter.Since = d
	}

	c, _, err := openCorpusDB(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus recent: %v\n", err)
		return 1
	}
	defer c.Close()

	entries, err := c.Recent(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus recent: %v\n", err)
		return 1
	}

	if len(entries) == 0 {
		fmt.Println("No entries found.")
		return 0
	}

	if *asJSON {
		type jsonEntry struct {
			ID         int64   `json:"id"`
			Decision   string  `json:"decision"`
			Command    string  `json:"command"`
			Reason     string  `json:"reason"`
			AgeSeconds float64 `json:"age_seconds"`
		}
		out := make([]jsonEntry, len(entries))
		for i, e := range entries {
			out[i] = jsonEntry{
				ID:         e.ID,
				Decision:   e.Decision,
				Command:    e.RawCommand,
				Reason:     e.Reasoning,
				AgeSeconds: time.Since(e.CreatedAt).Seconds(),
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "corpus recent: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	// Table output.
	fmt.Printf("%-6s  %-5s  %-3s  %-40s  %s\n", "ID", "AGE", "DEC", "CMD", "REASON")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range entries {
		age := formatAgeCompact(time.Since(e.CreatedAt))
		dec := abbreviateDecision(e.Decision)
		cmd := truncate(e.RawCommand, 40)
		reason := truncate(e.Reasoning, 30)
		fmt.Printf("%-6d  %-5s  %-3s  %-40s  %s\n", e.ID, age, dec, cmd, reason)
	}

	return 0
}

// formatAgeCompact returns a compact age string like "5s", "3m", "2h", "1d".
func formatAgeCompact(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// abbreviateDecision returns a 3-letter abbreviation for a decision string.
func abbreviateDecision(d string) string {
	switch d {
	case "allow", "user_approved":
		return "ALW"
	case "deny":
		return "DNY"
	default:
		if len(d) >= 3 {
			return strings.ToUpper(d[:3])
		}
		return strings.ToUpper(d)
	}
}

// truncate shortens s to at most n runes, appending "..." if truncated.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[:n])
	}
	return string(runes[:n-3]) + "..."
}

// formatAge returns a human-readable age string.
func formatAge(age time.Duration) string {
	switch {
	case age < time.Hour:
		mins := int(age.Minutes())
		if mins < 1 {
			mins = 1
		}
		return fmt.Sprintf("%dm ago", mins)
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(age.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(age.Hours()/24))
	}
}

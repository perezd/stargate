// Package main is the CLI entry point for the stargate bash command classifier.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/corpus"
	"github.com/limbic-systems/stargate/internal/parser"
	"github.com/limbic-systems/stargate/internal/server"
)

// isLoopbackAddr returns true if addr binds to an explicit loopback IP only.
// Hostnames (including "localhost") are rejected — only literal 127.0.0.0/8
// and [::1] are accepted to avoid DNS resolution surprises.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Version is the current build version. Override at build time via:
//
//	go build -ldflags="-X main.Version=1.2.3" ./cmd/stargate/
var Version = "0.2.0-dev"

const usage = `stargate — bash command classifier for AI coding agents

Usage:
  stargate [global flags] <subcommand> [subcommand args...]

Subcommands:
  serve           Start the HTTP classification server
  hook            Run as a Claude Code pre-tool-use hook (reads JSON from stdin)
  test            Classify a command and print the decision
  config          Config management (e.g. config validate)
  corpus          Manage the precedent corpus

Global flags:
  -c, --config PATH   Path to config file
  -v, --verbose       Enable debug logging to stderr
  --version           Print version and exit
  --help              Print this help and exit
`

// ResolveConfigPath determines the config file path using the following priority:
//  1. flagPath — value passed via -c/--config flag
//  2. STARGATE_CONFIG env var
//  3. ~/.config/stargate/stargate.toml
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}

	if env := os.Getenv("STARGATE_CONFIG"); env != "" {
		return env
	}

	home, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(home, ".config", "stargate", "stargate.toml")
	}

	return ""
}

// subcommandHandler is a function that handles a subcommand.
// It returns the process exit code.
type subcommandHandler func(args []string, configPath string, verbose bool) int

// handlers maps subcommand names to their handler functions.
var handlers = map[string]subcommandHandler{
	"serve":  handleServe,
	"hook":   handleHook,
	"test":   handleTest,
	"config": handleConfig,
	"corpus": handleCorpus,
}

func handleServe(args []string, configPath string, verbose bool) int {
	// Parse -l/--listen flag from args.
	var listenOverride string
	var unknown []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-l" || arg == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --listen requires a value")
				return 1
			}
			listenOverride = args[i]
		case strings.HasPrefix(arg, "--listen="):
			listenOverride = strings.TrimPrefix(arg, "--listen=")
		case strings.HasPrefix(arg, "-l="):
			listenOverride = strings.TrimPrefix(arg, "-l=")
		default:
			unknown = append(unknown, arg)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "serve: unknown argument(s): %s\n", strings.Join(unknown, " "))
		return 1
	}

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "serve: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: failed to load config: %v\n", err)
		return 1
	}
	cfg.Version = Version

	listenAddr := cfg.Server.Listen
	if listenOverride != "" {
		// The --listen flag bypasses config validation, so validate here.
		if !isLoopbackAddr(listenOverride) {
			fmt.Fprintf(os.Stderr, "serve: listen address %q must be a loopback IP (127.0.0.1 or [::1])\n", listenOverride)
			return 1
		}
		listenAddr = listenOverride
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 1
	}
	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Handle SIGINT/SIGTERM for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "stargate listening on %s\n", listenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case sig := <-sigCh:
		if verbose {
			fmt.Fprintf(os.Stderr, "debug: received signal %s, shutting down\n", sig)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "serve: shutdown error: %v\n", err)
			return 1
		}
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			return 1
		}
	}

	return 0
}

func handleHook(args []string, configPath string, verbose bool) int {
	fmt.Fprintln(os.Stderr, "hook: not implemented")
	return 1
}

func handleTest(args []string, configPath string, verbose bool) int {
	fmt.Fprintln(os.Stderr, "test: not implemented")
	return 1
}

func handleConfig(args []string, configPath string, verbose bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate config <validate|dump|rules|scopes>")
		return 1
	}

	switch args[0] {
	case "validate":
		return handleConfigValidate(configPath, verbose)
	case "dump", "rules", "scopes":
		fmt.Fprintf(os.Stderr, "config %s: not implemented\n", args[0])
		return 1
	default:
		fmt.Fprintf(os.Stderr, "config: unknown subcommand %q\n", args[0])
		return 1
	}
}

func handleConfigValidate(configPath string, _ bool) int {
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	redCount := len(cfg.Rules.Red)
	greenCount := len(cfg.Rules.Green)
	yellowCount := len(cfg.Rules.Yellow)

	fmt.Fprintf(os.Stderr, "Config valid. %d red, %d yellow, %d green rules loaded.\n",
		redCount, yellowCount, greenCount)
	return 0
}

func handleCorpus(args []string, configPath string, verbose bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: stargate corpus <stats|search|inspect|invalidate|clear|export|import>")
		return 1
	}

	switch args[0] {
	case "stats":
		return handleCorpusStats(args[1:], configPath, verbose)
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
	if !cfg.Corpus.Enabled {
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
			dbPath = home + "/" + dbPath[2:]
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
	cmds, err := parser.ParseAndWalk(command, "bash", nil)
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

	minSim := cfg.Corpus.MinSimilarity
	if minSim <= 0 {
		minSim = 0.0
	}
	maxPrecedents := cfg.Corpus.MaxPrecedents
	if maxPrecedents <= 0 {
		maxPrecedents = 10
	}
	maxPerPolarity := cfg.Corpus.MaxPrecedentsPerPolarity
	if maxPerPolarity <= 0 {
		maxPerPolarity = 5
	}

	lookupCfg := corpus.LookupConfig{
		MinSimilarity:  minSim,
		MaxPrecedents:  maxPrecedents,
		MaxPerPolarity: maxPerPolarity,
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

	var id int64
	if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
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

	var id int64
	if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
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

// parseGlobalArgs parses global flags from args (typically os.Args[1:]).
// It returns the resolved values and the remaining args (subcommand + its args).
// On --help or --version it prints and os.Exit immediately.
func parseGlobalArgs(args []string) (configFlag string, verbose bool, remaining []string) {
	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "--help" || arg == "-h":
			fmt.Print(usage)
			os.Exit(0)

		case arg == "--version":
			fmt.Println("stargate", Version)
			os.Exit(0)

		case arg == "-v" || arg == "--verbose":
			verbose = true

		case arg == "-c" || arg == "--config":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --config requires a value")
				os.Exit(1)
			}
			configFlag = args[i]

		case strings.HasPrefix(arg, "--config="):
			configFlag = strings.TrimPrefix(arg, "--config=")

		case strings.HasPrefix(arg, "-c="):
			configFlag = strings.TrimPrefix(arg, "-c=")

		default:
			// First non-flag arg: treat as the start of subcommand + its args.
			remaining = args[i:]
			return configFlag, verbose, remaining
		}

		i++
	}

	return configFlag, verbose, remaining
}

func main() {
	configFlag, verbose, remaining := parseGlobalArgs(os.Args[1:])

	if len(remaining) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	subcmd := remaining[0]
	subcmdArgs := remaining[1:]

	handler, ok := handlers[subcmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n\n", subcmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	configPath := ResolveConfigPath(configFlag)

	if verbose {
		fmt.Fprintf(os.Stderr, "debug: config path = %s\n", configPath)
	}

	os.Exit(handler(subcmdArgs, configPath, verbose))
}

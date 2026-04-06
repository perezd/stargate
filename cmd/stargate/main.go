// Package main is the CLI entry point for the stargate bash command classifier.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
//  3. $CLAUDE_PROJECT_DIR/.stargate.toml (if CLAUDE_PROJECT_DIR is set)
//  4. ~/.config/stargate/stargate.toml
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}

	if env := os.Getenv("STARGATE_CONFIG"); env != "" {
		return env
	}

	if projectDir := os.Getenv("CLAUDE_PROJECT_DIR"); projectDir != "" {
		return filepath.Join(projectDir, ".stargate.toml")
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
	fmt.Fprintln(os.Stderr, "serve: not implemented")
	return 1
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
	if len(args) > 0 && args[0] == "validate" {
		fmt.Fprintln(os.Stderr, "config validate: not implemented")
		return 1
	}
	fmt.Fprintf(os.Stderr, "config: unknown subcommand %q\n", strings.Join(args, " "))
	return 1
}

func handleCorpus(args []string, configPath string, verbose bool) int {
	fmt.Fprintln(os.Stderr, "corpus: not implemented")
	return 1
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

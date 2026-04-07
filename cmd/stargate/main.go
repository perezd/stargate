// Package main is the CLI entry point for the stargate bash command classifier.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/perezd/stargate/internal/config"
	"github.com/perezd/stargate/internal/server"
)

// isLoopbackAddr returns true if addr binds to a loopback interface only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
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

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: failed to load config: %v\n", err)
		return 1
	}

	listenAddr := cfg.Server.Listen
	if listenOverride != "" {
		listenAddr = listenOverride
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9099"
	}

	// Validate and enforce loopback-only binding per security spec.
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "serve: invalid listen address %q: %v\n", listenAddr, err)
		return 1
	}
	if !isLoopbackAddr(listenAddr) {
		fmt.Fprintf(os.Stderr, "serve: listen address %q is not loopback; stargate must bind to 127.0.0.1 or [::1]\n", listenAddr)
		return 1
	}

	srv := server.New(cfg)
	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: srv,
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

func handleConfigValidate(configPath string, verbose bool) int {
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

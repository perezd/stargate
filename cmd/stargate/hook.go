package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/limbic-systems/stargate/internal/adapter"
)

const defaultStargateURL = "http://127.0.0.1:9099"
const defaultTimeout = 35 * time.Second

const hookUsage = `Usage: stargate hook [flags]

Run as an agent hook adapter. Reads JSON from stdin and writes the hook
response to stdout.

Flags:
  --agent string       Agent type (required, e.g. "claude-code")
  --event string       Hook event (default "pre-tool-use")
  --url string         Stargate server URL (default: STARGATE_URL env or http://127.0.0.1:9099)
  --timeout duration   HTTP request timeout (default 35s)
  --allow-remote       Allow non-loopback server URLs
`

func handleHook(args []string, _ string, verbose bool) int {
	agent, event, urlFlag, timeout, allowRemote, err := parseHookFlags(args)
	if err != nil {
		if err == errShowHelp {
			fmt.Print(hookUsage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "hook: %v\n", err)
		return 2
	}

	// Validate agent.
	if agent != "claude-code" {
		fmt.Fprintf(os.Stderr, "hook: unsupported agent %q (supported: claude-code)\n", agent)
		return 2
	}

	// Validate event.
	if event != "pre-tool-use" && event != "post-tool-use" {
		fmt.Fprintf(os.Stderr, "hook: unsupported event %q (supported: pre-tool-use, post-tool-use)\n", event)
		return 2
	}

	// Resolve URL: flag → env → default.
	serverURL := resolveURL(urlFlag)

	cfg := adapter.ClientConfig{
		URL:         serverURL,
		Timeout:     timeout,
		AllowRemote: allowRemote,
		Verbose:     verbose,
	}

	// Validate URL (loopback check).
	if err := cfg.ValidateURL(); err != nil {
		fmt.Fprintf(os.Stderr, "hook: %v\n", err)
		return 2
	}

	ctx := context.Background()

	switch event {
	case "pre-tool-use":
		return adapter.HandlePreToolUse(ctx, os.Stdin, os.Stdout, os.Stderr, cfg)
	case "post-tool-use":
		return adapter.HandlePostToolUse(ctx, os.Stdin, os.Stderr, cfg)
	default:
		return 2
	}
}

// resolveURL returns the stargate server URL using priority: flag → env → default.
func resolveURL(flagURL string) string {
	if flagURL != "" {
		return flagURL
	}
	if env := os.Getenv("STARGATE_URL"); env != "" {
		return env
	}
	return defaultStargateURL
}

// errShowHelp is returned by parseHookFlags when --help is requested.
var errShowHelp = fmt.Errorf("help requested")

// parseHookFlags parses hook-specific flags from args.
func parseHookFlags(args []string) (agent, event, url string, timeout time.Duration, allowRemote bool, err error) {
	event = "pre-tool-use"
	timeout = defaultTimeout

	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "--help" || arg == "-h":
			return "", "", "", 0, false, errShowHelp

		case arg == "--agent":
			i++
			if i >= len(args) {
				return "", "", "", 0, false, fmt.Errorf("--agent requires a value")
			}
			agent = args[i]

		case strings.HasPrefix(arg, "--agent="):
			agent = strings.TrimPrefix(arg, "--agent=")

		case arg == "--event" || arg == "-e":
			i++
			if i >= len(args) {
				return "", "", "", 0, false, fmt.Errorf("--event requires a value")
			}
			event = args[i]

		case strings.HasPrefix(arg, "--event="):
			event = strings.TrimPrefix(arg, "--event=")

		case strings.HasPrefix(arg, "-e="):
			event = strings.TrimPrefix(arg, "-e=")

		case arg == "--url":
			i++
			if i >= len(args) {
				return "", "", "", 0, false, fmt.Errorf("--url requires a value")
			}
			url = args[i]

		case strings.HasPrefix(arg, "--url="):
			url = strings.TrimPrefix(arg, "--url=")

		case arg == "--timeout":
			i++
			if i >= len(args) {
				return "", "", "", 0, false, fmt.Errorf("--timeout requires a value")
			}
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				return "", "", "", 0, false, fmt.Errorf("--timeout: %w", err)
			}

		case strings.HasPrefix(arg, "--timeout="):
			timeout, err = time.ParseDuration(strings.TrimPrefix(arg, "--timeout="))
			if err != nil {
				return "", "", "", 0, false, fmt.Errorf("--timeout: %w", err)
			}

		case arg == "--allow-remote":
			allowRemote = true

		default:
			return "", "", "", 0, false, fmt.Errorf("unknown flag %q", arg)
		}

		i++
	}

	if agent == "" {
		return "", "", "", 0, false, fmt.Errorf("--agent is required")
	}

	if timeout <= 0 {
		return "", "", "", 0, false, fmt.Errorf("--timeout must be positive, got %v", timeout)
	}

	return agent, event, url, timeout, allowRemote, nil
}

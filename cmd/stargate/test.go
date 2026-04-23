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
	"github.com/limbic-systems/stargate/internal/config"
)

const testUsage = `Usage: stargate test [flags] <command>

Dry-run classify a shell command. Does not write to the corpus or
generate feedback tokens. Useful for rule development and debugging.

If <command> is "-", reads the command from stdin.

Modes:
  Server mode (default) — POSTs to <url>/test. Requires a running server.
  Offline mode (--offline) — Loads config, creates a classifier in-process.
                             Does not require a running server. Corpus is
                             disabled in offline mode.

Flags:
  --cwd string         Simulated working directory (default: current dir)
  --json               Output the full ClassifyResponse JSON
  --verbose            Include timing, LLM, and corpus fields in output
  --url string         Stargate server URL (default: http://127.0.0.1:9099)
  --timeout duration   HTTP request timeout (default 10s)
  --cached             Allow cache reads during dry-run (for debugging)
  --offline            Skip the server; classify in-process
`

type testFlags struct {
	cwd       string
	asJSON    bool
	verbose   bool
	url       string
	timeout   time.Duration
	useCache  bool
	offline   bool
	command   string
	readStdin bool
}

func handleTest(args []string, configPath string, _ bool) int {
	f, err := parseTestFlags(args)
	if err != nil {
		if err == errShowHelp {
			fmt.Print(testUsage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "test: %v\n", err)
		return 2
	}

	// Read command from stdin if requested. Limit to 1MB to prevent
	// unbounded memory consumption from unexpected input.
	if f.readStdin {
		const maxStdinBytes = 1 << 20
		limited := io.LimitReader(os.Stdin, maxStdinBytes+1)
		buf, err := io.ReadAll(limited)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test: reading stdin: %v\n", err)
			return 2
		}
		if len(buf) > maxStdinBytes {
			fmt.Fprintf(os.Stderr, "test: stdin exceeds %d bytes\n", maxStdinBytes)
			return 2
		}
		f.command = strings.TrimSpace(string(buf))
	}

	if f.command == "" {
		fmt.Fprintln(os.Stderr, "test: command is required (pass as arg or use - for stdin)")
		return 2
	}

	// Resolve CWD: flag → current directory.
	if f.cwd == "" {
		if cwd, err := os.Getwd(); err == nil {
			f.cwd = cwd
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	var resp *classifier.ClassifyResponse
	if f.offline {
		resp, err = runOffline(ctx, configPath, f)
	} else {
		resp, err = runServer(ctx, f)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "test: %v\n", err)
		return 1
	}
	if resp == nil {
		fmt.Fprintln(os.Stderr, "test: classifier returned nil response")
		return 1
	}

	printResponse(os.Stdout, resp, f)
	return 0
}

// testHTTPRequest is the wire format for the /test POST body.
type testHTTPRequest struct {
	Command  string `json:"command"`
	CWD      string `json:"cwd,omitempty"`
	UseCache bool   `json:"use_cache,omitempty"`
}

// runServer POSTs to <url>/test and returns the parsed response.
func runServer(ctx context.Context, f *testFlags) (*classifier.ClassifyResponse, error) {
	body := testHTTPRequest{
		Command:  f.command,
		CWD:      f.cwd,
		UseCache: f.useCache,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(f.url, "/") + "/test"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer httpResp.Body.Close() //nolint:errcheck

	if httpResp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("server returned %d: %s", httpResp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var resp classifier.ClassifyResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// runOffline classifies the command in-process, bypassing the server.
// Corpus is disabled to avoid requiring a writable corpus path.
func runOffline(ctx context.Context, configPath string, f *testFlags) (*classifier.ClassifyResponse, error) {
	if configPath == "" {
		return nil, fmt.Errorf("--offline requires a config file (use --config or set STARGATE_CONFIG)")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Disable corpus in offline mode so the CLI works without a writable
	// corpus path. All other security layers initialize identically to
	// server mode (rules, scopes, resolvers, scrubber).
	falseVal := false
	cfg.Corpus.Enabled = &falseVal

	clf, err := classifier.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create classifier: %w", err)
	}
	defer clf.Close() //nolint:errcheck

	req := classifier.ClassifyRequest{
		Command:  f.command,
		CWD:      f.cwd,
		DryRun:   true,
		UseCache: f.useCache,
	}
	return clf.Classify(ctx, req), nil
}

// printResponse writes the classification result to w in the requested format.
func printResponse(w io.Writer, resp *classifier.ClassifyResponse, f *testFlags) {
	if f.asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	// Default: one-liner.
	line := formatOneLiner(resp)
	fmt.Fprintln(w, line)

	if f.verbose {
		if resp.Timing != nil {
			fmt.Fprintf(w, "  timing: total=%.2fms parse=%dus rules=%dus llm=%.2fms\n",
				resp.Timing.TotalMs, resp.Timing.ParseUs, resp.Timing.RulesUs, resp.Timing.LLMMs)
		}
		if resp.LLMReview != nil && resp.LLMReview.Performed {
			fmt.Fprintf(w, "  llm: decision=%q rounds=%d duration=%.2fms\n",
				resp.LLMReview.Decision, resp.LLMReview.Rounds, resp.LLMReview.DurationMs)
			if resp.LLMReview.Reasoning != "" {
				fmt.Fprintf(w, "  llm reasoning: %s\n", resp.LLMReview.Reasoning)
			}
		}
		if resp.Corpus != nil {
			fmt.Fprintf(w, "  corpus: precedents=%d\n", resp.Corpus.PrecedentsFound)
		}
		fmt.Fprintf(w, "  trace_id: %s\n", resp.StargateTrID)
	}
}

// formatOneLiner produces a single-line human-readable summary.
func formatOneLiner(resp *classifier.ClassifyResponse) string {
	decision := strings.ToUpper(resp.Decision)
	action := resp.Action
	reason := resp.Reason
	ruleTag := ""
	if resp.Rule != nil {
		ruleTag = fmt.Sprintf("rules.%s[%d]", resp.Rule.Level, resp.Rule.Index)
	}
	if ruleTag != "" {
		return fmt.Sprintf("%s %s — %s (rule: %s)", decision, action, reason, ruleTag)
	}
	return fmt.Sprintf("%s %s — %s", decision, action, reason)
}

// parseTestFlags parses the test subcommand flags. Returns errShowHelp
// when --help is requested.
func parseTestFlags(args []string) (*testFlags, error) {
	f := &testFlags{
		url:     defaultStargateURL,
		timeout: defaultTimeout,
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "--help" || arg == "-h":
			return nil, errShowHelp

		case arg == "--cwd":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--cwd requires a value")
			}
			f.cwd = args[i]
		case strings.HasPrefix(arg, "--cwd="):
			f.cwd = strings.TrimPrefix(arg, "--cwd=")

		case arg == "--json":
			f.asJSON = true

		case arg == "--verbose", arg == "-v":
			f.verbose = true

		case arg == "--url":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--url requires a value")
			}
			f.url = args[i]
		case strings.HasPrefix(arg, "--url="):
			f.url = strings.TrimPrefix(arg, "--url=")

		case arg == "--timeout":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--timeout requires a value")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, fmt.Errorf("--timeout: %w", err)
			}
			f.timeout = d
		case strings.HasPrefix(arg, "--timeout="):
			d, err := time.ParseDuration(strings.TrimPrefix(arg, "--timeout="))
			if err != nil {
				return nil, fmt.Errorf("--timeout: %w", err)
			}
			f.timeout = d

		case arg == "--cached":
			f.useCache = true

		case arg == "--offline":
			f.offline = true

		case arg == "-":
			// Stdin sentinel must be the last argument — any trailing args
			// would be silently dropped when stdin overwrites f.command.
			if i+1 < len(args) {
				return nil, fmt.Errorf("'-' (stdin) must be the last argument; got extra: %v", args[i+1:])
			}
			f.readStdin = true

		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown flag %q", arg)
			}
			// Positional argument = command. Join remaining args with spaces
			// so multi-word commands work without explicit quoting.
			f.command = strings.Join(args[i:], " ")
			return validateTestFlags(f)
		}

		i++
	}

	return validateTestFlags(f)
}

// validateTestFlags checks invariants that must hold regardless of whether
// a positional arg was found (previously the timeout check only ran on the
// no-positional-arg path).
func validateTestFlags(f *testFlags) (*testFlags, error) {
	if f.timeout <= 0 {
		return nil, fmt.Errorf("--timeout must be positive, got %v", f.timeout)
	}
	return f, nil
}

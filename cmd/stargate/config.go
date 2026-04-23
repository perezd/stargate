package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/scrub"
)

const configUsage = `Usage: stargate config <action>

Configuration inspection and validation.

Actions:
  validate    Parse and validate the config file
  dump        Print the fully resolved config as TOML
  rules       Print a summary table of all loaded rules
  scopes      Print all defined scopes and their values
`

func handleConfig(args []string, configPath string, verbose bool) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Print(configUsage)
		return 0
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, configUsage)
		return 1
	}

	switch args[0] {
	case "validate":
		return handleConfigValidate(configPath, verbose)
	case "dump":
		return handleConfigDump(configPath)
	case "rules":
		return handleConfigRules(configPath)
	case "scopes":
		return handleConfigScopes(configPath)
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

func handleConfigDump(configPath string) int {
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Scrub secrets before TOML encoding. RedactedString.String() does NOT
	// protect against reflection-based TOML marshaling — the encoder sees
	// the raw underlying string value.
	if cfg.Telemetry.Password != "" {
		cfg.Telemetry.Password = "[REDACTED]"
	}

	// Scrub the LLM system prompt for embedded API keys or secrets using
	// the same scrubber that processes commands before LLM prompts.
	if cfg.LLM.SystemPrompt != "" {
		s, scrubErr := scrub.New(cfg.Scrubbing.ExtraPatterns)
		if scrubErr != nil {
			fmt.Fprintf(os.Stderr, "warning: scrubber init failed, redacting system_prompt entirely: %v\n", scrubErr)
			cfg.LLM.SystemPrompt = "[REDACTED - scrubber error]"
		} else {
			cfg.LLM.SystemPrompt = s.Text(cfg.LLM.SystemPrompt)
		}
	}

	// Print audit header as TOML comments.
	fmt.Printf("# stargate config dump\n")
	fmt.Printf("# config: %s\n", configPath)
	fmt.Printf("# version: %s\n", Version)
	fmt.Printf("# effective config (includes defaults)\n\n")

	enc := toml.NewEncoder(os.Stdout)
	if err := enc.Encode(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: encoding config: %v\n", err)
		return 1
	}
	return 0
}

func handleConfigRules(configPath string) int {
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("%-8s %-20s %-15s %-10s %-10s %s\n",
		"LEVEL", "COMMAND", "FLAGS", "ARGS", "SCOPE", "REASON")
	fmt.Println(strings.Repeat("-", 80))

	for _, r := range cfg.Rules.Red {
		printRule("red", r)
	}
	for _, r := range cfg.Rules.Green {
		printRule("green", r)
	}
	for _, r := range cfg.Rules.Yellow {
		printRule("yellow", r)
	}

	return 0
}

func printRule(level string, r config.Rule) {
	cmd := r.Command
	if cmd == "" && len(r.Commands) > 0 {
		cmd = strings.Join(r.Commands, ", ")
	}
	flags := "—"
	if len(r.Flags) > 0 {
		flags = strings.Join(r.Flags, ", ")
	}
	args := "—"
	if len(r.Args) > 0 {
		args = strings.Join(r.Args, ", ")
	}
	scope := "—"
	if r.Scope != "" {
		scope = r.Scope
	}
	reason := r.Reason
	if r.Pattern != "" {
		cmd = "/" + r.Pattern + "/"
	}

	fmt.Printf("%-8s %-20s %-15s %-10s %-10s %s\n",
		level, cmd, flags, args, scope, reason)
}

func handleConfigScopes(configPath string) int {
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if len(cfg.Scopes) == 0 {
		fmt.Println("no scopes defined")
		return 0
	}

	// Sort scope names for deterministic output across runs.
	names := make([]string, 0, len(cfg.Scopes))
	for name := range cfg.Scopes {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		fmt.Printf("%s:\n", name)
		for _, p := range cfg.Scopes[name] {
			fmt.Printf("  - %s\n", p)
		}
	}

	return 0
}

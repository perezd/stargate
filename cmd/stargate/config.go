package main

import (
	"fmt"
	"os"

	"github.com/limbic-systems/stargate/internal/config"
)

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

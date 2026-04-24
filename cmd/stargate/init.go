package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/limbic-systems/stargate/internal/adapter"
	"github.com/limbic-systems/stargate/internal/config"
)

//go:embed default-stargate.toml
var defaultConfig embed.FS

const initUsage = `Usage: stargate init [flags]

Set up the stargate environment. Creates the config file and directories
if they don't exist. Optionally resets data stores.

Flags:
  --reset-corpus    Delete the precedent corpus database
  --reset-traces    Delete all trace files
  --reset           Shorthand for --reset-corpus --reset-traces
`

func handleInit(args []string, configPath string, _ bool) int {
	resetCorpus, resetTraces, err := parseInitFlags(args)
	if err != nil {
		if err == errShowHelp {
			fmt.Print(initUsage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		return 1
	}

	// Resolve default config path if not specified.
	if configPath == "" {
		configPath = defaultConfigPath()
	}

	// --- Config file ---
	configDir := filepath.Dir(configPath)
	configCreated := false

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create directory.
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "init: create config directory: %v\n", err)
			return 1
		}

		// Write default config.
		defaultCfg, err := defaultConfig.ReadFile("default-stargate.toml")
		if err != nil {
			fmt.Fprintf(os.Stderr, "init: read embedded config: %v\n", err)
			return 1
		}
		if err := os.WriteFile(configPath, defaultCfg, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "init: write config: %v\n", err)
			return 1
		}
		configCreated = true
	}

	// --- Corpus directory ---
	corpusDir := filepath.Join(homeDir(), ".local", "share", "stargate")
	if err := os.MkdirAll(corpusDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "init: create corpus directory: %v\n", err)
		return 1
	}

	// --- Reset corpus ---
	if resetCorpus {
		corpusPath := filepath.Join(corpusDir, "precedents.db")
		if err := os.Remove(corpusPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "init: remove corpus: %v\n", err)
			return 1
		}
		// Also remove WAL and SHM files.
		os.Remove(corpusPath + "-wal")
		os.Remove(corpusPath + "-shm")
		fmt.Println("Corpus:  reset (database deleted)")
	}

	// --- Reset traces ---
	if resetTraces {
		traceDir, err := adapter.TraceDir()
		if err == nil {
			entries, _ := os.ReadDir(traceDir)
			removed := 0
			for _, e := range entries {
				if !e.IsDir() {
					os.Remove(filepath.Join(traceDir, e.Name()))
					removed++
				}
			}
			fmt.Printf("Traces:  reset (%d files removed)\n", removed)
		}
	}

	// --- Validate config ---
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: config validation failed: %v\n", err)
		return 1
	}

	// --- Summary ---
	if configCreated {
		fmt.Printf("Config:  %s (created)\n", configPath)
	} else {
		fmt.Printf("Config:  %s (exists)\n", configPath)
	}
	if !resetCorpus {
		fmt.Printf("Corpus:  %s (ready)\n", corpusDir)
	}
	fmt.Printf("Config valid. %d red, %d yellow, %d green rules loaded.\n",
		len(cfg.Rules.Red), len(cfg.Rules.Yellow), len(cfg.Rules.Green))

	return 0
}

func parseInitFlags(args []string) (resetCorpus, resetTraces bool, err error) {
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			return false, false, errShowHelp
		case "--reset-corpus":
			resetCorpus = true
		case "--reset-traces":
			resetTraces = true
		case "--reset":
			resetCorpus = true
			resetTraces = true
		default:
			return false, false, fmt.Errorf("unknown flag %q", arg)
		}
	}
	return resetCorpus, resetTraces, nil
}

func defaultConfigPath() string {
	return filepath.Join(homeDir(), ".config", "stargate", "stargate.toml")
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/stargate-" + strconv.Itoa(os.Getuid())
	}
	return home
}


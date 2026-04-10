package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return path
}

func TestLoadMinimalConfig(t *testing.T) {
	path := writeConfig(t, `
[server]
listen = "127.0.0.1:9099"
timeout = "10s"

[parser]
dialect = "bash"

[classifier]
default_decision = "yellow"
max_ast_depth = 64
max_command_length = 65536
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9099" {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, "127.0.0.1:9099")
	}
	if cfg.Classifier.DefaultDecision != "yellow" {
		t.Errorf("default_decision = %q, want %q", cfg.Classifier.DefaultDecision, "yellow")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	path := writeConfig(t, `
[classifier]
default_decision = "invalid"
`)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid default_decision")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/stargate.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name:    "invalid dialect",
			toml:    "[parser]\ndialect = \"fish\"",
			wantErr: "dialect",
		},
		{
			name:    "invalid server timeout",
			toml:    "[server]\ntimeout = \"not-a-duration\"",
			wantErr: "server.timeout",
		},
		{
			name:    "negative server timeout",
			toml:    "[server]\ntimeout = \"-5s\"",
			wantErr: "non-negative",
		},
		{
			name:    "negative corpus max_age",
			toml:    "[corpus]\nmax_age = \"-1h\"",
			wantErr: "non-negative",
		},
		{
			name:    "invalid corpus max_age",
			toml:    "[corpus]\nmax_age = \"bogus\"",
			wantErr: "corpus.max_age",
		},
		{
			name:    "valid corpus max_age with days",
			toml:    "[corpus]\nmax_age = \"90d\"",
			wantErr: "",
		},
		{
			name:    "invalid corpus prune_interval",
			toml:    "[corpus]\nprune_interval = \"xyz\"",
			wantErr: "corpus.prune_interval",
		},
		{
			name:    "invalid min_similarity too high",
			toml:    "[corpus]\nmin_similarity = 1.5",
			wantErr: "min_similarity",
		},
		{
			name:    "invalid min_similarity negative",
			toml:    "[corpus]\nmin_similarity = -0.1",
			wantErr: "min_similarity",
		},
		{
			name:    "invalid regex pattern",
			toml:    "[[rules.red]]\npattern = \"[invalid\"\nreason = \"test\"",
			wantErr: "invalid pattern",
		},
		{
			name:    "invalid command_cache_ttl",
			toml:    "[corpus]\ncommand_cache_ttl = \"not-a-duration\"",
			wantErr: "corpus.command_cache_ttl",
		},
		{
			name:    "negative command_cache_max_entries",
			toml:    "[corpus]\ncommand_cache_max_entries = -1",
			wantErr: "corpus.command_cache_max_entries",
		},
		{
			name:    "invalid server.listen format",
			toml:    "[server]\nlisten = \"not-host-port\"",
			wantErr: "server.listen",
		},
		{
			name:    "non-loopback server.listen",
			toml:    "[server]\nlisten = \"0.0.0.0:9099\"",
			wantErr: "loopback",
		},
		{
			name:    "invalid server.listen port",
			toml:    "[server]\nlisten = \"127.0.0.1:abc\"",
			wantErr: "port",
		},
		{
			name:    "server.listen port out of range",
			toml:    "[server]\nlisten = \"127.0.0.1:99999\"",
			wantErr: "port",
		},
		{
			name:    "negative llm.max_tokens",
			toml:    "[llm]\nmax_tokens = -1",
			wantErr: "llm.max_tokens",
		},
		{
			name:    "negative llm.max_file_size",
			toml:    "[llm]\nmax_file_size = -1",
			wantErr: "llm.max_file_size",
		},
		{
			name:    "llm.temperature too high",
			toml:    "[llm]\ntemperature = 3.0",
			wantErr: "llm.temperature",
		},
		{
			name:    "negative corpus.max_precedents",
			toml:    "[corpus]\nmax_precedents = -1",
			wantErr: "corpus.max_precedents",
		},
		{
			name:    "negative corpus.max_entries",
			toml:    "[corpus]\nmax_entries = -5",
			wantErr: "corpus.max_entries",
		},
		{
			name:    "invalid scrubbing extra_patterns",
			toml:    "[scrubbing]\nextra_patterns = [\"[broken\"]",
			wantErr: "scrubbing.extra_patterns",
		},
		{
			name:    "invalid corpus.store_decisions",
			toml:    "[corpus]\nstore_decisions = \"maybe\"",
			wantErr: "store_decisions",
		},
		{
			name:    "wrapper empty command",
			toml:    "[[wrappers]]\ncommand = \"\"",
			wantErr: "wrappers[0]: command must not be empty",
		},
		{
			name:    "wrapper duplicate command",
			toml:    "[[wrappers]]\ncommand = \"sudo\"\n[[wrappers]]\ncommand = \"sudo\"",
			wantErr: "duplicate command",
		},
		{
			name:    "wrapper negative flag arg count",
			toml:    "[[wrappers]]\ncommand = \"sudo\"\n[wrappers.flags]\n\"-u\" = -1",
			wantErr: "arg count must be non-negative",
		},
		{
			name:    "commands empty command",
			toml:    "[[commands]]\ncommand = \"\"",
			wantErr: "commands[0]: command must not be empty",
		},
		{
			name:    "commands duplicate command",
			toml:    "[[commands]]\ncommand = \"git\"\n[[commands]]\ncommand = \"git\"",
			wantErr: "duplicate command",
		},
		{
			name:    "commands negative flag arg count",
			toml:    "[[commands]]\ncommand = \"git\"\n[commands.flags]\n\"--author\" = -1",
			wantErr: "arg count must be non-negative",
		},
		{
			name:    "telemetry enabled without endpoint",
			toml:    "[telemetry]\nenabled = true\nendpoint = \"\"",
			wantErr: "telemetry.endpoint",
		},
		{
			name:    "invalid telemetry protocol",
			toml:    "[telemetry]\nprotocol = \"websocket\"",
			wantErr: "telemetry.protocol",
		},
		{
			name:    "invalid log level",
			toml:    "[log]\nlevel = \"trace\"",
			wantErr: "log.level",
		},
		{
			name:    "invalid log format",
			toml:    "[log]\nformat = \"xml\"",
			wantErr: "log.format",
		},
		{
			name:    "negative llm.max_files_per_request",
			toml:    "[llm]\nmax_files_per_request = -1",
			wantErr: "llm.max_files_per_request",
		},
		{
			name:    "negative llm.max_total_file_bytes",
			toml:    "[llm]\nmax_total_file_bytes = -1",
			wantErr: "llm.max_total_file_bytes",
		},
		{
			name:    "negative llm.max_calls_per_minute",
			toml:    "[llm]\nmax_calls_per_minute = -1",
			wantErr: "llm.max_calls_per_minute",
		},
		{
			name:    "negative corpus.max_writes_per_minute",
			toml:    "[corpus]\nmax_writes_per_minute = -1",
			wantErr: "corpus.max_writes_per_minute",
		},
		{
			name:    "negative corpus.max_reasoning_length",
			toml:    "[corpus]\nmax_reasoning_length = -1",
			wantErr: "corpus.max_reasoning_length",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.toml)

			_, err := config.Load(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

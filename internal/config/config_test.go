package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perezd/stargate/internal/config"
)

func TestLoadMinimalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[server]
listen = "127.0.0.1:9099"
timeout = "10s"

[parser]
dialect = "bash"

[classifier]
default_decision = "yellow"
max_ast_depth = 64
max_command_length = 65536
`), 0644)

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
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[classifier]
default_decision = "invalid"
`), 0644)

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
			toml:    `[parser]\ndialect = "fish"`,
			wantErr: "dialect",
		},
		{
			name:    "invalid server timeout",
			toml:    "[server]\ntimeout = \"not-a-duration\"",
			wantErr: "server.timeout",
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
			name:    "invalid exact_hit_mode",
			toml:    "[corpus]\nexact_hit_mode = \"bogus\"",
			wantErr: "exact_hit_mode",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "stargate.toml")
			os.WriteFile(path, []byte(tc.toml), 0644)

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
			if !contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

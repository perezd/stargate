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

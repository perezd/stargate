package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTestConfig: %v", err)
	}
	return path
}

func TestConfigValidate_ValidConfig(t *testing.T) {
	path := writeTestConfig(t, `
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`)

	code := handleConfigValidate(path, false)
	if code != 0 {
		t.Errorf("expected exit 0 for valid config, got %d", code)
	}
}

func TestConfigValidate_InvalidConfig(t *testing.T) {
	path := writeTestConfig(t, `
[classifier]
default_decision = "invalid"
`)

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open %q: %v", os.DevNull, err)
	}
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = origStderr; devNull.Close() }()

	code := handleConfigValidate(path, false)
	if code != 1 {
		t.Errorf("expected exit 1 for invalid config, got %d", code)
	}
}

func TestConfigValidate_MissingFile(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open %q: %v", os.DevNull, err)
	}
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = origStderr; devNull.Close() }()

	code := handleConfigValidate("/nonexistent/stargate.toml", false)
	if code != 1 {
		t.Errorf("expected exit 1 for missing file, got %d", code)
	}
}

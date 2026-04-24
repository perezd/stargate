package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInit_CreatesConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate", "stargate.toml")

	code := handleInit([]string{}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file was not created")
	}

	info, _ := os.Stat(configPath)
	if info.Size() < 1000 {
		t.Errorf("config file too small (%d bytes), expected full default config", info.Size())
	}
}

func TestInit_DoesNotOverwriteExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")

	// Write a custom config.
	custom := `
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`
	os.WriteFile(configPath, []byte(custom), 0644)

	code := handleInit([]string{}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	// Verify the file was NOT overwritten.
	content, _ := os.ReadFile(configPath)
	if string(content) != custom {
		t.Error("init overwrote existing config file")
	}
}

func TestInit_ResetCorpus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")

	// Create a fake corpus DB.
	corpusDir := filepath.Join(homeDir(), ".local", "share", "stargate")
	os.MkdirAll(corpusDir, 0755)
	fakeDB := filepath.Join(corpusDir, "precedents.db")

	// Only test if we can write to the corpus dir.
	if err := os.WriteFile(fakeDB+".test-init", []byte("test"), 0644); err != nil {
		t.Skip("cannot write to corpus directory")
	}
	os.Remove(fakeDB + ".test-init")

	// Write a minimal valid config.
	os.WriteFile(configPath, []byte(`
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`), 0644)

	code := handleInit([]string{"--reset-corpus"}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestInit_ResetTraces(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")
	os.WriteFile(configPath, []byte(`
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`), 0644)

	code := handleInit([]string{"--reset-traces"}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestInit_ResetBoth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")
	os.WriteFile(configPath, []byte(`
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`), 0644)

	code := handleInit([]string{"--reset"}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestInit_Help(t *testing.T) {
	code := handleInit([]string{"--help"}, "", false)
	if code != 0 {
		t.Errorf("exit = %d, want 0 for --help", code)
	}
}

func TestInit_UnknownFlag(t *testing.T) {
	code := handleInit([]string{"--bogus"}, "stargate.toml", false)
	if code != 1 {
		t.Errorf("exit = %d, want 1 for unknown flag", code)
	}
}

func TestParseInitFlags_Reset(t *testing.T) {
	corpus, traces, err := parseInitFlags([]string{"--reset"})
	if err != nil {
		t.Fatalf("parseInitFlags: %v", err)
	}
	if !corpus || !traces {
		t.Errorf("--reset should set both: corpus=%v traces=%v", corpus, traces)
	}
}

func TestParseInitFlags_Individual(t *testing.T) {
	corpus, traces, err := parseInitFlags([]string{"--reset-corpus"})
	if err != nil {
		t.Fatalf("parseInitFlags: %v", err)
	}
	if !corpus {
		t.Error("--reset-corpus should set corpus=true")
	}
	if traces {
		t.Error("--reset-corpus should not set traces=true")
	}
}

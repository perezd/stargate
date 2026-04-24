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

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if info.Size() < 1000 {
		t.Errorf("config file too small (%d bytes), expected full default config", info.Size())
	}
}

func TestInit_DoesNotOverwriteExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")

	custom := "[server]\nlisten = \"127.0.0.1:9099\"\n[classifier]\ndefault_decision = \"yellow\"\n"
	if err := os.WriteFile(configPath, []byte(custom), 0644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	code := handleInit([]string{}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(content) != custom {
		t.Error("init overwrote existing config file")
	}
}

func TestInit_ResetCorpus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")

	// Config with corpus path pointing into the temp dir.
	corpusPath := filepath.Join(dir, "corpus", "precedents.db")
	cfg := "[server]\nlisten = \"127.0.0.1:9099\"\n[classifier]\ndefault_decision = \"yellow\"\n[corpus]\npath = \"" + corpusPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Create fake corpus files.
	if err := os.MkdirAll(filepath.Dir(corpusPath), 0700); err != nil {
		t.Fatalf("create corpus dir: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(corpusPath+suffix, []byte("test"), 0644); err != nil {
			t.Fatalf("create corpus file: %v", err)
		}
	}

	code := handleInit([]string{"--reset-corpus"}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	// Verify all corpus files removed.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(corpusPath + suffix); !os.IsNotExist(err) {
			t.Errorf("corpus file %s still exists after reset", corpusPath+suffix)
		}
	}
}

func TestInit_ResetTraces(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")
	cfg := "[server]\nlisten = \"127.0.0.1:9099\"\n[classifier]\ndefault_decision = \"yellow\"\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	code := handleInit([]string{"--reset-traces"}, configPath, false)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestInit_ResetBoth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate.toml")
	cfg := "[server]\nlisten = \"127.0.0.1:9099\"\n[classifier]\ndefault_decision = \"yellow\"\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

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

func TestInit_IdempotentSecondRun(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "stargate", "stargate.toml")

	// First run creates.
	code := handleInit([]string{}, configPath, false)
	if code != 0 {
		t.Fatalf("first run exit = %d", code)
	}

	// Second run is idempotent.
	code = handleInit([]string{}, configPath, false)
	if code != 0 {
		t.Fatalf("second run exit = %d", code)
	}
}

func TestExpandHome(t *testing.T) {
	home := homeDir()
	tests := []struct {
		input string
		want  string
	}{
		{"~/foo", filepath.Join(home, "foo")},
		{"~", home},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		got := expandHome(tt.input)
		if got != tt.want {
			t.Errorf("expandHome(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

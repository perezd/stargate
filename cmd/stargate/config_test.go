package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
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

const testMinimalConfig = `
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
[[rules.red]]
command = "rm"
flags = ["-rf"]
reason = "dangerous"
[[rules.green]]
commands = ["ls", "echo"]
reason = "safe"
`

// captureStdout runs f and returns whatever it wrote to os.Stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer func() { os.Stdout = old }()
	os.Stdout = w
	f()
	w.Close()
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return string(buf)
}

// --- config dump ---

func TestConfigDump_ValidTOML(t *testing.T) {
	path := writeTestConfig(t, testMinimalConfig)
	out := captureStdout(t, func() {
		if code := handleConfigDump(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	var parsed map[string]any
	if _, err := toml.Decode(out, &parsed); err != nil {
		t.Errorf("dump output is not valid TOML: %v", err)
	}
}

func TestConfigDump_CommentHeader(t *testing.T) {
	path := writeTestConfig(t, testMinimalConfig)
	out := captureStdout(t, func() { handleConfigDump(path) })
	for _, want := range []string{"# stargate config dump", "# config:", "# version:", "# effective config"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing header %q in dump output", want)
		}
	}
}

func TestConfigDump_PasswordScrubbed(t *testing.T) {
	cfg := testMinimalConfig + `
[telemetry]
enabled = true
endpoint = "https://otlp.example.com"
password = "super-secret-password"
`
	path := writeTestConfig(t, cfg)
	out := captureStdout(t, func() {
		if code := handleConfigDump(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	if strings.Contains(out, "super-secret-password") {
		t.Error("dump output contains plaintext password")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Error("dump output missing [REDACTED] for password")
	}
}

func TestConfigDump_InvalidConfig(t *testing.T) {
	path := writeTestConfig(t, `
[classifier]
default_decision = "invalid"
`)
	code := handleConfigDump(path)
	if code != 1 {
		t.Errorf("exit = %d, want 1 for invalid config", code)
	}
}

func TestConfigDump_MissingConfig(t *testing.T) {
	code := handleConfigDump("")
	if code != 1 {
		t.Errorf("exit = %d, want 1 for missing config", code)
	}
}

func TestConfigDump_RoundTripIdempotency(t *testing.T) {
	path := writeTestConfig(t, testMinimalConfig)

	stripComments := func(s string) string {
		var lines []string
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(line, "#") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}

	dump1 := stripComments(captureStdout(t, func() {
		if code := handleConfigDump(path); code != 0 {
			t.Fatalf("first dump exit = %d", code)
		}
	}))

	path2 := writeTestConfig(t, dump1)
	dump2 := stripComments(captureStdout(t, func() {
		if code := handleConfigDump(path2); code != 0 {
			t.Fatalf("second dump exit = %d", code)
		}
	}))

	if dump1 != dump2 {
		t.Errorf("round-trip not idempotent")
	}
}

func TestConfigDump_SystemPromptScrubbed(t *testing.T) {
	cfg := testMinimalConfig + `
[llm]
system_prompt = "Use API key sk-ant-1234567890abcdef to authenticate"
`
	path := writeTestConfig(t, cfg)
	out := captureStdout(t, func() {
		if code := handleConfigDump(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	if strings.Contains(out, "sk-ant-1234567890abcdef") {
		t.Error("dump output contains raw API key in system_prompt — scrubbing failed")
	}
}

// --- config rules ---

func TestConfigRules_AllTiers(t *testing.T) {
	path := writeTestConfig(t, testMinimalConfig)
	out := captureStdout(t, func() {
		if code := handleConfigRules(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	if !strings.Contains(out, "red") {
		t.Error("missing red tier")
	}
	if !strings.Contains(out, "green") {
		t.Error("missing green tier")
	}
	if !strings.Contains(out, "LEVEL") {
		t.Error("missing header row")
	}
}

func TestConfigRules_EmptyTier(t *testing.T) {
	cfg := `
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`
	path := writeTestConfig(t, cfg)
	code := handleConfigRules(path)
	if code != 0 {
		t.Errorf("exit = %d, want 0 for empty rules", code)
	}
}

// --- config scopes ---

func TestConfigScopes_NoScopes(t *testing.T) {
	path := writeTestConfig(t, testMinimalConfig)
	out := captureStdout(t, func() {
		if code := handleConfigScopes(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	if !strings.Contains(out, "no scopes defined") {
		t.Errorf("expected 'no scopes defined', got: %q", out)
	}
}

func TestConfigScopes_WithScopes(t *testing.T) {
	cfg := testMinimalConfig + `
[scopes]
github_owners = ["my-org"]
`
	path := writeTestConfig(t, cfg)
	out := captureStdout(t, func() {
		if code := handleConfigScopes(path); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
	if !strings.Contains(out, "github_owners") || !strings.Contains(out, "my-org") {
		t.Errorf("expected scope in output, got: %q", out)
	}
}

// --- config help ---

func TestConfigHelp(t *testing.T) {
	code := handleConfig([]string{"--help"}, "", false)
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

func TestConfigNoArgs(t *testing.T) {
	code := handleConfig([]string{}, "", false)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

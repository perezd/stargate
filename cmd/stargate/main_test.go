package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveConfigPath_FlagOverridesAll verifies that an explicit flag path
// takes highest priority regardless of environment variables.
func TestResolveConfigPath_FlagOverridesAll(t *testing.T) {
	t.Setenv("STARGATE_CONFIG", "/env/path/config.toml")
	t.Setenv("CLAUDE_PROJECT_DIR", "/project")

	got := ResolveConfigPath("/flag/path/config.toml")
	want := "/flag/path/config.toml"
	if got != want {
		t.Errorf("ResolveConfigPath with flag: got %q, want %q", got, want)
	}
}

// TestResolveConfigPath_EnvVarOverridesDefaults verifies that STARGATE_CONFIG
// is used when no flag is provided.
func TestResolveConfigPath_EnvVarOverridesDefaults(t *testing.T) {
	t.Setenv("STARGATE_CONFIG", "/env/stargate.toml")
	os.Unsetenv("CLAUDE_PROJECT_DIR")

	got := ResolveConfigPath("")
	want := "/env/stargate.toml"
	if got != want {
		t.Errorf("ResolveConfigPath with STARGATE_CONFIG env: got %q, want %q", got, want)
	}
}

// TestResolveConfigPath_IgnoresClaudeProjectDir verifies that CLAUDE_PROJECT_DIR
// is not used for config resolution (removed per PR review — no magic paths).
func TestResolveConfigPath_IgnoresClaudeProjectDir(t *testing.T) {
	os.Unsetenv("STARGATE_CONFIG")
	t.Setenv("CLAUDE_PROJECT_DIR", "/my/project")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	got := ResolveConfigPath("")
	want := filepath.Join(home, ".config", "stargate", "stargate.toml")
	if got != want {
		t.Errorf("ResolveConfigPath should fall through to default, got %q, want %q", got, want)
	}
}

// TestResolveConfigPath_DefaultFallback verifies that the ~/.config/stargate/stargate.toml
// default is returned when no overrides are in effect.
func TestResolveConfigPath_DefaultFallback(t *testing.T) {
	os.Unsetenv("STARGATE_CONFIG")
	os.Unsetenv("CLAUDE_PROJECT_DIR")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	got := ResolveConfigPath("")
	want := filepath.Join(home, ".config", "stargate", "stargate.toml")
	if got != want {
		t.Errorf("ResolveConfigPath default: got %q, want %q", got, want)
	}
}

// TestHandlers_AllSubcommandsRegistered ensures every documented subcommand
// has a registered handler.
func TestHandlers_AllSubcommandsRegistered(t *testing.T) {
	expected := []string{"serve", "hook", "test", "config", "corpus"}
	for _, name := range expected {
		if _, ok := handlers[name]; !ok {
			t.Errorf("handler for subcommand %q is not registered", name)
		}
	}
}

// TestHandlers_UnknownSubcommandNotRegistered ensures a random name is absent.
func TestHandlers_UnknownSubcommandNotRegistered(t *testing.T) {
	if _, ok := handlers["nonexistent"]; ok {
		t.Error("unexpected handler registered for 'nonexistent'")
	}
}

// TestHandlers_UnimplementedReturnNonZero verifies not-yet-implemented handlers
// return non-zero exit codes.
func TestHandlers_UnimplementedReturnNonZero(t *testing.T) {
	devNull, _ := os.Open(os.DevNull)
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() {
		os.Stderr = origStderr
		devNull.Close()
	}()

	unimplemented := []string{"hook", "test", "corpus"}
	for _, name := range unimplemented {
		handler := handlers[name]
		code := handler(nil, "", false)
		if code == 0 {
			t.Errorf("handler %q returned exit code 0, expected non-zero (not implemented)", name)
		}
	}
}

func TestConfigValidate_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[server]
listen = "127.0.0.1:9099"
[classifier]
default_decision = "yellow"
`), 0644)

	code := handleConfigValidate(path, false)
	if code != 0 {
		t.Errorf("expected exit 0 for valid config, got %d", code)
	}
}

func TestConfigValidate_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[classifier]
default_decision = "invalid"
`), 0644)

	devNull, _ := os.Open(os.DevNull)
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = origStderr; devNull.Close() }()

	code := handleConfigValidate(path, false)
	if code != 1 {
		t.Errorf("expected exit 1 for invalid config, got %d", code)
	}
}

func TestConfigValidate_MissingFile(t *testing.T) {
	devNull, _ := os.Open(os.DevNull)
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = origStderr; devNull.Close() }()

	code := handleConfigValidate("/nonexistent/stargate.toml", false)
	if code != 1 {
		t.Errorf("expected exit 1 for missing file, got %d", code)
	}
}

// TestParseGlobalArgs_VerboseFlag verifies -v sets verbose.
func TestParseGlobalArgs_VerboseFlag(t *testing.T) {
	_, verbose, remaining := parseGlobalArgs([]string{"-v", "serve"})
	if !verbose {
		t.Error("expected verbose=true with -v flag")
	}
	if len(remaining) != 1 || remaining[0] != "serve" {
		t.Errorf("expected remaining=[serve], got %v", remaining)
	}
}

// TestParseGlobalArgs_ConfigFlag verifies -c captures the path.
func TestParseGlobalArgs_ConfigFlag(t *testing.T) {
	configFlag, _, remaining := parseGlobalArgs([]string{"-c", "/some/config.toml", "hook"})
	if configFlag != "/some/config.toml" {
		t.Errorf("expected configFlag=/some/config.toml, got %q", configFlag)
	}
	if len(remaining) != 1 || remaining[0] != "hook" {
		t.Errorf("expected remaining=[hook], got %v", remaining)
	}
}

// TestParseGlobalArgs_ConfigFlagEquals verifies --config=path syntax.
func TestParseGlobalArgs_ConfigFlagEquals(t *testing.T) {
	configFlag, _, _ := parseGlobalArgs([]string{"--config=/alt/path.toml", "test"})
	if configFlag != "/alt/path.toml" {
		t.Errorf("expected configFlag=/alt/path.toml, got %q", configFlag)
	}
}

// TestParseGlobalArgs_NoSubcommand verifies empty remaining when no subcommand given.
func TestParseGlobalArgs_NoSubcommand(t *testing.T) {
	_, _, remaining := parseGlobalArgs([]string{"-v"})
	if len(remaining) != 0 {
		t.Errorf("expected empty remaining, got %v", remaining)
	}
}

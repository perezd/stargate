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

// TestResolveConfigPath_ClaudeProjectDir verifies that $CLAUDE_PROJECT_DIR/.stargate.toml
// is used when no flag and no STARGATE_CONFIG are set.
func TestResolveConfigPath_ClaudeProjectDir(t *testing.T) {
	os.Unsetenv("STARGATE_CONFIG")
	t.Setenv("CLAUDE_PROJECT_DIR", "/my/project")

	got := ResolveConfigPath("")
	want := "/my/project/.stargate.toml"
	if got != want {
		t.Errorf("ResolveConfigPath with CLAUDE_PROJECT_DIR: got %q, want %q", got, want)
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

// TestHandlers_SubcommandHandlersReturnNonZero verifies each handler returns a
// non-zero exit code when the feature is not yet implemented.
func TestHandlers_SubcommandHandlersReturnNonZero(t *testing.T) {
	// Redirect stderr to suppress "not implemented" messages during tests.
	devNull, _ := os.Open(os.DevNull)
	origStderr := os.Stderr
	os.Stderr = devNull
	defer func() {
		os.Stderr = origStderr
		devNull.Close()
	}()

	for name, handler := range handlers {
		code := handler(nil, "", false)
		if code == 0 {
			t.Errorf("handler %q returned exit code 0, expected non-zero (not implemented)", name)
		}
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

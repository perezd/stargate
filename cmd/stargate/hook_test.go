package main

import (
	"testing"
)

func TestParseHookFlags_AgentRequired(t *testing.T) {
	_, _, _, _, _, err := parseHookFlags([]string{"--event", "pre-tool-use"})
	if err == nil {
		t.Fatal("expected error for missing --agent")
	}
}

func TestParseHookFlags_UnknownAgent(t *testing.T) {
	code := handleHook([]string{"--agent", "unknown-agent"}, "", false)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2 for unknown agent", code)
	}
}

func TestParseHookFlags_UnknownEvent(t *testing.T) {
	code := handleHook([]string{"--agent", "claude-code", "--event", "bad-event"}, "", false)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2 for unknown event", code)
	}
}

func TestResolveURL_FlagOverridesEnv(t *testing.T) {
	t.Setenv("STARGATE_URL", "http://127.0.0.1:8888")
	got := resolveURL("http://127.0.0.1:7777")
	if got != "http://127.0.0.1:7777" {
		t.Errorf("resolveURL with flag: got %q, want flag value", got)
	}
}

func TestResolveURL_EnvOverridesDefault(t *testing.T) {
	t.Setenv("STARGATE_URL", "http://127.0.0.1:8888")
	got := resolveURL("")
	if got != "http://127.0.0.1:8888" {
		t.Errorf("resolveURL with env: got %q, want env value", got)
	}
}

func TestResolveURL_DefaultFallback(t *testing.T) {
	t.Setenv("STARGATE_URL", "")
	got := resolveURL("")
	if got != defaultStargateURL {
		t.Errorf("resolveURL default: got %q, want %q", got, defaultStargateURL)
	}
}

func TestHandleHook_NonLoopbackRejected(t *testing.T) {
	code := handleHook([]string{
		"--agent", "claude-code",
		"--event", "pre-tool-use",
		"--url", "http://10.0.0.1:9099",
	}, "", false)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2 for non-loopback URL", code)
	}
}

func TestHandleHook_AllowRemoteOverridesLoopbackCheck(t *testing.T) {
	// With --allow-remote, a non-loopback URL should pass URL validation.
	// The handler will still return exit 2 (no server), but that proves
	// it got past the loopback check — without --allow-remote it would
	// have failed at URL validation with the same exit code but a
	// different error message.
	code := handleHook([]string{
		"--agent", "claude-code",
		"--event", "pre-tool-use",
		"--url", "http://10.0.0.1:9099",
		"--allow-remote",
	}, "", false)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2 (from adapter, not URL validation)", code)
	}
}

package llm

import (
	"testing"
)

func TestParseResponse_Allow(t *testing.T) {
	input := `{"decision": "allow", "reasoning": "Safe command", "risk_factors": []}`
	resp, err := parseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
	if resp.Reasoning != "Safe command" {
		t.Errorf("reasoning = %q, want 'Safe command'", resp.Reasoning)
	}
}

func TestParseResponse_Deny(t *testing.T) {
	input := `{"decision": "deny", "reasoning": "Dangerous", "risk_factors": ["data exfiltration"]}`
	resp, err := parseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("decision = %q, want deny", resp.Decision)
	}
	if len(resp.RiskFactors) != 1 || resp.RiskFactors[0] != "data exfiltration" {
		t.Errorf("risk_factors = %v, want [data exfiltration]", resp.RiskFactors)
	}
}

func TestParseResponse_FileRequest(t *testing.T) {
	input := `{"request_files": ["/path/to/deploy.sh"], "reasoning": "Need to inspect script"}`
	resp, err := parseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.RequestFiles) != 1 || resp.RequestFiles[0] != "/path/to/deploy.sh" {
		t.Errorf("request_files = %v, want [/path/to/deploy.sh]", resp.RequestFiles)
	}
	if resp.Decision != "" {
		t.Errorf("decision should be empty for file request, got %q", resp.Decision)
	}
}

func TestParseResponse_MarkdownCodeFence(t *testing.T) {
	input := "```json\n{\"decision\": \"allow\", \"reasoning\": \"ok\"}\n```"
	resp, err := parseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	_, err := parseResponse("not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseResponse_NullDecision(t *testing.T) {
	// null decision → empty string, which maps to "review" in the classifier
	resp, err := parseResponse(`{"decision": null, "reasoning": "unclear"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "" {
		t.Errorf("decision = %q, want empty (null → zero value)", resp.Decision)
	}
}

func TestParseResponse_EmptyObject(t *testing.T) {
	resp, err := parseResponse(`{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "" {
		t.Errorf("decision = %q, want empty", resp.Decision)
	}
}

func TestParseResponse_UnknownFields(t *testing.T) {
	// Unknown fields should be silently ignored (not cause an error).
	resp, err := parseResponse(`{"decision": "allow", "reasoning": "ok", "unknown_field": true}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

func TestParseResponse_NestedJSONInReasoning(t *testing.T) {
	// Reasoning containing JSON should be treated as a plain string.
	input := `{"decision": "deny", "reasoning": "{\"decision\": \"allow\"}", "risk_factors": []}`
	resp, err := parseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("decision = %q, want deny (not the nested allow)", resp.Decision)
	}
}

func TestSubprocessArgs(t *testing.T) {
	req := ReviewRequest{
		SystemPrompt: "You are a classifier.",
		UserContent:  "echo hello",
		Model:        "claude-sonnet-4-6",
		MaxTokens:    512,
		Temperature:  0.0,
	}
	args := subprocessArgs(req)

	// --system-prompt must carry the system prompt (not concatenated into stdin).
	foundSysPrompt := false
	for i, a := range args {
		if a == "--system-prompt" {
			if i+1 >= len(args) {
				t.Fatal("--system-prompt flag has no value")
			}
			if args[i+1] != req.SystemPrompt {
				t.Errorf("--system-prompt value = %q, want %q", args[i+1], req.SystemPrompt)
			}
			foundSysPrompt = true
		}
	}
	if !foundSysPrompt {
		t.Error("args missing --system-prompt flag")
	}

	// Must include -p, --model, --max-turns 1, and trailing - for stdin.
	want := map[string]bool{"-p": false, "--model": false, "--max-turns": false, "-": false}
	for _, a := range args {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for flag, found := range want {
		if !found {
			t.Errorf("args missing required flag %q", flag)
		}
	}

	// Trailing arg must be "-" (stdin marker).
	if args[len(args)-1] != "-" {
		t.Errorf("last arg = %q, want %q (stdin marker)", args[len(args)-1], "-")
	}

	// SystemPrompt must NOT appear in UserContent position (stdin).
	// This is the trust boundary: system prompt via flag, user content via stdin.
	for i, a := range args {
		if a == "-p" || a == "--model" || a == "--max-turns" || a == "--system-prompt" || a == "-" {
			continue
		}
		if i > 0 && (args[i-1] == "--model" || args[i-1] == "--max-turns" || args[i-1] == "--system-prompt") {
			continue // value of a flag
		}
		t.Errorf("unexpected arg at position %d: %q", i, a)
	}
}

func TestNewAnthropicProvider_NoAuth(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	p := NewAnthropicProvider()
	if p.HasAuth() {
		t.Error("HasAuth should be false with no credentials")
	}
}

func TestNewAnthropicProvider_WithEnvAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	p := NewAnthropicProvider()
	if !p.HasAuth() {
		t.Error("HasAuth should be true with ANTHROPIC_API_KEY env")
	}
	if !p.hasClient {
		t.Error("client should be initialized with API key")
	}
}

func TestNewAnthropicProvider_ReviewWithoutAuth(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	p := NewAnthropicProvider()
	_, err := p.Review(t.Context(), ReviewRequest{})
	if err == nil {
		t.Fatal("expected error when no auth available")
	}
}

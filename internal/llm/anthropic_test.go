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

func TestNewAnthropicProvider_NoAuth(t *testing.T) {
	// With no API key and no env vars, HasAuth should return false.
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	p := NewAnthropicProvider("")
	if p.HasAuth() {
		t.Error("HasAuth should be false with no credentials")
	}
}

func TestNewAnthropicProvider_WithAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	p := NewAnthropicProvider("sk-ant-test")
	if !p.HasAuth() {
		t.Error("HasAuth should be true with API key")
	}
	if !p.hasClient {
		t.Error("client should be initialized with API key")
	}
}

func TestNewAnthropicProvider_ReviewWithoutAuth(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	p := NewAnthropicProvider("")
	_, err := p.Review(t.Context(), ReviewRequest{})
	if err == nil {
		t.Fatal("expected error when no auth available")
	}
}

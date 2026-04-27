package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicProvider implements ReviewerProvider using the Anthropic API.
// It supports two auth paths: direct API key (via SDK) and OAuth token
// (via `claude -p` subprocess).
type AnthropicProvider struct {
	apiKey string           // direct API key (preferred)
	client anthropic.Client // initialized when apiKey is set
	hasClient bool
}

// NewAnthropicProvider creates a provider using environment variables for auth.
// Resolution order:
//  1. ANTHROPIC_API_KEY env → direct SDK path (fast, no subprocess)
//  2. CLAUDE_CODE_OAUTH_TOKEN env + claude binary on PATH → subprocess path
//  3. Neither → Review returns an error; caller disables LLM review
//
// No API key is accepted via config — secrets stay in env vars, not on disk.
func NewAnthropicProvider() *AnthropicProvider {
	key := os.Getenv("ANTHROPIC_API_KEY")

	p := &AnthropicProvider{apiKey: key}
	if key != "" {
		p.client = anthropic.NewClient(option.WithAPIKey(key))
		p.hasClient = true
	}
	return p
}

// Review sends the prompt to the Anthropic API and returns the parsed response.
func (p *AnthropicProvider) Review(ctx context.Context, req ReviewRequest) (ReviewResponse, error) {
	if p.hasClient {
		return p.reviewSDK(ctx, req)
	}

	// Fallback: subprocess via claude -p
	oauthToken := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN")
	if oauthToken == "" {
		return ReviewResponse{}, fmt.Errorf("llm: no API key or OAuth token available")
	}
	if !HasCLI() {
		return ReviewResponse{}, fmt.Errorf("llm: CLAUDE_CODE_OAUTH_TOKEN set but claude binary not found in PATH")
	}
	return p.reviewSubprocess(ctx, req)
}

// reviewSDK calls the Anthropic Messages API directly via the SDK.
func (p *AnthropicProvider) reviewSDK(ctx context.Context, req ReviewRequest) (ReviewResponse, error) {
	resp, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:       req.Model,
		MaxTokens:   int64(req.MaxTokens),
		Temperature: anthropic.Float(req.Temperature),
		System: []anthropic.TextBlockParam{
			{Text: req.SystemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(
				anthropic.NewTextBlock(req.UserContent),
			),
		},
	})
	if err != nil {
		return ReviewResponse{}, fmt.Errorf("llm: anthropic API error: %w", err)
	}

	// Concatenate all text blocks from the response (Anthropic responses
	// can contain multiple text blocks).
	var textParts []string
	for _, block := range resp.Content {
		if block.Type == "text" {
			textParts = append(textParts, block.Text)
		}
	}
	text := strings.Join(textParts, "")
	if text == "" {
		return ReviewResponse{}, fmt.Errorf("llm: empty response from Anthropic API")
	}

	parsed, err := parseResponse(text)
	parsed.RawBody = text
	return parsed, err
}

// reviewSubprocess calls `claude -p` with the prompt piped via stdin.
// Uses SIGTERM→SIGKILL with WaitDelay for graceful shutdown.
func (p *AnthropicProvider) reviewSubprocess(ctx context.Context, req ReviewRequest) (ReviewResponse, error) {
	cmd := exec.CommandContext(ctx, "claude", "-p", "--model", req.Model, "--max-turns", "1", "-")
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second

	// Pipe prompt via stdin — SystemPrompt + UserContent concatenated.
	cmd.Stdin = strings.NewReader(req.SystemPrompt + "\n\n" + req.UserContent)

	// Bounded stderr drain to prevent pipe deadlock.
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return ReviewResponse{}, fmt.Errorf("llm: stderr pipe: %w", err)
	}
	// Drain stderr to EOF to prevent pipe deadlock. Retain only the first
	// 4KB for diagnostics; discard the rest.
	var stderrBuf strings.Builder
	var wg sync.WaitGroup
	wg.Go(func() {
		io.Copy(&stderrBuf, io.LimitReader(stderrPipe, 4096)) //nolint:errcheck
		io.Copy(io.Discard, stderrPipe)                        //nolint:errcheck // drain remainder
	})

	output, err := cmd.Output()
	wg.Wait() // Join stderr goroutine before returning.
	if err != nil {
		stderr := stderrBuf.String()
		return ReviewResponse{}, fmt.Errorf("llm: claude subprocess error: %w (stderr: %s)", err, stderr)
	}

	resp, err := parseResponse(string(output))
	resp.RawBody = string(output)
	return resp, err
}

// parseResponse extracts a ReviewResponse from the LLM's JSON output.
// Unknown JSON fields are silently ignored (not treated as errors).
// Type mismatches (e.g., decision as int) cause a parse error → "review".
func parseResponse(text string) (ReviewResponse, error) {
	// The LLM may wrap JSON in markdown code fences — extract the content.
	// Only attempt fence extraction if the response starts with a fence to
	// avoid false-matching backticks inside valid JSON strings.
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```") {
		rest := text[3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if end := strings.Index(rest, "```"); end >= 0 {
			text = strings.TrimSpace(rest[:end])
		}
	}

	var raw struct {
		Decision     string   `json:"decision"`
		Reasoning    string   `json:"reasoning"`
		RiskFactors  []string `json:"risk_factors"`
		RequestFiles []string `json:"request_files"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return ReviewResponse{}, fmt.Errorf("llm: failed to parse LLM response: %w", err)
	}

	return ReviewResponse{
		Decision:     raw.Decision,
		Reasoning:    raw.Reasoning,
		RiskFactors:  raw.RiskFactors,
		RequestFiles: raw.RequestFiles,
	}, nil
}

// HasAuth returns true if this provider has credentials available
// (either API key or OAuth token).
func (p *AnthropicProvider) HasAuth() bool {
	if p.apiKey != "" {
		return true
	}
	return os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != ""
}

// HasCLI returns true if the `claude` binary is on PATH.
func HasCLI() bool {
	_, err := exec.LookPath("claude")
	return err == nil
}

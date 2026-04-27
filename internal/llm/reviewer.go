// Package llm implements the LLM review subsystem: provider interface
// and prompt building with XML fence security. File retrieval, rate
// limiting, and the Anthropic provider are added in a follow-up PR.
package llm

import "context"

// ReviewRequest carries structured prompt components to the provider.
// SystemPrompt and UserContent are logically distinct and MUST remain so:
//   - SDK providers map them to the API's native system/messages fields.
//   - Subprocess providers serialize them into a single stdin payload in
//     deterministic order (system first, then user) with an explicit
//     delimiter, preserving the boundary between trusted and untrusted content.
type ReviewRequest struct {
	SystemPrompt string  // Security instructions and decision framework
	UserContent  string  // Untrusted data: command, AST, files, precedents, scopes
	Model        string  // Model ID (e.g., "claude-sonnet-4-6")
	MaxTokens    int     // Max response tokens
	Temperature  float64 // 0 for deterministic classification
}

// ReviewResponse is the parsed LLM response.
type ReviewResponse struct {
	Decision     string   // "allow" or "deny"; anything else → action "review"
	Reasoning    string   // Informational only — never influences classification
	RiskFactors  []string // Concerns identified by the LLM
	RequestFiles []string // Non-empty = file request, not a verdict
	RawBody      string   // raw LLM output text (concatenated text blocks / subprocess stdout) for debug
}

// ReviewerProvider is the interface for LLM classification providers.
// The first-class implementation uses the Anthropic Go SDK; the subprocess
// fallback uses `claude -p`. Additional providers can be added by
// implementing this interface.
type ReviewerProvider interface {
	Review(ctx context.Context, req ReviewRequest) (ReviewResponse, error)
}

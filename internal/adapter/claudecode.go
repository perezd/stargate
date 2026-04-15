package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// maxStdinBytes is the maximum size of stdin we'll read (1 MB).
const maxStdinBytes = 1 << 20

// orphanMaxAge is the maximum age of orphan trace files before cleanup.
const orphanMaxAge = 5 * time.Minute

// preToolUseInput is Claude Code's PreToolUse JSON payload from stdin.
type preToolUseInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
	SessionID string          `json:"session_id"`
	CWD       string          `json:"cwd"`
}

// bashToolInput extracts the command from Bash tool input.
type bashToolInput struct {
	Command string `json:"command"`
}

// hookOutput is the JSON written to stdout for Claude Code hooks.
type hookOutput struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
}

// hookSpecificOutput contains the permission decision for PreToolUse hooks.
type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// postToolUseInput is Claude Code's PostToolUse JSON payload from stdin.
type postToolUseInput struct {
	ToolName  string `json:"tool_name"`
	ToolUseID string `json:"tool_use_id"`
	SessionID string `json:"session_id"`
}

// HandlePostToolUse reads Claude Code's PostToolUse JSON from stdin,
// loads the trace file from pre-tool-use, sends feedback, and cleans up.
// Always returns 0 (fire-and-forget). Errors are non-fatal and may be
// written to stderr; post-tool-use must never block the agent.
func HandlePostToolUse(ctx context.Context, stdin io.Reader, stderr io.Writer, cfg ClientConfig) int {
	input, err := parsePostToolUseInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "adapter: post-tool-use: %v\n", err)
		return 0
	}

	if err := ValidateToolUseID(input.ToolUseID); err != nil {
		fmt.Fprintf(stderr, "adapter: post-tool-use: %v\n", err)
		return 0
	}

	dir, err := TraceDir()
	if err != nil {
		fmt.Fprintf(stderr, "adapter: post-tool-use: %v\n", err)
		return 0
	}

	trace, err := ReadTrace(dir, input.ToolUseID)
	if err != nil {
		// Missing or corrupted trace file — nothing to do.
		fmt.Fprintf(stderr, "adapter: post-tool-use: %v\n", err)
		return 0
	}

	// No feedback token means feedback would fail; clean up and exit.
	if trace.FeedbackToken == "" {
		if err := DeleteTrace(dir, input.ToolUseID); err != nil {
			fmt.Fprintf(stderr, "adapter: post-tool-use: delete trace: %v\n", err)
		}
		return 0
	}

	// Send feedback to stargate server.
	feedbackReq := FeedbackRequest{
		StargateTrID:  trace.StargateTrID,
		ToolUseID:     input.ToolUseID,
		FeedbackToken: trace.FeedbackToken,
		Outcome:       "executed",
		Context: map[string]any{
			"session_id": input.SessionID,
			"agent":      "claude-code",
		},
	}

	if err := SendFeedback(ctx, cfg, feedbackReq); err != nil {
		// Feedback failed — preserve trace for orphan cleanup retry window.
		fmt.Fprintf(stderr, "adapter: post-tool-use: feedback failed: %v\n", err)
		return 0
	}

	// Successful feedback — delete trace file.
	if err := DeleteTrace(dir, input.ToolUseID); err != nil {
		fmt.Fprintf(stderr, "adapter: post-tool-use: delete trace: %v\n", err)
	}
	return 0
}

// parsePostToolUseInput reads and validates the PostToolUse JSON from stdin.
func parsePostToolUseInput(stdin io.Reader) (*postToolUseInput, error) {
	limited := io.LimitReader(stdin, maxStdinBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) > maxStdinBytes {
		return nil, fmt.Errorf("stdin exceeds %d bytes", maxStdinBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("stdin is empty")
	}

	var input postToolUseInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parsing stdin JSON: %w", err)
	}

	return &input, nil
}

// HandlePreToolUse reads Claude Code's PreToolUse JSON from stdin,
// classifies the command via the stargate server, and writes the hook
// response to stdout. Stores trace data for post-tool-use correlation.
// Returns exit code: 0 for valid hook responses, 2 for fatal errors.
func HandlePreToolUse(ctx context.Context, stdin io.Reader, stdout io.Writer, stderr io.Writer, cfg ClientConfig) int {
	// Run orphan cleanup best-effort before classification.
	cleanupOrphansBestEffort()

	// Read and parse stdin.
	input, err := parsePreToolUseInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "adapter: %v\n", err)
		return 2
	}

	// Reject empty tool_name — required field, fail-closed.
	if input.ToolName == "" {
		fmt.Fprintf(stderr, "adapter: tool_name is empty\n")
		return 2
	}

	// Non-Bash tools pass through immediately.
	if input.ToolName != "Bash" {
		return writeAllowResponse(stdout, stderr, "non-Bash tool: "+input.ToolName)
	}

	// Extract command from tool_input.
	var toolInput bashToolInput
	if err := json.Unmarshal(input.ToolInput, &toolInput); err != nil {
		fmt.Fprintf(stderr, "adapter: parsing tool_input: %v\n", err)
		return 2
	}
	if toolInput.Command == "" {
		fmt.Fprintf(stderr, "adapter: tool_input.command is empty\n")
		return 2
	}

	// Validate tool_use_id before any filesystem operation.
	if err := ValidateToolUseID(input.ToolUseID); err != nil {
		fmt.Fprintf(stderr, "adapter: %v\n", err)
		return 2
	}

	// Classify via stargate server.
	classifyReq := ClassifyRequest{
		Command: toolInput.Command,
		CWD:     input.CWD,
		Context: map[string]any{
			"session_id":  input.SessionID,
			"tool_use_id": input.ToolUseID,
		},
	}

	resp, err := Classify(ctx, cfg, classifyReq)
	if err != nil {
		fmt.Fprintf(stderr, "adapter: classify: %v\n", err)
		return 2
	}

	// Store trace for post-tool-use feedback correlation.
	if err := storeTrace(input.ToolUseID, resp); err != nil {
		// Non-fatal — classification still valid, but feedback correlation
		// will fail. Log so operators can diagnose filesystem issues.
		fmt.Fprintf(stderr, "adapter: store trace: %v\n", err)
	}

	// Map action to permission decision and write response.
	return writeClassifyResponse(stdout, stderr, resp)
}

// parsePreToolUseInput reads and validates the PreToolUse JSON from stdin.
func parsePreToolUseInput(stdin io.Reader) (*preToolUseInput, error) {
	limited := io.LimitReader(stdin, maxStdinBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) > maxStdinBytes {
		return nil, fmt.Errorf("stdin exceeds %d bytes", maxStdinBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("stdin is empty")
	}

	var input preToolUseInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parsing stdin JSON: %w", err)
	}

	return &input, nil
}

// storeTrace writes the trace file for post-tool-use correlation.
// Skips writing when there's no feedback token — without a token,
// post-tool-use feedback would always fail, creating guaranteed orphans.
func storeTrace(toolUseID string, resp *ClassifyResponse) error {
	if resp.FeedbackToken == nil || *resp.FeedbackToken == "" {
		return nil
	}

	dir, err := TraceDir()
	if err != nil {
		return err
	}

	return WriteTrace(dir, TraceData{
		StargateTrID:  resp.StargateTrID,
		FeedbackToken: *resp.FeedbackToken,
		ToolUseID:     toolUseID,
	})
}

// cleanupOrphansBestEffort runs orphan cleanup, ignoring errors.
func cleanupOrphansBestEffort() {
	dir, err := TraceDir()
	if err != nil {
		return
	}
	_ = CleanupOrphans(dir, orphanMaxAge)
}

// mapActionToDecision converts a classify action to a Claude Code permission decision.
// Unknown actions map to "deny" (fail-closed).
func mapActionToDecision(action string) string {
	switch action {
	case "allow":
		return "allow"
	case "review":
		return "ask"
	case "block":
		return "deny"
	default:
		return "deny"
	}
}

// writeAllowResponse writes a permissionDecision=allow to stdout and returns exit 0.
// Returns exit 2 if writing to stdout fails (broken pipe, etc.).
func writeAllowResponse(stdout io.Writer, stderr io.Writer, reason string) int {
	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "adapter: writing hook response: %v\n", err)
		return 2
	}
	return 0
}

// writeClassifyResponse maps the classify response to hook output and writes it.
// Returns exit 2 if writing to stdout fails.
func writeClassifyResponse(stdout io.Writer, stderr io.Writer, resp *ClassifyResponse) int {
	decision := mapActionToDecision(resp.Action)

	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: resp.Reason,
		},
	}

	if resp.Guidance != "" {
		out.SystemMessage = resp.Guidance
	}

	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "adapter: writing hook response: %v\n", err)
		return 2
	}
	return 0
}

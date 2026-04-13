// Package feedback provides HMAC-based feedback token management and an HTTP
// handler for recording user approval/rejection outcomes.
package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/limbic-systems/stargate/internal/corpus"
	"github.com/limbic-systems/stargate/internal/ttlmap"
)

// TraceInfo holds the classification context needed to verify and record feedback.
// Structural fields are carried from the original classification so user_approved
// corpus entries have the same signature/command_names as the original judgment.
type TraceInfo struct {
	Decision      string   // rule tier (e.g., "yellow") for HMAC recomputation
	ToolUseID     string
	TraceID       string
	Signature     string   // structural signature from original classification
	SignatureHash string   // SHA-256 of signature
	CommandNames  []string // command names from original classification
	Flags         []string // flags from original classification
	RawCommand    string   // scrubbed raw command
	CWD           string
	SessionID     string
	Agent         string
}

// FeedbackRequest is the JSON body for POST /feedback.
type FeedbackRequest struct {
	StargateTrID  string         `json:"stargate_trace_id"`
	ToolUseID     string         `json:"tool_use_id"`
	FeedbackToken string         `json:"feedback_token"`
	Outcome       string         `json:"outcome"`
	Context       map[string]any `json:"context,omitempty"`
}

// Handler processes feedback submissions, verifying HMAC tokens and writing
// user_approved entries to the corpus.
type Handler struct {
	corpus   *corpus.Corpus
	secret   []byte
	traceMap *ttlmap.TTLMap[string, TraceInfo]
}

// NewHandler creates a feedback handler. The corpus may be nil (feedback is
// accepted but not persisted). The TTL map holds trace info for 5 minutes.
func NewHandler(ctx context.Context, c *corpus.Corpus, secret []byte) *Handler {
	return &Handler{
		corpus: c,
		secret: secret,
		traceMap: ttlmap.New[string, TraceInfo](ctx, ttlmap.Options{
			SweepInterval: 30 * time.Second,
		}),
	}
}

// RecordTrace stores classification context so that a subsequent feedback
// submission can be verified and recorded. Called by the classifier after
// YELLOW decisions.
func (h *Handler) RecordTrace(info TraceInfo) {
	h.traceMap.Set(info.TraceID, info, 5*time.Minute)
}

// HandleFeedback processes POST /feedback requests.
func (h *Handler) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req FeedbackRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	// Validate required fields.
	if req.StargateTrID == "" || req.ToolUseID == "" || req.Outcome == "" || req.FeedbackToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing required field: stargate_trace_id, tool_use_id, outcome, and feedback_token are all required",
		})
		return
	}

	// Lookup trace in TTL map.
	info, found := h.traceMap.Get(req.StargateTrID)
	if !found {
		fmt.Fprintf(os.Stderr, "feedback: WARN trace %q expired or not found\n", req.StargateTrID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "trace_expired"})
		return
	}

	// Verify tool_use_id matches the recorded trace. Reject with 403 and a
	// generic message — don't reveal which field caused the mismatch.
	if req.ToolUseID != info.ToolUseID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid feedback token"})
		return
	}

	// Verify HMAC token.
	if !VerifyToken(h.secret, req.FeedbackToken, info.TraceID, info.ToolUseID, info.Decision) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid feedback token"})
		return
	}

	// Write user_approved to corpus for executed YELLOW decisions.
	// The entry carries structural fields from the original classification
	// so it's discoverable by future precedent lookups.
	if req.Outcome == "executed" && info.Decision == "yellow" && h.corpus != nil {
		entry := corpus.PrecedentEntry{
			Signature:     info.Signature,
			SignatureHash: info.SignatureHash,
			CommandNames:  info.CommandNames,
			Flags:         info.Flags,
			RawCommand:    info.RawCommand,
			CWD:           info.CWD,
			Decision:      "user_approved",
			TraceID:       info.TraceID,
			SessionID:     info.SessionID,
			Agent:         info.Agent,
		}
		if err := h.corpus.Write(entry); err != nil {
			// Non-fatal: rate limiting or DB errors are logged but don't fail the request.
			fmt.Fprintf(os.Stderr, "feedback: corpus write: %v\n", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

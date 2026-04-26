package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/limbic-systems/stargate/internal/classifier"
)

// TestRequest is the body schema for POST /test. It embeds ClassifyRequest
// and adds one optional field (use_cache). This keeps use_cache off the
// /classify schema — /classify uses DisallowUnknownFields and rejects it.
type TestRequest struct {
	classifier.ClassifyRequest
	UseCache bool `json:"use_cache,omitempty"`
}

// handleTest is a dry-run alias for /classify. It skips corpus writes,
// cache writes, and feedback token generation. Cache reads are skipped by
// default but can be enabled with use_cache=true in the request body.
// Telemetry spans include stargate.dry_run=true for dashboard filtering.
// The LLM pipeline runs normally and shares the same rate-limit budget
// as /classify (same Classifier instance, same llmProvider).
func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	cmdLen := min(int64(cfg.Classifier.MaxCommandLength), 1<<30)
	maxBody := max(cmdLen*4, 1<<20)
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var req TestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "unexpected trailing data after JSON object")
		return
	}

	if strings.TrimSpace(req.Command) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required field: command")
		return
	}

	// Extract the ClassifyRequest and inject dry-run flags.
	classifyReq := req.ClassifyRequest
	classifyReq.DryRun = true
	classifyReq.UseCache = req.UseCache

	ctx, cancel := applyTimeout(r.Context(), cfg.Server.Timeout)
	defer cancel()

	resp := s.clf.Classify(ctx, classifyReq)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

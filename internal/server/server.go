// Package server implements the stargate HTTP classification server.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/perezd/stargate/internal/classifier"
	"github.com/perezd/stargate/internal/config"
)

// Server is the stargate HTTP server.
type Server struct {
	mux        *http.ServeMux
	cfg        atomic.Pointer[config.Config]
	clf        *classifier.Classifier
	startTime  time.Time
}

// New creates a new Server with the given config and registers all routes.
func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server.New: config must not be nil")
	}
	clf, err := classifier.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("server.New: classifier init: %w", err)
	}
	s := &Server{
		mux:       http.NewServeMux(),
		clf:       clf,
		startTime: time.Now(),
	}
	s.cfg.Store(cfg)
	s.registerRoutes()
	return s, nil
}

// ServeHTTP implements http.Handler by delegating to the mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("POST /classify", s.handleClassify)
	s.mux.HandleFunc("POST /feedback", stubHandler)
	s.mux.HandleFunc("POST /reload", stubHandler)
	s.mux.HandleFunc("POST /test", stubHandler)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":         "ok",
		"uptime_seconds": time.Since(s.startTime).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	// Limit request body to prevent oversized payloads from consuming memory.
	// The command field has its own max-length check in the classifier, but we
	// also need to bound the total JSON body (which includes context, description, etc.).
	cfg := s.cfg.Load()
	// Body limit must exceed MaxCommandLength to ensure the classifier (not the
	// transport) handles oversized commands with a proper ClassifyResponse.
	// Cap the multiplied value to avoid int64 overflow on extreme configs.
	cmdLen := min(int64(cfg.Classifier.MaxCommandLength), 1<<30) // cap at 1GB before multiply
	maxBody := max(cmdLen*4, 1<<20)                               // 4x headroom, min 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var req classifier.ClassifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Distinguish oversized payloads from malformed JSON.
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Reject trailing top-level data after the JSON object.
	// dec.More() only checks within containers; a second Decode that
	// returns io.EOF confirms nothing else follows.
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "unexpected trailing data after JSON object")
		return
	}

	if strings.TrimSpace(req.Command) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required field: command")
		return
	}

	resp := s.clf.Classify(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

func stubHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"}) //nolint:errcheck
}

// Package server implements the stargate HTTP classification server.
package server

import (
	"encoding/json"
	"net/http"
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
// Panics if cfg is nil or if the classifier cannot be initialised.
func New(cfg *config.Config) *Server {
	if cfg == nil {
		panic("server.New: config must not be nil")
	}
	clf, err := classifier.New(cfg)
	if err != nil {
		panic("server.New: classifier init failed: " + err.Error())
	}
	s := &Server{
		mux:       http.NewServeMux(),
		clf:       clf,
		startTime: time.Now(),
	}
	s.cfg.Store(cfg)
	s.registerRoutes()
	return s
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
	var req classifier.ClassifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Command == "" {
		writeJSONError(w, http.StatusBadRequest, "command field is required")
		return
	}

	cfg := s.cfg.Load()
	if cfg.Classifier.MaxCommandLength > 0 && len(req.Command) > cfg.Classifier.MaxCommandLength {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "command exceeds maximum allowed length")
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

// Package server implements the stargate HTTP classification server.
package server

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/perezd/stargate/internal/config"
)

// Server is the stargate HTTP server.
type Server struct {
	mux       *http.ServeMux
	cfg       atomic.Pointer[config.Config]
	startTime time.Time
}

// New creates a new Server with the given config and registers all routes.
// Panics if cfg is nil.
func New(cfg *config.Config) *Server {
	if cfg == nil {
		panic("server.New: config must not be nil")
	}
	s := &Server{
		mux:       http.NewServeMux(),
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
	s.mux.HandleFunc("POST /classify", stubHandler)
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

func stubHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"}) //nolint:errcheck
}

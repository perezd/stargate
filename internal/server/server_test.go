package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perezd/stargate/internal/config"
	"github.com/perezd/stargate/internal/server"
)

func TestHealthEndpoint(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Listen: "127.0.0.1:9099"},
	}
	srv := server.New(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if _, ok := body["version"]; ok {
		t.Error("health should not expose version")
	}
	if _, ok := body["uptime_seconds"]; !ok {
		t.Error("missing uptime_seconds field")
	}
}

func TestStubEndpointsReturn501(t *testing.T) {
	cfg := &config.Config{}
	srv := server.New(cfg)

	endpoints := []struct{ method, path string }{
		{"POST", "/classify"},
		{"POST", "/feedback"},
		{"POST", "/reload"},
		{"POST", "/test"},
	}
	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
			}
		})
	}
}

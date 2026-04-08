package scopes

import (
	"context"
	"testing"

	"github.com/limbic-systems/stargate/internal/rules"
)

func TestResolveURLDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		wantDomain  string
		wantOK      bool
	}{
		// Basic URL extraction.
		{
			name:       "https URL",
			args:       []string{"https://api.example.com/path"},
			wantDomain: "api.example.com",
			wantOK:     true,
		},
		{
			name:       "http URL",
			args:       []string{"http://example.com/file"},
			wantDomain: "example.com",
			wantOK:     true,
		},
		{
			name:       "URL is not first arg",
			args:       []string{"-o", "file", "https://example.com"},
			wantDomain: "example.com",
			wantOK:     true,
		},
		{
			name:       "flag before URL",
			args:       []string{"-H", "Auth: token", "https://api.example.com"},
			wantDomain: "api.example.com",
			wantOK:     true,
		},

		// Port stripping.
		{
			name:       "port stripped",
			args:       []string{"https://example.com:8080/path"},
			wantDomain: "example.com",
			wantOK:     true,
		},

		// Schemeless URL.
		{
			name:       "schemeless domain",
			args:       []string{"example.com/path"},
			wantDomain: "example.com",
			wantOK:     true,
		},

		// Userinfo stripped.
		{
			name:       "userinfo in URL",
			args:       []string{"https://user:pass@example.com/path"},
			wantDomain: "example.com",
			wantOK:     true,
		},

		// IPv6.
		{
			name:       "IPv6 with port",
			args:       []string{"https://[::1]:8080/path"},
			wantDomain: "::1",
			wantOK:     true,
		},

		// Rejected schemes.
		{
			name:   "file scheme rejected",
			args:   []string{"file:///etc/passwd"},
			wantOK: false,
		},
		{
			name:   "data scheme rejected",
			args:   []string{"data:text/plain;base64,aGVsbG8="},
			wantOK: false,
		},

		// No URL found.
		{
			name:   "only flags no URL",
			args:   []string{"-v", "--help"},
			wantOK: false,
		},
		{
			name:   "no args",
			args:   []string{},
			wantOK: false,
		},
		{
			name:   "flags and paths only",
			args:   []string{"-o", "/tmp/output", "-H", "Content-Type: json"},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cmd := rules.CommandInfo{Args: tc.args}
			got, ok, err := ResolveURLDomain(context.Background(), cmd, "/tmp")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (domain=%q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.wantDomain {
				t.Fatalf("domain = %q, want %q", got, tc.wantDomain)
			}
		})
	}
}

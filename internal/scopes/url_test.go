package scopes_test

import (
	"context"
	"testing"

	"github.com/limbic-systems/stargate/internal/rules"
	"github.com/limbic-systems/stargate/internal/scopes"
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

		// Rejected schemes (allowlist: only http/https accepted).
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
		{
			name:   "ftp scheme rejected",
			args:   []string{"ftp://files.example.com/pub/file.tar.gz"},
			wantOK: false,
		},
		{
			name:   "ssh scheme rejected",
			args:   []string{"ssh://git@github.com/owner/repo"},
			wantOK: false,
		},

		// Continue scanning after rejected scheme (fix #1).
		{
			name:       "rejected scheme then valid URL",
			args:       []string{"file:///etc/passwd", "https://api.example.com/path"},
			wantDomain: "api.example.com",
			wantOK:     true,
		},

		// Filename false-positive guard (fix #3).
		{
			name:   "output.txt not a domain",
			args:   []string{"-o", "output.txt"},
			wantOK: false,
		},
		{
			name:   "config.json not a domain",
			args:   []string{"config.json"},
			wantOK: false,
		},
		{
			name:       "domain with path not confused with filename",
			args:       []string{"example.com/api/v1"},
			wantDomain: "example.com",
			wantOK:     true,
		},

		// Relative path with dotted filename not confused with domain.
		{
			name:       "dir/output.txt before real URL",
			args:       []string{"dir/output.txt", "https://api.example.com"},
			wantDomain: "api.example.com",
			wantOK:     true,
		},
		{
			name:   "dir/output.txt alone",
			args:   []string{"dir/output.txt"},
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cmd := rules.CommandInfo{Args: tc.args}
			got, ok, err := scopes.ResolveURLDomain(context.Background(), cmd, "/tmp")
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

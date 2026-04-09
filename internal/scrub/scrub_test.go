package scrub

import (
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/types"
)

// newScrubber is a test helper that creates a Scrubber with no extra patterns.
func newScrubber(t *testing.T) *Scrubber {
	t.Helper()
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) unexpected error: %v", err)
	}
	return s
}

func TestScrubEnvVars(t *testing.T) {
	s := newScrubber(t)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "single env var before command",
			in:   "GITHUB_TOKEN=ghp_abc123 curl https://api.github.com",
			// env assign is redacted; the ghp_ pattern is already gone after env redaction
			want: "GITHUB_TOKEN=[REDACTED] curl https://api.github.com",
		},
		{
			name: "var name preserved",
			in:   "SECRET=supersecret echo hello",
			want: "SECRET=[REDACTED] echo hello",
		},
		{
			name: "multiple env vars",
			in:   "FOO=bar BAZ=qux cmd",
			want: "FOO=[REDACTED] BAZ=[REDACTED] cmd",
		},
		{
			name: "env var at start of string",
			in:   "MY_TOKEN=abc123",
			want: "MY_TOKEN=[REDACTED]",
		},
		{
			name: "lowercase var not matched",
			in:   "lowercase=value cmd",
			want: "lowercase=value cmd",
		},
		{
			name: "no env vars unchanged",
			in:   "echo hello world",
			want: "echo hello world",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Command(tc.in)
			if got != tc.want {
				t.Errorf("Command(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestScrubTokenPatterns(t *testing.T) {
	s := newScrubber(t)

	tests := []struct {
		name    string
		in      string
		wantSub string // substring that must NOT appear in output; or use want for exact
		want    string
	}{
		{
			name:    "GitHub personal access token ghp_",
			in:      "Authorization: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantSub: "ghp_",
			want:    "Authorization: [REDACTED]",
		},
		{
			name:    "Anthropic API key sk-ant-",
			in:      "key: sk-ant-api03-sometoken123",
			wantSub: "sk-ant-",
			want:    "key: [REDACTED]",
		},
		{
			name:    "GitLab CI token glc_",
			in:      "glc_abcDEF-123_xyz",
			wantSub: "glc_",
			want:    "[REDACTED]",
		},
		{
			name:    "Bearer token",
			in:      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
			wantSub: "eyJhbGciOiJIUzI1NiJ9",
			want:    "Authorization: [REDACTED]",
		},
		{
			name:    "token= assignment",
			in:      "--token=mysecretvalue123",
			wantSub: "mysecretvalue123",
			want:    "--[REDACTED]",
		},
		{
			name:    "AWS access key AKIA",
			in:      "AKIAIOSFODNN7EXAMPLE",
			wantSub: "AKIAIOSFODNN7EXAMPLE",
			want:    "[REDACTED]",
		},
		{
			name:    "npm token npm_",
			in:      "npm_abcDEF123456",
			wantSub: "npm_",
			want:    "[REDACTED]",
		},
		{
			name:    "PyPI token pypi-",
			in:      "pypi-abc123DEF456",
			wantSub: "pypi-abc123",
			want:    "[REDACTED]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Text(tc.in)
			if tc.want != "" && got != tc.want {
				t.Errorf("Text(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
			if tc.wantSub != "" && strings.Contains(got, tc.wantSub) {
				t.Errorf("Text(%q) still contains %q: %q", tc.in, tc.wantSub, got)
			}
		})
	}
}

func TestScrubURLCredentials(t *testing.T) {
	s := newScrubber(t)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "https URL with userinfo",
			in:   "https://user:pass@host/path",
			want: "https://[REDACTED]@host/path",
		},
		{
			name: "URL without userinfo unchanged",
			in:   "https://host/path",
			want: "https://host/path",
		},
		{
			name: "multiple URLs in one string",
			in:   "clone https://alice:secret@github.com/org/repo and https://bob:hunter2@gitlab.com/foo/bar",
			want: "clone https://[REDACTED]@github.com/org/repo and https://[REDACTED]@gitlab.com/foo/bar",
		},
		{
			name: "non-HTTP scheme ftp with userinfo",
			in:   "ftp://user:pass@ftp.example.com/file.txt",
			want: "ftp://[REDACTED]@ftp.example.com/file.txt",
		},
		{
			name: "URL without credentials mixed with credentialed URL",
			in:   "git clone https://user:tok@host/repo && cd repo",
			want: "git clone https://[REDACTED]@host/repo && cd repo",
		},
		{
			name: "URL with username but no password",
			in:   "https://user@host/path",
			want: "https://[REDACTED]@host/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Text(tc.in)
			if got != tc.want {
				t.Errorf("Text(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestScrubExtraPatterns(t *testing.T) {
	t.Run("custom pattern redacted", func(t *testing.T) {
		s, err := New([]string{`mysecret-[a-z0-9]+`})
		if err != nil {
			t.Fatalf("New with extra pattern: %v", err)
		}
		in := "auth mysecret-abc123"
		got := s.Text(in)
		if strings.Contains(got, "mysecret-abc123") {
			t.Errorf("Text(%q) still contains secret: %q", in, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("Text(%q) missing [REDACTED]: %q", in, got)
		}
	})

	t.Run("multiple extra patterns", func(t *testing.T) {
		s, err := New([]string{`pat_[a-z]+`, `sig_[A-Z]+`})
		if err != nil {
			t.Fatalf("New with extra patterns: %v", err)
		}
		in := "pat_abc and sig_XYZ"
		got := s.Text(in)
		if strings.Contains(got, "pat_abc") || strings.Contains(got, "sig_XYZ") {
			t.Errorf("Text(%q) still contains secret(s): %q", in, got)
		}
	})

	t.Run("extra pattern does not affect unmatched text", func(t *testing.T) {
		s, err := New([]string{`custom-[0-9]+`})
		if err != nil {
			t.Fatalf("New with extra pattern: %v", err)
		}
		in := "nothing to redact here"
		got := s.Text(in)
		if got != in {
			t.Errorf("Text(%q) should be unchanged, got %q", in, got)
		}
	})
}

func TestScrubCommandInfo(t *testing.T) {
	s := newScrubber(t)

	original := types.CommandInfo{
		Name:       "curl",
		Args:       []string{"https://api.github.com", "Bearer eyJtoken123"},
		Flags:      []string{"-H", "--silent", "--token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		Subcommand: "",
		Env: map[string]string{
			"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			"SECRET":       "topsecret",
		},
		Redirects: []types.RedirectInfo{
			{Op: ">", File: "output.txt"},
		},
	}

	result := s.CommandInfo(original)

	t.Run("env values redacted", func(t *testing.T) {
		for k, v := range result.Env {
			if v != "[REDACTED]" {
				t.Errorf("Env[%q] = %q, want [REDACTED]", k, v)
			}
		}
	})

	t.Run("env keys preserved", func(t *testing.T) {
		for k := range original.Env {
			if _, ok := result.Env[k]; !ok {
				t.Errorf("Env key %q missing from result", k)
			}
		}
	})

	t.Run("args scrubbed", func(t *testing.T) {
		for _, arg := range result.Args {
			if strings.Contains(arg, "eyJtoken123") {
				t.Errorf("Args still contains secret: %q", arg)
			}
		}
	})

	t.Run("flags scrubbed", func(t *testing.T) {
		if len(result.Flags) != len(original.Flags) {
			t.Fatalf("Flags length mismatch: got %d, want %d", len(result.Flags), len(original.Flags))
		}
		// Non-secret flags should be unchanged.
		if result.Flags[0] != "-H" {
			t.Errorf("Flags[0] = %q, want -H", result.Flags[0])
		}
		if result.Flags[1] != "--silent" {
			t.Errorf("Flags[1] = %q, want --silent", result.Flags[1])
		}
		// Secret-bearing flag should be scrubbed.
		if strings.Contains(result.Flags[2], "ghp_") {
			t.Errorf("Flags[2] still contains secret: %q", result.Flags[2])
		}
	})

	t.Run("original env unmodified (deep copy)", func(t *testing.T) {
		for k, v := range original.Env {
			if v == "[REDACTED]" {
				t.Errorf("original.Env[%q] was mutated to [REDACTED]", k)
			}
		}
	})

	t.Run("original args unmodified (deep copy)", func(t *testing.T) {
		// The original arg with a bearer token should still be present in original.
		found := false
		for _, arg := range original.Args {
			if strings.Contains(arg, "Bearer") {
				found = true
				break
			}
		}
		if !found {
			t.Error("original.Args was mutated; Bearer arg no longer present")
		}
	})

	t.Run("redirects deep copied", func(t *testing.T) {
		if len(result.Redirects) != len(original.Redirects) {
			t.Fatalf("Redirects length mismatch: got %d, want %d", len(result.Redirects), len(original.Redirects))
		}
		if result.Redirects[0] != original.Redirects[0] {
			t.Errorf("Redirects[0] changed: got %+v, want %+v", result.Redirects[0], original.Redirects[0])
		}
	})

	t.Run("nil env handled", func(t *testing.T) {
		cmd := types.CommandInfo{Name: "ls"}
		out := s.CommandInfo(cmd)
		if out.Env != nil {
			t.Errorf("expected nil Env for empty input, got %v", out.Env)
		}
	})

	t.Run("nil args handled", func(t *testing.T) {
		cmd := types.CommandInfo{Name: "ls"}
		out := s.CommandInfo(cmd)
		if out.Args != nil {
			t.Errorf("expected nil Args for empty input, got %v", out.Args)
		}
	})
}

func TestScrubText(t *testing.T) {
	s := newScrubber(t)

	t.Run("token patterns applied", func(t *testing.T) {
		in := "use token Bearer abc123def for auth"
		got := s.Text(in)
		if strings.Contains(got, "abc123def") {
			t.Errorf("Text(%q) still contains token value: %q", in, got)
		}
	})

	t.Run("URL credentials applied", func(t *testing.T) {
		in := "see https://user:pass@example.com for details"
		got := s.Text(in)
		if strings.Contains(got, "pass") {
			t.Errorf("Text(%q) still contains password: %q", in, got)
		}
		if !strings.Contains(got, "[REDACTED]@example.com") {
			t.Errorf("Text(%q) missing redacted URL: %q", in, got)
		}
	})

	t.Run("env assigns NOT applied by Text", func(t *testing.T) {
		// VAR=value should NOT be redacted by Text (only by Command).
		in := "SOME_VAR=plainvalue"
		got := s.Text(in)
		if got != in {
			t.Errorf("Text(%q) should not redact env assigns, got %q", in, got)
		}
	})

	t.Run("plain text unchanged", func(t *testing.T) {
		in := "no secrets here at all"
		got := s.Text(in)
		if got != in {
			t.Errorf("Text(%q) should be unchanged, got %q", in, got)
		}
	})
}

func TestNewInvalidPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{
			name:    "unclosed bracket",
			pattern: `[invalid`,
		},
		{
			name:    "unclosed paren",
			pattern: `(unclosed`,
		},
		{
			name:    "invalid quantifier",
			pattern: `*badstart`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New([]string{tc.pattern})
			if err == nil {
				t.Errorf("New(%q) expected error for invalid pattern, got nil", tc.pattern)
			}
		})
	}
}

func TestScrubNoFalsePositives(t *testing.T) {
	s := newScrubber(t)

	tests := []struct {
		name string
		in   string
	}{
		{
			name: "ghp without underscore",
			in:   "ghp is not a token prefix",
		},
		{
			name: "token without equals",
			in:   "the token was lost",
		},
		{
			name: "bearer without following value",
			// "Bearer" alone (no space + alphanum) should not match
			in: "Bearer",
		},
		{
			name: "npm without underscore",
			in:   "npm install lodash",
		},
		{
			name: "AKIA too short",
			// AKIA + fewer than 16 uppercase/digits should not match
			in: "AKIASHORT",
		},
		{
			name: "pypi without hyphen",
			in:   "pypi package index",
		},
		{
			name: "sk-ant without full prefix",
			in:   "sk-ant",
		},
		{
			name: "glc without underscore",
			in:   "glc is a compiler flag",
		},
		{
			name: "URL without at-sign",
			in:   "https://example.com/path",
		},
		{
			name: "plain equals sign in lowercase var",
			in:   "count=5 items",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Text(tc.in)
			if strings.Contains(got, "[REDACTED]") {
				t.Errorf("Text(%q) false positive: got %q", tc.in, got)
			}
		})
	}
}

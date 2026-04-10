// Package scrub redacts secrets from command strings, CommandInfo structs,
// and arbitrary text before they are sent to LLM prompts or stored in the
// precedent corpus.
//
// Built-in patterns cover: environment variable values, common token formats
// (ghp_, sk-ant-, glc_, Bearer, token=, AKIA, npm_, pypi-), and URL
// credentials (RFC 3986 userinfo). Operators can add extra patterns via config.
package scrub

import (
	"fmt"
	"regexp"

	"github.com/limbic-systems/stargate/internal/types"
)

// scrubPattern pairs a regex with a replacement string.
// Patterns may use capturing groups; the replacement can reference them
// (e.g., "${1}[REDACTED]" to preserve a prefix like "Bearer " or "token=").
type scrubPattern struct {
	re   *regexp.Regexp
	repl string
}

// builtinPatternDefs are compiled once at Scrubber construction time.
// Patterns with prefixes (Bearer, token=) preserve the prefix for context.
var builtinPatternDefs = []struct {
	pattern string
	repl    string
}{
	{`ghp_[a-zA-Z0-9]{36,}`, "[REDACTED]"},
	{`sk-ant-[a-zA-Z0-9_-]+`, "[REDACTED]"},
	{`glc_[a-zA-Z0-9_-]+`, "[REDACTED]"},
	{`(?i)(bearer\s+)[a-zA-Z0-9._\-]+`, "${1}[REDACTED]"},
	{`(?i)(token=)[a-zA-Z0-9._\-]+`, "${1}[REDACTED]"},
	{`AKIA[A-Z0-9]{16}`, "[REDACTED]"},
	{`npm_[a-zA-Z0-9]+`, "[REDACTED]"},
	{`pypi-[a-zA-Z0-9]+`, "[REDACTED]"},
}

// envAssignRe matches VAR=value at the start of a command or after whitespace.
// Captures: (1) start-of-string or whitespace, (2) VAR= prefix, (3) value to redact.
// Limitations:
//   - Only matches POSIX-convention uppercase variable names ([A-Z_][A-Z0-9_]*).
//     Lowercase/mixed-case names (e.g., github_token=...) are NOT matched to
//     avoid false positives on config file key=value pairs. The built-in token
//     patterns catch common secrets regardless of assignment form.
//   - Only matches unquoted single-token values and stops before common shell
//     metacharacters so adjacent operators are preserved (FOO=bar;rm stays as
//     FOO=[REDACTED];rm).
//   - Quoted values like FOO="a b" are partially matched. The AST-level
//     CommandInfo.Env scrubbing handles quoted assignments correctly; this
//     regex is defense-in-depth for simple cases.
var envAssignRe = regexp.MustCompile(`(^|\s)([A-Z_][A-Z0-9_]*=)([^\s;|&()<>]+)`)

// Scrubber applies secret redaction using compiled regex patterns.
// It is safe for concurrent use once constructed.
type Scrubber struct {
	patterns []scrubPattern
}

// New creates a Scrubber with built-in patterns plus any extra patterns.
// Extra patterns use a plain "[REDACTED]" replacement (no prefix preservation).
// Returns an error if any extra pattern fails to compile.
func New(extraPatterns []string) (*Scrubber, error) {
	compiled := make([]scrubPattern, 0, len(builtinPatternDefs)+len(extraPatterns))
	for _, def := range builtinPatternDefs {
		re, err := regexp.Compile(def.pattern)
		if err != nil {
			return nil, fmt.Errorf("scrub: invalid builtin pattern %q: %w", def.pattern, err)
		}
		compiled = append(compiled, scrubPattern{re: re, repl: def.repl})
	}
	for _, p := range extraPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("scrub: invalid pattern %q: %w", p, err)
		}
		compiled = append(compiled, scrubPattern{re: re, repl: "[REDACTED]"})
	}
	return &Scrubber{patterns: compiled}, nil
}

// Command redacts secrets in a raw command string.
// Applies: env var value redaction, token patterns, URL credential scrubbing.
func (s *Scrubber) Command(raw string) string {
	result := s.scrubEnvAssigns(raw)
	result = s.scrubTokenPatterns(result)
	result = s.scrubURLCredentials(result)
	return result
}

// Text redacts secrets in arbitrary text (e.g., file contents, LLM reasoning).
// Applies env var redaction (covers .env files, configs), token patterns, and
// URL credential scrubbing.
func (s *Scrubber) Text(text string) string {
	result := s.scrubEnvAssigns(text)
	result = s.scrubTokenPatterns(result)
	result = s.scrubURLCredentials(result)
	return result
}

// CommandInfo returns a sanitized copy of the CommandInfo with secrets redacted.
// Env values are replaced with [REDACTED]; args matching token patterns are
// redacted. The original CommandInfo is not modified.
func (s *Scrubber) CommandInfo(cmd types.CommandInfo) types.CommandInfo {
	out := cmd        // shallow copy
	out.RawNode = nil // clear AST pointer to prevent unsanitized data leaking

	// Scrub Subcommand (derived from first positional arg, can contain secrets).
	out.Subcommand = s.Text(cmd.Subcommand)

	// Deep copy and redact Env values. Copy when non-nil (preserve nil vs empty).
	if cmd.Env != nil {
		out.Env = make(map[string]string, len(cmd.Env))
		for k := range cmd.Env {
			out.Env[k] = "[REDACTED]"
		}
	}

	// Deep copy and redact matching Args.
	if cmd.Args != nil {
		out.Args = make([]string, len(cmd.Args))
		for i, arg := range cmd.Args {
			out.Args[i] = s.Text(arg)
		}
	}

	// Deep copy and redact Flags — flag tokens may include inline values
	// (e.g., --token=ghp_abc, -HAuthorization:Bearer...) that contain secrets.
	if cmd.Flags != nil {
		out.Flags = make([]string, len(cmd.Flags))
		for i, flag := range cmd.Flags {
			out.Flags[i] = s.Text(flag)
		}
	}

	// Deep copy and scrub Redirects — targets can contain secrets in filenames.
	if cmd.Redirects != nil {
		out.Redirects = make([]types.RedirectInfo, len(cmd.Redirects))
		for i, r := range cmd.Redirects {
			out.Redirects[i] = types.RedirectInfo{
				Op:   r.Op,
				File: s.Text(r.File),
			}
		}
	}

	return out
}

// scrubEnvAssigns redacts values in VAR=value patterns.
func (s *Scrubber) scrubEnvAssigns(text string) string {
	return envAssignRe.ReplaceAllString(text, "${1}${2}[REDACTED]")
}

// scrubTokenPatterns applies all compiled regex patterns.
func (s *Scrubber) scrubTokenPatterns(text string) string {
	for _, p := range s.patterns {
		text = p.re.ReplaceAllString(text, p.repl)
	}
	return text
}

// urlWithUserinfoRe matches the scheme://userinfo@ portion of URLs.
// Captures: (1) scheme://, (2) userinfo within the authority, (3) @.
// The userinfo capture must end before any '/', '?', or '#' so path/query/
// fragment content like https://example.com/@user is not treated as userinfo.
// Preserves original whitespace (does not tokenize by Fields).
var urlWithUserinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s@/?#]+)(@)`)

// scrubURLCredentials strips the userinfo component from URLs per RFC 3986.
// e.g., https://user:pass@host/path → https://[REDACTED]@host/path
// Preserves original whitespace.
func (s *Scrubber) scrubURLCredentials(text string) string {
	return urlWithUserinfoRe.ReplaceAllString(text, "${1}[REDACTED]${3}")
}

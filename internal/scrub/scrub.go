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
	"net/url"
	"regexp"
	"strings"

	"github.com/limbic-systems/stargate/internal/types"
)

// builtinPatterns are compiled once at Scrubber construction time.
var builtinPatternStrings = []string{
	`ghp_[a-zA-Z0-9]{36,}`,
	`sk-ant-[a-zA-Z0-9_-]+`,
	`glc_[a-zA-Z0-9_-]+`,
	`Bearer\s+[a-zA-Z0-9._\-]+`,
	`token=[a-zA-Z0-9._\-]+`,
	`AKIA[A-Z0-9]{16}`,
	`npm_[a-zA-Z0-9]+`,
	`pypi-[a-zA-Z0-9]+`,
}

// envAssignRe matches VAR=value at the start of a command or after whitespace.
// Captures: (1) VAR= prefix, (2) value to redact.
var envAssignRe = regexp.MustCompile(`(^|\s)([A-Z_][A-Z0-9_]*=)(\S+)`)

// Scrubber applies secret redaction using compiled regex patterns.
// It is safe for concurrent use once constructed.
type Scrubber struct {
	patterns []*regexp.Regexp
}

// New creates a Scrubber with built-in patterns plus any extra patterns.
// Returns an error if any extra pattern fails to compile.
func New(extraPatterns []string) (*Scrubber, error) {
	all := make([]string, 0, len(builtinPatternStrings)+len(extraPatterns))
	all = append(all, builtinPatternStrings...)
	all = append(all, extraPatterns...)

	compiled := make([]*regexp.Regexp, 0, len(all))
	for _, p := range all {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("scrub: invalid pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
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
// Applies token patterns and URL credential scrubbing (not env assigns, since
// the text may not be a command).
func (s *Scrubber) Text(text string) string {
	result := s.scrubTokenPatterns(text)
	result = s.scrubURLCredentials(result)
	return result
}

// CommandInfo returns a deep copy of the CommandInfo with secrets redacted.
// Env values are replaced with [REDACTED]; args matching token patterns are
// redacted. The original CommandInfo is not modified.
func (s *Scrubber) CommandInfo(cmd types.CommandInfo) types.CommandInfo {
	out := cmd // shallow copy

	// Deep copy and redact Env values.
	if len(cmd.Env) > 0 {
		out.Env = make(map[string]string, len(cmd.Env))
		for k := range cmd.Env {
			out.Env[k] = "[REDACTED]"
		}
	}

	// Deep copy and redact matching Args.
	if len(cmd.Args) > 0 {
		out.Args = make([]string, len(cmd.Args))
		for i, arg := range cmd.Args {
			out.Args[i] = s.Text(arg)
		}
	}

	// Deep copy Flags (not redacted — flags don't contain secrets).
	if len(cmd.Flags) > 0 {
		out.Flags = make([]string, len(cmd.Flags))
		copy(out.Flags, cmd.Flags)
	}

	// Deep copy Redirects.
	if len(cmd.Redirects) > 0 {
		out.Redirects = make([]types.RedirectInfo, len(cmd.Redirects))
		copy(out.Redirects, cmd.Redirects)
	}

	return out
}

// scrubEnvAssigns redacts values in VAR=value patterns.
func (s *Scrubber) scrubEnvAssigns(text string) string {
	return envAssignRe.ReplaceAllString(text, "${1}${2}[REDACTED]")
}

// scrubTokenPatterns applies all compiled regex patterns.
func (s *Scrubber) scrubTokenPatterns(text string) string {
	for _, re := range s.patterns {
		text = re.ReplaceAllString(text, "[REDACTED]")
	}
	return text
}

// scrubURLCredentials strips the userinfo component from URLs per RFC 3986.
// e.g., https://user:pass@host/path → https://[REDACTED]@host/path
func (s *Scrubber) scrubURLCredentials(text string) string {
	// Split on whitespace to find URL-like tokens.
	words := strings.Fields(text)
	changed := false
	for i, word := range words {
		// Quick check: must contain :// and @ to have userinfo.
		if !strings.Contains(word, "://") || !strings.Contains(word, "@") {
			continue
		}
		u, err := url.Parse(word)
		if err != nil || u.User == nil {
			continue
		}
		u.User = url.User("[REDACTED]")
		words[i] = u.String()
		changed = true
	}
	if !changed {
		return text
	}
	return strings.Join(words, " ")
}

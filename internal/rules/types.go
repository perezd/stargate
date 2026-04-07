// Package rules defines the command classification types and rule engine.
package rules

import "mvdan.cc/sh/v3/syntax"

// CommandInfo represents a single command invocation extracted from the AST.
type CommandInfo struct {
	Name       string            // Resolved command name (after prefix stripping)
	Args       []string          // Positional arguments
	Flags      []string          // Flags (short and long, as parsed)
	Subcommand string            // First positional argument (after global flag skipping), when present
	Redirects  []RedirectInfo    // File redirections
	Env        map[string]string // Inline env vars (e.g., FOO=bar cmd)
	Context    CommandContext    // Where in the AST tree this lives
	RawNode    *syntax.CallExpr  // Pointer back to AST node
}

// RedirectInfo describes a single file redirection.
type RedirectInfo struct {
	Op   string // ">", ">>", "<", "2>", "&>", etc.
	File string // Redirect target operand (filename, fd, or dynamic word)
}

// CommandContext describes where a command appears in the AST structure.
type CommandContext struct {
	PipelinePosition int    // 0 = not in pipe, 1 = first stage, 2+ = subsequent stages
	SubshellDepth    int    // Nesting depth in subshells
	InSubstitution   bool   // Inside command substitution ($(), ``) or process substitution (<(), >())
	InCondition      bool   // Inside if/while test
	InFunction       string // Name of enclosing function, if any
	ParentOperator   string // "&&", "||", ";", "|", "|&"
}

package parser

import (
	"bytes"
	"strings"
	"sync"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/rules"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// maxWrapperDepth is the maximum recursion depth for prefix stripping.
// Commands nested deeper than this are treated as unresolvable.
const maxWrapperDepth = 16

// WrapperDef holds the parsed metadata for a single wrapper command.
type WrapperDef struct {
	// Flags maps flag name to the number of extra arguments it consumes (0 = boolean flag).
	Flags map[string]int
	// NoStrip lists flag values that suppress stripping (e.g. "-v" for "command -v").
	NoStrip []string
	// ConsumeEnvAssigns causes VAR=val tokens to be skipped before the real command.
	ConsumeEnvAssigns bool
	// ConsumeFirstPositional causes the first non-flag positional to be skipped
	// (used by timeout, whose first positional is the duration).
	ConsumeFirstPositional bool
}

// WalkerConfig provides the metadata the walker needs for prefix stripping
// and subcommand extraction. Built from config.Config.
type WalkerConfig struct {
	// Wrappers maps wrapper command names to their config.
	Wrappers map[string]WrapperDef
	// CommandFlags maps command names to their global flags for subcommand extraction.
	// The int value is the number of extra arguments the flag consumes.
	CommandFlags map[string]map[string]int
}

// NewWalkerConfig builds a WalkerConfig from the config-package types.
func NewWalkerConfig(wrappers []config.WrapperConfig, commands []config.CommandFlagsConfig) *WalkerConfig {
	wc := &WalkerConfig{
		Wrappers:     make(map[string]WrapperDef, len(wrappers)),
		CommandFlags: make(map[string]map[string]int, len(commands)),
	}
	for _, w := range wrappers {
		wc.Wrappers[w.Command] = WrapperDef{
			Flags:                  w.Flags,
			NoStrip:                w.NoStrip,
			ConsumeEnvAssigns:      w.ConsumeEnvAssigns,
			ConsumeFirstPositional: w.ConsumeFirstPositional,
		}
	}
	for _, c := range commands {
		wc.CommandFlags[c.Command] = c.Flags
	}
	return wc
}

// DefaultWalkerConfig returns a WalkerConfig built from the package defaults.
func DefaultWalkerConfig() *WalkerConfig {
	return NewWalkerConfig(config.DefaultWrappers(), config.DefaultCommandFlags())
}

// printerPool reuses syntax.Printer instances across concurrent calls.
var printerPool = sync.Pool{
	New: func() any { return syntax.NewPrinter() },
}

// wordToString converts a syntax.Word to its string representation.
func wordToString(w *syntax.Word) string {
	var buf bytes.Buffer
	p := printerPool.Get().(*syntax.Printer)
	_ = p.Print(&buf, w)
	printerPool.Put(p)
	return buf.String()
}

// wordLiteral extracts the plain literal string from a word. Returns the
// literal value and whether the word was fully resolvable (no dynamic parts).
//
// Resolution rules:
//   - Lit values have backslashes stripped (bash: `\rm` resolves to `rm`).
//   - SglQuoted with Dollar=true (ANSI-C `$'...'`) is decoded via expand.Format
//     so `$'\x72\x6d'`, `$'\u0072\u006d'`, `$'\162\155'` all resolve to `rm`.
//   - SglQuoted with Dollar=false ('...') returns the raw value.
//   - DblQuoted is recursed via dblQuotedLiteral.
func wordLiteral(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// Strip backslash escapes: bash treats \c as c for most characters.
			// e.g. `\rm` becomes `rm`, `r\m` becomes `rm`.
			sb.WriteString(stripBackslashes(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				// ANSI-C quoting: decode \x, \u, \U, \0NN, \a, \b, \t, \n, etc.
				decoded, _, err := expand.Format(nil, p.Value, nil)
				if err != nil {
					return "", false
				}
				// Truncate at first null byte: $'rm\x00garbage' must resolve
				// to "rm", not "rm\x00garbage". The kernel's execve() treats
				// the command name as a C string (null-terminated), so bash
				// actually executes "rm". Without truncation, the rule engine
				// would see "rm\x00garbage" and fail to match the "rm" rule.
				if idx := strings.IndexByte(decoded, 0); idx >= 0 {
					decoded = decoded[:idx]
				}
				sb.WriteString(decoded)
			} else {
				sb.WriteString(p.Value)
			}
		case *syntax.DblQuoted:
			inner, ok := dblQuotedLiteral(p)
			if !ok {
				return "", false
			}
			sb.WriteString(inner)
		default:
			// ParamExp, CmdSubst, ArithmExp, etc. — unresolvable.
			return "", false
		}
	}
	return sb.String(), true
}

// stripBackslashes removes bash-style backslash escapes from a literal.
// Bash interprets `\c` as `c` for any character outside newlines. The sh
// parser preserves backslashes in Lit.Value verbatim, so the walker must
// strip them to get the effective command name. A trailing backslash is
// preserved (it would be a line continuation in source, but in a parsed
// Lit it is just a literal backslash).
func stripBackslashes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			// Skip the backslash, keep the next byte.
			sb.WriteByte(s[i+1])
			i++
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// dblQuotedLiteral extracts a literal from a DblQuoted word part.
// Backslash stripping is NOT applied here — inside double quotes, bash
// only interprets \$, \\, \", \`, and \+newline. Other backslash
// sequences like "\r" are literal (the backslash is preserved). The
// parser already handles this distinction, so we return p.Value raw.
func dblQuotedLiteral(dq *syntax.DblQuoted) (string, bool) {
	var sb strings.Builder
	for _, part := range dq.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// isUnresolvable returns true if the word contains dynamic parts that prevent
// static analysis (parameter expansion, command substitution, arithmetic).
func isUnresolvable(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			return true
		}
	}
	return false
}

// isBraceExpansion detects brace expansion patterns in command-name position,
// in both comma-separated ({a,b,c}) and range ({a..z}, {1..3}) forms.
// Only unquoted literals are checked — brace expansion doesn't occur inside
// quotes, so "{rm,ls}" and '{a..z}' are not flagged.
func isBraceExpansion(w *syntax.Word) bool {
	// Must be a single bare Lit part (no quoting).
	if len(w.Parts) != 1 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	val := lit.Value
	if !strings.Contains(val, "{") {
		return false
	}
	return strings.Contains(val, ",") || strings.Contains(val, "..")
}

// walkerState tracks the AST traversal context.
type walkerState struct {
	results []rules.CommandInfo
	cfg     *WalkerConfig

	// Pipeline position stack (1-indexed, 0 = not in pipeline).
	pipelineStack []int

	// Subshell nesting depth.
	subshellDepth int

	// Command substitution nesting depth.
	substDepth int

	// Condition nesting depth (if/while condition lists).
	conditionDepth int

	// Function name stack.
	funcStack []string

	// Parent operator stack ("&&", "||", ";", "|").
	parentOpStack []string
}

// currentContext builds a CommandContext from the walker's current state.
func (ws *walkerState) currentContext() rules.CommandContext {
	inSubst := ws.substDepth > 0
	ctx := rules.CommandContext{
		SubshellDepth:  ws.subshellDepth,
		InSubstitution: inSubst,
		InCondition:    ws.conditionDepth > 0,
	}
	// Commands inside substitutions ($(), <(), >()) run in their own
	// execution context — they don't inherit the outer pipeline position.
	if !inSubst && len(ws.pipelineStack) > 0 {
		ctx.PipelinePosition = ws.pipelineStack[len(ws.pipelineStack)-1]
	}
	if len(ws.funcStack) > 0 {
		ctx.InFunction = ws.funcStack[len(ws.funcStack)-1]
	}
	if len(ws.parentOpStack) > 0 {
		ctx.ParentOperator = ws.parentOpStack[len(ws.parentOpStack)-1]
	}
	return ctx
}

// Walk traverses a parsed AST and extracts all command invocations.
// If cfg is nil, DefaultWalkerConfig() is used.
func Walk(file *syntax.File, cfg *WalkerConfig) []rules.CommandInfo {
	if file == nil {
		return nil
	}
	if cfg == nil {
		cfg = DefaultWalkerConfig()
	}
	ws := &walkerState{cfg: cfg}
	walkStmts(ws, file.Stmts)
	return ws.results
}

// walkStmts processes a list of statements.
func walkStmts(ws *walkerState, stmts []*syntax.Stmt) {
	for _, stmt := range stmts {
		walkStmt(ws, stmt)
	}
}

// walkStmt processes a single statement and attaches redirects to the
// CommandInfo corresponding to the statement's direct Cmd only (not to
// commands inside $() substitutions).
func walkStmt(ws *walkerState, stmt *syntax.Stmt) {
	if stmt == nil {
		return
	}
	directIdx := len(ws.results)
	walkCmd(ws, stmt.Cmd)

	// Walk redirect operands for embedded substitutions (e.g., > "$(gen)").
	for _, r := range stmt.Redirs {
		if r.Word != nil {
			walkWordSubsts(ws, r.Word)
		}
		if r.Hdoc != nil {
			walkWordSubsts(ws, r.Hdoc)
		}
	}

	if len(stmt.Redirs) > 0 && directIdx < len(ws.results) {
		redirs := extractRedirects(stmt.Redirs)
		switch c := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			// Attach to the direct command, but only if extractCallExpr actually
			// appended a CommandInfo (it won't for assignment-only stmts like FOO=bar).
			if directIdx < len(ws.results) && ws.results[directIdx].RawNode == c {
				ws.results[directIdx].Redirects = append(ws.results[directIdx].Redirects, redirs...)
			}
		case *syntax.BinaryCmd:
			// For pipelines (cmd1 | cmd2 > out), attach to the last stage's
			// direct command. If the last stage is compound, find the last
			// direct CallExpr inside it.
			stages := collectPipelineStages(c)
			if len(stages) > 0 {
				lastStage := stages[len(stages)-1]
				if ce, ok := lastStage.Cmd.(*syntax.CallExpr); ok {
					for i := len(ws.results) - 1; i >= directIdx; i-- {
						if ws.results[i].RawNode == ce {
							ws.results[i].Redirects = append(ws.results[i].Redirects, redirs...)
							break
						}
					}
				} else {
					// Compound last stage — propagate to all direct commands whose
					// AST position falls within the last stage's span. This avoids
					// mutable walker state that nested pipelines could clobber.
					stageStart := lastStage.Cmd.Pos().Offset()
					stageEnd := lastStage.Cmd.End().Offset()
					for i := directIdx; i < len(ws.results); i++ {
						r := &ws.results[i]
						if r.RawNode == nil || r.Context.InSubstitution {
							continue
						}
						nodeStart := r.RawNode.Pos().Offset()
						nodeEnd := r.RawNode.End().Offset()
						if nodeStart >= stageStart && nodeEnd <= stageEnd {
							r.Redirects = append(r.Redirects, redirs...)
						}
					}
				}
			}
		default:
			// For compound commands (subshells, blocks, if/while), propagate
			// redirects to ALL direct (non-substitution) commands inside,
			// since the redirect affects the compound's I/O for all contained
			// commands.
			for i := directIdx; i < len(ws.results); i++ {
				r := &ws.results[i]
				if r.RawNode != nil && !r.Context.InSubstitution {
					r.Redirects = append(r.Redirects, redirs...)
				}
			}
		}
	}
}

// walkCmd dispatches to the appropriate handler based on command type.
func walkCmd(ws *walkerState, cmd syntax.Command) {
	if cmd == nil {
		return
	}
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		ws.extractCallExpr(c)
		// Walk CmdSubst nodes embedded inside arguments.
		walkCallExprSubsts(ws, c)

	case *syntax.BinaryCmd:
		walkBinaryCmd(ws, c)

	case *syntax.Subshell:
		ws.subshellDepth++
		walkStmts(ws, c.Stmts)
		ws.subshellDepth--

	case *syntax.FuncDecl:
		name := ""
		if c.Name != nil {
			name = c.Name.Value
		}
		ws.funcStack = append(ws.funcStack, name)
		walkStmt(ws, c.Body)
		ws.funcStack = ws.funcStack[:len(ws.funcStack)-1]

	case *syntax.IfClause:
		walkIfClause(ws, c)

	case *syntax.WhileClause:
		ws.conditionDepth++
		walkStmts(ws, c.Cond)
		ws.conditionDepth--
		walkStmts(ws, c.Do)

	case *syntax.ForClause:
		// Walk the iteration list for command substitutions (e.g., for x in $(gen); do ...).
		switch loop := c.Loop.(type) {
		case *syntax.WordIter:
			for _, item := range loop.Items {
				walkWordSubsts(ws, item)
			}
		case *syntax.CStyleLoop:
			// C-style for loop: for ((init; cond; post)); do ... done
			// Walk each arithmetic expression for nested command substitutions.
			if loop.Init != nil {
				walkArithmExpr(ws, loop.Init)
			}
			if loop.Cond != nil {
				walkArithmExpr(ws, loop.Cond)
			}
			if loop.Post != nil {
				walkArithmExpr(ws, loop.Post)
			}
		}
		walkStmts(ws, c.Do)

	case *syntax.CaseClause:
		walkWordSubsts(ws, c.Word)
		for _, item := range c.Items {
			// Walk patterns for command substitutions (e.g., case $x in $(pat)) ...).
			for _, pat := range item.Patterns {
				walkWordSubsts(ws, pat)
			}
			walkStmts(ws, item.Stmts)
		}

	case *syntax.Block:
		walkStmts(ws, c.Stmts)

	case *syntax.DeclClause:
		for _, a := range c.Args {
			if a.Value != nil {
				walkWordSubsts(ws, a.Value)
			}
			// Array assignments (e.g. `declare -a arr=($(cmd))`) store the
			// value in a.Array, not a.Value. Walk each element's Value.
			// ArrayElem.Value can be nil for associative array entries
			// like `declare -A x=([index]=)` — guard against that.
			if a.Array != nil {
				for _, elem := range a.Array.Elems {
					if elem == nil {
						continue
					}
					if elem.Value != nil {
						walkWordSubsts(ws, elem.Value)
					}
					// Associative array keys can contain command substitutions:
					// declare -A arr=([$(dangerous)]=val). The Index field is an
					// ArithmExpr (which includes *syntax.Word) — walk it to find
					// any nested CmdSubst.
					if elem.Index != nil {
						walkArithmExpr(ws, elem.Index)
					}
				}
			}
		}

	case *syntax.TestClause:
		// Extended test clause [[ ... ]] — walk Word nodes inside TestExpr
		// tree so command substitutions like `[[ $(cmd) == x ]]` are found.
		walkTestExpr(ws, c.X)

	case *syntax.TimeClause:
		// time <stmt> — walk the inner statement.
		walkStmt(ws, c.Stmt)

	case *syntax.CoprocClause:
		// coproc <stmt> — walk the inner statement.
		walkStmt(ws, c.Stmt)

	case *syntax.ArithmCmd:
		if c.X != nil {
			walkArithmExpr(ws, c.X)
		}

	case *syntax.LetClause:
		for _, expr := range c.Exprs {
			walkArithmExpr(ws, expr)
		}
	}
}

// walkBinaryCmd walks a binary command, tracking pipeline positions for pipes.
func walkBinaryCmd(ws *walkerState, bc *syntax.BinaryCmd) {
	isPipe := bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll

	if isPipe {
		pipeOp := "|"
		if bc.Op == syntax.PipeAll {
			pipeOp = "|&"
		}
		stages := collectPipelineStages(bc)
		for i, stmt := range stages {
			pos := i + 1 // 1-indexed: 1 = first stage, 2+ = subsequent
			ws.pipelineStack = append(ws.pipelineStack, pos)
			ws.parentOpStack = append(ws.parentOpStack, pipeOp)
			walkStmt(ws, stmt)
			ws.parentOpStack = ws.parentOpStack[:len(ws.parentOpStack)-1]
			ws.pipelineStack = ws.pipelineStack[:len(ws.pipelineStack)-1]
		}
		return
	}

	op := binCmdOpString(bc.Op)
	ws.parentOpStack = append(ws.parentOpStack, op)
	walkStmt(ws, bc.X)
	walkStmt(ws, bc.Y)
	ws.parentOpStack = ws.parentOpStack[:len(ws.parentOpStack)-1]
}

// collectPipelineStages flattens a chain of pipe BinaryCmds into an ordered
// slice of statements.
func collectPipelineStages(bc *syntax.BinaryCmd) []*syntax.Stmt {
	var stages []*syntax.Stmt
	var collect func(x, y *syntax.Stmt)
	collect = func(x, y *syntax.Stmt) {
		// Unwrap left side if it is itself a pipe.
		if x != nil {
			if bc2, ok := x.Cmd.(*syntax.BinaryCmd); ok && (bc2.Op == syntax.Pipe || bc2.Op == syntax.PipeAll) {
				collect(bc2.X, bc2.Y)
			} else {
				stages = append(stages, x)
			}
		}
		if y != nil {
			stages = append(stages, y)
		}
	}
	collect(bc.X, bc.Y)
	return stages
}

// binCmdOpString converts a BinCmdOperator to its string representation.
func binCmdOpString(op syntax.BinCmdOperator) string {
	switch op {
	case syntax.AndStmt:
		return "&&"
	case syntax.OrStmt:
		return "||"
	default:
		return ";"
	}
}

// walkIfClause handles if/elif/else chains.
func walkIfClause(ws *walkerState, ic *syntax.IfClause) {
	ws.conditionDepth++
	walkStmts(ws, ic.Cond)
	ws.conditionDepth--
	walkStmts(ws, ic.Then)
	if ic.Else != nil {
		walkIfClause(ws, ic.Else)
	}
}

// walkCallExprSubsts walks CmdSubst nodes embedded in CallExpr arguments.
func walkCallExprSubsts(ws *walkerState, ce *syntax.CallExpr) {
	for _, arg := range ce.Args {
		walkWordSubsts(ws, arg)
	}
	for _, assign := range ce.Assigns {
		if assign.Value != nil {
			walkWordSubsts(ws, assign.Value)
		}
	}
}

// walkWordSubsts visits CmdSubst nodes inside a word and walks their bodies.
func walkWordSubsts(ws *walkerState, w *syntax.Word) {
	if w == nil {
		return
	}
	walkWordParts(ws, w.Parts)
}

// walkWordParts recursively walks word parts to find all nested command
// substitutions, including those inside parameter expansions (${x:-$(cmd)}),
// arithmetic expansions ($(($(cmd)))), double quotes, and process substitutions.
func walkWordParts(ws *walkerState, parts []syntax.WordPart) {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.CmdSubst:
			ws.substDepth++
			walkStmts(ws, p.Stmts)
			ws.substDepth--
		case *syntax.DblQuoted:
			walkWordParts(ws, p.Parts)
		case *syntax.ProcSubst:
			ws.substDepth++
			walkStmts(ws, p.Stmts)
			ws.substDepth--
		case *syntax.ParamExp:
			// Walk nested words in parameter expansions:
			// ${x:-$(cmd)}, ${x:+$(cmd)}, ${x/pattern/$(cmd)}, etc.
			if p.Exp != nil {
				walkWordSubsts(ws, p.Exp.Word)
			}
			if p.Repl != nil {
				walkWordSubsts(ws, p.Repl.Orig)
				walkWordSubsts(ws, p.Repl.With)
			}
			// Walk slice expressions: ${x:$(offset):$(length)}
			if p.Slice != nil {
				if p.Slice.Offset != nil {
					walkArithmExpr(ws, p.Slice.Offset)
				}
				if p.Slice.Length != nil {
					walkArithmExpr(ws, p.Slice.Length)
				}
			}
			// Walk array index expressions: ${x[$(idx)]}
			if p.Index != nil {
				walkArithmExpr(ws, p.Index)
			}
		case *syntax.ArithmExp:
			// Walk nested expressions in arithmetic expansions: $(($(cmd) + 1))
			if p.X != nil {
				walkArithmExpr(ws, p.X)
			}
		}
	}
}

// walkTestExpr recursively walks a test expression tree (as used inside
// `[[ ... ]]`) and walks any Word nodes for nested command substitutions.
// Handles BinaryTest (`[[ X == Y ]]`), UnaryTest (`[[ -f X ]]`),
// ParenTest (`[[ ( X ) ]]`), and Word (the leaves).
func walkTestExpr(ws *walkerState, expr syntax.TestExpr) {
	switch t := expr.(type) {
	case *syntax.Word:
		walkWordSubsts(ws, t)
	case *syntax.BinaryTest:
		walkTestExpr(ws, t.X)
		walkTestExpr(ws, t.Y)
	case *syntax.UnaryTest:
		walkTestExpr(ws, t.X)
	case *syntax.ParenTest:
		walkTestExpr(ws, t.X)
	}
}

// walkArithmExpr recursively walks arithmetic expressions to find nested
// command substitutions (e.g., $(($(gen) + 1))).
func walkArithmExpr(ws *walkerState, expr syntax.ArithmExpr) {
	switch e := expr.(type) {
	case *syntax.Word:
		walkWordParts(ws, e.Parts)
	case *syntax.BinaryArithm:
		walkArithmExpr(ws, e.X)
		walkArithmExpr(ws, e.Y)
	case *syntax.UnaryArithm:
		walkArithmExpr(ws, e.X)
	case *syntax.ParenArithm:
		walkArithmExpr(ws, e.X)
	case *syntax.FlagsArithm:
		walkArithmExpr(ws, e.X)
	}
}

// extractCallExpr processes a CallExpr node and appends a CommandInfo.
func (ws *walkerState) extractCallExpr(ce *syntax.CallExpr) {
	if len(ce.Args) == 0 {
		return
	}

	env := extractEnv(ce.Assigns)
	name, remainingArgs, lookupMode := resolveCommand(ce.Args, 0, ws.cfg.Wrappers)

	var flags, positional []string
	var subcommand string
	var rawArgs []string
	if name == "" {
		// Unresolvable command — treat all remaining args as raw positional
		// without flag parsing or subcommand extraction.
		for _, w := range remainingArgs {
			if lit, ok := wordLiteral(w); ok {
				positional = append(positional, lit)
			} else {
				positional = append(positional, wordToString(w))
			}
		}
	} else {
		rawArgs = make([]string, len(remainingArgs))
		for i, w := range remainingArgs {
			if lit, ok := wordLiteral(w); ok {
				rawArgs[i] = lit
			} else {
				rawArgs[i] = wordToString(w)
			}
		}
		flags, positional, subcommand = classifyArgs(name, remainingArgs, ws.cfg.CommandFlags)
		if lookupMode {
			// Lookup wrappers (e.g., "command -v foo") aren't executing —
			// don't promote args to subcommand as it would trip subcommand rules.
			subcommand = ""
		}
	}

	ctx := ws.currentContext()

	info := rules.CommandInfo{
		Name:       name,
		Args:       positional,
		Flags:      flags,
		RawArgs:    rawArgs,
		Subcommand: subcommand,
		Env:        env,
		Context:    ctx,
		RawNode:    ce,
	}

	ws.results = append(ws.results, info)
}

// extractEnv builds an env map from Assign nodes on a CallExpr.
func extractEnv(assigns []*syntax.Assign) map[string]string {
	if len(assigns) == 0 {
		return nil
	}
	env := make(map[string]string, len(assigns))
	for _, a := range assigns {
		if a.Name == nil {
			continue
		}
		key := a.Name.Value
		val := ""
		if a.Value != nil {
			if lit, ok := wordLiteral(a.Value); ok {
				val = lit
			} else {
				val = wordToString(a.Value)
			}
		}
		env[key] = val
	}
	return env
}

// resolveCommand strips prefix wrapper commands from args and returns the
// resolved command name, remaining argument words, and whether the command is
// in "lookup mode" (e.g., "command -v foo" — not executing, just querying).
// depth limits recursion.
func resolveCommand(args []*syntax.Word, depth int, wrappers map[string]WrapperDef) (name string, remaining []*syntax.Word, lookupMode bool) {
	if depth >= maxWrapperDepth {
		return "", args, false
	}
	if len(args) == 0 {
		return "", nil, false
	}

	cmdWord := args[0]
	rest := args[1:]

	// Check for unresolvable dynamic command names.
	// Return full args so the command token is preserved in positional args.
	if isUnresolvable(cmdWord) {
		return "", args, false
	}

	// Check for brace expansion evasion.
	if isBraceExpansion(cmdWord) {
		return "", args, false
	}

	lit, ok := wordLiteral(cmdWord)
	if !ok {
		return "", args, false
	}

	wrapper, isWrapper := wrappers[lit]
	if !isWrapper {
		return lit, rest, false
	}

	// Check NoStrip flags — if the first arg matches, don't strip this wrapper.
	// This is a lookup/query mode (e.g., "command -v foo").
	for _, ns := range wrapper.NoStrip {
		if len(rest) > 0 {
			if first, ok := wordLiteral(rest[0]); ok && first == ns {
				return lit, rest, true
			}
		}
	}

	// Skip this wrapper's flags and any special positional tokens.
	rest = skipWrapperArgs(rest, wrapper)

	// If stripping consumed everything, the wrapper itself is the command
	// (e.g., "sudo -v", "env FOO=bar" with no inner command).
	// Return original rest so the wrapper's flags/args are preserved for classification.
	if len(rest) == 0 {
		return lit, args[1:], false
	}

	// If the remaining args still start with a flag token, skipWrapperArgs
	// stopped on an unknown flag. We cannot safely strip the wrapper because
	// we don't know how many arguments the unknown flag consumes. Return the
	// wrapper name with all remaining args for classification.
	if firstLit, ok := wordLiteral(rest[0]); ok && strings.HasPrefix(firstLit, "-") {
		return lit, args[1:], false
	}

	return resolveCommand(rest, depth+1, wrappers)
}

// isShellAssignment returns true if s looks like a shell variable assignment
// (NAME=... where NAME is a valid POSIX identifier: [a-zA-Z_][a-zA-Z0-9_]*).
func isShellAssignment(s string) bool {
	name, _, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return false
	}
	for i, c := range []byte(name) {
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}
	return true
}

// isShellAssignmentWord checks if a syntax.Word looks like a shell variable
// assignment (NAME=...), handling quoted values like FOO="$bar".
func isShellAssignmentWord(w *syntax.Word) bool {
	if len(w.Parts) == 0 {
		return false
	}
	// Unquoted or partially quoted: first part is a Lit with NAME= prefix.
	if lit, ok := w.Parts[0].(*syntax.Lit); ok {
		return isShellAssignment(lit.Value)
	}
	// Fully double-quoted: "FOO=$bar" — the shell removes quotes, passing
	// FOO=... to the wrapper. Check for NAME= prefix inside the DblQuoted.
	if len(w.Parts) == 1 {
		if dq, ok := w.Parts[0].(*syntax.DblQuoted); ok && len(dq.Parts) > 0 {
			if lit, ok := dq.Parts[0].(*syntax.Lit); ok {
				return isShellAssignment(lit.Value)
			}
		}
	}
	return false
}

// skipWrapperArgs skips flags and special positional tokens for a wrapper command.
// It handles:
//   - Boolean flags (value 0 in Flags map)
//   - Flags that consume N arguments (value N in Flags map)
//   - --flag=value forms
//   - -- terminator
//   - VAR=val assignments (when ConsumeEnvAssigns is set)
//   - The first non-flag positional (when ConsumeFirstPositional is set, e.g. timeout duration)
func skipWrapperArgs(args []*syntax.Word, def WrapperDef) []*syntax.Word {
	firstPositionalConsumed := false
	endOfOptions := false
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			// Non-literal word — check for env assignments like FOO="$bar"
			// using the AST structure (first part is a Lit with NAME= prefix).
			if def.ConsumeEnvAssigns && isShellAssignmentWord(args[0]) {
				args = args[1:]
				continue
			}
			if def.ConsumeFirstPositional && !firstPositionalConsumed {
				args = args[1:]
				firstPositionalConsumed = true
				continue
			}
			break
		}

		// -- terminates flag processing but not env-assign/positional consumption.
		if !endOfOptions && lit == "--" {
			args = args[1:]
			endOfOptions = true
			continue
		}

		// Flag token (only before --).
		// Only skip flags that are explicitly known in def.Flags. Unknown flags
		// stop processing (fail-closed — the wrapper cannot be safely stripped
		// when we don't know how many arguments an unknown flag consumes).
		if !endOfOptions && strings.HasPrefix(lit, "-") {
			flagName, _, hasEq := strings.Cut(lit, "=")
			if def.Flags == nil {
				break
			}
			argc, known := def.Flags[flagName]
			if !known {
				break
			}
			args = args[1:]
			if argc > 0 && !hasEq {
				for j := 0; j < argc && len(args) > 0; j++ {
					args = args[1:]
				}
			}
			continue
		}

		// VAR=val assignment (env-like wrappers). Only match valid shell
		// identifiers before = to avoid consuming URLs or other =-containing args.
		if def.ConsumeEnvAssigns && isShellAssignment(lit) {
			args = args[1:]
			continue
		}

		// First positional argument (timeout-like wrappers: the duration).
		if def.ConsumeFirstPositional && !firstPositionalConsumed {
			firstPositionalConsumed = true
			args = args[1:]
			continue
		}

		// Non-flag, non-special positional: this is the real command.
		break
	}
	return args
}

// classifyArgs splits args into flags, positional args, and the subcommand.
// cmdName is used to look up known global flags that should be skipped
// (along with their arguments) when finding the subcommand.
func classifyArgs(cmdName string, args []*syntax.Word, commandFlags map[string]map[string]int) (flags []string, positional []string, subcommand string) {
	endOfOptions := false
	subcommandFound := false
	globalFlags := commandFlags[cmdName]

	for i := 0; i < len(args); i++ {
		w := args[i]
		lit, ok := wordLiteral(w)
		if !ok {
			raw := wordToString(w)
			positional = append(positional, raw)
			// Don't promote dynamic words to subcommand — they're unresolvable.
			// Mark the subcommand slot as consumed so later positionals aren't
			// promoted either (e.g., "git $X status" shouldn't set subcommand="status").
			if !subcommandFound {
				subcommandFound = true
			}
			continue
		}

		if !endOfOptions && lit == "--" {
			endOfOptions = true
			continue
		}

		if !endOfOptions && strings.HasPrefix(lit, "-") {
			flags = append(flags, lit)

			// If this is a known global flag that consumes arguments, skip them.
			if globalFlags != nil {
				flagName, _, hasEq := strings.Cut(lit, "=")
				if argc, known := globalFlags[flagName]; known && argc > 0 && !hasEq {
					// Skip the next `argc` args — they belong to this global
					// flag and are not positional arguments for the command.
					for j := 0; j < argc && i+1 < len(args); j++ {
						i++
					}
				}
			}
			continue
		}

		// Positional argument.
		positional = append(positional, lit)
		if !endOfOptions && !subcommandFound {
			subcommand = lit
			subcommandFound = true
		}
	}
	return
}

// extractRedirects converts Redirect nodes into RedirectInfo values.
func extractRedirects(redirs []*syntax.Redirect) []rules.RedirectInfo {
	result := make([]rules.RedirectInfo, 0, len(redirs))
	for _, r := range redirs {
		file := ""
		if r.Word != nil {
			file = wordToString(r.Word)
		}
		op := r.Op.String()
		// Prepend fd number if present (e.g., "2>" instead of ">").
		if r.N != nil {
			op = r.N.Value + op
		}
		result = append(result, rules.RedirectInfo{
			Op:   op,
			File: file,
		})
	}
	return result
}

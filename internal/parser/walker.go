package parser

import (
	"bytes"
	"strings"

	"github.com/perezd/stargate/internal/config"
	"github.com/perezd/stargate/internal/rules"
	"mvdan.cc/sh/v3/syntax"
)

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

// wordToString converts a syntax.Word to its string representation.
// Creates a new printer per call to be safe for concurrent use.
func wordToString(w *syntax.Word) string {
	var buf bytes.Buffer
	p := syntax.NewPrinter()
	_ = p.Print(&buf, w)
	return buf.String()
}

// wordLiteral extracts the plain literal string from a word. Returns the
// literal value and whether the word was fully resolvable (no dynamic parts).
func wordLiteral(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
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

// dblQuotedLiteral extracts a literal from a DblQuoted word part.
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

// isBraceExpansion returns true if the word looks like a brace expansion
// attempt (contains both '{' and ','), which is an evasion technique.
func isBraceExpansion(w *syntax.Word) bool {
	lit, ok := wordLiteral(w)
	if !ok {
		return false
	}
	// Detect both comma-separated ({a,b,c}) and range ({a..z}, {1..3}) forms.
	if !strings.Contains(lit, "{") {
		return false
	}
	return strings.Contains(lit, ",") || strings.Contains(lit, "..")
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
	ctx := rules.CommandContext{
		SubshellDepth:  ws.subshellDepth,
		InSubstitution: ws.substDepth > 0,
		InCondition:    ws.conditionDepth > 0,
	}
	if len(ws.pipelineStack) > 0 {
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

	if len(stmt.Redirs) > 0 && directIdx < len(ws.results) {
		redirs := extractRedirects(stmt.Redirs)
		switch stmt.Cmd.(type) {
		case *syntax.CallExpr:
			// Attach to the direct command, but only if extractCallExpr actually
			// appended a CommandInfo (it won't for assignment-only stmts like FOO=bar).
			ce := stmt.Cmd.(*syntax.CallExpr)
			if directIdx < len(ws.results) && ws.results[directIdx].RawNode == ce {
				ws.results[directIdx].Redirects = append(ws.results[directIdx].Redirects, redirs...)
			}
		case *syntax.BinaryCmd:
			// For pipelines (cmd1 | cmd2 > out), attach to the last stage's
			// direct command. If the last stage is compound, find the last
			// direct CallExpr inside it.
			bc := stmt.Cmd.(*syntax.BinaryCmd)
			stages := collectPipelineStages(bc)
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
					// Compound last stage — find last direct CallExpr inside.
					for i := len(ws.results) - 1; i >= directIdx; i-- {
						r := &ws.results[i]
						if r.RawNode != nil && !r.Context.InSubstitution {
							r.Redirects = append(r.Redirects, redirs...)
							break
						}
					}
				}
			}
		default:
			// For compound commands (subshells, blocks, if/while), propagate
			// redirects to the last direct (non-substitution) CallExpr inside,
			// since the redirect affects the compound's I/O which flows through
			// its contained commands.
			for i := len(ws.results) - 1; i >= directIdx; i-- {
				r := &ws.results[i]
				if r.RawNode != nil && !r.Context.InSubstitution {
					r.Redirects = append(r.Redirects, redirs...)
					break
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
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, item := range wi.Items {
				walkWordSubsts(ws, item)
			}
		}
		walkStmts(ws, c.Do)

	case *syntax.CaseClause:
		walkWordSubsts(ws, c.Word)
		for _, item := range c.Items {
			walkStmts(ws, item.Stmts)
		}

	case *syntax.Block:
		walkStmts(ws, c.Stmts)

	case *syntax.DeclClause:
		for _, a := range c.Args {
			if a.Value != nil {
				walkWordSubsts(ws, a.Value)
			}
		}

	case *syntax.TimeClause:
		// time <stmt> — walk the inner statement.
		walkStmt(ws, c.Stmt)

	case *syntax.CoprocClause:
		// coproc <stmt> — walk the inner statement.
		walkStmt(ws, c.Stmt)

	case *syntax.ArithmCmd, *syntax.LetClause:
		// No sub-commands to extract.
	}
}

// walkBinaryCmd walks a binary command, tracking pipeline positions for pipes.
func walkBinaryCmd(ws *walkerState, bc *syntax.BinaryCmd) {
	isPipe := bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll

	if isPipe {
		stages := collectPipelineStages(bc)
		for i, stmt := range stages {
			pos := i + 1 // 1-indexed: 1 = source, 2+ = sink
			ws.pipelineStack = append(ws.pipelineStack, pos)
			ws.parentOpStack = append(ws.parentOpStack, "|")
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
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.CmdSubst:
			ws.substDepth++
			walkStmts(ws, p.Stmts)
			ws.substDepth--
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if cs, ok := dp.(*syntax.CmdSubst); ok {
					ws.substDepth++
					walkStmts(ws, cs.Stmts)
					ws.substDepth--
				}
			}
		case *syntax.ProcSubst:
			ws.substDepth++
			walkStmts(ws, p.Stmts)
			ws.substDepth--
		}
	}
}

// extractCallExpr processes a CallExpr node and appends a CommandInfo.
func (ws *walkerState) extractCallExpr(ce *syntax.CallExpr) {
	if len(ce.Args) == 0 {
		return
	}

	env := extractEnv(ce.Assigns)
	name, remainingArgs := resolveCommand(ce.Args, 0, ws.cfg.Wrappers)

	var flags, positional []string
	var subcommand string
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
		flags, positional, subcommand = classifyArgs(name, remainingArgs, ws.cfg.CommandFlags)
	}

	ctx := ws.currentContext()

	info := rules.CommandInfo{
		Name:       name,
		Args:       positional,
		Flags:      flags,
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
// resolved command name and remaining argument words. depth limits recursion.
func resolveCommand(args []*syntax.Word, depth int, wrappers map[string]WrapperDef) (string, []*syntax.Word) {
	if depth >= 16 {
		return "", args
	}
	if len(args) == 0 {
		return "", nil
	}

	cmdWord := args[0]
	rest := args[1:]

	// Check for unresolvable dynamic command names.
	// Return full args so the command token is preserved in positional args.
	if isUnresolvable(cmdWord) {
		return "", args
	}

	// Check for brace expansion evasion.
	if isBraceExpansion(cmdWord) {
		return "", args
	}

	lit, ok := wordLiteral(cmdWord)
	if !ok {
		return "", args
	}

	wrapper, isWrapper := wrappers[lit]
	if !isWrapper {
		return lit, rest
	}

	// Check NoStrip flags — if the first arg matches, don't strip this wrapper.
	for _, ns := range wrapper.NoStrip {
		if len(rest) > 0 {
			if first, ok := wordLiteral(rest[0]); ok && first == ns {
				return lit, rest
			}
		}
	}

	// Skip this wrapper's flags and any special positional tokens.
	rest = skipWrapperArgs(rest, wrapper)

	return resolveCommand(rest, depth+1, wrappers)
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
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			break
		}

		// -- terminates flag processing; consume it and stop.
		if lit == "--" {
			args = args[1:]
			break
		}

		// Flag token.
		if strings.HasPrefix(lit, "-") {
			flagName, _, hasEq := strings.Cut(lit, "=")
			args = args[1:]
			// Consume extra positional arguments this flag takes (only when not --flag=val form).
			if def.Flags != nil {
				if argc, known := def.Flags[flagName]; known && argc > 0 && !hasEq {
					for j := 0; j < argc && len(args) > 0; j++ {
						args = args[1:]
					}
				}
			}
			continue
		}

		// VAR=val assignment (env-like wrappers).
		if def.ConsumeEnvAssigns && strings.Contains(lit, "=") {
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
			// Dynamic word — treat as positional.
			raw := wordToString(w)
			positional = append(positional, raw)
			if !endOfOptions && !subcommandFound {
				subcommand = raw
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

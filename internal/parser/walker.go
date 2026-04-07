package parser

import (
	"bytes"
	"strings"

	"github.com/perezd/stargate/internal/rules"
	"mvdan.cc/sh/v3/syntax"
)

// prefixCommands are wrapper commands that should be stripped to reveal the
// real command underneath.
var prefixCommands = map[string]bool{
	"command": true,
	"builtin": true,
	"env":     true,
	"sudo":    true,
	"doas":    true,
	"nice":    true,
	"nohup":   true,
	"time":    true,
	"strace":  true,
	"watch":   true,
	"timeout": true,
}

// printer is a package-level printer for converting syntax.Word to strings.
var printer = syntax.NewPrinter()

// wordToString converts a syntax.Word to its string representation.
func wordToString(w *syntax.Word) string {
	var buf bytes.Buffer
	_ = printer.Print(&buf, w)
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
	return strings.Contains(lit, "{") && strings.Contains(lit, ",")
}

// walkerState tracks the AST traversal context.
type walkerState struct {
	results []rules.CommandInfo

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
func Walk(file *syntax.File) []rules.CommandInfo {
	ws := &walkerState{}
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
	// Only attach statement-level redirects when the statement's direct Cmd is
	// a CallExpr. For compound commands (subshells, blocks, if/while), redirects
	// apply to the compound itself, not to the first nested CallExpr inside.
	_, isCallExpr := stmt.Cmd.(*syntax.CallExpr)
	directIdx := len(ws.results)
	walkCmd(ws, stmt.Cmd)

	if isCallExpr && len(stmt.Redirs) > 0 && directIdx < len(ws.results) {
		redirs := extractRedirects(stmt.Redirs)
		ws.results[directIdx].Redirects = append(ws.results[directIdx].Redirects, redirs...)
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
			walkStmts(ws, p.Stmts)
		}
	}
}

// extractCallExpr processes a CallExpr node and appends a CommandInfo.
func (ws *walkerState) extractCallExpr(ce *syntax.CallExpr) {
	if len(ce.Args) == 0 {
		return
	}

	env := extractEnv(ce.Assigns)
	name, remainingArgs := resolveCommand(ce.Args, 0)
	flags, positional, subcommand := classifyArgs(name, remainingArgs)

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
			lit, _ := wordLiteral(a.Value)
			val = lit
		}
		env[key] = val
	}
	return env
}

// resolveCommand strips prefix wrapper commands from args and returns the
// resolved command name and remaining argument words. depth limits recursion.
func resolveCommand(args []*syntax.Word, depth int) (string, []*syntax.Word) {
	if depth >= 16 {
		return "", nil
	}
	if len(args) == 0 {
		return "", nil
	}

	cmdWord := args[0]
	rest := args[1:]

	// Check for unresolvable dynamic command names.
	if isUnresolvable(cmdWord) {
		return "", rest
	}

	// Check for brace expansion evasion.
	if isBraceExpansion(cmdWord) {
		return "", rest
	}

	lit, ok := wordLiteral(cmdWord)
	if !ok {
		return "", rest
	}

	if !prefixCommands[lit] {
		return lit, rest
	}

	// Strip prefix; handle special argument-consuming prefixes.
	switch lit {
	case "env":
		rest = skipEnvFlags(rest)
	case "nice":
		rest = skipNiceFlags(rest)
	case "timeout":
		rest = skipTimeoutDuration(rest)
	case "sudo":
		rest = skipSudoFlags(rest)
	}

	return resolveCommand(rest, depth+1)
}

// skipEnvFlags skips env-specific flags and VAR=val assignments.
func skipEnvFlags(args []*syntax.Word) []*syntax.Word {
	// Flags that take no extra argument.
	noArgFlags := map[string]bool{"-i": true, "--": true}
	// Flags that consume the next argument.
	takesArgFlags := map[string]bool{"-u": true, "-S": true}
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			break
		}
		if lit == "--" {
			args = args[1:]
			break
		}
		if takesArgFlags[lit] {
			args = args[1:] // skip flag
			if len(args) > 0 {
				args = args[1:] // skip its argument
			}
			continue
		}
		if noArgFlags[lit] {
			args = args[1:]
			continue
		}
		// Skip VAR=val assignments.
		if strings.Contains(lit, "=") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

// skipNiceFlags skips nice's -n <value> and other flags.
func skipNiceFlags(args []*syntax.Word) []*syntax.Word {
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			break
		}
		if lit == "-n" {
			args = args[1:] // skip -n
			if len(args) > 0 {
				args = args[1:] // skip value
			}
			continue
		}
		if strings.HasPrefix(lit, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

// skipTimeoutDuration skips timeout's flags and duration argument.
// Handles flags that consume arguments: -k/--kill-after, -s/--signal.
func skipTimeoutDuration(args []*syntax.Word) []*syntax.Word {
	takesArg := map[string]bool{
		"-k": true, "--kill-after": true,
		"-s": true, "--signal": true,
	}
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			break
		}
		if !strings.HasPrefix(lit, "-") {
			// First non-flag is the duration — skip it and return.
			args = args[1:]
			break
		}
		// Check for --flag=value form.
		flagName := lit
		if idx := strings.Index(lit, "="); idx >= 0 {
			flagName = lit[:idx]
		}
		args = args[1:]
		// If this flag consumes an argument and wasn't --flag=value, skip next.
		if takesArg[flagName] && !strings.Contains(lit, "=") && len(args) > 0 {
			args = args[1:]
		}
	}
	return args
}

// skipSudoFlags skips sudo's flags before the command.
func skipSudoFlags(args []*syntax.Word) []*syntax.Word {
	// Flags that consume the next argument.
	takesArg := map[string]bool{
		"-u": true, "-g": true, "-c": true, "-D": true,
		"-r": true, "-t": true, "-T": true, "-U": true,
	}
	// Flags that take no extra argument.
	noArg := map[string]bool{
		"-h": true, "-i": true, "-s": true, "-l": true, "-v": true,
		"-k": true, "-K": true, "-n": true, "-b": true,
		"-e": true, "-A": true, "-S": true, "-H": true,
		"-P": true,
	}
	for len(args) > 0 {
		lit, ok := wordLiteral(args[0])
		if !ok {
			break
		}
		if lit == "--" {
			args = args[1:]
			break
		}
		if noArg[lit] {
			args = args[1:]
			continue
		}
		if takesArg[lit] {
			args = args[1:] // skip flag
			if len(args) > 0 {
				args = args[1:] // skip its argument
			}
			continue
		}
		break
	}
	return args
}

// knownGlobalFlags maps command names to their global flags and how many
// arguments each flag consumes. Commands not in this map have no special
// global flag handling.
var knownGlobalFlags = map[string]map[string]int{
	"git": {
		"-C": 1, "--git-dir": 1, "--work-tree": 1,
		"--no-pager": 0, "--bare": 0, "--no-replace-objects": 0,
	},
	"docker": {
		"--context": 1, "-c": 1, "--host": 1, "-H": 1,
		"--log-level": 1, "-l": 1, "--tls": 0, "--tlsverify": 0,
		"--config": 1, "-D": 0, "--debug": 0,
	},
	"gh": {
		"--repo": 1, "-R": 1,
	},
	"kubectl": {
		"--context": 1, "--namespace": 1, "-n": 1,
		"--cluster": 1, "--user": 1, "--kubeconfig": 1,
		"-s": 1, "--server": 1,
	},
}

// classifyArgs splits args into flags, positional args, and the subcommand.
// cmdName is used to look up known global flags that should be skipped
// (along with their arguments) when finding the subcommand.
func classifyArgs(cmdName string, args []*syntax.Word) (flags []string, positional []string, subcommand string) {
	endOfOptions := false
	subcommandFound := false
	globalFlags := knownGlobalFlags[cmdName]

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
				// Check for --flag=value form.
				flagName := lit
				if idx := strings.Index(lit, "="); idx >= 0 {
					flagName = lit[:idx]
				}
				if argc, known := globalFlags[flagName]; known && argc > 0 && !strings.Contains(lit, "=") {
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

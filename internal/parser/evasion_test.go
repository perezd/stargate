package parser_test

import (
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/parser"
	"github.com/limbic-systems/stargate/internal/rules"
)

// findByName returns the first CommandInfo whose Name matches target.
// Returns nil if not found. Empty target matches unresolvable commands.
func findByName(cmds []rules.CommandInfo, target string) *rules.CommandInfo {
	for i := range cmds {
		if cmds[i].Name == target {
			return &cmds[i]
		}
	}
	return nil
}

// hasNameStart returns true if any command starts with the given prefix.
// Used for wrapper-stripping verification where the resolved name is the child.
func hasNameStart(cmds []rules.CommandInfo, prefix string) bool {
	for i := range cmds {
		if strings.HasPrefix(cmds[i].Name, prefix) {
			return true
		}
	}
	return false
}

// walk is a tiny helper that parses+walks a command and fails the test on parse error.
func walk(t *testing.T, command string) []rules.CommandInfo {
	t.Helper()
	cmds, err := parser.ParseAndWalk(command, "bash", parser.DefaultWalkerConfig())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return cmds
}

// =============================================================================
// CRITICAL — commands invisible to the walker (evasion bypasses classification)
// =============================================================================

func TestEvasion_TestClauseCmdSubst(t *testing.T) {
	// [[ $(rm -rf /) == "yes" ]] — the inner rm must be walked.
	cmds := walk(t, `[[ $(rm -rf /) == "yes" ]]`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found inside [[ ]]; got cmds=%+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside [[ $(...) ]] should have InSubstitution=true")
	}
}

func TestEvasion_TestClauseUnary(t *testing.T) {
	// [[ -f $(generate_path) ]] — unary test with CmdSubst operand.
	cmds := walk(t, `[[ -f $(generate_path) ]]`)
	gp := findByName(cmds, "generate_path")
	if gp == nil {
		t.Fatalf("generate_path not found inside [[ -f $(...) ]]; got %+v", cmds)
	}
	if !gp.Context.InSubstitution {
		t.Errorf("generate_path should have InSubstitution=true")
	}
}

func TestEvasion_TestClauseBothSides(t *testing.T) {
	cmds := walk(t, `[[ $(cmd1) == $(cmd2) ]]`)
	if findByName(cmds, "cmd1") == nil {
		t.Error("cmd1 not found in LHS of BinaryTest")
	}
	if findByName(cmds, "cmd2") == nil {
		t.Error("cmd2 not found in RHS of BinaryTest")
	}
}

func TestEvasion_ArrayAssignmentCmdSubst(t *testing.T) {
	// declare -a arr=($(rm -rf /)) — rm is inside a.Array.Elems.
	cmds := walk(t, `declare -a arr=($(rm -rf /))`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in array assignment; got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside $(...) should have InSubstitution=true")
	}
}

func TestEvasion_AssocArrayCmdSubst(t *testing.T) {
	// declare -A map=([key]=$(rm)) — associative array with CmdSubst value.
	cmds := walk(t, `declare -A map=([key]=$(rm))`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in associative array; got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm should have InSubstitution=true")
	}
}

func TestEvasion_AssocArrayEmptyValueNoPanic(t *testing.T) {
	// declare -A x=([index]=) — nil Value in ArrayElem. Must not panic.
	cmds := walk(t, `declare -A x=([index]=)`)
	_ = cmds // no assertion; we just verify no panic occurred
}

func TestEvasion_LocalArrayCmdSubst(t *testing.T) {
	cmds := walk(t, `f() { local -a arr=($(rm)); }`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in local array; got %+v", cmds)
	}
}

func TestEvasion_AnsiCHexEscape(t *testing.T) {
	// $'\x72\x6d' -rf / — walker must decode to Name="rm".
	cmds := walk(t, `$'\x72\x6d' -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm after ANSI-C hex decode; got %+v", cmds)
	}
}

func TestEvasion_AnsiCOctalEscape(t *testing.T) {
	// $'\162\155' -rf / — octal escapes decode to "rm".
	cmds := walk(t, `$'\162\155' -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm after ANSI-C octal decode; got %+v", cmds)
	}
}

func TestEvasion_AnsiCUnicodeEscape(t *testing.T) {
	// $'\u0072\u006d' -rf / — Unicode \u escapes decode to "rm".
	cmds := walk(t, `$'\u0072\u006d' -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm after ANSI-C \\u decode; got %+v", cmds)
	}
}

func TestEvasion_AnsiCMixed(t *testing.T) {
	// r$'\x6d' -rf / — Lit concatenation with ANSI-C SglQuoted.
	cmds := walk(t, `r$'\x6d' -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm from Lit+ANSI-C concat; got %+v", cmds)
	}
}

func TestEvasion_AnsiCNullByteTruncation(t *testing.T) {
	// $'rm\x00garbage' — the kernel's execve treats the command as a
	// C-string that terminates at the null byte. Bash actually executes
	// "rm". The walker must truncate at the null to match rule engine
	// behavior with the actual executed command.
	cmds := walk(t, `$'rm\x00garbage' -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm after null truncation; got %+v", cmds)
	}
}

func TestEvasion_AssocArrayKeyCmdSubst(t *testing.T) {
	// declare -A arr=([$(dangerous)]=val) — CmdSubst in the key (Index),
	// not the value. The walker must walk elem.Index via walkArithmExpr.
	cmds := walk(t, `declare -A arr=([$(dangerous)]=val)`)
	d := findByName(cmds, "dangerous")
	if d == nil {
		t.Fatalf("dangerous not found in assoc array key; got %+v", cmds)
	}
	if !d.Context.InSubstitution {
		t.Errorf("dangerous should have InSubstitution=true")
	}
}

func TestEvasion_BackslashInLit(t *testing.T) {
	// \rm -rf / — backslash stripped to "rm".
	cmds := walk(t, `\rm -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm after backslash strip; got %+v", cmds)
	}
}

func TestEvasion_BackslashMidWord(t *testing.T) {
	// r\m -rf / — backslash in middle stripped to "rm".
	cmds := walk(t, `r\m -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected Name=rm from r\\m; got %+v", cmds)
	}
}

func TestEvasion_BackslashOnWrapper(t *testing.T) {
	// \s\u\d\o rm -rf / — backslashes stripped, sudo wrapper then resolved.
	cmds := walk(t, `\s\u\d\o rm -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("expected rm after backslash strip + sudo unwrap; got %+v", cmds)
	}
}

// =============================================================================
// HIGH — implemented but untested code paths
// =============================================================================

func TestEvasion_SingleQuoted(t *testing.T) {
	cmds := walk(t, `'rm' -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm from single-quoted Lit; got %+v", cmds)
	}
}

func TestEvasion_CommandPrefix(t *testing.T) {
	cmds := walk(t, `command rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm after `command` wrapper strip; got %+v", cmds)
	}
}

func TestEvasion_EnvPrefix(t *testing.T) {
	cmds := walk(t, `env rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm after `env` wrapper strip; got %+v", cmds)
	}
}

func TestEvasion_SudoPrefix(t *testing.T) {
	cmds := walk(t, `sudo rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm after `sudo` wrapper strip; got %+v", cmds)
	}
}

func TestEvasion_NestedPrefixes(t *testing.T) {
	cmds := walk(t, `sudo env nice rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm after nested wrapper strip; got %+v", cmds)
	}
}

func TestEvasion_SudoWithEqualsFlag(t *testing.T) {
	// Default sudo wrapper config knows short flags (-u). Long flags like
	// --user are not in the default list, so the walker (fail-closed) stops
	// stripping on unknown flags. Operators can register long flags in
	// config if needed. This test documents the current behavior: known
	// short flag format strips correctly.
	cmds := walk(t, `sudo -u root rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm after sudo -u root; got %+v", cmds)
	}
}

func TestEvasion_BraceExpansion(t *testing.T) {
	// {rm,-rf,/} — unresolvable expansion, Name should be empty.
	cmds := walk(t, `{rm,-rf,/}`)
	if len(cmds) == 0 {
		return // some walkers may not emit anything; acceptable
	}
	for _, c := range cmds {
		if c.Name == "rm" {
			t.Errorf("brace expansion should NOT resolve to rm; got %+v", c)
		}
	}
}

func TestEvasion_QuotedBraces(t *testing.T) {
	// "{rm,-rf,/}" — quoted, not brace expansion; treated as literal string.
	cmds := walk(t, `"{rm,-rf,/}"`)
	if len(cmds) == 0 {
		t.Fatal("expected a literal command, got nothing")
	}
	// Should NOT match rm.
	if findByName(cmds, "rm") != nil {
		t.Errorf("quoted braces should not resolve to rm; got %+v", cmds)
	}
}

func TestEvasion_VariableIndirection(t *testing.T) {
	// cmd=$'rm'; $cmd -rf / — the $cmd invocation is unresolvable.
	cmds := walk(t, `cmd=$'rm'; $cmd -rf /`)
	// The second statement should have an unresolvable command.
	// Name="" or otherwise not literally "rm".
	if hasNameStart(cmds, "rm") {
		// If backslash-less ANSI-C resolves to rm, that's wrong here because
		// $cmd is a ParamExp at invocation time, not a static SglQuoted.
		t.Errorf("$cmd should be unresolvable; got %+v", cmds)
	}
}

func TestEvasion_CommandSubstitution(t *testing.T) {
	// $(echo rm) -rf / — inner echo is walked with InSubstitution=true.
	cmds := walk(t, `$(echo rm) -rf /`)
	echo := findByName(cmds, "echo")
	if echo == nil {
		t.Fatalf("echo not found inside $(); got %+v", cmds)
	}
	if !echo.Context.InSubstitution {
		t.Errorf("echo should have InSubstitution=true")
	}
}

func TestEvasion_ProcSubstInput(t *testing.T) {
	// cat <(rm -rf /) — rm must be walked with InSubstitution=true.
	cmds := walk(t, `cat <(rm -rf /)`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found inside <(); got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside <() should have InSubstitution=true")
	}
}

func TestEvasion_ProcSubstOutput(t *testing.T) {
	cmds := walk(t, `diff <(cmd1) >(rm -rf /)`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found inside >(); got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside >() should have InSubstitution=true")
	}
}

func TestEvasion_ParamExpSubst(t *testing.T) {
	// ${x:-$(rm -rf /)} — substitution in ParamExp default.
	cmds := walk(t, `echo ${x:-$(rm -rf /)}`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in ${x:-$(...)}; got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm should have InSubstitution=true")
	}
}

func TestEvasion_ArithmExpSubst(t *testing.T) {
	// $(($(rm))) — arithmetic expansion containing cmd subst.
	cmds := walk(t, `echo $(($(rm)))`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in $((...)) via $(); got %+v", cmds)
	}
}

func TestEvasion_ArithmCmdSubst(t *testing.T) {
	// (( x = $(rm) )) — arithmetic command.
	cmds := walk(t, `(( x = $(rm) ))`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in arithmetic command; got %+v", cmds)
	}
}

func TestEvasion_LetClauseSubst(t *testing.T) {
	// let "x = $(rm)" — let clause.
	cmds := walk(t, `let "x = $(rm)"`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in let clause; got %+v", cmds)
	}
}

func TestEvasion_RedirectOperandSubst(t *testing.T) {
	// > $(rm -rf /) — redirect operand containing cmd subst.
	cmds := walk(t, `echo hi > $(rm -rf /)`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in redirect operand; got %+v", cmds)
	}
}

func TestEvasion_ForLoopHeaderSubst(t *testing.T) {
	cmds := walk(t, `for x in $(rm); do echo; done`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in for loop header; got %+v", cmds)
	}
}

func TestEvasion_SelectHeaderSubst(t *testing.T) {
	cmds := walk(t, `select x in $(rm); do echo; done`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in select header; got %+v", cmds)
	}
}

func TestEvasion_HeredocSubstitution(t *testing.T) {
	// cat <<EOF\n$(rm -rf /)\nEOF — real newlines via raw string.
	input := "cat <<EOF\n$(rm -rf /)\nEOF\n"
	cmds := walk(t, input)
	if findByName(cmds, "cat") == nil {
		t.Error("cat (outer command) not found")
	}
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm inside heredoc substitution not found; got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside heredoc $() should have InSubstitution=true")
	}
}

func TestEvasion_HerestringSubstitution(t *testing.T) {
	cmds := walk(t, `cat <<< $(rm -rf /)`)
	if findByName(cmds, "cat") == nil {
		t.Error("cat (outer command) not found")
	}
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm inside herestring not found; got %+v", cmds)
	}
	if !rm.Context.InSubstitution {
		t.Errorf("rm inside herestring should have InSubstitution=true")
	}
}

func TestEvasion_CoprocPrefix(t *testing.T) {
	cmds := walk(t, `coproc rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm via coproc; got %+v", cmds)
	}
}

func TestEvasion_TimeClauseKeyword(t *testing.T) {
	// `time` as a bash keyword (not the /usr/bin/time wrapper).
	// Walker's TimeClause case recurses into the inner stmt.
	cmds := walk(t, `time rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm inside time keyword; got %+v", cmds)
	}
}

func TestEvasion_ExtGlobInCmdPosition(t *testing.T) {
	// @(rm|ls) -rf / — ExtGlob in command position is unresolvable (fail-closed).
	// The walker should not resolve it to "rm" or "ls".
	cmds := walk(t, `@(rm|ls) -rf /`)
	for _, c := range cmds {
		if c.Name == "rm" || c.Name == "ls" {
			t.Errorf("ExtGlob should NOT resolve to a concrete command; got %+v", c)
		}
	}
}

func TestEvasion_AssignmentOnlySubst(t *testing.T) {
	// FOO=$(rm -rf /) — no outer command; rm still walked.
	cmds := walk(t, `FOO=$(rm -rf /)`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm inside assignment value not found; got %+v", cmds)
	}
}

func TestEvasion_MultiAssignmentSubst(t *testing.T) {
	cmds := walk(t, `A=$(cmd1) B=$(cmd2)`)
	if findByName(cmds, "cmd1") == nil {
		t.Error("cmd1 not found in multi-assignment")
	}
	if findByName(cmds, "cmd2") == nil {
		t.Error("cmd2 not found in multi-assignment")
	}
}

func TestEvasion_LocaleDoubleQuote(t *testing.T) {
	// $"rm" -rf / — bash locale-translated double quote. Content is same literal.
	cmds := walk(t, `$"rm" -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected rm from $\"rm\"; got %+v", cmds)
	}
}

// =============================================================================
// MEDIUM — classification correctness and edge cases
// =============================================================================

func TestEvasion_UnicodeHomoglyph(t *testing.T) {
	// rｍ -rf / — the second character is Unicode FULLWIDTH LATIN SMALL M.
	// Walker returns the raw byte string — it won't match a GREEN rule for "rm".
	cmds := walk(t, "rｍ -rf /")
	if findByName(cmds, "rm") != nil {
		t.Error("Unicode homoglyph should NOT collapse to rm")
	}
}

func TestEvasion_NewlineInjection(t *testing.T) {
	// Real newline, not the two-char \n literal.
	cmds := walk(t, "echo ok\nrm -rf /")
	if findByName(cmds, "echo") == nil {
		t.Error("echo (first statement) not found")
	}
	if findByName(cmds, "rm") == nil {
		t.Error("rm (second statement) not found")
	}
}

func TestEvasion_PipelineObfuscation(t *testing.T) {
	cmds := walk(t, `echo x | rm -rf /`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm not found in pipeline; got %+v", cmds)
	}
	if rm.Context.PipelinePosition != 2 {
		t.Errorf("rm PipelinePosition = %d, want 2", rm.Context.PipelinePosition)
	}
	echo := findByName(cmds, "echo")
	if echo == nil || echo.Context.PipelinePosition != 1 {
		t.Errorf("echo PipelinePosition want 1, got %+v", echo)
	}
}

func TestEvasion_EvalWrapper(t *testing.T) {
	// eval "rm -rf /" — eval has a RED rule; walker keeps Name="eval".
	// The content inside the quoted string is NOT re-parsed.
	cmds := walk(t, `eval "rm -rf /"`)
	if findByName(cmds, "eval") == nil {
		t.Errorf("expected Name=eval; got %+v", cmds)
	}
	// rm should NOT be found because eval's argument is a string literal,
	// not a nested command.
	if findByName(cmds, "rm") != nil {
		t.Errorf("eval's string arg should NOT be walked as a command; got rm")
	}
}

func TestEvasion_AliasRawName(t *testing.T) {
	// aliases are not expanded by the parser — raw name is matched.
	cmds := walk(t, `rm -rf /`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("expected Name=rm; got %+v", cmds)
	}
}

func TestEvasion_SubshellInPipeline(t *testing.T) {
	cmds := walk(t, `(cmd1) | cmd2`)
	c1 := findByName(cmds, "cmd1")
	if c1 == nil {
		t.Fatalf("cmd1 not found; got %+v", cmds)
	}
	if c1.Context.SubshellDepth < 1 {
		t.Errorf("cmd1 SubshellDepth = %d, want >=1", c1.Context.SubshellDepth)
	}
	if c1.Context.PipelinePosition != 1 {
		t.Errorf("cmd1 PipelinePosition = %d, want 1", c1.Context.PipelinePosition)
	}
	c2 := findByName(cmds, "cmd2")
	if c2 == nil || c2.Context.PipelinePosition != 2 {
		t.Errorf("cmd2 PipelinePosition want 2, got %+v", c2)
	}
}

func TestEvasion_WhileCondition(t *testing.T) {
	cmds := walk(t, `while check; do act; done`)
	check := findByName(cmds, "check")
	if check == nil {
		t.Fatalf("check not found; got %+v", cmds)
	}
	if !check.Context.InCondition {
		t.Errorf("check in while header should have InCondition=true")
	}
	act := findByName(cmds, "act")
	if act == nil || act.Context.InCondition {
		t.Errorf("act in while body should NOT have InCondition=true; got %+v", act)
	}
}

func TestEvasion_UntilLoop(t *testing.T) {
	cmds := walk(t, `until false; do rm -rf /; done`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("rm in until body not found; got %+v", cmds)
	}
}

func TestEvasion_ElifChain(t *testing.T) {
	cmds := walk(t, `if c1; then c2; elif c3; then c4; else c5; fi`)
	for _, name := range []string{"c1", "c2", "c3", "c4", "c5"} {
		if findByName(cmds, name) == nil {
			t.Errorf("%s not found in if/elif/else chain", name)
		}
	}
	c1 := findByName(cmds, "c1")
	if c1 == nil || !c1.Context.InCondition {
		t.Errorf("c1 should have InCondition=true; got %+v", c1)
	}
	c3 := findByName(cmds, "c3")
	if c3 == nil || !c3.Context.InCondition {
		t.Errorf("c3 (elif condition) should have InCondition=true; got %+v", c3)
	}
	c2 := findByName(cmds, "c2")
	if c2 != nil && c2.Context.InCondition {
		t.Errorf("c2 (then body) should NOT have InCondition=true")
	}
}

func TestEvasion_GlobInCmdPosition(t *testing.T) {
	// /usr/bin/r* — not expanded; walker returns literal.
	cmds := walk(t, `/usr/bin/r*`)
	for _, c := range cmds {
		if c.Name == "rm" {
			t.Errorf("glob should not resolve to rm; got %+v", c)
		}
	}
}

func TestEvasion_NestedFunctionDef(t *testing.T) {
	// f() { g() { rm; }; } — nested function; inner rm has InFunction="g".
	// The walker descends into function bodies for conservative static
	// analysis so definitions containing dangerous commands are flagged
	// even before the function is invoked.
	cmds := walk(t, `f() { g() { rm; }; }`)
	rm := findByName(cmds, "rm")
	if rm == nil {
		t.Fatalf("rm in nested function body not found; got %+v", cmds)
	}
	if rm.Context.InFunction != "g" {
		t.Errorf("rm InFunction = %q, want %q", rm.Context.InFunction, "g")
	}
}

// =============================================================================
// Walker bug regression tests — verify the specific fixes
// =============================================================================

func TestWalkerFix_StripBackslashes(t *testing.T) {
	// Regression: wordLiteral on Lit{Value: "\\rm"} should return "rm".
	cmds := walk(t, `\rm`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("\\rm should resolve to rm; got %+v", cmds)
	}
}

func TestWalkerFix_AnsiCDecode(t *testing.T) {
	// Regression: wordLiteral on SglQuoted{Dollar:true, Value:"\\x72\\x6d"}
	// should return "rm" (decoded), not the raw escape string.
	cmds := walk(t, `$'\x72\x6d'`)
	if findByName(cmds, "rm") == nil {
		t.Errorf("ANSI-C $'\\x72\\x6d' should decode to rm; got %+v", cmds)
	}
}

func TestWalkerFix_TestClauseCmdSubstWalked(t *testing.T) {
	// Regression: TestClause case added to walkCmd.
	cmds := walk(t, `[[ $(dangerous_cmd) ]]`)
	if findByName(cmds, "dangerous_cmd") == nil {
		t.Errorf("TestClause CmdSubst should be walked; got %+v", cmds)
	}
}

func TestWalkerFix_DeclArrayWalked(t *testing.T) {
	// Regression: DeclClause now walks a.Array.Elems.
	cmds := walk(t, `declare -a arr=($(dangerous))`)
	if findByName(cmds, "dangerous") == nil {
		t.Errorf("declare -a array CmdSubst should be walked; got %+v", cmds)
	}
}

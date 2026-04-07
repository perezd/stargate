package parser

import (
	"strings"
	"testing"
)

// ---- Parse tests ----

func TestParseSimpleCommand(t *testing.T) {
	f, err := Parse("git status", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil AST")
	}
}

func TestParseInvalidCommand(t *testing.T) {
	_, err := Parse("echo 'unterminated", "bash")
	if err == nil {
		t.Fatal("expected error for unterminated quote, got nil")
	}
}

func TestParseDialects(t *testing.T) {
	tests := []struct {
		dialect string
		cmd     string
	}{
		{"bash", "echo hi"},
		{"posix", "echo hi"},
		{"mksh", "echo hi"},
		{"unknown", "echo hi"}, // should default to bash
	}
	for _, tt := range tests {
		t.Run(tt.dialect, func(t *testing.T) {
			f, err := Parse(tt.cmd, tt.dialect)
			if err != nil {
				t.Fatalf("Parse(%q, %q) error: %v", tt.cmd, tt.dialect, err)
			}
			if f == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}

// ---- Basic Walk tests ----

func TestWalkSimpleCommand(t *testing.T) {
	infos, err := ParseAndWalk("git status", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 command, got %d", len(infos))
	}
	if infos[0].Name != "git" {
		t.Errorf("expected name=git, got %q", infos[0].Name)
	}
	if infos[0].Subcommand != "status" {
		t.Errorf("expected subcommand=status, got %q", infos[0].Subcommand)
	}
}

func TestWalkMultipleArgs(t *testing.T) {
	infos, err := ParseAndWalk("ls -la /tmp", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 command, got %d", len(infos))
	}
	cmd := infos[0]
	if cmd.Name != "ls" {
		t.Errorf("expected name=ls, got %q", cmd.Name)
	}
	if len(cmd.Flags) != 1 || cmd.Flags[0] != "-la" {
		t.Errorf("expected flags=[-la], got %v", cmd.Flags)
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "/tmp" {
		t.Errorf("expected args=[/tmp], got %v", cmd.Args)
	}
}

func TestWalkPipeline(t *testing.T) {
	infos, err := ParseAndWalk("cat f | grep foo | wc -l", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(infos))
	}
	// Check names.
	names := []string{infos[0].Name, infos[1].Name, infos[2].Name}
	expected := []string{"cat", "grep", "wc"}
	for i, n := range expected {
		if names[i] != n {
			t.Errorf("stage %d: expected name=%q, got %q", i+1, n, names[i])
		}
	}
	// Check pipeline positions.
	for i, info := range infos {
		expectedPos := i + 1
		if info.Context.PipelinePosition != expectedPos {
			t.Errorf("stage %d: expected PipelinePosition=%d, got %d",
				i+1, expectedPos, info.Context.PipelinePosition)
		}
	}
}

func TestWalkLogicalOps(t *testing.T) {
	infos, err := ParseAndWalk("cmd1 && cmd2 || cmd3", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(infos))
	}
	names := []string{"cmd1", "cmd2", "cmd3"}
	for i, info := range infos {
		if info.Name != names[i] {
			t.Errorf("index %d: expected name=%q, got %q", i, names[i], info.Name)
		}
	}
}

func TestWalkSemicolon(t *testing.T) {
	infos, err := ParseAndWalk("cmd1; cmd2", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(infos))
	}
	if infos[0].Name != "cmd1" {
		t.Errorf("expected cmd1, got %q", infos[0].Name)
	}
	if infos[1].Name != "cmd2" {
		t.Errorf("expected cmd2, got %q", infos[1].Name)
	}
}

// ---- Flag extraction ----

func TestWalkFlagExtraction(t *testing.T) {
	infos, err := ParseAndWalk("rm -rf /tmp", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 command, got %d", len(infos))
	}
	cmd := infos[0]
	if cmd.Name != "rm" {
		t.Errorf("expected name=rm, got %q", cmd.Name)
	}
	if len(cmd.Flags) != 1 || cmd.Flags[0] != "-rf" {
		t.Errorf("expected flags=[-rf], got %v", cmd.Flags)
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "/tmp" {
		t.Errorf("expected args=[/tmp], got %v", cmd.Args)
	}
}

func TestWalkLongFlags(t *testing.T) {
	infos, err := ParseAndWalk("curl --silent --output f url", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 command, got %d", len(infos))
	}
	cmd := infos[0]
	if cmd.Name != "curl" {
		t.Errorf("expected name=curl, got %q", cmd.Name)
	}
	if len(cmd.Flags) != 2 {
		t.Errorf("expected 2 flags, got %v", cmd.Flags)
	} else {
		if cmd.Flags[0] != "--silent" {
			t.Errorf("expected --silent, got %q", cmd.Flags[0])
		}
		if cmd.Flags[1] != "--output" {
			t.Errorf("expected --output, got %q", cmd.Flags[1])
		}
	}
}

// ---- Environment variables ----

func TestWalkInlineEnv(t *testing.T) {
	infos, err := ParseAndWalk("FOO=bar BAZ=qux cmd", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 command, got %d", len(infos))
	}
	cmd := infos[0]
	if cmd.Name != "cmd" {
		t.Errorf("expected name=cmd, got %q", cmd.Name)
	}
	if cmd.Env["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", cmd.Env["FOO"])
	}
	if cmd.Env["BAZ"] != "qux" {
		t.Errorf("expected BAZ=qux, got %q", cmd.Env["BAZ"])
	}
}

// ---- Prefix stripping ----

func TestWalkPrefixStripping(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantFlags   []string
		wantArgs    []string
	}{
		{
			name:     "command builtin",
			input:    "command rm -rf /",
			wantName: "rm",
			wantFlags: []string{"-rf"},
			wantArgs:  []string{"/"},
		},
		{
			name:     "env prefix",
			input:    "env ls -la",
			wantName: "ls",
			wantFlags: []string{"-la"},
		},
		{
			name:     "sudo prefix",
			input:    "sudo rm -rf /",
			wantName: "rm",
			wantFlags: []string{"-rf"},
			wantArgs:  []string{"/"},
		},
		{
			name:     "nice with -n",
			input:    "nice -n 19 ls",
			wantName: "ls",
		},
		{
			name:     "nohup",
			input:    "nohup cmd",
			wantName: "cmd",
		},
		{
			name:     "timeout with duration",
			input:    "timeout 5 curl http://example.com",
			wantName: "curl",
			wantArgs: []string{"http://example.com"},
		},
		{
			name:     "nested sudo env nice",
			input:    "sudo env nice rm -f /tmp/x",
			wantName: "rm",
			wantFlags: []string{"-f"},
			wantArgs:  []string{"/tmp/x"},
		},
		{
			name:     "builtin prefix",
			input:    "builtin echo hello",
			wantName: "echo",
			wantArgs: []string{"hello"},
		},
		{
			name:     "strace prefix",
			input:    "strace ls",
			wantName: "ls",
		},
		{
			name:     "watch prefix",
			input:    "watch df -h",
			wantName: "df",
			wantFlags: []string{"-h"},
		},
		{
			name:     "doas prefix",
			input:    "doas rm /etc/passwd",
			wantName: "rm",
			wantArgs: []string{"/etc/passwd"},
		},
		{
			name:     "time prefix",
			input:    "time make all",
			wantName: "make",
			wantArgs: []string{"all"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos, err := ParseAndWalk(tt.input, "bash")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// The walker extracts one CommandInfo per CallExpr using the resolved command name, so infos[0] is the command under test.
			if len(infos) == 0 {
				t.Fatalf("expected at least 1 command, got 0")
			}
			cmd := infos[0]
			if cmd.Name != tt.wantName {
				t.Errorf("expected name=%q, got %q", tt.wantName, cmd.Name)
			}
			for _, wf := range tt.wantFlags {
				found := false
				for _, f := range cmd.Flags {
					if f == wf {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected flag %q in %v", wf, cmd.Flags)
				}
			}
			for _, wa := range tt.wantArgs {
				found := false
				for _, a := range cmd.Args {
					if a == wa {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected arg %q in %v", wa, cmd.Args)
				}
			}
		})
	}
}

func TestWalkPrefixDepthLimit(t *testing.T) {
	// Build 20 nested "command " prefixes.
	input := strings.Repeat("command ", 20) + "rm"
	infos, err := ParseAndWalk(input, "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 result")
	}
	// Should be unresolvable (empty name) due to depth limit.
	if infos[0].Name != "" {
		t.Errorf("expected empty Name (depth limit exceeded), got %q", infos[0].Name)
	}
}

// ---- Evasion detection ----

func TestWalkUnresolvableVar(t *testing.T) {
	infos, err := ParseAndWalk("$CMD arg", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if infos[0].Name != "" {
		t.Errorf("expected empty Name for variable command, got %q", infos[0].Name)
	}
}

func TestWalkBraceExpansion(t *testing.T) {
	// Brace expansion like {rm,-rf,/} — the shell parses this as a Lit with
	// braces. We detect it as an evasion.
	infos, err := ParseAndWalk("{rm,-rf,/}", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if infos[0].Name != "" {
		t.Errorf("expected empty Name for brace expansion command, got %q", infos[0].Name)
	}
}

func TestWalkCommandSubstitution(t *testing.T) {
	// $(echo rm) as command name → unresolvable outer command.
	infos, err := ParseAndWalk("$(echo rm) arg", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 result")
	}
	// The outer command should be unresolvable.
	if infos[0].Name != "" {
		t.Errorf("expected empty Name for substitution command, got %q", infos[0].Name)
	}
}

func TestWalkNestedSubstitution(t *testing.T) {
	// echo $(rm -rf /) — should find both "echo" and "rm" inside $().
	infos, err := ParseAndWalk("echo $(rm -rf /)", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) < 2 {
		t.Fatalf("expected at least 2 commands (echo + rm), got %d", len(infos))
	}
	names := make(map[string]bool)
	for _, info := range infos {
		names[info.Name] = true
	}
	if !names["echo"] {
		t.Errorf("expected to find 'echo' command, got %v", names)
	}
	if !names["rm"] {
		t.Errorf("expected to find 'rm' command inside substitution, got %v", names)
	}
	// The rm command should be marked as in substitution.
	for _, info := range infos {
		if info.Name == "rm" && !info.Context.InSubstitution {
			t.Errorf("expected rm to have InSubstitution=true")
		}
	}
}

// ---- Quoting evasion ----

func TestWalkQuotingEvasion(t *testing.T) {
	// 'rm' -rf / — single quotes around the command name, parser resolves it.
	infos, err := ParseAndWalk("'rm' -rf /", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if infos[0].Name != "rm" {
		t.Errorf("expected name=rm (quotes resolved), got %q", infos[0].Name)
	}
}

// ---- Subshell ----

func TestWalkSubshell(t *testing.T) {
	infos, err := ParseAndWalk("(cmd1; cmd2)", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(infos))
	}
	for i, info := range infos {
		if info.Context.SubshellDepth != 1 {
			t.Errorf("command %d: expected SubshellDepth=1, got %d", i, info.Context.SubshellDepth)
		}
	}
}

func TestWalkNestedSubshell(t *testing.T) {
	// Note: ((cmd)) is arithmetic syntax in bash; use "( (cmd) )" for nested subshells.
	infos, err := ParseAndWalk("( (cmd) )", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	// The inner command should have SubshellDepth=2.
	found := false
	for _, info := range infos {
		if info.Name == "cmd" && info.Context.SubshellDepth == 2 {
			found = true
		}
	}
	if !found {
		depths := make([]int, len(infos))
		for i, info := range infos {
			depths[i] = info.Context.SubshellDepth
		}
		t.Errorf("expected cmd with SubshellDepth=2, got depths=%v names=%v",
			depths, func() []string {
				ns := make([]string, len(infos))
				for i, info := range infos {
					ns[i] = info.Name
				}
				return ns
			}())
	}
}

// ---- Redirections ----

func TestWalkRedirects(t *testing.T) {
	infos, err := ParseAndWalk("echo foo > out.txt 2>/dev/null", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	cmd := infos[0]
	if cmd.Name != "echo" {
		t.Errorf("expected name=echo, got %q", cmd.Name)
	}
	if len(cmd.Redirects) != 2 {
		t.Fatalf("expected 2 redirects, got %d: %+v", len(cmd.Redirects), cmd.Redirects)
	}
	// Check that we have a stdout redirect and a stderr redirect.
	ops := make(map[string]bool)
	for _, r := range cmd.Redirects {
		ops[r.Op] = true
	}
	if !ops[">"] {
		t.Errorf("expected '>' redirect, got %v", cmd.Redirects)
	}
	if !ops["2>"] {
		t.Errorf("expected '2>' redirect, got %v", cmd.Redirects)
	}
}

func TestWalkRedirectsNotAttachedToSubstitutionCommands(t *testing.T) {
	// echo $(cat file) > out.txt — the redirect belongs to echo, not cat.
	infos, err := ParseAndWalk("echo $(cat file) > out.txt", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Expect two commands: echo and cat (inside $()).
	if len(infos) < 2 {
		t.Fatalf("expected at least 2 commands (echo + cat), got %d", len(infos))
	}
	echoIdx, catIdx := -1, -1
	for i, info := range infos {
		switch info.Name {
		case "echo":
			echoIdx = i
		case "cat":
			catIdx = i
		}
	}
	if echoIdx < 0 {
		t.Fatal("expected to find 'echo' command")
	}
	if catIdx < 0 {
		t.Fatal("expected to find 'cat' command inside substitution")
	}
	if len(infos[echoIdx].Redirects) != 1 {
		t.Errorf("echo: expected 1 redirect, got %d: %+v", len(infos[echoIdx].Redirects), infos[echoIdx].Redirects)
	}
	if len(infos[catIdx].Redirects) != 0 {
		t.Errorf("cat: expected 0 redirects (redirect should not propagate into $()), got %d: %+v",
			len(infos[catIdx].Redirects), infos[catIdx].Redirects)
	}
}

// ---- End of options ----

func TestWalkEndOfOptions(t *testing.T) {
	// "git -- status" → status is a positional arg after --, NOT a subcommand.
	infos, err := ParseAndWalk("git -- status", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	cmd := infos[0]
	if cmd.Name != "git" {
		t.Errorf("expected name=git, got %q", cmd.Name)
	}
	if cmd.Subcommand != "" {
		t.Errorf("expected empty subcommand (status is after --), got %q", cmd.Subcommand)
	}
	// status should be in positional args.
	found := false
	for _, a := range cmd.Args {
		if a == "status" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'status' in args, got %v", cmd.Args)
	}
}

// ---- Function definitions ----

func TestWalkFunctionBody(t *testing.T) {
	// f() { rm -rf /; } → finds "rm" inside function body with InFunction="f".
	infos, err := ParseAndWalk("f() { rm -rf /; }", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	found := false
	for _, info := range infos {
		if info.Name == "rm" {
			found = true
			if info.Context.InFunction != "f" {
				t.Errorf("expected InFunction=f, got %q", info.Context.InFunction)
			}
		}
	}
	if !found {
		t.Errorf("expected to find 'rm' command inside function body")
	}
}

func TestWalkInCondition(t *testing.T) {
	// if cmd1; then cmd2; fi — cmd1 is in the condition, cmd2 is in the body.
	infos, err := ParseAndWalk("if cmd1; then cmd2; fi", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(infos))
	}
	cmd1idx, cmd2idx := -1, -1
	for i, info := range infos {
		switch info.Name {
		case "cmd1":
			cmd1idx = i
		case "cmd2":
			cmd2idx = i
		}
	}
	if cmd1idx < 0 {
		t.Fatal("expected to find 'cmd1'")
	}
	if cmd2idx < 0 {
		t.Fatal("expected to find 'cmd2'")
	}
	if !infos[cmd1idx].Context.InCondition {
		t.Errorf("cmd1: expected InCondition=true (it's in the if condition), got false")
	}
	if infos[cmd2idx].Context.InCondition {
		t.Errorf("cmd2: expected InCondition=false (it's in the then body), got true")
	}
}

// ---- ParseAndWalk convenience ----

func TestParseAndWalkReturnsError(t *testing.T) {
	_, err := ParseAndWalk("echo 'unterminated", "bash")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---- RawNode ----

func TestWalkRawNodeSet(t *testing.T) {
	infos, err := ParseAndWalk("ls -la", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	if infos[0].RawNode == nil {
		t.Error("expected RawNode to be set, got nil")
	}
}

// ---- env prefix with flags ----

func TestWalkEnvPrefixWithFlags(t *testing.T) {
	// env -i FOO=bar ls → strips -i and FOO=bar, finds ls.
	infos, err := ParseAndWalk("env -i FOO=bar ls", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	if infos[0].Name != "ls" {
		t.Errorf("expected name=ls after env flags, got %q", infos[0].Name)
	}
}

func TestWalkGlobalFlagArgsNotInArgs(t *testing.T) {
	// "git -C /tmp status" — /tmp is consumed by -C, should not appear in Args.
	infos, err := ParseAndWalk("git -C /tmp status", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	for _, arg := range infos[0].Args {
		if arg == "/tmp" {
			t.Error("global flag argument /tmp should not appear in Args")
		}
	}
}

func TestWalkTimeoutWithKillFlag(t *testing.T) {
	// "timeout -k 5s 10s cmd" — -k consumes 5s, 10s is the duration, cmd is the command.
	infos, err := ParseAndWalk("timeout -k 5s 10s cmd", "bash")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("expected at least 1 command")
	}
	if infos[0].Name != "cmd" {
		t.Errorf("expected name=cmd, got %q", infos[0].Name)
	}
}

func TestWalkSubcommandGlobalFlagSkipping(t *testing.T) {
	tests := []struct {
		cmd     string
		wantSub string
	}{
		{"git -C /tmp status", "status"},
		{"git --no-pager log", "log"},
		{"git --git-dir=/tmp/.git status", "status"},
		{"docker --context remote ps", "ps"},
		{"docker -H unix:///var/run/docker.sock ps", "ps"},
		{"gh --repo owner/repo pr list", "pr"},
		{"gh -R owner/repo issue create", "issue"},
		{"kubectl --namespace kube-system get pods", "get"},
		{"kubectl -n default describe pod foo", "describe"},
		{"git -- status", ""},           // -- terminates: status is arg, not subcmd
		{"git -C /tmp -- status", ""},   // -- after global flag
		{"ls -la /tmp", "/tmp"},         // no global flag map; first positional (/tmp) becomes subcommand (rule engine ignores it for commands without subcommand rules)
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			infos, err := ParseAndWalk(tc.cmd, "bash")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(infos) == 0 {
				t.Fatal("expected at least 1 command")
			}
			if infos[0].Subcommand != tc.wantSub {
				t.Errorf("subcommand = %q, want %q", infos[0].Subcommand, tc.wantSub)
			}
		})
	}
}

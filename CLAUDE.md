# Stargate

## Security Framework

Stargate is a security-critical component — it sits in the trust path between an AI coding agent and shell execution. Every change must be evaluated against its security layers.

| Layer | Defense | Protects Against | Key Paths |
|-------|---------|------------------|-----------|
| **AST Parsing** | Full shell AST via `mvdan.cc/sh/v3`, fail-closed on parse errors, depth/length limits | Command obfuscation, quoting evasion, injection via substitution/expansion | `internal/parser/` |
| **Rule Engine** | TOML-defined RED/GREEN/YELLOW rules, priority-ordered evaluation, scope-bound matching via resolvers | Dangerous command execution, unauthorized resource access | `internal/rules/`, `internal/scopes/` |
| **Contextual Trust** | Operator-defined scopes in `stargate.toml` (outside repo), resolvers that validate targets against scopes, `.git/config` treated as untrusted claim | Scope bypass via malicious git config, prompt injection adding remotes, traversal in API paths | `internal/scopes/`, `stargate.toml` |
| **LLM Review** | Provider-agnostic LLM classification for ambiguous commands, precedent corpus injection, file retrieval with path validation | False negatives from rule gaps, novel attack patterns | `internal/llm/`, `internal/corpus/` |

**Defense-in-depth:** No single layer is sufficient alone. If you weaken one layer, you must add compensating controls in another. The rule engine works even if the LLM is unavailable. Scopes work even if the rule engine has gaps. The parser catches evasion even if rules are too permissive.

**Trust boundaries:**
- `stargate.toml` is the root trust anchor. It lives outside any repo and cannot be modified by repo contents, prompt injection, or `.git/config` manipulation.
- `.git/config` is untrusted input — read but never trusted. Resolver values are validated against scopes.
- The LLM reviewer receives scopes as read-only context, never as instructions to modify them.
- `stargate` listens only on `127.0.0.1`. The trust boundary is the local machine.

---

## Modification Protocol

### Milestone Transition Protocol

After merging a significant PR (typically a milestone), perform a design verification pass before starting the next milestone:

1. **Retrospective** — Document what was underspecified, what drove review feedback, and what edge cases were discovered during implementation. Add a retrospective note to the implementation plan.
2. **Spec hardening** — Update the design spec with lessons learned: edge case matrices, explicit design decisions, known limitations. The spec should be enriched with implementation knowledge so future milestones benefit.
3. **Panel review of next milestone's design** — Before writing implementation code, enumerate the edge cases for the next milestone's component and run the expert panel against the spec section. Resolve all findings in the spec before starting implementation.
4. **Design verification in the plan** — If the panel surfaced decisions (e.g., "how should flag normalization work?"), record them explicitly in the spec and plan. Don't discover design decisions through code review — discover them through design review.

This protocol exists because M1 (Parser + Walker) demonstrated that underspecified design leads to long review tails (84 threads, 20 rounds). The cost of a 30-minute design verification pass is much lower than 20 rounds of implementation-time discovery.

### PR Review Loop Protocol

After a PR is created and pushed, run an automated review loop:

0. **Request initial Copilot review** immediately after creating the PR:
   ```bash
   gh api repos/{owner}/{repo}/pulls/{N}/requested_reviewers -X POST -f 'reviewers[]=copilot-pull-request-reviewer[bot]'
   ```

1. **Poll for review feedback** — run an inline polling loop as a background Bash command. Each PR gets its own independent background poller (multiple PRs can poll simultaneously). Replace `{N}` with the PR number:
   ```
   Bash(run_in_background=true, timeout=2100000, command="for i in $(seq 1 6); do echo \"Poll $i/6 at $(date)\"; UNRESOLVED=$(gh api graphql -f query='{ repository(owner: \"{owner}\", name: \"{repo}\") { pullRequest(number: {N}) { reviewThreads(last: 50) { nodes { id isResolved } } } } }' --jq '[.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved == false)] | length'); COPILOT=$(gh api repos/{owner}/{repo}/pulls/{N}/reviews --paginate --jq '[.[] | select(.user.login | test(\"copilot\"))] | last | .body // \"\"'); [ \"$UNRESOLVED\" -gt 0 ] 2>/dev/null && echo \"FOUND: $UNRESOLVED unresolved threads\" && exit 0; echo \"$COPILOT\" | grep -q 'generated no new comments' && echo 'TERMINAL: Copilot reports no new comments' && exit 0; echo \"No findings (unresolved=$UNRESOLVED)\"; [ $i -lt 6 ] && sleep 300; done; echo 'TIMEOUT: No reviews after 6 polls'")
   ```
   Note: `reviewThreads(last: 50)` does not paginate via `--paginate` for GraphQL. This is sufficient because threads are resolved each round and never accumulate past 50. The loop performs 6 polls with 5 sleeps (~25min of sleeping plus API call time); the timeout (2,100,000ms = 35min) provides wall-clock buffer.
   Do NOT use subagents for polling — they can't get bash permission approval in background mode.

2. **When unresolved threads are found**, the main agent:
   - Reads ALL findings (use `--paginate` on all `gh api` list endpoints — reviews, comments, threads)
   - Applies the `receiving-code-review` skill: evaluate each finding against the codebase, push back with technical reasoning where appropriate, fix what's valid
   - Dispatches subagents for implementation fixes if needed
   - Runs a self-review before pushing (go test, go vet, check for related issues in the same category)
   - Pushes the branch
   - Replies to and resolves each review thread via the GitHub API
   - Re-requests Copilot review: `gh api repos/{owner}/{repo}/pulls/{N}/requested_reviewers -X POST -f 'reviewers[]=copilot-pull-request-reviewer[bot]'`

3. **Re-launch the background poller** — return to step 1 with a new background Bash command.

4. **Terminal state:** Copilot's review says "generated no new comments" AND 0 unresolved threads → halt and await instructions.

**Critical:** Always use `--paginate` on GitHub API list endpoints. Without it, reviews beyond the first page (30 items) are silently missed.

### Layer-Impact Assessment

Before every modification, explicitly state:

1. Which security layers are affected (or "none").
2. Why — a brief justification, not just a label.
3. Whether a full panel review is triggered.

### Panel Review

A full synthetic panel review is required for: changes to any security-layer code (see key paths above), new resolvers, rule engine logic changes, LLM prompt modifications, scope validation changes, precedent corpus schema changes, adapter protocol changes, and new designs or specifications.

**Core panel (always present):**

1. **Application security specialist** — evaluates command classification correctness, evasion resistance, fail-closed behavior
2. **Offensive security / red team analyst** — attempts to bypass classification via obfuscation, injection, scope manipulation, prompt injection
3. **Systems engineer** — evaluates Go implementation correctness, concurrency safety, resource management, error handling
4. **Compliance and risk management advisor** — evaluates trust model coherence, data handling (command logging, secrets in args), audit trail completeness

**Flex specialists (add based on change scope):**

- **Shell internals expert** — parser changes, AST walking, new evasion mitigations
- **LLM security specialist** — prompt injection resistance, LLM response validation, file retrieval path safety
- **Observability engineer** — OTel instrumentation, trace propagation, metric cardinality, Grafana Cloud integration
- **Supply chain security specialist** — new dependencies, Go module changes, build pipeline
- **API design specialist** — `/classify` and `/feedback` protocol changes, adapter interface changes

Select relevant flex specialists based on the nature of the change.

### Security Design Checklist

Before the panel convenes, the design must explicitly address each of the following. Responses must cite **specific artifacts** — file paths, code locations, data sources, and actor identities. "N/A" requires a one-line justification.

- **Trust anchor mutability:** Is any data source this design relies on writable at runtime? By whom? Through what mechanisms (file edit, command, env var, config include, `.git/config` manipulation, prompt injection)? Scopes must only come from `stargate.toml` — never from repo contents.
- **Fail mode:** When this component errors, does the system fail-open or fail-closed? Is that the right default for this security context? Parse errors, resolver failures, LLM timeouts, and config errors must all fail toward the more restrictive classification.
- **Evasion surface:** Could this change be circumvented by command obfuscation (quoting, escaping, variable indirection, command substitution, unicode homoglyphs)? Does the parser resolve the evasion before the rule engine sees it? If not, what catches it?
- **Scope boundary integrity:** Does this change affect how resolved values are validated against scopes? Could a crafted input cause a resolver to return a value that incorrectly matches a trusted scope pattern (e.g., glob injection, path traversal in API paths)?
- **LLM prompt safety:** Does this change modify what the LLM sees? Could an attacker influence the prompt contents through command arguments, file contents, or git config to manipulate the LLM's classification decision?
- **File retrieval safety:** If this change involves file reading (LLM file retrieval, config loading, resolver inference), are paths validated against `allowed_paths`/`denied_paths`? Could symlinks, relative paths, or race conditions expose files outside the intended boundary?
- **Sensitive data exposure:** Could this change cause credentials, tokens, or secrets to appear in logs, telemetry, the precedent corpus, HTTP responses, or LLM prompts? Trace the origin of every value written to external outputs.
- **Allowlist vs blocklist:** Does this design enumerate known-good values (allowlist) or known-bad values (blocklist)? If blocklist, what happens when a new value is introduced? Stargate's design philosophy favors allowlists — GREEN rules enumerate safe commands, RED rules enumerate dangerous patterns, and the default is YELLOW (fail-closed for unknowns).
- **Layer compensation:** Does this change weaken any security layer? If so, what compensating control exists in another layer? Describe the specific attack path and how the compensating control blocks it.

**Process:**

Each expert **MUST** run as a separate subagent with a cleared context. Provide each expert with the design/spec documents and any relevant diffs for review.

0. Verify the design author has completed the Security Design Checklist with specific, justified responses. If incomplete, return for revision before proceeding.
1. Each expert evaluates the change from their perspective.
2. Findings are ranked by severity: critical / high / medium / low.
3. Each delivers a verdict: **approve**, **approve-with-conditions**, or **request-changes**.
4. If any expert raises concerns, address them and re-run the panel.
5. Iterate until all experts sign off without concerns.
6. Unresolvable risks go to `docs/accepted-risks.md`.

The panel is not a rubber stamp. Genuinely reason from each expert's perspective and challenge assumptions across rounds.

---

## Project Reference

### Language and Toolchain

- Go (latest stable)
- `CGO_ENABLED=0` for static binaries
- `go test ./...` for all tests
- `go vet ./...` for static analysis

### Key Dependencies

| Module | Purpose |
|--------|---------|
| `mvdan.cc/sh/v3` | Shell parser and AST |
| `github.com/anthropics/anthropic-sdk-go` | Anthropic/Claude LLM provider |
| `github.com/BurntSushi/toml` | TOML config parsing |
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO) |
| `go.opentelemetry.io/otel` | OpenTelemetry SDK |

### Directory Map

- `cmd/stargate/` — CLI entry point, subcommand dispatch
- `internal/config/` — TOML parsing, validation, hot-reload
- `internal/parser/` — Shell parsing, AST walking, CommandInfo extraction
- `internal/rules/` — Rule compilation and matching
- `internal/scopes/` — Scope definitions, resolver interface, built-in resolvers
- `internal/llm/` — Provider interface, Anthropic implementation, prompt templating, file retrieval
- `internal/classifier/` — Pipeline orchestration (parse -> rules -> corpus -> LLM)
- `internal/corpus/` — SQLite precedent corpus, structural signatures, similarity search
- `internal/telemetry/` — OTel SDK init, logs, metrics, traces
- `internal/adapter/` — Agent-specific hook adapters (Claude Code, etc.)
- `internal/server/` — HTTP handlers (/classify, /feedback, /health, /reload, /test)
- `internal/feedback/` — Feedback processing, trace correlation, corpus update
- `stargate.toml` — Example/default config

### Conventional Commits

All commit messages follow the conventional commits standard:

- Format: `type(scope): description`
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`
- Scope references the affected component:
  - `feat(scopes): add kubernetes context resolver`
  - `fix(parser): handle ANSI-C quoting in variable names`
  - `refactor(llm): extract provider interface`
  - `test(corpus): add similarity scoring edge cases`
- Describe the "why" not just the "what."

### License

Apache-2.0

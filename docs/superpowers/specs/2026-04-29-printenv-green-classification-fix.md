# Fix: printenv GREEN Classification Leaks Environment Secrets

**Issue:** [#35](https://github.com/limbic-systems/stargate/issues/35)
**Date:** 2026-04-29

## Problem

`printenv` is classified as GREEN (always allow) in both `cmd/stargate/default-stargate.toml` and `stargate.toml`, grouped with read-only system info commands (`date`, `cal`, `uname`, `hostname`, `id`, `whoami`).

Unlike those commands, `printenv` (and `env` without arguments) dumps **all environment variables**, including high-value secrets:

- `GH_PAT` / `GH_TOKEN` (GitHub personal access tokens)
- `CLAUDE_CODE_OAUTH_TOKEN` (Claude Code auth)
- `FLY_ACCESS_TOKEN` (Fly.io API)
- `ANTHROPIC_API_KEY`
- `STARGATE_OTEL_USERNAME` / `STARGATE_OTEL_PASSWORD` (Grafana credentials)

Since GREEN means auto-allow with no review, the agent can run `printenv` at any time and all secrets enter the conversation context. The scrubbing layer's `extra_patterns` catch some formats (`ghp_*`, `sk-ant-*`) but not all — OAuth tokens and Fly access tokens lack recognizable prefixes.

**Additional finding:** `env` is GREEN in `stargate.toml` (line 190) despite being correctly classified as YELLOW with `llm_review = true` in `default-stargate.toml` (line 460). This is the same vulnerability.

## Affected Security Layers

| Layer | Affected? | Justification |
|-------|-----------|---------------|
| AST Parsing | No | No parser changes |
| Rule Engine | **Yes** — config change | Moving commands between classification tiers |
| Contextual Trust | No | No scope or resolver changes |
| LLM Review | **Indirectly** | `printenv` will now reach LLM review when classified YELLOW |

## Design

### Approach

Move `printenv` and `env` from GREEN to explicit YELLOW rules with `llm_review = true`. This is consistent with how `env` is already handled in `default-stargate.toml` and provides the right security posture:

- **Bare `printenv` / `env`** (dumps all vars): LLM review flags this as risky and prompts the user.
- **`printenv VAR_NAME`** (targeted lookup): LLM review evaluates whether the specific variable is sensitive, allowing legitimate use with low friction.

### Changes

#### 1. `cmd/stargate/default-stargate.toml`

**Remove `printenv` from GREEN system-info rule (line 297):**

```toml
# Before:
[[rules.green]]
commands = ["date", "cal", "printenv", "uname", "hostname", "id", "whoami"]
reason = "System info queries (read-only)."

# After:
[[rules.green]]
commands = ["date", "cal", "uname", "hostname", "id", "whoami"]
reason = "System info queries (read-only)."
```

**Add YELLOW rule for `printenv` near the existing `env` YELLOW rule (after line 462):**

```toml
[[rules.yellow]]
command = "printenv"
llm_review = true
reason = "printenv reveals environment variable values and can expose secrets; the no-argument form is especially risky as it dumps the full environment."
```

#### 2. `stargate.toml`

**Remove both `env` and `printenv` from GREEN system-info rule (line 190):**

```toml
# Before:
[[rules.green]]
commands = ["date", "cal", "env", "printenv", "uname", "hostname", "id", "whoami"]
reason = "System info queries."

# After:
[[rules.green]]
commands = ["date", "cal", "uname", "hostname", "id", "whoami"]
reason = "System info queries (read-only)."
```

**Add YELLOW rules for both `printenv` and `env`:**

```toml
[[rules.yellow]]
command = "env"
llm_review = true
reason = "Bare env prints environment variables and may expose secrets (tokens, API keys, credentials)."

[[rules.yellow]]
command = "printenv"
llm_review = true
reason = "printenv reveals environment variable values and can expose secrets; the no-argument form is especially risky as it dumps the full environment."
```

Note: `env` is a registered wrapper — the parser strips it when an inner command follows (e.g., `env FOO=bar cmd` resolves to `cmd`). This rule only fires for bare `env` (no inner command), so the reason text accurately describes the gated behavior.

#### 3. Test

Add a test in `internal/rules/` that verifies:

- `printenv` (bare) classifies as YELLOW with `llm_review = true`
- `printenv HOME` (with args) classifies as YELLOW with `llm_review = true`
- `env` (bare) classifies as YELLOW with `llm_review = true`
- `env VAR=val cmd` classifies as YELLOW with `llm_review = true`
- Remaining system-info commands (`date`, `cal`, `uname`, `hostname`, `id`, `whoami`) remain GREEN (regression guard)
- Compound command `printenv | grep TOKEN` is not classified as GREEN (pipeline where `printenv` is not GREEN prevents all-green result)

### Alternatives Considered

| Option | Description | Why Not |
|--------|-------------|---------|
| RED for bare + YELLOW for targeted (issue Option 4) | `pattern` regex to block bare `printenv`, allow `printenv VAR` as YELLOW | `pattern` matches the full raw command string, making it fragile for pipelines and compound commands. `env` with assignment syntax (`env FOO=bar cmd`) would be incorrectly blocked. Adds complexity without proportional benefit since LLM review handles the distinction well. |
| Implicit YELLOW via default (issue Option 1 variant) | Just remove from GREEN, rely on default YELLOW | No explicit documentation of WHY these commands need review. Future maintainers would lack context. |
| Add scrubbing patterns (issue Option 3) | Keep GREEN, add regex patterns for remaining secret formats | Doesn't prevent secrets from entering conversation context — only redacts from LLM prompts and corpus. Incomplete by design since new secret formats won't match. |

### Security Design Checklist

- **Trust anchor mutability:** No change. `stargate.toml` remains the trust anchor. This change only modifies which tier commands are classified into within existing config files.
- **Fail mode:** Improved. `printenv` and `env` now fail toward review (YELLOW) rather than auto-allow (GREEN). If the LLM is unavailable, the default YELLOW behavior prompts the user, which is the correct fail-closed posture.
- **Evasion surface:** The rule engine matches on the resolved command name from the AST, not raw text. Obfuscation attempts (quoting, variable indirection, ANSI-C quoting) are resolved by the parser before the rule engine sees them. **Known limitation:** The parser does not strip directory prefixes — `/usr/bin/printenv` produces `Name: "/usr/bin/printenv"`, which won't match a rule for `"printenv"`. This is a pre-existing issue affecting all rules system-wide (e.g., `/usr/bin/rm` also bypasses RED rules). It should be addressed as a separate parser-level fix (basename normalization) rather than in this config-only change. See Residual Risks below.
- **Scope boundary integrity:** No change. No resolvers or scopes are involved in this fix.
- **LLM prompt safety:** No change to prompt templates. `printenv` commands will now appear in LLM review prompts, but command arguments are already part of the standard prompt — no new injection surface.
- **File retrieval safety:** N/A. No file reading involved.
- **Sensitive data exposure:** This fix **reduces** exposure. Currently, `printenv` output (containing secrets) enters the conversation freely. After the fix, the LLM reviews the command first. **Residual risk:** if the LLM approves the command (e.g., for legitimate debugging), secrets still enter the conversation context, corpus, and telemetry. This is a review gate, not a prevention control. Tokens without recognizable prefixes (OAuth, Fly access tokens) also bypass the scrubbing layer's `extra_patterns`. See Residual Risks below.
- **Allowlist vs blocklist:** Maintains the allowlist philosophy. GREEN explicitly enumerates safe commands. Removing `printenv` and `env` from that allowlist means they fall to the review tier, consistent with the principle that unknowns default to YELLOW.
- **Layer compensation:** No layer is weakened. The rule engine layer is strengthened by reclassifying these commands to a more appropriate tier.

## Residual Risks

These are known limitations that are **not addressed by this fix** because they are either pre-existing systemic issues or fundamentally difficult to solve without unacceptable friction. Each should be tracked as a separate follow-up issue.

### 1. Absolute-path bypass (pre-existing, systemic)

`/usr/bin/printenv` bypasses the YELLOW rule because the parser does not strip directory prefixes from command names. The rule engine performs exact string matching, so `"/usr/bin/printenv" != "printenv"`. This affects ALL rules system-wide — not just `printenv`. Fix: add basename normalization in `resolveCommand` or `matchRule`. Severity: HIGH (but pre-existing and out of scope for this config change).

### 2. Alternative env-dumping commands (pre-existing)

Several GREEN commands can leak environment variables through indirect means:

- `echo $SECRET_VAR` / `printf '%s\n' $SECRET_VAR` — shell expansion occurs before Stargate sees output. `echo` and `printf` are GREEN.
- `cat /proc/self/environ` — dumps all env vars as null-separated pairs. `cat` is GREEN.
- `grep KEY /proc/self/environ` — targeted extraction. `grep` is GREEN.

These are fundamentally harder to fix because making `echo`, `cat`, or `grep` YELLOW would cause massive friction for legitimate use. The scrubbing layer provides partial mitigation for secrets with recognizable prefixes.

### 3. Post-approval secret exposure

YELLOW with LLM review is a **review gate**, not a **prevention control**. If the LLM approves a `printenv` invocation (e.g., for legitimate debugging), all secrets enter the conversation context, the precedent corpus, and telemetry. Tokens without recognizable prefixes (OAuth, Fly access tokens) bypass the scrubbing layer's `extra_patterns`.

### 4. Historical corpus contamination

Pre-fix GREEN approvals of `printenv` in the precedent corpus may influence future LLM decisions toward approval. Mitigated by corpus `max_age` expiry.

## Panel Review

### Experts Consulted

| Expert | Verdict | Key Findings |
|--------|---------|-------------|
| Application Security | Approve | `env` execution risk noted; `bash -c printenv` pre-existing; no corpus entry for LLM guidance |
| Red Team | Approve-with-conditions | `echo $VAR`, `cat /proc/self/environ` bypass vectors (pre-existing); `go env` leaks Go-relevant vars |
| Systems Engineer | Approve | Harmonize `env` reason text; add compound command tests; test plan suggestions incorporated |
| Compliance & Risk | Approve-with-conditions | Post-approval exposure; scrubbing gaps; audit trail adequate but implicit |
| Shell Internals | Request-changes | `/usr/bin/printenv` absolute-path bypass (pre-existing systemic issue) |

### Resolution

- **Shell Internals' blocking finding** (absolute-path bypass): Verified as real but pre-existing and systemic — affects all rules, not introduced by this fix. Documented as Residual Risk #1. Will be tracked as a separate follow-up issue for parser-level basename normalization.
- **Red Team conditions**: Alternative env-dumping vectors documented as Residual Risk #2. These are pre-existing and fundamentally harder to fix.
- **Compliance conditions**: Post-approval exposure documented as Residual Risk #3. Scrubbing gap acknowledged.
- **Systems Engineer suggestions**: Reason text harmonized, test plan expanded with compound command cases.

### Final Sign-Off

All findings addressed. No unresolved blocking issues remain within the scope of this fix (config-only reclassification of `printenv` and `env` from GREEN to YELLOW).

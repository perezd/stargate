# Stargate

A bash command classifier for AI coding agents. Stargate sits between an AI coding agent and shell execution, parsing commands into ASTs, evaluating them against configurable rules, and escalating ambiguous commands to an LLM for review.

## Quick Start

### 1. Install

```bash
go install github.com/limbic-systems/stargate/cmd/stargate@latest
```

Or build from source:

```bash
git clone https://github.com/limbic-systems/stargate.git
cd stargate
just build
just install
```

### 2. Create a config

Create `~/.config/stargate/stargate.toml`:

```toml
[server]
listen = "127.0.0.1:9099"

[classifier]
default_decision = "yellow"

[[rules.red]]
command = "rm"
flags = ["-rf", "-fr"]
args = ["/"]
reason = "recursive force delete of root"

[[rules.green]]
commands = ["git", "ls", "cat", "echo", "pwd", "head", "tail", "wc"]
reason = "safe read-only commands"
```

> **Security:** `stargate.toml` MUST live outside any repository that stargate guards. A config inside a repo is writable by repo contents and therefore untrusted. The default path `~/.config/stargate/stargate.toml` is outside all repos.

### 3. Start the server

```bash
stargate serve
```

### 4. Configure Claude Code

Add to your Claude Code hooks configuration (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "stargate hook --agent claude-code --event pre-tool-use"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "stargate hook --agent claude-code --event post-tool-use"
          }
        ]
      }
    ]
  }
}
```

## CLI Reference

| Subcommand | Description |
|-----------|-------------|
| `stargate serve` | Start the HTTP classification server |
| `stargate hook` | Run as a Claude Code hook adapter (reads JSON from stdin) |
| `stargate test <command>` | Dry-run classify a command for debugging |
| `stargate config validate` | Validate the config file |
| `stargate config dump` | Print the effective config as TOML |
| `stargate config rules` | Print a summary of loaded rules |
| `stargate corpus stats` | Print corpus statistics |

Run `stargate <subcommand> --help` for detailed flags.

## How It Works

Every command goes through a classification pipeline: **parse** (shell AST via `mvdan.cc/sh/v3`) → **walk** (extract command names, flags, args, context) → **rules** (RED/GREEN/YELLOW matching with scope-bound conditions) → **corpus** (check precedent judgments) → **LLM review** (for ambiguous YELLOW commands) → **respond** (allow/ask/deny).

- **GREEN** commands execute silently
- **YELLOW** commands prompt the user for approval (or go to LLM review)
- **RED** commands are blocked

## Security Notes

- **Trust anchor:** `stargate.toml` must live outside any repository that stargate guards. The config is the root trust anchor — it defines what commands are safe, dangerous, or ambiguous. A config inside a repo could be modified by repo contents or prompt injection.

- **Fail-closed:** If the stargate server is unreachable, the hook exits with code 2 (blocking error in Claude Code). Commands are NOT silently allowed when the server is down.

- **`config dump` sensitivity:** Password fields are scrubbed in `config dump` output, but other values (LLM system prompts, scrubbing patterns) appear as-is. Use environment variables for credentials rather than embedding them in the TOML file.

- **Localhost only:** The server binds to `127.0.0.1` only. Non-loopback bind addresses are rejected by both the config validator and the `--listen` flag. The `--allow-remote` flag on `stargate hook` controls the *hook client* connecting to a remote server, not the server bind address.

## Development

Requires [Go](https://go.dev/) 1.26+ and [just](https://github.com/casey/just).

```bash
just test        # Run all tests with race detector
just vet         # Run go vet
just vuln        # Run govulncheck for known vulnerabilities
just build       # Build for local platform
just build-all   # Cross-compile for linux/darwin × amd64/arm64
just checksums   # Generate SHA256SUMS for release binaries
just clean       # Remove build artifacts
```

## License

[Apache-2.0](LICENSE)

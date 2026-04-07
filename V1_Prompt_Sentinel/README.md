# Prompt Sentinel

**Host-side security enforcement for Claude Code.**

Prompt Sentinel intercepts AI-generated tool calls before they execute, evaluates them against configurable policies, and maintains tamper-evident audit logs. It enforces a single principle: **a model-generated tool call is a proposal, not an authorization.**

```
User Prompt --> [Prompt Override Detection] --> [Policy Evaluation] --> ALLOW / ASK / DENY
                                                       |
                                              [Audit + Alert Logs]
```

---

## Why Prompt Sentinel

Claude Code is powerful. It can read files, edit code, run shell commands, and write to disk. Prompt Sentinel adds a trusted enforcement boundary between what the model *wants* to do and what it's *allowed* to do.

| Threat | How Prompt Sentinel Handles It |
|--------|-------------------------------|
| Prompt injection ("ignore previous instructions") | Detected at prompt submission; model warned content is untrusted |
| Access to `.env`, `.git/`, private keys, secrets | Blocked by pattern detection before the tool executes |
| Uncontrolled `curl`, `ssh`, `scp`, `export` | Paused for manual user review |
| Runaway tool usage | Per-session quotas (e.g., max 25 Bash calls) |
| Mid-session config tampering | SHA256 manifest verification; high-severity alerts |
| Unauthorized tool parameters | Allowlist enforcement per tool |

---

## Quick Start

### 1. Install as a Claude Code Plugin

Copy the plugin into your project:

```bash
cp -r prompt-sentinel-claude/ your-project/.claude/plugins/prompt-sentinel-claude/
```

That's it. **No pip install required.** The hooks resolve the bundled runtime automatically.

### 2. Verify It's Working

Start a Claude Code session in your project. You should see:

> Prompt_Sentinel trusted launch completed.

Try a command that touches a protected pattern:

```
> Read the .env file
# --> Prompt_Sentinel blocked Bash: matched protected pattern(s) ['.env']
```

### 3. Optional: Install the CLI

For policy validation, audit inspection, and capability ticket management:

```bash
pip install ./prompt-sentinel-core   # Requires Python 3.11+
```

---

## How It Works

Prompt Sentinel uses Claude Code's [hook system](https://docs.anthropic.com/en/docs/claude-code/hooks) to intercept seven lifecycle events:

| Hook | Event | What It Does |
|------|-------|-------------|
| `trusted_launch.py` | SessionStart | Verifies instruction files and manifest integrity |
| `user_prompt_submit.py` | UserPromptSubmit | Detects prompt injection patterns |
| `pre_tool_firewall.py` | PreToolUse | **Primary gate** -- evaluates policy, blocks dangerous patterns, flags sensitive operations |
| `post_tool_use.py` | PostToolUse | Appends audit record |
| `config_tamper_alert.py` | ConfigChange | Detects instruction/config file changes mid-session |
| `config_tamper_alert.py` | InstructionsLoaded | Verifies manifest on instruction reload |
| `stop.py` | Stop | Logs session termination |

### Decision Logic (PreToolUse)

```
Tool call proposed (Bash, Edit, or Write)
  |
  +--> Policy check: tool allowed? params valid? quota remaining?
  |      NO --> DENY (blocked, alert emitted)
  |
  +--> Block patterns: .env, .git/, id_rsa, secret, deploy, bypass?
  |      YES --> DENY (blocked, alert emitted)
  |
  +--> Ask patterns: curl, ssh, scp, export, token?
  |    Capability required?
  |      YES --> ASK (paused for user review)
  |
  +--> ALLOW
```

---

## Policy Configuration

Policies are JSON files that define what each tool is permitted to do.

### Default Policy

```json
{
  "tool_permissions": {
    "Bash": {
      "allowed_params": ["command", "cmd", "input", "stdin", "description"],
      "max_calls_per_session": 25
    },
    "Edit": {
      "allowed_params": ["file_path", "path", "old_string", "new_string", "replace_all"],
      "max_calls_per_session": 40
    },
    "Write": {
      "allowed_params": ["file_path", "path", "content", "append", "prepend"],
      "max_calls_per_session": 40
    }
  },
  "capability_required_tools": [],
  "meta": { "policy_name": "claude-default" }
}
```

### Policy Cascade

Prompt Sentinel checks for policies in this order (first found wins):

1. **Project-local:** `.claude/prompt-sentinel.policy.json`
2. **Plugin-bundled:** `policies/claude-default-policy.json`
3. **Core default:** `prompt-sentinel-core/.../default-policy.json`

### Custom Policy Example

Create `.claude/prompt-sentinel.policy.json` to restrict your project:

```json
{
  "tool_permissions": {
    "Bash": {
      "allowed_params": ["command", "description"],
      "max_calls_per_session": 10
    },
    "Edit": {
      "allowed_params": ["file_path", "old_string", "new_string", "replace_all"],
      "max_calls_per_session": 20
    }
  },
  "capability_required_tools": ["sensitive_export"],
  "meta": { "policy_name": "locked-down" }
}
```

---

## Project Structure

```
prompt-sentinel-claude/
  .claude-plugin/
    plugin.json                  Plugin manifest
  hooks/
    hooks.json                   Hook wiring (uses ${CLAUDE_PLUGIN_ROOT})
    common.py                    Shared helpers, policy resolution, audit
    trusted_launch.py            Session startup verification
    user_prompt_submit.py        Prompt injection detection
    pre_tool_firewall.py         Pre-execution policy gate
    post_tool_use.py             Post-execution audit
    config_tamper_alert.py       Mid-session tamper detection
    stop.py                      Session stop audit
  agents/
    prompt-sentinel-guardian.md   Security-focused review subagent
  policies/
    claude-default-policy.json   Default Claude Code policy
  prompt-sentinel-core/
    src/prompt_sentinel/
      core/                      Policy engine, audit, capabilities, detection
      cli/                       Command-line interface
      adapters/                  Claude Code and Codex integrations
      policies/                  Bundled policy tiers
      schemas/                   JSON schemas for validation
    tests/                       Comprehensive test suite
    pyproject.toml               Package metadata (Python 3.11+)
  manifests/                     Manifest templates
  references/                    Background docs (policy model, plugin usage)
  settings.template.json         Settings template for standalone use
  SKILL.md                       Claude Code skill definition
  CLAUDE.md                      Trust model instructions
  MANUAL.md                      Full reference manual
```

---

## Audit and Alerting

### Audit Log

`.claude/prompt-sentinel.audit.jsonl` -- every tool call, session start, and session stop:

```bash
# View recent entries
prompt-sentinel audit tail --audit-log .claude/prompt-sentinel.audit.jsonl

# Filter by tool
prompt-sentinel audit tail --tool Bash --limit 50

# Export to a SIEM
prompt-sentinel audit export --destination https://siem.example.com/ingest \
  --header "Authorization:Bearer tok123"
```

### Alert Log

`.claude/prompt-sentinel.alerts.jsonl` -- policy denials, block-pattern matches, tamper events, prompt injection attempts.

---

## Capability Tickets

For approval-gated operations, Prompt Sentinel supports Ed25519-signed capability tickets -- cryptographic proof that a specific action was authorized.

```bash
# Issue a ticket
prompt-sentinel issue-capability \
  --authority admin@example.com \
  --audience local.prompt-sentinel \
  --operation sensitive_export \
  --session-id abc123 \
  --scope scope.json \
  --params params.json \
  --private-key keys/sentinel.key

# Verify a ticket
prompt-sentinel verify-capability \
  --capability ticket.json \
  --public-key keys/sentinel.key.pub \
  --params params.json \
  --session-id abc123
```

---

## CLI Quick Reference

| Command | Description |
|---------|-------------|
| `prompt-sentinel check-proposal` | Evaluate a tool proposal against policy |
| `prompt-sentinel policy validate` | Validate a policy file |
| `prompt-sentinel policy summary` | Show safe policy summary |
| `prompt-sentinel issue-capability` | Issue a signed approval ticket |
| `prompt-sentinel verify-capability` | Verify a ticket's signature and params |
| `prompt-sentinel audit tail` | Show recent audit entries |
| `prompt-sentinel audit export` | Export audit log (file, https, s3, stdout) |

---

## Requirements

- **Python 3.11+** (for hook execution)
- **cryptography >= 42.0.0** (bundled dependency for capability tickets)
- **Claude Code** with hook support

---

## Documentation

| Document | Description |
|----------|-------------|
| [MANUAL.md](MANUAL.md) | Complete reference manual |
| [references/policy-model.md](references/policy-model.md) | Trust model and separation of concerns |
| [references/plugin-usage.md](references/plugin-usage.md) | Plugin layout and integration details |
| [SKILL.md](SKILL.md) | Claude Code skill definition |
| [CLAUDE.md](CLAUDE.md) | Trust model instructions for the model |

---

## License

See repository root for license information.

# Prompt Sentinel Manual

**Version 0.1.0** | Host-Side Security Enforcement for Claude Code

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Hooks Reference](#hooks-reference)
6. [Policy System](#policy-system)
7. [Pattern Detection](#pattern-detection)
8. [Capability Tickets](#capability-tickets)
9. [Audit and Alerting](#audit-and-alerting)
10. [CLI Reference](#cli-reference)
11. [Guardian Subagent](#guardian-subagent)
12. [Manifest Verification](#manifest-verification)
13. [Troubleshooting](#troubleshooting)

---

## Introduction

Prompt Sentinel is a host-side security enforcement layer for Claude Code. It intercepts AI tool calls **before they execute**, evaluates them against configurable policies, and maintains tamper-evident audit logs of all decisions.

The core principle: **a model-generated tool call is a proposal, not an authorization.** Authorization belongs to the host runtime.

### What It Protects Against

- **Prompt injection** -- detects instruction-override patterns in user prompts
- **Sensitive file access** -- blocks reads/writes to `.env`, `.git/`, private keys, secrets
- **Uncontrolled shell commands** -- gates `curl`, `ssh`, `scp`, `export` behind manual review
- **Tool quota abuse** -- enforces per-session limits on Bash, Edit, and Write calls
- **Configuration tampering** -- detects changes to instruction files and hook configs mid-session
- **Unauthorized parameter use** -- rejects tool calls with unknown or disallowed parameters

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| Fail-safe defaults | If the guard layer is unavailable, actions are denied |
| Deterministic enforcement | Hooks run *before* tool execution, not as cleanup |
| Separation of concerns | Untrusted input, policy evaluation, and execution are isolated |
| Tamper evidence | Audit logs are hash-chained JSONL; manifests track instruction file integrity |
| Least privilege | Sensitive actions require explicit capability tickets or manual approval |

---

## Architecture Overview

```
                        User Prompt
                             |
                    +--------v--------+
                    | UserPromptSubmit |  Detect prompt override patterns
                    +--------+--------+
                             |
                    +--------v--------+
                    |   PreToolUse    |  Policy evaluation + pattern detection
                    +--------+--------+
                             |
               +-------------+-------------+
               |             |             |
            ALLOW          ASK          DENY
               |             |             |
          Execute tool   Pause for     Block tool,
          normally       user review   emit alert
               |             |
               v             v
        +-----------+
        | PostToolUse|  Append audit record
        +-----------+
```

### Layers

1. **Plugin layer** -- `.claude-plugin/plugin.json` registers skills, agents, and hooks with Claude Code
2. **Hook layer** -- Python scripts in `hooks/` that intercept lifecycle events (thin; delegates to core)
3. **Core runtime** -- `prompt-sentinel-core/` contains the policy engine, audit chain, capability service, and detection logic (thick; all business logic lives here)
4. **Policy layer** -- JSON policy files define tool permissions, quotas, and capability requirements

### Data Flow

```
Hook receives event via stdin (JSON)
  -> common.py normalizes the proposal
  -> core runtime evaluates against policy
  -> EnforcementDecision returned (allowed, reason, capability_required)
  -> Hook emits response to stdout (allow / ask / deny)
  -> Audit/alert records appended to JSONL logs
```

---

## Installation

### As a Claude Code Plugin (Recommended)

Copy or symlink the entire plugin folder into your target project:

```
your-project/
  .claude/
    plugins/
      prompt-sentinel-claude/    <-- copy this entire folder here
```

**No pip install is required.** The hooks resolve the bundled `prompt-sentinel-core/src` at runtime via `sys.path` insertion.

### Plugin Structure

```
prompt-sentinel-claude/
  .claude-plugin/plugin.json     Plugin manifest
  SKILL.md                       Skill definition
  CLAUDE.md                      Trust model instructions
  hooks/
    hooks.json                   Hook wiring
    common.py                    Shared helpers
    trusted_launch.py            Session startup verification
    user_prompt_submit.py        Prompt override detection
    pre_tool_firewall.py         Pre-execution policy gate
    post_tool_use.py             Post-execution audit
    config_tamper_alert.py       Tamper detection
    stop.py                      Session stop audit
  agents/
    prompt-sentinel-guardian.md   Guardian subagent definition
  policies/
    claude-default-policy.json   Default Claude Code policy
  prompt-sentinel-core/          Bundled runtime (no install needed)
  manifests/                     Manifest templates
  references/                    Background documentation
  settings.template.json         Settings template for projects
```

### Optional: CLI Installation

For command-line access to policy validation, capability management, and audit tools:

```bash
pip install ./prompt-sentinel-core
```

Requires Python 3.11+ and `cryptography>=42.0.0`.

### Project Settings

Copy `settings.template.json` to your project's `.claude/settings.json` to wire hooks for standalone (non-plugin) use:

```json
{
  "hooks": {
    "SessionStart": [{ "matcher": "startup|resume|clear|compact",
      "hooks": [{ "type": "command", "command": "python .claude/hooks/trusted_launch.py" }] }],
    "UserPromptSubmit": [{ "matcher": "",
      "hooks": [{ "type": "command", "command": "python .claude/hooks/user_prompt_submit.py" }] }],
    "PreToolUse": [{ "matcher": "Bash|Edit|Write",
      "hooks": [{ "type": "command", "command": "python .claude/hooks/pre_tool_firewall.py" }] }],
    "PostToolUse": [{ "matcher": "Bash|Edit|Write",
      "hooks": [{ "type": "command", "command": "python .claude/hooks/post_tool_use.py" }] }],
    "Stop": [{ "matcher": "",
      "hooks": [{ "type": "command", "command": "python .claude/hooks/stop.py" }] }]
  }
}
```

---

## Configuration

### Policy Cascade

Prompt Sentinel resolves policy files in this order (first found wins):

| Priority | Path | Use Case |
|----------|------|----------|
| 1 | `.claude/prompt-sentinel.policy.json` | Project-local override |
| 2 | `policies/claude-default-policy.json` | Plugin-bundled Claude policy |
| 3 | `prompt-sentinel-core/.../default-policy.json` | Core fallback |

To customize, create `.claude/prompt-sentinel.policy.json` in your project root.

### Local Files Created at Runtime

Prompt Sentinel creates these files in your project's `.claude/` directory:

| File | Purpose |
|------|---------|
| `prompt-sentinel.audit.jsonl` | Append-only tool call audit log |
| `prompt-sentinel.alerts.jsonl` | High-severity alert log |
| `prompt-sentinel.policy.json` | Optional project-local policy override |
| `prompt-sentinel.manifest.json` | Optional instruction file hash manifest |

---

## Hooks Reference

### SessionStart -- `trusted_launch.py`

**Trigger:** Session startup, resume, clear, or compact events.

**What it does:**
1. Checks for the presence of critical instruction files (`CLAUDE.md`, `.claude/settings.json`, `.claude/settings.local.json`) and all hook scripts
2. Verifies the instruction manifest (if present) by comparing SHA256 hashes
3. Emits alerts for missing files or manifest mismatches
4. Writes a `trusted_launch` audit record

**Output:** Always allows the session to proceed, but injects context reminding the model to treat instruction files as mutable and rely on hook enforcement.

### UserPromptSubmit -- `user_prompt_submit.py`

**Trigger:** Every user prompt submission.

**What it does:**
1. Scans the prompt text for instruction-override patterns (e.g., "ignore previous instructions")
2. If patterns are found, emits a `prompt_override_attempt` alert
3. Injects a context note telling the model to treat the prompt as untrusted

**Output:** Always allows the prompt, but annotates it when override patterns are detected.

### PreToolUse -- `pre_tool_firewall.py`

**Trigger:** Before any `Bash`, `Edit`, or `Write` tool call executes.

This is the primary enforcement hook. It performs three checks in order:

1. **Policy evaluation** -- Calls the core runtime to check tool permissions, parameter allowlists, path whitelists, and session quotas. If the policy denies the call, the hook returns `deny`.

2. **Block-pattern detection** -- Scans tool input text for dangerous patterns (`.env`, `.git/`, `id_rsa`, `secret`, `deploy`, `bypass`). If matched, the hook returns `deny`.

3. **Ask-pattern / capability detection** -- Scans for review-worthy patterns (`curl`, `ssh`, `scp`, `export`, `token`) or checks if the tool requires a capability ticket. If matched, the hook returns `ask` (pauses for user review).

4. **Allow** -- If all checks pass, the tool is allowed to execute.

**Decision Flow:**

| Check | Result | Hook Decision |
|-------|--------|--------------|
| Policy denies | Fail | `deny` |
| Block pattern matched | Fail | `deny` |
| Ask pattern matched | Flag | `ask` (user review) |
| Capability required | Flag | `ask` (user review) |
| All clear | Pass | `allow` |

### PostToolUse -- `post_tool_use.py`

**Trigger:** After any `Bash`, `Edit`, or `Write` tool call completes.

**What it does:** Appends a `PostToolUse` audit record with the tool name and session ID.

### ConfigChange / InstructionsLoaded -- `config_tamper_alert.py`

**Trigger:** When project settings, user settings, skills, policy settings, or instruction files change during a session.

**What it does:**
1. Verifies the instruction manifest (if present)
2. Emits a high-severity `config_or_instruction_change` alert
3. Injects context noting that the session state may be untrusted

### Stop -- `stop.py`

**Trigger:** Session end.

**What it does:** Appends a `Stop` audit record with session ID and working directory.

---

## Policy System

### Policy Structure

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
  "meta": {
    "policy_name": "claude-default",
    "notes": "Starter Claude Code policy for Prompt_Sentinel hooks"
  }
}
```

### Tool Permission Fields

| Field | Type | Description |
|-------|------|-------------|
| `allowed_params` | `string[]` | Parameter names the tool is permitted to use. Unknown params are rejected. |
| `max_calls_per_session` | `integer` | Maximum times this tool can be called per session. Exceeding returns `deny`. |
| `path_whitelist` | `string[]` | Glob patterns for allowed file paths (e.g., `["src/**", "tests/**"]`). |
| `sensitive_action_class` | `string` | One of `standard`, `restricted`, `privileged`, `approval-gated`. Classes above `standard` require capability tickets. |
| `retention_class` | `string` | Audit retention classification. |
| `approval_scope` | `string` | Scope identifier for capability ticket matching. |

### Capability-Required Tools

The `capability_required_tools` array lists tool names that always require a signed capability ticket before execution. Without a valid ticket, the hook returns `ask`.

### Customizing Policy

Create `.claude/prompt-sentinel.policy.json` in your project:

```json
{
  "tool_permissions": {
    "Bash": {
      "allowed_params": ["command", "description"],
      "max_calls_per_session": 10,
      "path_whitelist": ["src/**", "tests/**"]
    },
    "Edit": {
      "allowed_params": ["file_path", "old_string", "new_string", "replace_all"],
      "max_calls_per_session": 20
    },
    "Write": {
      "allowed_params": ["file_path", "content"],
      "max_calls_per_session": 10
    }
  },
  "capability_required_tools": ["sensitive_export"],
  "meta": {
    "policy_name": "my-project-policy"
  }
}
```

### Validating Policy

```bash
prompt-sentinel policy validate --policy .claude/prompt-sentinel.policy.json
```

---

## Pattern Detection

### Prompt Override Patterns

Detected in user prompts by `user_prompt_submit.py`:

| Pattern | Purpose |
|---------|---------|
| `ignore previous instructions` | Prompt injection attempt |
| `disregard system prompt` | System prompt override |
| `reveal hidden policy` | Policy exfiltration |
| `show me your system prompt` | System prompt exfiltration |

Detection is case-insensitive substring matching. When matched, the prompt is flagged but still allowed -- the model is warned that the content is untrusted.

### Tool Text Patterns

Detected in tool call parameters by `pre_tool_firewall.py`:

**Block patterns** (tool call is denied):

| Pattern | Risk |
|---------|------|
| `.env` | Environment variable / secret file |
| `.git/` | Git internals |
| `id_rsa` | SSH private key |
| `secret` | Secret/credential files |
| `deploy` | Deployment scripts/configs |
| `bypass` | Security bypass attempt |

**Ask patterns** (tool call paused for user review):

| Pattern | Risk |
|---------|------|
| `curl` | Network request / data exfiltration |
| `ssh` | Remote shell access |
| `scp` | Remote file transfer |
| `export` | Environment variable export |
| `token` | Token/credential handling |

---

## Capability Tickets

Capability tickets are Ed25519-signed authorization tokens for approval-gated operations. They provide cryptographic proof that a specific action was approved by an authorized party.

### Ticket Structure

```json
{
  "key_id": "local-dev-key",
  "authority": "admin@example.com",
  "audience": "local.prompt-sentinel",
  "issued_at": 1712345678,
  "expires_at": 1712349278,
  "nonce": "unique-random-value",
  "operation": "sensitive_export",
  "session_id": "abc123",
  "scope": { "env": "staging" },
  "params_hash_b64": "base64-encoded-sha256-of-params",
  "signature_b64": "base64-encoded-ed25519-signature"
}
```

### Issuing a Ticket

```bash
# Generate a keypair (auto-created if missing)
prompt-sentinel issue-capability \
  --authority admin@example.com \
  --audience local.prompt-sentinel \
  --operation sensitive_export \
  --session-id abc123 \
  --scope scope.json \
  --params params.json \
  --private-key keys/sentinel.key
```

### Verifying a Ticket

```bash
prompt-sentinel verify-capability \
  --capability ticket.json \
  --public-key keys/sentinel.key.pub \
  --params params.json \
  --session-id abc123
```

### How Tickets Are Used

1. The `PolicyEnforcer` checks if the tool is in `capability_required_tools` or has a sensitive action class
2. If a capability is required and no valid ticket is presented, the hook returns `ask`
3. The user or administrator issues a ticket via the CLI
4. The ticket is passed to `evaluate_proposal()` and verified against the expected parameters
5. If verification succeeds, the action proceeds

---

## Audit and Alerting

### Audit Log

**Location:** `.claude/prompt-sentinel.audit.jsonl`

Append-only JSONL file recording every tool call lifecycle event:

```jsonl
{"event": "trusted_launch", "session_id": "s1", "files": {"CLAUDE.md": "present"}, ...}
{"event": "PostToolUse", "tool_name": "Bash", "session_id": "s1"}
{"event": "Stop", "session_id": "s1", "cwd": "/path/to/project"}
```

When using the core runtime's `AuditChain`, records are hash-chained with `prev_hash` and `entry_hash` fields for tamper detection.

### Alert Log

**Location:** `.claude/prompt-sentinel.alerts.jsonl`

Records high-severity events:

| Event | Severity | Trigger |
|-------|----------|---------|
| `prompt_override_attempt` | medium | Override pattern in user prompt |
| `pre_tool_policy_denial` | high | Policy denied a tool call |
| `pre_tool_block` | high | Block pattern matched in tool input |
| `pre_tool_requires_review` | medium | Ask pattern matched or capability required |
| `trusted_launch_missing_file` | medium | Critical file missing at session start |
| `instruction_manifest_mismatch` | high | Instruction file hash changed |
| `config_or_instruction_change` | high | Config/instruction file modified mid-session |

### Viewing Audit Logs

```bash
# Last 20 entries
prompt-sentinel audit tail --audit-log .claude/prompt-sentinel.audit.jsonl

# Filter by event type
prompt-sentinel audit tail --event PostToolUse --limit 50

# Filter by tool
prompt-sentinel audit tail --tool Bash
```

### Exporting Audit Logs

```bash
# Export to file
prompt-sentinel audit export --destination file:///path/to/export.jsonl

# Export to webhook
prompt-sentinel audit export --destination https://siem.example.com/ingest \
  --header "Authorization:Bearer token123"

# Export to S3
prompt-sentinel audit export --destination s3://bucket/prefix/audit.jsonl

# Export to stdout
prompt-sentinel audit export --destination stdout

# Only entries after a timestamp
prompt-sentinel audit export --destination stdout --after 1712345678
```

---

## CLI Reference

Install the CLI with `pip install ./prompt-sentinel-core`.

### Commands

#### `prompt-sentinel check-proposal`

Evaluate a tool proposal against a policy.

```bash
prompt-sentinel check-proposal \
  --policy policy.json \
  --proposal proposal.json \
  [--audit-log audit.jsonl] \
  [--base-dir .] \
  [--session-id SESSION] \
  [--user-id USER] \
  [--role ROLE] \
  [--tenant TENANT] \
  [--public-key key.pub] \
  [--capability ticket.json] \
  [--audience AUDIENCE]
```

**Exit codes:** `0` = allowed, `2` = denied.

**Proposal format:**
```json
{ "tool": "Bash", "params": { "command": "ls -la" } }
```

#### `prompt-sentinel policy validate`

Validate a policy file against the schema.

```bash
prompt-sentinel policy validate --policy policy.json
```

#### `prompt-sentinel policy summary`

Emit a safe summary of a policy (no internal details exposed).

```bash
prompt-sentinel policy summary --policy policy.json
```

#### `prompt-sentinel issue-capability`

Issue a signed capability ticket.

```bash
prompt-sentinel issue-capability \
  --authority AUTHORITY \
  --audience AUDIENCE \
  --operation OPERATION \
  --session-id SESSION \
  --scope scope.json \
  --params params.json \
  --private-key key.pem \
  [--public-key key.pub] \
  [--key-id KEY_ID]
```

#### `prompt-sentinel verify-capability`

Verify a capability ticket.

```bash
prompt-sentinel verify-capability \
  --capability ticket.json \
  --public-key key.pub \
  --params params.json \
  --session-id SESSION \
  [--audience AUDIENCE]
```

#### `prompt-sentinel audit tail`

Show recent audit entries.

```bash
prompt-sentinel audit tail \
  [--audit-log audit.jsonl] \
  [--limit 20] \
  [--event EVENT_TYPE] \
  [--tool TOOL_NAME]
```

#### `prompt-sentinel audit export`

Export audit log to an external sink.

```bash
prompt-sentinel audit export \
  --destination URI \
  [--audit-log audit.jsonl] \
  [--after TIMESTAMP] \
  [--header Key:Value]
```

Supported destinations: `file://`, `https://`, `s3://`, `stdout`.

---

## Guardian Subagent

Prompt Sentinel includes a security-focused subagent definition at `agents/prompt-sentinel-guardian.md`. When invoked, the guardian:

1. Identifies the actual operation being proposed
2. Checks whether the action should be evaluated by Prompt Sentinel
3. Prefers the least-privilege path
4. Explains denials and suggests compliant alternatives
5. Requests proper capabilities instead of improvising around restrictions
6. Treats instruction/config changes as tamper events

The guardian is automatically discoverable by Claude Code through the plugin manifest.

---

## Manifest Verification

Instruction manifests track SHA256 hashes of mutable files (CLAUDE.md, settings, hooks) to detect unauthorized changes.

### Creating a Manifest

Use the template at `manifests/instruction-manifest.template.json` or the generation script:

```bash
python scripts/generate_manifest.py
```

Save the output to `.claude/prompt-sentinel.manifest.json`.

### How Verification Works

1. At session start, `trusted_launch.py` loads the manifest and recomputes hashes for each listed file
2. If any file's current hash doesn't match the stored hash, a high-severity `instruction_manifest_mismatch` alert is emitted
3. When configs change mid-session, `config_tamper_alert.py` re-verifies the manifest
4. The model is warned that the session state may be untrusted

---

## Troubleshooting

### Hook not firing

- Verify `hooks.json` is correctly referenced in `.claude-plugin/plugin.json`
- Check that the matcher regex matches the tool name (e.g., `Bash|Edit|Write`)
- Ensure Python 3.11+ is available in the shell PATH

### Policy denial unexpected

- Check which policy file is being used: project-local > bundled > core default
- Run `prompt-sentinel policy validate --policy <path>` to verify the policy
- Check if a block pattern is matching unintentionally (e.g., `secret` in a file path like `client_secret_config.py`)

### Audit log not created

- The `.claude/` directory must be writable
- Hooks create the directory automatically via `mkdir(parents=True, exist_ok=True)`

### Manifest mismatch on every launch

- Regenerate the manifest after any intentional changes to instruction files
- The manifest is optional -- delete `.claude/prompt-sentinel.manifest.json` to disable verification

### Tool quota exceeded

- Quotas are per-session, per-tool
- Increase `max_calls_per_session` in the policy, or start a new session
- Check `prompt-sentinel audit tail --tool Bash` to see how many calls were made

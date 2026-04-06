# Claude Code Manual

This manual describes how to use the Claude Code Prompt_Sentinel scaffold.

## Relevant folder

`AGENT_CORE/prompt-sentinel-claude/`

## Components

- `CLAUDE.md`
- `settings.template.json`
- `agents/prompt-sentinel-guardian.md`
- hook scripts under `hooks/`
- starter policy at `policies/claude-default-policy.json`
- manifest template at `manifests/instruction-manifest.template.json`

## Why hooks are the key layer

Claude Code loads `CLAUDE.md` automatically, but that file is still mutable.
Hooks are the deterministic layer that can block, ask, or allow before tools
execute. That makes them the right place for the firewall.

## Recommended setup

1. Copy `CLAUDE.md` into the protected repo or user memory location.
2. Merge `settings.template.json` into `.claude/settings.json`.
3. Copy the hook scripts into `.claude/hooks/`.
4. Copy `policies/claude-default-policy.json` to `.claude/prompt-sentinel.policy.json` and tune it.
5. Copy `manifests/instruction-manifest.template.json` to `.claude/prompt-sentinel.manifest.json` and replace the placeholder hashes.
6. Optionally install the guardian subagent.

## Runtime wiring

The hook bundle imports `prompt-sentinel-core` directly from the sibling
`AGENT_CORE/prompt-sentinel-core/src` tree, then uses:

- prompt detection from `prompt_sentinel.core.detection`
- manifest verification from `prompt_sentinel.core.manifests`
- proposal evaluation from `prompt_sentinel.core.runtime`

## Hook roles in this scaffold

- `trusted_launch.py`
  fingerprints important files and verifies the manifest when present
- `user_prompt_submit.py`
  detects prompt override patterns and emits alerts
- `pre_tool_firewall.py`
  evaluates proposals with the core runtime, then overlays risk-pattern review
- `config_tamper_alert.py`
  alerts on config or instruction changes and includes manifest mismatch state
- `post_tool_use.py`
  appends audit entries
- `stop.py`
  appends session-end audit markers

## Files to watch for tamper

At minimum:

- `CLAUDE.md`
- `.claude/settings.json`
- skill or subagent files
- hook scripts themselves

## Recommended policy

- use `PreToolUse` to gate shell, write, and edit paths
- use `UserPromptSubmit` to catch common override patterns
- use `ConfigChange` and `InstructionsLoaded` to detect trust-state changes
- store audit and alert logs outside model context

## Important limitation

Telling Claude in `CLAUDE.md` to always run the firewall is helpful, but it is
not enough by itself. The stronger guarantee comes from hooks and external
policy, not prompt text alone.

## Next implementation steps

- add manifest coverage for hook files and agent files
- forward high-severity alerts to the control plane
- add approval-service integration for ask or deny paths
- connect the hook policy to sealed policy bundles instead of plain JSON

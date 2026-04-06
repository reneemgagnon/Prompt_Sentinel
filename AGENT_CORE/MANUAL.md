# Prompt_Sentinel Manual

This manual explains how to use the `AGENT_CORE` scaffold to protect coding
agents with Prompt_Sentinel.

## Product split

- `prompt-sentinel-core`
  Local enforcement runtime, CLI, manifests, and audit primitives.
- `prompt-sentinel-codex`
  Codex skill and plugin wrapper.
- `prompt-sentinel-claude`
  Claude Code hooks, subagent, and `CLAUDE.md` starter.
- `prompt-sentinel-control-plane`
  Team and enterprise service skeleton for policies, approvals, alerts, and
  threat-vector sharing.

## Security model

Prompt files like `CLAUDE.md` or `AGENTS.md` are guidance, not roots of trust.
The trust order should be:

1. Trusted launch and manifest verification
2. External policy and enforcement runtime
3. Pre-tool firewall checks
4. Audit and alert emission
5. Agent-readable instructions

## Detection and alerts

Prompt_Sentinel should alert on:

- prompt override attempts
- approval bypass attempts
- protected path or secret access attempts
- config or instruction changes during a session
- repeated denied retries
- suspicious export or network behavior

Keep alerts structured and safe to share:

- severity
- event class
- source type
- tool name when relevant
- session id when available
- fingerprints and redacted examples instead of full sensitive payloads

## Threat-vector sharing

Share vectors safely by publishing:

- class names like `instruction-override`, `approval-evasion`, `sensitive-path-probe`
- hashes or fingerprints
- redacted exemplars
- policy or rule updates that mitigate the class

Do not share raw customer prompts, secrets, or proprietary repository content by
default.

## Manuals

- Read `MANUAL_CODEX.md` for Codex deployment.
- Read `MANUAL_CLAUDECODE.md` for Claude Code deployment.
- Read `HARDENING_DESIGN.md` for the cross-agent trust model.

# AGENT_CORE

Scaffold for productizing Prompt_Sentinel as a cross-agent protection platform.

## Layout

- `prompt-sentinel-core/`
  Local runtime, CLI, policy primitives, and adapter modules.
- `prompt-sentinel-codex/`
  Codex plugin + skill wrapper.
- `prompt-sentinel-claude/`
  Claude Code hooks, subagent, and `CLAUDE.md` bundle.
- `prompt-sentinel-control-plane/`
  Control-plane service skeleton for policies, approvals, keys, and audit export.

## Intent

This folder is a starter architecture, not a finished migration from the
prototype files in the repo root. The next implementation step is to move the
working V3 logic into `prompt-sentinel-core/src/prompt_sentinel/core/`.

# AGENT_CORE

AGENT_CORE is the product workspace for Prompt_Sentinel.

It now serves three purposes:

- package the local runtime and CLI that enforce trusted action boundaries
- distribute agent-native wrappers for Codex and Claude
- hold the enterprise control-plane scaffolding for approvals, policy distribution, and telemetry

## Layout

- `prompt-sentinel-claude/prompt-sentinel-core/`: the installable `prompt-sentinel-core` runtime package
- `prompt-sentinel-codex/`: plugin and skill distribution for Codex environments
- `prompt-sentinel-claude/`: Claude Code hooks, settings templates, and wrapper assets
- `prompt-sentinel-control-plane/`: enterprise service and shared schemas

## Current State

This workspace is no longer just a placeholder architecture. The runtime package now exposes the planned product CLI surface, tiered policy packs, and packaged schemas.

The remaining work is mostly expansion rather than migration:

- deepen the control-plane service
- connect hosted approvals and search to the Guard add-on
- harden key custody and multi-tenant governance for enterprise deployments
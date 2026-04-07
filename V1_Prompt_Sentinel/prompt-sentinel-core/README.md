# prompt-sentinel-core

Installable local runtime, CLI, and SDK for Prompt_Sentinel.

## What It Does

- evaluates untrusted tool proposals against host-side policy
- issues and verifies signed capability tickets
- records tamper-evident audit logs
- ships policy packs for Core, Guard, and Enterprise tiers
- exposes adapters for Codex and Claude-oriented integrations

## CLI

```bash
prompt-sentinel check-proposal
prompt-sentinel issue-capability
prompt-sentinel verify-capability
prompt-sentinel policy validate
prompt-sentinel policy summary
prompt-sentinel audit tail
prompt-sentinel audit export
```

## Bundled Assets

- policies: `src/prompt_sentinel/policies/`
- schemas: `src/prompt_sentinel/schemas/`
- adapters: `src/prompt_sentinel/adapters/`

## Position In The Product

This package is the Core layer of Prompt_Sentinel. It is the deterministic runtime that the paid Guard add-on and Enterprise control plane build on top of.
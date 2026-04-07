# Prompt_Sentinel

Prompt_Sentinel is the trusted action boundary for coding agents.

Instead of asking an LLM to protect itself, Prompt_Sentinel keeps policy, approvals, and audit decisions in trusted host-side code. The model can propose actions; the runtime decides what actually executes.

## Product Shape

Prompt_Sentinel is now organized around three commercial layers:

- Core: local runtime, CLI, sealed policy handling, signed capability flow, local audit chain, Codex and Claude adapters.
- Guard Add-On: managed policy packs, approval workflows, better denial UX, hosted audit search, and team presets.
- Enterprise: centralized policy distribution, approval services, SSO/RBAC, SIEM export, KMS/HSM integration, and long-retention compliance reporting.

This repo implements the Core runtime directly and includes the Guard and Enterprise scaffolding under `AGENT_CORE/`.

## What Is In This Repo

- `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/`: installable runtime and CLI
- `AGENT_CORE/prompt-sentinel-codex/`: Codex plugin and skill distribution layer
- `AGENT_CORE/prompt-sentinel-control-plane/`: enterprise control-plane skeleton and schemas
- `.agents/skills/prompt-sentinel-guardian/`: repo-local Codex skill for guarded workflows
- `V3_LLM_Boundary_Crypto_end_to_end.py`: the original end-to-end prototype retained as a runnable reference
- `deployment_guide.md`: framework integration examples for LangChain, LlamaIndex, and FastAPI

## Install

From the repo root:

```bash
pip install -e .
```

That installs the `prompt-sentinel` CLI from the root workspace while sourcing the runtime package from `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src`.

## CLI Surface

Prompt_Sentinel now exposes the commercial command surface described in the product plan:

```bash
prompt-sentinel check-proposal --policy policy.json --proposal proposal.json
prompt-sentinel issue-capability --authority policy_engine --audience local.prompt-sentinel --operation approve_tool_call --session-id sess-1 --scope scope.json --params params.json --private-key keys/dev.key
prompt-sentinel verify-capability --capability ticket.json --public-key keys/dev.key.pub --params params.json --session-id sess-1
prompt-sentinel policy validate --policy policy.json
prompt-sentinel policy summary --policy policy.json
prompt-sentinel audit tail --audit-log prompt_sentinel.audit.jsonl --limit 10
prompt-sentinel audit export --audit-log prompt_sentinel.audit.jsonl --destination stdout
```

Backward-compatible aliases also exist for `policy-summary`, `policy-validate`, `audit-tail`, and `audit-export`.

## Policy Packs

The packaged runtime now ships with policy packs for each commercial tier:

- Core default: `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/default-policy.json`
- Guard team: `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/guard-team-policy.json`
- Enterprise default: `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/enterprise-default-policy.json`

These policies include:

- tool allowlists and parameter allowlists
- path controls and quotas
- sensitive action classes
- approval scopes
- audit retention classes
- inheritance hooks for managed policy layering

## Schemas

Installable schemas now ship with the runtime package:

- policy bundle schema
- capability ticket schema
- audit export record schema

See `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/schemas/`.

Enterprise-facing schemas remain under `AGENT_CORE/prompt-sentinel-control-plane/schemas/`.

## Runtime Guarantees

Prompt_Sentinel’s strongest guarantees remain host-enforced:

- sealed policy stays outside model context
- signed capability tickets bind approvals to session, audience, expiry, nonce, and exact parameters
- every tool decision is audit-chained
- policy denials are explicit instead of being silently worked around

## Validation And Commercial Fit

The repo is now structured to support the add-on-first motion:

- Core can be adopted locally by individual developers and platform teams.
- Guard policy packs and audit surfaces map cleanly to a paid security add-on.
- The enterprise control-plane package provides the path to centralized governance and larger contracts.

## Development

Run focused tests from the packaged runtime directory:

```bash
cd AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core
pytest tests -q
```

The original V3 demo remains useful for concept validation:

```bash
python V3_LLM_Boundary_Crypto_end_to_end.py
```
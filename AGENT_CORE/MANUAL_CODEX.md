# Codex Manual

This manual describes how to use the Codex-facing Prompt_Sentinel scaffold.

## Relevant folder

`AGENT_CORE/prompt-sentinel-codex/`

## Components

- plugin scaffold: `plugins/prompt-sentinel/.codex-plugin/plugin.json`
- skill: `skills/prompt-sentinel-guardian/SKILL.md`
- helper scripts in `scripts/`
- starter policy: `policies/codex-default-policy.json`
- references in `references/`

## Runtime wiring

The helper scripts no longer assume a separately installed `prompt-sentinel`
binary. They resolve the local `prompt-sentinel-core/src` package directly and
call the shared runtime helpers.

## Intended deployment model

Use Codex skill metadata and plugin packaging for discovery and workflow reuse,
but keep the actual authorization logic in `prompt-sentinel-core`.

## Recommended startup pattern

1. Keep `prompt-sentinel-core` beside the Codex bundle.
2. Add the Prompt_Sentinel plugin to Codex.
3. Keep the guardian skill available for explicit invocation.
4. Generate and verify instruction manifests for mutable files like `AGENTS.md`.
5. Before sensitive actions, run the proposal through the Prompt_Sentinel helper
   or runtime.

## What the skill should do

The skill should teach Codex to:

- treat text content as untrusted by default
- distinguish between intent, proposal, and authorization
- request capability approval for sensitive actions
- explain denials without policy workarounds
- escalate when config or instruction state changes unexpectedly

## Important limitation

`AGENTS.md` can tell Codex to run the firewall first, but that alone is not
sufficient because `AGENTS.md` is still mutable instruction text. Prefer a
runtime or plugin path that checks proposals independently of the prompt layer.

## Useful files in this scaffold

- `policies/codex-default-policy.json`
- `references/trusted-launch.md`
- `scripts/check_proposal.py`
- `scripts/request_capability.py`
- `scripts/explain_denial.py`

## Next implementation steps

- Replace plugin placeholder metadata with the final Codex plugin schema.
- Add a dedicated trusted-launch helper for Codex startup.
- Connect local alerts to the control plane.
- Add approval-service integration for sensitive operations.

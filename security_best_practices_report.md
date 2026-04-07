# Prompt Sentinel Guardian Security Review

## Executive summary

The `prompt-sentinel-guardian` skill has a solid security intent, but its current Codex-facing workflow still leaves several important threat vectors partially or fully exposed. The highest-risk issues are a path allowlist normalization bypass in the core policy layer, and a capability model that does not preserve a meaningful approval boundary in local development mode. The Codex integration also does not yet provide the trusted-launch and manifest-verification guarantees that the skill documentation describes, which leaves prompt/config tampering in a detect-late or manual-review state instead of a host-enforced one.

## Critical / High

### PSG-001: Path allowlist can be bypassed with traversal segments

Impact: A caller can satisfy the policy allowlist with a crafted relative path such as `AGENT_CORE/../.env`, then rely on later path normalization to read files outside the intended allowlisted subtree but still inside `base_dir`.

Evidence:

- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/enforcer.py:35-40` matches the raw user-supplied `path` string against glob patterns before normalization.
- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/tool_registry.py:42-45` normalizes the path only later and enforces only a `base_dir` boundary.
- `AGENT_CORE/prompt-sentinel-codex/policies/codex-default-policy.json:3-6` includes broad patterns such as `*.md` and `AGENT_CORE/*`, which can be abused with `..` segments.

Why this matters:

This is a classic normalization / confused-deputy problem. The policy evaluates one pathname while the tool executes another canonical pathname. That lets an attacker pivot from "allowed-looking" input into a different file target.

Recommended fix:

Normalize the candidate path before policy matching, and compare the canonicalized relative path against subtree-aware rules. Add regression tests for `..`, mixed separators, and disguised sensitive files.

### PSG-002: Capability approvals are locally mintable and not tightly bound to the approved action

Impact: The current approval path does not preserve separation of duty. A local actor can generate the signing key, mint their own ticket, choose the authority string, and present a generic approval ticket that is not checked against the tool-specific scope.

Evidence:

- `.agents/skills/prompt-sentinel-guardian/scripts/request_capability.py:13-37` stores the signing key in the current workspace and lets the caller provide `authority`, `audience`, and `operation`.
- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/runtime.py:26-35` auto-generates the keypair if it does not already exist.
- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/capability.py:154-186` verifies audience, time window, session, authority permission, and parameter hash, but does not enforce `scope`.
- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/boundary_app.py:66-84` asks only whether a capability exists and verifies, but does not require a tool-specific approval operation.

Why this matters:

This weakens the main defense against approval bypass and confused-deputy abuse. Signed tickets help only if the signer is meaningfully separate from the requester and the ticket is bound to the exact action being approved.

Recommended fix:

Use a signer outside the agent workspace for anything stronger than a demo path. Bind tickets to a required operation derived from the requested tool, and enforce the declared `scope` during verification.

## Medium

### PSG-003: Documented tamper and trusted-launch protections are not actually wired for Codex yet

Impact: The skill tells the agent to treat instruction changes as tamper signals, but the Codex integration does not yet have the trusted-launch helper or automatic manifest verification needed to enforce that claim outside prompt text.

Evidence:

- `.agents/skills/prompt-sentinel-guardian/SKILL.md:24-39` instructs the agent to treat mid-session instruction changes as tamper and to rely on bundled references/scripts.
- `.agents/skills/prompt-sentinel-guardian/references/trusted-launch.md:7-11` says manifest verification should happen before the agent session begins.
- `AGENT_CORE/MANUAL_CODEX.md:49-51` explicitly notes that `AGENTS.md` alone is not sufficient because it is mutable instruction text.
- `AGENT_CORE/MANUAL_CODEX.md:61-66` lists a dedicated Codex trusted-launch helper and approval-service integration as future work.

Why this matters:

This leaves prompt/config tampering and startup TOCTOU in a weaker state than the skill description implies. An attacker who can alter instruction files still has a window before any independent Codex-side enforcement would notice.

Recommended fix:

Add a Codex-native trusted-launch path that verifies instruction manifests before privileged work begins, and make manifest mismatch handling part of the default startup flow rather than a manual convention.

### PSG-004: The documented helper-script approval flow is incomplete

Impact: The skill teaches users to use the helper scripts for approval-gated actions, but the wrapper that evaluates proposals cannot consume a capability ticket or public key, while the capability wrapper hard-codes a session id that does not match the evaluator's default behavior.

Evidence:

- `.agents/skills/prompt-sentinel-guardian/SKILL.md:27-39` points users to the wrapper scripts as the main workflow.
- `.agents/skills/prompt-sentinel-guardian/scripts/check_proposal.py:17-34` accepts only policy and proposal files and does not expose capability or public-key inputs.
- `.agents/skills/prompt-sentinel-guardian/scripts/request_capability.py:26-36` hard-codes `session_id = "codex-session"`.
- `AGENT_CORE/prompt-sentinel-core/src/prompt_sentinel/core/runtime.py:89-114` generates a random session id unless one is explicitly supplied.

Why this matters:

When the documented safe path is awkward or nonfunctional, operators tend to bypass it. In security tooling, friction can become a fail-open behavior.

Recommended fix:

Expose `--session-id`, `--public-key`, and `--capability` in the skill wrappers, and make the wrapper flow match the core CLI end to end.

## Residual strengths

- The skill correctly frames user text, repo content, and tool output as untrusted by default.
- The core runtime keeps policy decisions and tool execution separate.
- The audit chain, manifest utilities, and Claude hook integration show the intended architecture and can be reused for a stronger Codex integration.

## Testing gaps

- I did not find coverage for path normalization attacks against the allowlist.
- I did not find coverage that enforces capability `scope` semantics at verification time.
- I did not find Codex-specific tests for trusted launch or mid-session instruction tamper handling.

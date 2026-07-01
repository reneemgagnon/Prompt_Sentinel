# Hardening Design

Prompt_Sentinel should be treated as a trusted action boundary for coding agents.

## Trusted launch

Trusted launch means the firewall starts before privileged agent work.

### Startup sequence

1. Launch Prompt_Sentinel runtime.
2. Load policy bundle and key material.
3. Verify instruction-manifest hashes for mutable guidance files.
4. Start the agent session.
5. Enforce pre-tool checks on sensitive actions.
6. Admit MCP servers and tool schemas only after provenance, transport, and schema-hash checks.

## Why mutable instruction files are not enough

`CLAUDE.md`, `AGENTS.md`, and skills improve behavior, but they are not a root of
trust because they are mutable text. Prompt_Sentinel should therefore:

- verify their integrity with manifests or signatures
- alert when they change mid-session
- continue enforcing policy outside the model context

## Enforcement layers

1. Instruction layer
   `CLAUDE.md`, `AGENTS.md`, skill instructions
2. Deterministic enforcement layer
   hooks, plugin runtime, local CLI checks
3. Trusted policy layer
   sealed policy bundles and signed capabilities
4. Observability layer
   audit chain, alerts, threat vectors
5. MCP admission layer
   server allowlists, full-schema hash pins, STDIO launcher policy, cross-server data-flow controls

## Current scaffold mapping

- runtime and policy evaluation live in `prompt-sentinel-core`
- Codex helper scripts call the core runtime directly
- Claude hooks call the core runtime directly
- trusted launch checks manifest integrity when `.claude/prompt-sentinel.manifest.json` exists
- MCP admission manifests hash full tool descriptors and are verified against policy pins
- MCP calls can be authorized without local execution so hooks can guard host-managed tools
- alerts and threat-vector schemas live in `prompt-sentinel-control-plane`

## Safe federation loop

1. Detect a local event.
2. Emit alert.
3. Cluster alerts into vector classes.
4. Sanitize and approve shareable vectors.
5. Distribute updated policies or detection rules back to clients.

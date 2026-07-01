# Prompt_Sentinel

Prompt_Sentinel is a trusted action boundary for coding agents.

Instead of asking an LLM to protect itself, Prompt_Sentinel keeps policy,
approval, and audit decisions in trusted host-side code. The model can propose
actions; the runtime decides what is authorized, what needs a capability ticket,
what should be audited, and what must be denied.

## Why It Exists

Coding agents now act across files, shells, browsers, plugins, and MCP servers.
That creates a boundary problem: untrusted text can shape trusted actions.

Prompt_Sentinel separates:

- untrusted user, repository, retrieved, and tool-output text
- model-generated tool proposals
- host-side authorization
- trusted execution
- audit and alerting

The important rule is simple: a model-generated tool call is a proposal, not an
authorization.

## Product Shape

Prompt_Sentinel is organized around three layers:

- Core: local runtime, CLI, sealed policy handling, signed capability flow,
  local audit chain, and Codex/Claude adapters.
- Guard Add-On: managed policy packs, approval workflows, better denial UX,
  hosted audit search, and team presets.
- Enterprise: centralized policy distribution, approval services, SSO/RBAC,
  SIEM export, KMS/HSM integration, and long-retention compliance reporting.

This repo implements the Core runtime directly and includes Guard and Enterprise
scaffolding under `AGENT_CORE/`.

## Repository Map

- `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/`: authoritative
  installable runtime and CLI used by the root package.
- `AGENT_CORE/prompt-sentinel-codex/`: Codex plugin and skill distribution
  layer.
- `AGENT_CORE/prompt-sentinel-control-plane/`: enterprise control-plane
  skeleton and schemas.
- `AGENT_CORE/prompt-sentinel-core/`: standalone runtime copy kept in sync for
  packaging/distribution work.
- `V1_Prompt_Sentinel/prompt-sentinel-core/`: V1 package copy kept in sync for
  compatibility.
- `V3_LLM_Boundary_Crypto_end_to_end.py`: original end-to-end prototype kept as
  a runnable reference.
- `deployment_guide.md`: framework integration examples for LangChain,
  LlamaIndex, and FastAPI.

## Install

From the repo root:

```bash
pip install -e .
```

That installs the `prompt-sentinel` CLI while sourcing the runtime package from:

```text
AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src
```

## CLI Surface

Core policy and proposal checks:

```bash
prompt-sentinel check-proposal --policy policy.json --proposal proposal.json
prompt-sentinel check-proposal --policy policy.json --proposal proposal.json --execute
prompt-sentinel policy validate --policy policy.json
prompt-sentinel policy summary --policy policy.json
```

Signed capability flow:

```bash
prompt-sentinel issue-capability \
  --authority policy_engine \
  --audience local.prompt-sentinel \
  --operation approve_tool_call \
  --session-id sess-1 \
  --scope scope.json \
  --params params.json \
  --private-key keys/dev.key

prompt-sentinel verify-capability \
  --capability ticket.json \
  --public-key keys/dev.key.pub \
  --params params.json \
  --session-id sess-1 \
  --operation approve_tool_call \
  --scope scope.json
```

Audit inspection and export:

```bash
prompt-sentinel audit tail --audit-log prompt_sentinel.audit.jsonl --limit 10
prompt-sentinel audit export --audit-log prompt_sentinel.audit.jsonl --destination stdout
```

Backward-compatible aliases still exist for `policy-summary`,
`policy-validate`, `audit-tail`, and `audit-export`.

## MCP Poisoning Hardening

Prompt_Sentinel now includes an MCP admission and pinning layer. It treats MCP
server metadata, tool descriptors, tool schemas, tool arguments, and tool output
as untrusted input until the trusted runtime verifies them.

The MCP layer hardens against:

- poisoned tool descriptions or schemas that contain hidden instructions
- server rug-pulls where a tool changes after approval
- unapproved MCP servers or new tools appearing in `tools/list`
- unsafe STDIO server launches through shells or command injection
- cross-server data laundering from a trusted server into a third-party server
- tool output that attempts to trigger follow-up secret reads or exfiltration
- capability confusion by checking expected operation and scope

### MCP Admission Workflow

1. Capture the MCP server `tools/list` response to JSON.
2. Build an admission manifest from that response.
3. Review descriptor risks and schema hashes.
4. Pin the approved server, transport, tools, and schema hashes in policy.
5. Verify the manifest against policy before enabling the server.
6. Pass MCP tool-call metadata to Prompt_Sentinel at runtime.

Example:

```bash
prompt-sentinel mcp build-manifest \
  --tools finance.tools.json \
  --server-id finance \
  --publisher example \
  --transport streamable-http \
  --server-url https://finance.example/mcp \
  --output finance.manifest.json

prompt-sentinel mcp verify-manifest \
  --manifest finance.manifest.json \
  --policy policy.json
```

For STDIO MCP servers, the manifest and policy can also include the launch
command:

```bash
prompt-sentinel mcp build-manifest \
  --tools local.tools.json \
  --server-id local-search \
  --transport stdio \
  --command python \
  --arg -m \
  --arg local_search_server \
  --output local-search.manifest.json
```

STDIO launch policy denies shell usage, unsafe metacharacters, and commands that
are not allowlisted.

### MCP Policy Fields

MCP policy is expressed alongside normal tool permissions:

```json
{
  "tool_permissions": {
    "Bash": {
      "allowed_params": ["command", "cmd", "input", "stdin", "description"],
      "max_calls_per_session": 25
    }
  },
  "mcp_transport": {
    "stdio": {
      "allowed_commands": ["python", "python3", "node", "npx", "uvx"]
    }
  },
  "mcp_servers": {
    "finance": {
      "enabled": true,
      "transport": "streamable-http",
      "url": "https://finance.example/mcp",
      "publisher": "example",
      "trust_tier": "trusted",
      "tools": {
        "lookup_invoice": {
          "schema_hash": "REPLACE_WITH_MANIFEST_SCHEMA_HASH",
          "allowed_params": ["invoice_id"],
          "max_calls_per_session": 5
        }
      }
    },
    "enrichment": {
      "enabled": true,
      "transport": "streamable-http",
      "url": "https://enrich.example/mcp",
      "publisher": "third-party",
      "trust_tier": "third-party",
      "tools": {
        "lookup_invoice": {
          "schema_hash": "REPLACE_WITH_MANIFEST_SCHEMA_HASH",
          "allowed_params": ["invoice_id"]
        }
      }
    }
  },
  "mcp_data_flows": {
    "allowed": [
      {"from": "finance", "to": "enrichment"}
    ],
    "blocked": []
  }
}
```

By default, data from one MCP server cannot be passed into a third-party or
untrusted MCP server unless `mcp_data_flows.allowed` explicitly permits that
edge.

### Runtime MCP Calls

Host adapters should name MCP tools with one of the supported forms:

```text
mcp__<server_id>__<tool_name>
mcp:<server_id>:<tool_name>
```

MCP proposals should include metadata when available:

```json
{
  "tool": "mcp__finance__lookup_invoice",
  "params": {
    "invoice_id": "INV-1"
  },
  "metadata": {
    "schema_hash": "REPLACE_WITH_MANIFEST_SCHEMA_HASH",
    "input_origins": []
  }
}
```

`input_origins` is used for cross-server data-flow checks. Tool output is also
scanned for prompt-like follow-up instructions and sensitive payload patterns so
poisoned responses can be audited and reviewed.

## Policy Packs

The packaged runtime ships with starter policy packs:

- Core default:
  `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/default-policy.json`
- Guard team:
  `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/guard-team-policy.json`
- Enterprise default:
  `AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/policies/enterprise-default-policy.json`

These policies cover:

- tool allowlists and parameter allowlists
- path controls and quotas
- sensitive action classes
- approval scopes and operations
- MCP transport rules, server pins, and data-flow rules
- audit retention classes
- inheritance hooks for managed policy layering

## Runtime Guarantees

Prompt_Sentinel's strongest guarantees are host-enforced:

- sealed policy stays outside model context
- signed capability tickets bind approvals to session, audience, expiry, nonce,
  operation, scope, and exact parameters
- every tool decision is audit-chained
- MCP servers and tools are admitted only after manifest and policy checks
- policy denials are explicit instead of being silently worked around

## Hooks And Adapters

Claude and Codex adapters call the shared runtime helpers instead of duplicating
authorization logic. The Claude hook matcher now covers standard local tools and
MCP tool names:

```text
Bash|Edit|Write|mcp__.*|mcp:.*
```

Hooks evaluate proposals with `execute=false`, which lets the host deny unsafe
MCP/tool proposals without executing them locally. Trusted execution remains a
separate runtime step.

## Schemas

Installable schemas ship with the runtime package:

- policy bundle schema
- capability ticket schema
- audit export record schema

See:

```text
AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/src/prompt_sentinel/schemas/
```

Enterprise-facing schemas remain under:

```text
AGENT_CORE/prompt-sentinel-control-plane/schemas/
```

## Development

Run focused tests from the repo root:

```bash
python -m pytest AGENT_CORE/prompt-sentinel-claude/prompt-sentinel-core/tests -q
python -m pytest AGENT_CORE/prompt-sentinel-core/tests -q
python -m pytest V1_Prompt_Sentinel/prompt-sentinel-core/tests -q
```

The original V3 demo remains useful for concept validation:

```bash
python V3_LLM_Boundary_Crypto_end_to_end.py
```

## Current Security Posture

The project is now partially hardened against MCP poisoning in the places this
repo controls:

- MCP admission manifests pin full tool descriptors by hash.
- Policy verifies approved servers, transports, tools, and schema hashes.
- STDIO launch rules reject shell-style command execution.
- Runtime checks enforce MCP parameter allowlists and call quotas.
- Cross-server data flows are explicit.
- Tool output risk is audited.

Remaining hardening depends on host integration: the agent host must capture
`tools/list`, run manifest verification before enabling servers, pass schema
hash metadata on MCP calls, and keep Prompt_Sentinel outside model-controlled
state.
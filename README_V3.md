# V3 LLM Boundary Crypto (End-to-End)

A practical **host-enforced security boundary** for LLM-integrated chat apps.

This project is designed to demonstrate a core safety architecture:

- The **LLM is not a security boundary**
- The LLM may **propose** actions (tool calls), but only the **host runtime** can **authorize** and **execute**
- Authorization is enforced using **sealed policies**, **signed capability tickets**, and **tamper-evident audit logs**

> File: `V3_LLM_Boundary_Crypto_end_to_end.py`

---

## What this is (and is not)

### This is
- An end-to-end runnable reference implementation for:
  - sealed policy storage (AES-GCM)
  - strict host-side tool policy enforcement
  - signed capability tickets (Ed25519) with:
    - audience binding
    - expiry
    - nonce/replay defense
    - binding to proposed parameters via `params_hash`
  - hash-chained audit logging (tamper-evident JSONL)

### This is not
- A complete government deployment package (no KMS/HSM integration, no FIPS module selection, no centralized logging pipeline, no policy language like Rego).
- A “prompt trick” defense. The model can still be tricked; **the boundary prevents tricked output from becoming privileged execution**.

---

## Architecture (high level)

**Untrusted side**
- User text
- Model outputs (including structured tool proposals)

**Trusted side**
- Policy vault unsealing + enforcement
- Capability verification
- Tool execution
- Audit logs
- Session “facts” (identity/tenant/role), injected by the host

**Execution flow**
1. Host loads and unseals a **sealed policy bundle**.
2. LLM emits a structured proposal: `{"tool": "...", "params": {...}}`
3. Host validates proposal against policy:
   - tool allowlist
   - allowed params (deny unknown)
   - path allowlists (for file reads)
   - per-session quotas
4. If the operation is classified as sensitive, host also requires a **capability ticket**:
   - verified signature
   - expiry and audience checks
   - nonce replay defense
   - session binding (`session_id`)
   - `params_hash` binding (prevents “sign A, execute B”)
5. Host executes the tool via a trusted registry.
6. Host writes a hash-chained audit entry.

---

## Files produced by the demo

When you run the script, it creates:

- `demo_data/hello.txt`  
  Allowlisted test file for `file_read`.

- `.v3_keys/`  
  Local demo keys (NOT for production):
  - Ed25519 keys per authority
  - AES-256 key for policy vault

- `v3_audit_log.jsonl`  
  Hash-chained audit log entries (tamper-evident).

---

## Install

Python 3.10+ recommended.

```bash
pip install cryptography
```

---

## Run

```bash
python V3_LLM_Boundary_Crypto_end_to_end.py
```

You’ll get an interactive prompt:

```
proposal>
```

This prompt simulates “structured LLM output” (JSON).

---

## Try these proposals

### 1) Allowed file read (allowlisted)
```json
{"tool":"file_read","params":{"path":"demo_data/hello.txt"}}
```

### 2) Denied file read (blocked path)
```json
{"tool":"file_read","params":{"path":"/etc/passwd"}}
```

### 3) Sensitive export without capability (denied)
```json
{"tool":"sensitive_export","params":{"dataset":"patient_data","format":"json"}}
```

### 4) Issue a capability, then retry export
At the prompt:

```
/cap privacy_officer
```

Then re-run:

```json
{"tool":"sensitive_export","params":{"dataset":"patient_data","format":"json"}}
```

---

## Policy format (JSON)

The demo uses a simple JSON policy schema:

```json
{
  "tool_permissions": {
    "file_read": {
      "allowed_params": ["path"],
      "path_whitelist": ["demo_data/*", "/abs/path/to/demo_data/*"],
      "max_calls_per_session": 5
    }
  },
  "capability_required_tools": ["sensitive_export"],
  "meta": { "policy_name": "demo_policy" }
}
```

### Supported fields

#### `tool_permissions` (required)
Map of tool name → tool rules:

- `allowed_params`: list of param names permitted (unknown params are denied)
- `path_whitelist`: list of glob patterns (only enforced when present)
- `max_calls_per_session`: integer quota per session per tool

#### `capability_required_tools` (optional)
List of tools that require a valid signed capability ticket to execute.

> The demo also includes an optional heuristic: certain `file_read` paths containing strings like `patient` or `phi` can trigger a capability requirement.

---

## Capability tickets (signed “permission slips”)

A capability ticket is an authenticated approval from a trusted authority (e.g., “privacy_officer”), signed with Ed25519.

The ticket binds:
- **who** approved (authority + key_id)
- **where** it’s valid (audience)
- **when** it’s valid (iat/exp)
- **replay defense** (nonce)
- **which session** it is for (session_id)
- **what** it covers (operation + scope)
- **exact params** it approves (`params_hash`)

This prevents:
- replay across sessions
- reuse after expiry
- swapping the approved parameters at execution time

---

## Audit log (tamper-evident JSONL)

`v3_audit_log.jsonl` is append-only JSONL where each entry includes:
- `prev_hash` (the previous entry hash)
- `entry_hash` (sha256 hash over the entry contents + prev_hash)

This gives you a simple tamper-evident chain. In production you’d typically:
- ship logs to a centralized immutable store
- periodically sign/anchor hashes
- minimize sensitive content in logs (store hashes/refs, not PHI)

---

## Security properties you get

- **Prompt injection resistance at the execution layer**  
  Even if the model is socially engineered, it can’t exceed host policy.

- **No “policy leakage” to the model**  
  Policy is sealed; only a safe summary is exposed.

- **Replay-resistant privileged approvals**  
  Capability tickets include nonce + expiry and are verified on the host.

- **Scope and parameter binding**  
  Signed approvals are bound to the exact proposed parameters.

- **Quotas & least privilege**  
  Per-tool quotas and allowlists help constrain blast radius.

---

## Limitations (intentional)

This is a demo-focused reference implementation. The following are NOT production-ready:

- **Key storage**: `LocalKeyStore` writes keys to disk in plaintext.  
  Replace with KMS/HSM/TPM integration.

- **Replay cache**: in-memory only.  
  Replace with Redis/DB TTL store.

- **Policy language**: basic JSON rules.  
  Replace with a formal policy engine (e.g., OPA/Rego) for complex deployments.

- **Crypto posture**:
  - Ed25519 is not post-quantum
  - No hybrid signature mode is included in V3
  - No FIPS module selection guidance is included

---

## Hardening checklist (for real deployments)

1. **Replace LocalKeyStore** with KMS/HSM-backed key ops (signing & AEAD keys).
2. **Persist replay cache** with TTL in a shared store.
3. **Use a real policy engine** for complex authorization logic.
4. **Add identity/session attestation** (mTLS, JWT, device posture, etc.) and treat those as host “facts.”
5. **Centralize audit logs** (immutable store, SIEM integration, periodic anchoring/signing).
6. **Add explicit “break glass” flows** with multi-party approval and tight auditing.
7. **Threat model** around tool surfaces, retrieval, and data exfiltration paths.

---

## License

Not specified in this V3 file. If you intend government procurement usage, ensure the repository has a single, unambiguous license (and that it matches the headers in older files).

---

## Contact / intent

If you’re using this as a starting point for a government-facing prototype, the next step is usually a **deployment profile**:
- which network environments
- which data classes (e.g., Protected B / Secret)
- which key custody model
- which audit requirements
- which approval authorities and their capability scopes

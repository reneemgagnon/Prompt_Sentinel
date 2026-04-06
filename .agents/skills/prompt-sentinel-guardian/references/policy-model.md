# Policy Model

Prompt_Sentinel uses a host-enforced trust split:

- user input is untrusted
- model proposals are untrusted
- only host-side code may authorize or execute tools

The minimum product boundary should separate:

1. Policy storage
2. Proposal evaluation
3. Capability issuance and verification
4. Trusted tool execution
5. Audit logging
6. Tamper and alert handling

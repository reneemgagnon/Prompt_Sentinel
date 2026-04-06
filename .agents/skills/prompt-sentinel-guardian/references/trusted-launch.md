# Trusted Launch

Trusted launch means the guard layer starts before the agent begins privileged work.

## Startup order

1. Load Prompt_Sentinel runtime.
2. Verify policy bundle and key material.
3. Verify instruction-manifest hashes for `AGENTS.md`, skill files, and plugin config.
4. Start the agent session.
5. Evaluate sensitive proposals through the runtime before execution.

## Why this matters

Instruction files help, but they are not a root of trust. If they change, Prompt_Sentinel
should alert and require review instead of silently trusting the new instructions.

# Plugin Usage

This Claude package is a self-contained, shareable plugin. Everything needed
to enforce Prompt_Sentinel lives inside this folder.

## Layout

```
prompt-sentinel-claude/
  .claude-plugin/plugin.json   Plugin manifest (points to skills, agents, hooks)
  SKILL.md                     Skill definition (discovered at package root)
  CLAUDE.md                    Trust-model instructions
  prompt-sentinel-core/        Bundled runtime (no pip install needed)
    src/prompt_sentinel/       Core modules, policies, schemas
    pyproject.toml             Optional: pip-installable for CLI access
  hooks/                       Deterministic enforcement hooks
    hooks.json                 Hook wiring (uses ${CLAUDE_PLUGIN_ROOT})
    common.py                  Shared helpers (resolves core from package root)
    pre_tool_firewall.py       PreToolUse policy gate
    post_tool_use.py           PostToolUse audit
    trusted_launch.py          SessionStart manifest verification
    config_tamper_alert.py     Config/instruction change detection
    user_prompt_submit.py      Prompt-override pattern detection
    stop.py                    Session stop audit
  agents/                      Subagent definitions
    prompt-sentinel-guardian.md Guarded-review specialist
  policies/                    Claude-specific policy overrides
  manifests/                   Instruction manifest templates
  references/                  Background documentation
  settings.template.json       Template for project .claude/settings.json
```

## How it works

1. **Plugin discovery**: `.claude-plugin/plugin.json` tells Claude Code where
   skills, agents, and hooks live.
2. **Core resolution**: `hooks/common.py` resolves the bundled
   `prompt-sentinel-core/src` relative to the package root so no installation
   is required.
3. **Hook execution**: `hooks.json` uses `${CLAUDE_PLUGIN_ROOT}` so hooks
   resolve correctly regardless of where the plugin is installed.
4. **Policy cascade**: hooks check project-local policy first, then the
   bundled claude policy, then the core default policy.

## Sharing

Copy or symlink the entire `prompt-sentinel-claude/` folder into a target
project's `.claude/plugins/` directory. No pip install is needed for hook
enforcement. Optionally run `pip install ./prompt-sentinel-core` for CLI
access.

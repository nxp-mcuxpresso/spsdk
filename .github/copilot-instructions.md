# SPSDK Copilot Instructions

The canonical, tool-agnostic instructions for working on SPSDK now live in
**[AGENTS.md](../AGENTS.md)** at the repository root. That file covers:

- Project overview
- Build, test, and lint commands (`codecheck`, `pytest`)
- Architecture (package layout, device database, plugin system, CLI conventions)
- Key conventions (commit messages, file headers, docstrings, typing, testing)

GitHub Copilot (cloud agent, VS Code, and Copilot Chat) also reads
`AGENTS.md` automatically, so this file is kept only as a pointer for tools
that specifically look for `.github/copilot-instructions.md`. Update
`AGENTS.md`, not this file.

## Development Workflow Skill

For step-by-step guidance on resolving individual JIRA tasks in SPSDK
(branching, implementation, testing, code quality checks), see the
`spsdk-development-workflow` skill at
[`.claude/skills/spsdk-development-workflow/SKILL.md`](../.claude/skills/spsdk-development-workflow/SKILL.md).
This location is auto-discovered by Claude Code and opencode (via
`.opencode/opencode.json`) and is also readable directly by GitHub Copilot.

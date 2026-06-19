---
name: spsdk-development-workflow
description: >-
  Development workflow for the SPSDK project. Use this skill whenever working
  on an SPSDK Jira ticket, bug fix, feature, or any code change in the SPSDK
  repository. Provides step-by-step guidance for analysis, branching,
  implementation, testing, and code quality checks.
---

# SPSDK Development Workflow Skill

This skill documents the approved development process for SPSDK. Follow this workflow to ensure code quality, proper tracking, and consistency across the project.

## Server Access Information

### JIRA Server
- **URL**: https://jira.sw.nxp.com/
- **Project**: SPSDK
- **Ticket Format**: SPSDK-XXXX
- **Access Token**: Use environment variable `JIRA_TOKEN_FOR_COPILOT`

### Bitbucket Server
- **URL**: https://bitbucket.sw.nxp.com/
- **Repository**: PROVISIONING/spsdk
- **Access Token**: Use environment variable `BITBUCKET_TOKEN_FOR_COPILOT`

---

## Phase 1: Issue Analysis & Planning

### Checkpoint 1.1: Move Issue to Analysis — DO THIS FIRST
**As soon as you start working on a ticket, immediately move it to "Analysis" status in JIRA.**
This must be the very first action, before reading the issue or touching any code.

- [ ] **IMMEDIATELY** transition the JIRA ticket to **"Analysis"** status
- [ ] Read the full issue description, acceptance criteria, and any linked issues
- [ ] Review existing code/database related to the issue

### Checkpoint 1.2: Analyze if Code Change is Needed
- **Case A (No Code Changes Required)**:
  - [ ] Write detailed description of findings in JIRA comment
  - [ ] Move ticket directly to **"Review"** status
  - [ ] Request manual verification/closure from the assignee
  - [ ] DONE — no branch creation needed

- **Case B (Code Changes Required)**:
  - [ ] Document your analysis findings
  - [ ] Proceed to Phase 2: Branching & Implementation

---

## Phase 2: Branching & Setup

### Checkpoint 2.1: Create Feature Branch

Branch naming convention:
```raw
[SPSDK-xxxx] Problem Name
```

With optional prefix:
```raw
bugfix/[SPSDK-xxxx]-problem-name
feature/[SPSDK-xxxx]-problem-name
```

**Important**: Branch off from **MASTER** unless user explicitly specifies otherwise (e.g., NPI branches, integration branches).

```bash
git checkout -B "bugfix/SPSDK-1234-fix-smr-verification"
```

**Important**: When pushing a new branch, always use `-u` flag to set upstream tracking:

```bash
git push -u origin feature/SPSDK-1234-feature-name
```

Without `-u`, VS Code will still show "Publish Branch" even though the branch exists on remote, because no upstream tracking is configured.

### Checkpoint 2.2: Verify Environment
- [ ] Using local venv if it exists in repo, otherwise create clean environment:
  uv pip install -e ".[all]"
  uv pip install -r requirements-develop.txt --extra-index-url https://nl2-nxrm.sw.nxp.com/repository/spsdk_pypi/simple
- [ ] If working with plugins, also install them:
  # From SPSDK plugins repository
  # https://bitbucket.sw.nxp.com/projects/SPSDK/repos/spsdk_plugins/browse
- [ ] Verify installation: `python -c "import spsdk; print(spsdk.__version__)"`

---

## Phase 3: Implementation

### Checkpoint 3.1: Investigation & Root Cause Analysis
**DO NOT make quick fixes without understanding the root cause.**

- [ ] Locate the relevant code/database files
- [ ] Trace the execution flow for the reported issue
- [ ] Identify the **root cause**, not just symptoms
- [ ] Document findings in git commits as you progress

### Checkpoint 3.2: Leverage Existing SPSDK APIs
**Prefer reusing existing patterns and APIs over creating new ones.**

- [ ] Check `spsdk/utils/` for common utilities
- [ ] Review similar implementations in the codebase
- [ ] Follow established patterns for device database lookups
- [ ] Ask user before introducing new patterns/APIs

### Checkpoint 3.3: Data & Configuration Changes
**Never modify data (YAML, database) without explicit user confirmation.**

- [ ] Identify which data files need changes
- [ ] **ALWAYS ask the user**: 
  - "I found that data file `spsdk/data/devices/mcxn556s/cmpa.json` needs updates. Can you confirm this is the correct source of truth?"
  - "Should I modify the database or request the change from the hardware/documentation team?"
- [ ] Wait for user approval before applying changes
- [ ] Document the reason for data changes in commit message

### Checkpoint 3.4: Implementation Best Practices
- [ ] Use existing SPSDK APIs and utilities
- [ ] Follow code conventions from copilot-instructions.md
- [ ] Add type annotations (full typing required)
- [ ] Add comprehensive docstrings (Google-style)
- [ ] Think through all implications of changes:
  - What else might break?
  - Are there edge cases?
  - Does this affect other families/devices?

---

## Phase 4: Testing

### Checkpoint 4.1: Unit Tests for New Code
**For every new feature or public API, add corresponding unit tests.**

- [ ] Create test file matching source structure: `tests/<module>/test_<feature>.py`
- [ ] Add `conftest.py` fixtures if needed
- [ ] Create test data in `tests/<module>/data/` directory
- [ ] Tests should cover:
  - Happy path (success case)
  - Error cases and edge cases
  - Integration with existing code

### Checkpoint 4.2: Verify Test Coverage
- [ ] Run tests locally: `pytest tests/<relevant_path>/`
- [ ] Check coverage is reasonable for new code
- [ ] All tests pass before moving to linting

---

## Phase 5: Code Quality Checks

### Checkpoint 5.1: Quick Lint Check (Fast Feedback Loop)
For first quick validation use RUFF only:
```bash
codecheck -c ruff -f
```
This auto-fixes most issues and provides immediate feedback.

### Checkpoint 5.2: Full Codecheck
Run complete code quality check:
```bash
codecheck -s -o reports
```

---

## General Guidelines

### Communication & Decisions
- **Ask before implementing major changes** — Don't assume, verify with user
- **Prefer discussion over quick fixes** — Take time to understand the problem fully
- **Document your reasoning** — In commits, comments, and code
- **Escalate uncertainty** — Ask user if you're unsure about design/approach

### Common Pitfalls to Avoid
❌ **Don't**:
- Modify data files without user approval
- Make quick one-line fixes without understanding root cause
- Run linters directly (e.g., `black` instead of `codecheck`)
- Forget type annotations (mypy is strict)
- Create commits without JIRA ticket prefix
- Assume device database structure — verify first
- Skip tests for "simple" changes
- Leave temporary files/directories in the workspace (e.g., generated templates, test outputs)

✅ **Do**:
- **Move ticket to "Analysis" immediately when starting work**
- Ask questions when unsure
- Use existing APIs and patterns
- Run full `codecheck` before PR
- Write comprehensive tests
- Format commits with ticket reference
- Document complex logic
- Consider side effects and implications
- **Clean up after yourself** — delete any temporary files, generated templates, test outputs, or scratch directories created during investigation. Use `Remove-Item -Recurse -Force` for directories

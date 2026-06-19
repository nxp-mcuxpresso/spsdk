# SPSDK Copilot Instructions

## Project Overview

SPSDK (Secure Provisioning SDK) is an NXP open-source Python library and CLI toolkit for connecting with NXP MCU/MPU devices for secure provisioning, firmware signing, key management, and programming. It supports a wide family of NXP chips via a family-aware database system.

## Build, Test, and Lint Commands

### Install
```bash
uv pip install ".[all]"
pip install -r requirements-develop.txt
```

### Run all checks (pytest + linters)
```bash
codecheck -s -o reports
```

### Run tests only
```bash
pytest tests/
```

### Run a single test file
```bash
pytest tests/pfr/test_pfr.py
```

### Run a single test function
```bash
pytest tests/pfr/test_pfr.py::test_generate_cmpa
```

### Run tests matching a keyword
```bash
pytest -k "test_rsa"
```

### Run individual linters
Always use `codecheck -c <name>` to run a single linter — do **not** invoke linters directly (e.g. `black`, `pylint`, `mypy`). This ensures the same configuration and plugins as CI.

```bash
codecheck -c black          # check formatting
codecheck -c isort          # check import order
codecheck -c pylint         # static analysis
codecheck -c mypy           # type checking
codecheck -c ruff           # fast linter
codecheck -c pydocstyle     # docstring style
codecheck -c copyright      # file header check
codecheck -c radon_d        # cyclomatic complexity (fails on D or worse)
codecheck -c bandit         # security scan
codecheck -c cspell         # spell check
```

Some linters support auto-fixing with `-f` / `--fix`:
```bash
codecheck -c black -f       # auto-format code
codecheck -c isort -f       # auto-sort imports
codecheck -c ruff -f        # auto-fix ruff issues
```

Available checker names: `pytest`, `gitcov`, `pylint`, `mypy`, `dependencies`, `pydocstyle`, `radon_c`, `radon_d`, `radon_mi`, `radon_hal`, `radon_raw`, `black`, `isort`, `copyright`, `py_headers`, `cyclic`, `cspell`, `bandit`, `lychee`, `ruff`, `black_nb`, `isort_nb`, `jupyter`.

`codecheck` (from `nxp_codecheck`) orchestrates all checks: pytest, pylint, mypy, ruff, black, isort, pydocstyle, bandit, copyright, cspell, and more. See `[tool.nxp_codecheck]` in `pyproject.toml` for the full list.

## Architecture

### Package Layout
- `spsdk/apps/` — Click-based CLI entry points, one file per tool (e.g., `blhost.py`, `nxpimage.py`). Each app has a `safe_main()` function decorated with `@catch_spsdk_error`, which is the `[project.scripts]` entry point.
- `spsdk/utils/` — Core infrastructure: database, config, schema validation, registers, plugin manager, misc helpers.
- `spsdk/crypto/` — Cryptography: keys, certs, hash, signature providers.
- `spsdk/mboot/`, `spsdk/sdp/`, `spsdk/ele/` etc. — Protocol implementations per NXP device family/interface.
- `spsdk/data/` — YAML device database. Each device has `spsdk/data/devices/<chip>/database.yaml` with memory maps, feature flags, and configuration.
- `spsdk/data/common/` — Shared defaults and schemas (`database_defaults.yaml`, JSON schemas).

### Device Database
All device-specific behavior is driven by YAML files in `spsdk/data/devices/<family>/database.yaml`. `DatabaseManager` (singleton) loads and caches these. Features are resolved via `spsdk/utils/family.py` and `FamilyRevision`. If a device aliases another (`alias: lpc5506`), it inherits that device's configuration.

### ConfigBaseClass Pattern
Most SDK features (PFR, image, fuses, etc.) implement the `ConfigBaseClass` from `spsdk/utils/abstract_features.py`. Implementors must provide:
- `FEATURE` class variable (matches a key in device database features)
- `get_validation_schemas(family)` → list of JSON schema dicts
- `load_from_config(config)` → `Self`
- `verify()` → `Verifier`
- `get_config_template(family)` → YAML string

This pattern ensures every feature can validate its config, generate templates, and report what families it supports.

### Plugin / Service Provider System
Plugins are discovered via setuptools entry points or file paths. Plugin types: `spsdk.sp` (signature providers), `spsdk.device.interface`, `spsdk.debug_probe`, `spsdk.wpc.service`, `spsdk.sb31kdp`, `spsdk.pkp`. See `spsdk/utils/plugins.py`.

Extensible components (e.g., signature providers, WPC services) follow the `ServiceProvider` pattern from `spsdk/utils/service_provider.py`: define a base class extending `ServiceProvider`, implement subclasses with an `identifier` attribute, and register via setuptools entry points. The plugin system auto-discovers them at runtime.

### CLI Conventions
- All apps use Click with `CommandsTreeGroup` (supports command tree display).
- Common options are in `spsdk/apps/utils/common_cli_options.py`: `spsdk_family_option`, `spsdk_mboot_interface`, `spsdk_apps_common_options`.
- Every CLI entry point ends with:
  @catch_spsdk_error
  def safe_main() -> None:
      sys.exit(main())
```raw
- `INT` is a custom Click param type supporting `0x`, `0b`, `0o` prefixes and `_` separators.

### Configuration & Schema Validation
- Configs are loaded with `spsdk/utils/config.py` (`Config` class, wraps ruamel.yaml).
- Validation uses `fastjsonschema` via `spsdk/utils/schema_validator.py`.
- YAML configs use commented output (`CommentedConfig`) to preserve inline documentation in templates.

## Key Conventions

### Commit Messages
Commit messages must start with a JIRA ticket reference extracted from the current branch name:
- Branch `bugfix/SPSDK-1234-fix-something` → prefix `[SPSDK-1234]`
- Branch `feature/SPSDK-5678-add-support` → prefix `[SPSDK-5678]`
- If the branch name contains no `SPSDK-NNNN` pattern, omit the prefix.

```
[SPSDK-1234] Short description of what changed

Optional longer explanation of why the change was made,
what problem it solves, and any non-obvious side effects.

To get the current branch name: `git rev-parse --abbrev-ref HEAD`

### File Headers
Every Python file must have this header (year range should include current year):
```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright <year>-<year> NXP
#
# SPDX-License-Identifier: BSD-3-Clause
```
The `py_headers` and `copyright` checks enforce this.

### Docstrings
Google-style docstrings enforced by `pydocstyle`. Include `:param name:` and `:return:` lines. Module docstrings are required.

### Enumerations
Use `SpsdkEnum` (from `spsdk/utils/spsdk_enum.py`) instead of standard `Enum`. Members are `(tag: int, label: str, description: str)` tuples.

### Exceptions
All custom exceptions inherit from `SPSDKError` (in `spsdk/exceptions.py`). Use specific subclasses like `SPSDKValueError`, `SPSDKKeyError`, `SPSDKTypeError`. CLI-level errors use `SPSDKAppError`.

### Type Annotations
Full type annotations required (`mypy` with `disallow_untyped_defs = true`). Use `from typing_extensions import Self` for methods returning `Self`.

### Testing
- Tests mirror the source structure: `tests/pfr/` tests `spsdk/pfr/`.
- Each test subdirectory has a `data/` folder with fixtures.
- Use the `data_dir` fixture (from `tests/conftest.py`) to get the path to `tests/<module>/data/`.
- Use the `cli_runner` fixture (`tests/cli_runner.CliRunner`) for CLI tests. It wraps Click's CliRunner and auto-validates exit codes:
  def test_something(cli_runner):
      result = cli_runner.invoke(main, ["--help"])  # expects exit code 0
      result = cli_runner.invoke(main, ["bad"], expected_code=1)
```raw
- `SPSDK_ENV_CACHE_DISABLED=False` and `SPSDK_DEBUG_LOGGING_DISABLED=True` are set globally in conftest.

### Line Length
100 characters (black, isort both configured to 100).

### Pylint
Pylint is configured via `.pylintrc` with custom plugins: `docparams`, `no_self_use`, and `spsdk_pylint_plugins` (from `spsdk-pylint-plugins` package). Always run via `codecheck -c pylint` to ensure the correct plugin configuration is loaded.

## Workflow for Resolving JIRA Tasks

For step-by-step guidance on resolving individual JIRA tasks in SPSDK, refer to **[SKILL_SPSDK_DEVELOPMENT_WORKFLOW.md](SKILL_SPSDK_DEVELOPMENT_WORKFLOW.md)**.

This document covers the complete workflow from issue analysis through implementation, testing, and code quality checks:
- **Phase 1**: Issue Analysis & Planning
- **Phase 2**: Branching & Environment Setup
- **Phase 3**: Implementation Best Practices
- **Phase 4**: Testing & Coverage
- **Phase 5**: Code Quality Checks
- **General Guidelines**: Common pitfalls and best practices

```
## Workflow for Resolving JIRA Tasks

For step-by-step guidance on resolving individual JIRA tasks in SPSDK, refer to **[SKILL_SPSDK_DEVELOPMENT_WORKFLOW.md](SKILL_SPSDK_DEVELOPMENT_WORKFLOW.md)**.

This document covers the complete workflow from issue analysis through implementation, testing, and code quality checks:
- **Phase 1**: Issue Analysis & Planning
- **Phase 2**: Branching & Environment Setup
- **Phase 3**: Implementation Best Practices
- **Phase 4**: Testing & Coverage
- **Phase 5**: Code Quality Checks
- **General Guidelines**: Common pitfalls and best practices
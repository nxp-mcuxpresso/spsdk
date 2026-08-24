#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Shared context loader for docstring updater tools.

Loads project-specific context and guidelines from docstring_context.yaml
so the same configuration can be reused across method, class, and module
docstring updaters — and easily adapted for other NXP projects.
"""

import os

import yaml

CONTEXT_FILE = os.path.join(os.path.dirname(__file__), "docstring_context.yaml")


def load_docstring_context(context_type: str, context_file: str | None = None) -> str:
    """Load project context and type-specific guidelines from YAML configuration.

    :param context_type: The type of guidelines to load: "method", "class", or "module".
    :param context_file: Optional path to a custom context YAML file.
        Defaults to docstring_context.yaml in the same directory.
    :return: Combined context string with project info and type-specific guidelines.
    :raises FileNotFoundError: If the context YAML file does not exist.
    :raises KeyError: If the requested context_type guidelines are missing from the file.
    """
    path = context_file or CONTEXT_FILE
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    guidelines_key = f"{context_type}_guidelines"
    if guidelines_key not in config:
        raise KeyError(
            f"Missing '{guidelines_key}' in {path}. " f"Available keys: {list(config.keys())}"
        )

    return config.get("project_context", "") + "\n" + config[guidelines_key]

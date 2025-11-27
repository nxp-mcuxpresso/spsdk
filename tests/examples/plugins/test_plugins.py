#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK plugin template testing utilities.

This module provides test functionality for validating SPSDK plugin templates
and cookiecutter-based code generation. It ensures that plugin templates
can be properly instantiated and function correctly.
"""

import os
from typing import Any

import pytest
from cookiecutter.main import cookiecutter

TEMPLATES = [
    "cookiecutter-spsdk-debug-probe-plugin.zip",
    "cookiecutter-spsdk-device-interface-plugin.zip",
    "cookiecutter-spsdk-sp-plugin.zip",
    "cookiecutter-spsdk-wpc-service-plugin.zip",
]


@pytest.mark.parametrize("template", TEMPLATES)
def test_cookiecutter_templates(pytestconfig: Any, tmpdir: str, template: str) -> None:
    """Test cookiecutter template generation and validation.

    This test function validates that cookiecutter templates can be successfully
    generated and contain the expected project structure files.

    :param pytestconfig: Pytest configuration object containing test session information.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param template: Name of the template directory to test.
    :raises AssertionError: If the generated project directory or pyproject.toml file doesn't exist.
    """
    template_path = pytestconfig.rootpath.joinpath("examples", "plugins", "templates", template)
    project_dir = cookiecutter(
        str(template_path),
        no_input=True,
        output_dir=str(tmpdir),
    )
    assert os.path.isdir(project_dir)
    assert os.path.isfile(os.path.join(project_dir, "pyproject.toml"))

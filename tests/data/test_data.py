#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK test data validation module.

This module contains tests for validating SPSDK data files and their formats,
ensuring data integrity and schema compliance across the project.
"""

from pathlib import Path

import pytest

from .validate_json_files import JsonSchemaValidator

_CURRENT_DIR = Path(__file__).parent
_SCHEMAS_DIR = _CURRENT_DIR / "json_schemas"
_VALIDATOR = JsonSchemaValidator(root_dir=".", schemas_dir=str(_SCHEMAS_DIR))


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_spsdk_data_registers_format_parametrized(test_path: str) -> None:
    """Test SPSDK data format for JSON registers/fuses definition with parametrization.

    This test validates JSON files in the specified SPSDK data directories against their respective schemas.
    It uses JsonSchemaValidator to check all JSON files in the given path and reports any validation errors.

    :param test_path: Relative path to the directory containing JSON files to validate.
    :raises AssertionError: When one or more JSON files fail schema validation.
    """
    full_path = _CURRENT_DIR / test_path

    if not full_path.exists():
        pytest.skip(f"Test path {full_path} does not exist")

    results = _VALIDATOR.validate_all(search_dir=str(full_path))

    invalid_files = []
    for file_path, result in results.items():
        if not result["valid"]:
            invalid_files.append(f"{file_path}: {result['error']}")

    assert not invalid_files, f"Invalid JSON files found in {full_path}:\n" + "\n".join(
        invalid_files
    )

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest
from pathlib import Path
from .validate_json_files import JsonSchemaValidator


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_spsdk_data_registers_format_parametrized(test_path):
    """Test SPSDK data format for JSON registers/fuses definition with parametrization.

    This test validates JSON files in the specified SPSDK data directories against their respective schemas.
    """
    # Get the current file's directory
    current_dir = Path(__file__).parent

    # Path to the json schemas folder
    schemas_dir = current_dir / "json_schemas"

    # Create validator with the schemas directory
    validator = JsonSchemaValidator(root_dir=".", schemas_dir=str(schemas_dir))

    # Resolve the test path
    full_path = current_dir / test_path

    if not full_path.exists():
        pytest.skip(f"Test path {full_path} does not exist")

    # Validate all JSON files in the path
    results = validator.validate_all(search_dir=str(full_path))

    # Check results
    invalid_files = []
    for file_path, result in results.items():
        if not result["valid"]:
            invalid_files.append(f"{file_path}: {result['error']}")

    # Assert all files are valid
    assert not invalid_files, f"Invalid JSON files found in {full_path}:\n" + "\n".join(
        invalid_files
    )

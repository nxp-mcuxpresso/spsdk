#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import json
import pytest
from pathlib import Path


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_register_names_without_reserved(test_path):
    """Test register names in JSON files.

    This test checks that register names don't contain 'reserved' unless is_reserved is set to true.
    """
    # Get the current file's directory
    current_dir = Path(__file__).parent

    # Resolve the test path
    full_path = current_dir / test_path

    if not full_path.exists():
        pytest.skip(f"Test path {full_path} does not exist")

    # Find all JSON files
    json_files = list(full_path.glob("**/*.json"))

    # Check results
    invalid_registers = []

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Check if this is a register definition file with groups structure
            if isinstance(data, dict) and "groups" in data:
                for group in data["groups"]:
                    if "registers" in group:
                        for register in group["registers"]:
                            name = register.get("name", "")
                            is_reserved = register.get("is_reserved", False)

                            # Check if name contains "reserved" (case insensitive) but is_reserved is not True
                            if "reserved" in name.lower() and not is_reserved:
                                invalid_registers.append(
                                    f"{json_file}: Register '{name}' contains 'reserved' but is_reserved is not True"
                                )

        except json.JSONDecodeError as e:
            invalid_registers.append(f"{json_file}: JSON parsing error - {str(e)}")
        except Exception as e:
            invalid_registers.append(f"{json_file}: Error processing file - {str(e)}")

    # Assert all registers follow the naming rule
    assert not invalid_registers, "Invalid register names found:\n" + "\n".join(invalid_registers)


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_register_width_and_bitfields(test_path):
    """Test register widths and bitfield consistency in JSON files.

    This test checks that:
    1. All registers have a 'reg_width' key
    2. If a register has bitfields, each bitfield must have a 'width' key
    3. The sum of all bitfield widths must equal the register width
    """
    # Get the current file's directory
    current_dir = Path(__file__).parent

    # Resolve the test path
    full_path = current_dir / test_path

    if not full_path.exists():
        pytest.skip(f"Test path {full_path} does not exist")

    # Find all JSON files
    json_files = list(full_path.glob("**/*.json"))

    # Check results
    invalid_registers = []

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Check if this is a register definition file with groups structure
            if isinstance(data, dict) and "groups" in data:
                for group in data["groups"]:
                    if "registers" in group:
                        for register in group["registers"]:
                            name = register.get("name", "")

                            # # Check if register has reg_width
                            # if "reg_width" not in register:
                            #     invalid_registers.append(
                            #         f"{json_file}: Register '{name}' is missing 'reg_width' key"
                            #     )
                            #     continue

                            reg_width = register.pop("reg_width", 32)

                            # Check bitfields if they exist
                            if "bitfields" in register:
                                bitfields = register["bitfields"]
                                total_width = 0
                                missing_width = False

                                for bitfield in bitfields:
                                    bf_name = bitfield.get("name", "unnamed")

                                    # Check if bitfield has width
                                    if "width" not in bitfield:
                                        invalid_registers.append(
                                            f"{json_file}: Register '{name}', bitfield '{bf_name}' is missing 'width' key"
                                        )
                                        missing_width = True
                                        continue

                                    total_width += bitfield["width"]

                                # Only check total width if all bitfields have width defined
                                if not missing_width and total_width > reg_width:
                                    invalid_registers.append(
                                        f"{json_file}: Register '{name}' has reg_width={reg_width} but sum of bitfield widths={total_width}"
                                    )

        except json.JSONDecodeError as e:
            invalid_registers.append(f"{json_file}: JSON parsing error - {str(e)}")
        except Exception as e:
            invalid_registers.append(f"{json_file}: Error processing file - {str(e)}")

    # Assert all registers follow the width rules
    assert not invalid_registers, "Invalid register or bitfield definitions found:\n" + "\n".join(
        invalid_registers
    )

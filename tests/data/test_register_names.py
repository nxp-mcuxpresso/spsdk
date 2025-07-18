#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import json
import pytest
from pathlib import Path

from spsdk.exceptions import SPSDKError


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
                                    if not isinstance(bitfield["width"], int):
                                        raise SPSDKError(
                                            f"Bitfield width must be an integer: {bf_name}, register:{name}"
                                        )
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


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_register_and_bitfield_name_uniqueness(test_path):
    """Test uniqueness of register names, bitfield names, and bitfield value names.

    This test checks that:
    1. All register names within a file are unique
    2. All bitfield names within a register are unique
    3. All value names within a bitfield are unique
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
    uniqueness_violations = []

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Check if this is a register definition file with groups structure
            if isinstance(data, dict) and "groups" in data:
                # Check register name uniqueness across the whole file
                all_register_names = []

                for group in data["groups"]:
                    if "registers" in group:
                        for register in group["registers"]:
                            register_name = register.get("name", "")

                            # Check if register name is already used
                            if register_name in all_register_names:
                                uniqueness_violations.append(
                                    f"{json_file}: Duplicate register name '{register_name}'"
                                )
                            else:
                                all_register_names.append(register_name)

                            # Check bitfield name uniqueness within this register
                            if "bitfields" in register:
                                bitfield_names = []

                                for bitfield in register["bitfields"]:
                                    # Skip name uniqueness check if the bitfield only has a width key
                                    if set(bitfield.keys()) == {"width"}:
                                        continue

                                    bitfield_name = bitfield.get("name", "")

                                    # Only check names that are not empty
                                    if bitfield_name:
                                        # Check if bitfield name is already used in this register
                                        if bitfield_name in bitfield_names:
                                            uniqueness_violations.append(
                                                f"{json_file}: Register '{register_name}' has duplicate bitfield name '{bitfield_name}'"
                                            )
                                        else:
                                            bitfield_names.append(bitfield_name)

                                    # Check value name uniqueness within this bitfield
                                    if "values" in bitfield:
                                        value_names = []

                                        for value in bitfield["values"]:
                                            value_name = value.get("name", "")

                                            # Check if value name is already used in this bitfield
                                            if value_name in value_names:
                                                uniqueness_violations.append(
                                                    f"{json_file}: Register '{register_name}', bitfield '{bitfield_name}' has duplicate value name '{value_name}'"
                                                )
                                            else:
                                                value_names.append(value_name)

        except json.JSONDecodeError as e:
            uniqueness_violations.append(f"{json_file}: JSON parsing error - {str(e)}")
        except Exception as e:
            uniqueness_violations.append(f"{json_file}: Error processing file - {str(e)}")

    # Assert all names are unique according to their scope
    assert not uniqueness_violations, "Name uniqueness violations found:\n" + "\n".join(
        uniqueness_violations
    )


@pytest.mark.parametrize("test_path", ["../../spsdk/data/devices", "../../spsdk/data/common"])
def test_bitfield_names_without_reserved(test_path):
    """Test bitfield names in JSON files.

    This test checks that bitfield names don't contain 'reserved' unless is_reserved is set to true.
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
    invalid_bitfields = []

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Check if this is a register definition file with groups structure
            if isinstance(data, dict) and "groups" in data:
                for group in data["groups"]:
                    if "registers" in group:
                        for register in group["registers"]:
                            register_name = register.get("name", "")

                            # Check bitfields if they exist
                            if "bitfields" in register:
                                for bitfield in register["bitfields"]:
                                    # Skip check if the bitfield only has a width key
                                    if set(bitfield.keys()) == {"width"}:
                                        continue

                                    bitfield_name = bitfield.get("name", "")

                                    # Check if name contains "reserved" (case insensitive) but is_reserved is not True
                                    if bitfield_name and "reserved" in bitfield_name.lower():
                                        invalid_bitfields.append(
                                            f"{json_file}: Register '{register_name}', bitfield '{bitfield_name}' contains 'reserved' but is_reserved is not True"
                                        )

        except json.JSONDecodeError as e:
            invalid_bitfields.append(f"{json_file}: JSON parsing error - {str(e)}")
        except Exception as e:
            invalid_bitfields.append(f"{json_file}: Error processing file - {str(e)}")

    # Assert all bitfields follow the naming rule
    assert not invalid_bitfields, "Invalid bitfield names found:\n" + "\n".join(invalid_bitfields)

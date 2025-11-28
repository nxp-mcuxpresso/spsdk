#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK register configuration validation test utilities.

This module provides comprehensive validation functions for testing register
configurations used in SPSDK. It validates various aspects of register
definitions including naming conventions, bitfield constraints, access rights,
and data consistency across different register types.
"""

import json
import os
import re
from pathlib import Path
from typing import Optional

import pytest


def validate_register_names_without_reserved(data: dict) -> dict:
    """Validate register names with 'reserved' have is_reserved=true.

    This function checks if registers containing 'reserved' in their name have the
    is_reserved flag properly set to True. It traverses through groups and their
    registers to identify naming inconsistencies.

    :param data: Dictionary containing register groups and their register definitions.
    :return: Dictionary mapping register names to error descriptions, empty if no errors found.
    """
    errors: dict[str, str] = {}

    if isinstance(data, dict) and "groups" in data:
        for group in data["groups"]:
            if "registers" in group:
                for register in group["registers"]:
                    name = register.get("name", "")
                    is_reserved = register.get("is_reserved", False)

                    if "reserved" in name.lower() and not is_reserved:
                        errors[name] = (
                            f"Register '{name}' contains 'reserved' but is_reserved is not True"
                        )

    return errors


def validate_register_width_and_bitfields(data: dict) -> dict:
    """Validate register widths and bitfield consistency.

    Analyzes register configuration data to ensure that bitfield widths are properly
    defined and their sum matches the declared register width. Validates both
    individual bitfield properties and overall register consistency.

    :param data: Dictionary containing register configuration with groups, registers, and bitfields structure.
    :return: Dictionary mapping register names or bitfield names to error descriptions, empty if no errors found.
    """
    errors: dict[str, str] = {}

    if isinstance(data, dict) and "groups" in data:
        for group in data["groups"]:
            if "registers" in group:
                for register in group["registers"]:
                    name = register.get("name", "")
                    reg_width = register.get("reg_width", 32)

                    if "bitfields" in register:
                        bitfields = register["bitfields"]
                        total_width = 0
                        missing_width = False

                        for bitfield in bitfields:
                            bf_name = bitfield.get("name", "unnamed")
                            bf_key = f"{name}.{bf_name}"

                            if "width" not in bitfield:
                                errors[bf_key] = (
                                    f"Register '{name}', bitfield '{bf_name}' is missing 'width' key"
                                )
                                missing_width = True
                                continue

                            if not isinstance(bitfield["width"], int):
                                errors[bf_key] = (
                                    f"Bitfield width must be an integer: {bf_name}, register:{name}"
                                )
                                missing_width = True
                                continue

                            total_width += bitfield["width"]
                        if not missing_width and total_width != reg_width:
                            if total_width > reg_width:
                                errors[name] = (
                                    f"Register '{name}' has reg_width={reg_width} but sum of bitfield "
                                    f"widths={total_width} (exceeds register width)"
                                )
                            else:
                                errors[name] = (
                                    f"Register '{name}' has reg_width={reg_width} but sum of bitfield "
                                    f"widths={total_width} (does not match register width)"
                                )
    return errors


def validate_register_and_bitfield_name_uniqueness(data: dict) -> dict:
    """Validate uniqueness of register names, bitfield names, and bitfield value names.

    Also validates uniqueness of deprecated_names in combination with standard names.
    Checks for duplicate register names across the entire data structure, duplicate
    bitfield names within each register, and duplicate value names within each bitfield.

    :param data: Dictionary containing register groups with registers, bitfields, and values structure.
    :return: Dictionary with validation errors where keys are error identifiers
        and values are error descriptions, empty dict if no errors found.
    """
    errors = {}

    if isinstance(data, dict) and "groups" in data:
        # Check register name uniqueness across the whole file
        all_register_names = []

        for group in data["groups"]:
            if "registers" in group:
                for register in group["registers"]:
                    register_name = register.get("name", "")

                    # Check if register name is already used
                    if register_name in all_register_names:
                        errors[f"duplicate_register_{register_name}"] = (
                            f"Duplicate register name '{register_name}'"
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
                                bf_key = f"{register_name}.{bitfield_name}"

                                # Check if bitfield name is already used in this register
                                if bitfield_name in bitfield_names:
                                    errors[f"duplicate_bitfield_{bf_key}"] = (
                                        f"Register '{register_name}' has duplicate bitfield name '{bitfield_name}'"
                                    )
                                else:
                                    bitfield_names.append(bitfield_name)

                            # Check value name uniqueness within this bitfield (including deprecated_names)
                            if "values" in bitfield:
                                value_names = []
                                all_value_names = []  # Combined standard + backward names

                                for value in bitfield["values"]:
                                    value_name = value.get("name", "")
                                    val_key = f"{register_name}.{bitfield_name}.{value_name}"

                                    # Check if value name is already used in this bitfield
                                    if value_name in value_names:
                                        errors[f"duplicate_value_{val_key}"] = (
                                            f"Register '{register_name}', bitfield '{bitfield_name}' "
                                            f"has duplicate value name '{value_name}'"
                                        )
                                    else:
                                        value_names.append(value_name)
                                        all_value_names.append(value_name)

                                    # Check deprecated_names uniqueness
                                    if "deprecated_names" in value and isinstance(
                                        value["deprecated_names"], list
                                    ):
                                        for backward_name in value["deprecated_names"]:
                                            if not isinstance(backward_name, str):
                                                continue

                                            backward_key = (
                                                f"{register_name}.{bitfield_name}.{backward_name}"
                                            )

                                            # Check if backward name conflicts with any existing
                                            # name (standard or backward)
                                            if backward_name in all_value_names:
                                                errors[
                                                    f"duplicate_backward_name_{backward_key}"
                                                ] = (
                                                    f"Register '{register_name}', bitfield '{bitfield_name}' "
                                                    f"has backward name '{backward_name}' "
                                                    "that conflicts with existing value name"
                                                )
                                            else:
                                                all_value_names.append(backward_name)

    return errors


def validate_bitfield_names_without_reserved(data: dict) -> dict:
    """Validate bitfield names don't contain 'reserved' unless is_reserved is set to true.

    This method checks all bitfields in register groups to ensure that bitfield names
    containing 'reserved' (case insensitive) have the is_reserved flag properly set.
    Bitfields with only a width key are skipped during validation.

    :param data: Dictionary containing register groups with registers and bitfields structure.
    :return: Dictionary mapping register_name.bitfield_name to error descriptions, empty if no errors found.
    """
    errors: dict[str, str] = {}

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
                                bf_key = f"{register_name}.{bitfield_name}"
                                errors[bf_key] = (
                                    f"Register '{register_name}', bitfield '{bitfield_name}' "
                                    "contains 'reserved' but is_reserved is not True"
                                )

    return errors


def validate_register_and_bitfield_names_no_double_spaces(data: dict) -> dict:
    """Validate register and bitfield names don't contain double spaces.

    This function traverses through the data structure containing register groups
    and validates that neither register names nor bitfield names contain consecutive
    spaces, which could indicate formatting issues or data corruption.

    :param data: Dictionary containing register configuration with groups, registers, and bitfields.
    :return: Dictionary mapping problematic names to error descriptions, empty if no errors found.
    """

    errors: dict[str, str] = {}
    double_space = "  "

    if isinstance(data, dict) and "groups" in data:
        for group in data["groups"]:
            if "registers" in group:
                for register in group["registers"]:
                    register_name = register.get("name", "")

                    # Check if register name contains double spaces
                    if double_space in register_name:
                        errors[register_name] = f"Register '{register_name}' contains double spaces"

                    # Check bitfields if they exist
                    if "bitfields" in register:
                        for bitfield in register["bitfields"]:
                            # Skip check if the bitfield only has a width key (unnamed/reserved bitfields)
                            if set(bitfield.keys()) == {"width"}:
                                continue

                            bitfield_name = bitfield.get("name", "")

                            # Check if bitfield name contains double spaces
                            if bitfield_name and double_space in bitfield_name:
                                bf_key = f"{register_name}.{bitfield_name}"
                                errors[bf_key] = (
                                    f"Register '{register_name}', bitfield '{bitfield_name}' contains double spaces"
                                )

    return errors


def validate_shadow_register_requirements(data: dict) -> dict:
    """Validate shadow register configuration requirements.

    Validates that if any register contains "shadow_reg_offset_int" field with a valid offset,
    then "shadow_reg_base_addr_int" must be specified at the root level with a valid address.
    Shadow registers are considered disabled when their values are set to -1.

    :param data: Register configuration data containing groups and registers.
    :return: Dictionary with validation errors where keys are error identifiers and values
        are error descriptions. Empty dictionary if no errors found.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    # Check if any register has shadow_reg_offset_int
    registers_with_shadow_offset = []

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")

            # Check for shadow_reg_offset_int field
            if "shadow_reg_offset_int" in register:
                # Check if the value is not -1 (which means no shadow register)
                offset_value = register["shadow_reg_offset_int"]
                if offset_value != "-1" and offset_value != -1:
                    registers_with_shadow_offset.append(reg_name)

    # If we found registers with shadow offsets, check for base address
    if registers_with_shadow_offset:
        # Check for shadow_reg_base_addr_int at root level
        has_base_address = False

        if "shadow_reg_base_addr_int" in data:
            base_address_value = data["shadow_reg_base_addr_int"]
            # Check if the value is not -1 (which means shadow registers not supported)
            if base_address_value != "-1" and base_address_value != -1:
                has_base_address = True

        if not has_base_address:
            # Create error for each register that has shadow offset
            for reg_name in registers_with_shadow_offset:
                if "shadow_reg_base_addr_int" not in data:
                    errors[f"shadow_base_missing_{reg_name}"] = (
                        f"Register '{reg_name}' has shadow_reg_offset_int but "
                        f"shadow_reg_base_addr_int is not specified at root level"
                    )
                else:
                    errors[f"shadow_base_disabled_{reg_name}"] = (
                        f"Register '{reg_name}' has shadow_reg_offset_int but "
                        f"shadow_reg_base_addr_int is set to -1 (disabled)"
                    )

    return errors


def validate_default_value_within_register_mask(data: dict) -> dict:
    """Validate that default values are within the register mask limits.

    The method validates both register and bitfield default values against their
    respective width constraints. For example, 8-bit register (width=8) can have
    max value of 255 (2^8 - 1). Supports both integer and string (hex/decimal) formats.

    :param data: Dictionary containing register groups with registers and bitfields configuration.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_width = register.get("reg_width", 32)

            # Calculate maximum value for this register width
            # For n-bit register, max value is (2^n - 1)
            try:
                max_register_value = (2**reg_width) - 1
            except (TypeError, ValueError):
                # Skip if reg_width is not a valid integer
                continue

            # Check if register has a default value
            if "default" in register:
                default_value = register["default"]

                # Convert string hex/decimal to integer if needed
                if isinstance(default_value, str):
                    try:
                        # Handle hex strings (0x...) and decimal strings
                        if default_value.lower().startswith("0x"):
                            default_int = int(default_value, 16)
                        else:
                            default_int = int(default_value)
                    except ValueError:
                        errors[f"{reg_name}_default_format"] = (
                            f"Register '{reg_name}' has invalid default value format: '{default_value}'"
                        )
                        continue
                elif isinstance(default_value, int):
                    default_int = default_value
                else:
                    errors[f"{reg_name}_default_type"] = (
                        f"Register '{reg_name}' default value must be integer or string, got {type(default_value)}"
                    )
                    continue

                # Check if default value exceeds register mask
                if default_int > max_register_value:
                    errors[f"{reg_name}_default_overflow"] = (
                        f"Register '{reg_name}' default value {default_int} (0x{default_int:X}) "
                        f"exceeds maximum for {reg_width}-bit register "
                        f"(max: {max_register_value}, 0x{max_register_value:X})"
                    )
                elif default_int < 0:
                    errors[f"{reg_name}_default_negative"] = (
                        f"Register '{reg_name}' default value {default_int} is negative, "
                        f"expected value between 0 and {max_register_value}"
                    )

            # Also check bitfield default values if they exist
            if "bitfields" in register and isinstance(register["bitfields"], list):
                for bitfield in register["bitfields"]:
                    if not isinstance(bitfield, dict):
                        continue

                    bf_name = bitfield.get("name", "unnamed")
                    bf_width = bitfield.get("width")

                    if not isinstance(bf_width, int) or bf_width <= 0:
                        continue

                    # Calculate maximum value for this bitfield width
                    max_bitfield_value = (2**bf_width) - 1

                    if "default" in bitfield:
                        bf_default = bitfield["default"]

                        # Convert string to integer if needed
                        if isinstance(bf_default, str):
                            try:
                                if bf_default.lower().startswith("0x"):
                                    bf_default_int = int(bf_default, 16)
                                else:
                                    bf_default_int = int(bf_default)
                            except ValueError:
                                errors[f"{reg_name}.{bf_name}_default_format"] = (
                                    f"Bitfield '{bf_name}' in register '{reg_name}' has invalid "
                                    f"default value format: '{bf_default}'"
                                )
                                continue
                        elif isinstance(bf_default, int):
                            bf_default_int = bf_default
                        else:
                            errors[f"{reg_name}.{bf_name}_default_type"] = (
                                f"Bitfield '{bf_name}' in register '{reg_name}' default value "
                                f"must be integer or string, got {type(bf_default)}"
                            )
                            continue

                        # Check if bitfield default value exceeds bitfield mask
                        if bf_default_int > max_bitfield_value:
                            errors[f"{reg_name}.{bf_name}_default_overflow"] = (
                                f"Bitfield '{bf_name}' in register '{reg_name}' default value "
                                f"{bf_default_int} (0x{bf_default_int:X}) "
                                f"exceeds maximum for {bf_width}-bit bitfield (max: {max_bitfield_value}"
                                f", 0x{max_bitfield_value:X})"
                            )
                        elif bf_default_int < 0:
                            errors[f"{reg_name}.{bf_name}_default_negative"] = (
                                f"Bitfield '{bf_name}' in register '{reg_name}' default "
                                f"value {bf_default_int} is negative, "
                                f"expected value between 0 and {max_bitfield_value}"
                            )

    return errors


def validate_access_rights_consistency(data: dict) -> dict:
    """Validate that register and bitfield access rights are consistent.

    Checks if register access does not allow read, there should be no readable bit-fields.
    Based on schema enum: ["RW", "WO", "RO", "WRITE_CONST", "none"].

    :param data: Dictionary containing register groups with registers and bitfields data.
    :return: Dictionary with identifier as key and error description as value, empty if no errors.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    # Define readable and non-readable access types based on schema
    readable_access_types = {"RW", "RO"}  # Read-Write and Read-Only

    def is_readable_access(access_str: str) -> bool:
        """Check if access string indicates readable access.

        Determines whether the provided access string represents a readable access type
        by checking if it exists in the predefined readable access types collection.

        :param access_str: Access string to check for readable permissions.
        :return: True if access string indicates readable access, True by default for non-string types.
        """
        if not isinstance(access_str, str):
            return True  # Default to readable (RW) if not specified

        return access_str in readable_access_types

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_access = register.get("access", "RW")  # Default to RW per schema

            # Check if register is readable
            register_is_readable = is_readable_access(reg_access)

            # If register is not readable, check bitfields for readable access
            if not register_is_readable:
                if "bitfields" in register and isinstance(register["bitfields"], list):
                    for bitfield in register["bitfields"]:
                        if not isinstance(bitfield, dict):
                            continue

                        # Skip bitfields that only have width (unnamed/reserved)
                        if set(bitfield.keys()) == {"width"}:
                            continue

                        bf_name = bitfield.get("name", "unnamed")
                        bf_access = bitfield.get("access")

                        # If bitfield has explicit access, check it
                        if bf_access is not None:
                            if is_readable_access(bf_access):
                                bf_key = f"{reg_name}.{bf_name}"
                                errors[f"access_mismatch_{bf_key}"] = (
                                    f"Register '{reg_name}' has non-readable access '{reg_access}' "
                                    f"but bitfield '{bf_name}' has readable access '{bf_access}'"
                                )
                        # If bitfield doesn't specify access, it inherits from register (correct behavior)

    return errors


def validate_write_access_rights_consistency(data: dict) -> dict:
    """Validate that register and bitfield write access rights are consistent.

    If register access does not allow write, there should be no writable bit-fields.
    Based on schema enum: ["RW", "WO", "RO", "WRITE_CONST", "none"].

    :param data: Dictionary containing register groups data structure.
    :return: Dictionary with validation errors where keys are error identifiers and
        values are error descriptions, empty dict if no errors found.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    # Define writable and non-writable access types based on schema
    writable_access_types = {"RW", "WO", "WRITE_CONST"}  # Read-Write, Write-Only, Write-Const

    def is_writable_access(access_str: str) -> bool:
        """Check if access string indicates writable access.

        The method determines whether the provided access string represents a writable
        access type by checking against predefined writable access types.

        :param access_str: Access string to check for writable permissions.
        :return: True if access string indicates writable access, True by default if not a string.
        """
        if not isinstance(access_str, str):
            return True  # Default to writable (RW) if not specified

        return access_str in writable_access_types

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_access = register.get("access", "RW")  # Default to RW per schema

            # Check if register is writable
            register_is_writable = is_writable_access(reg_access)

            # If register is not writable, check bitfields for writable access
            if not register_is_writable:
                if "bitfields" in register and isinstance(register["bitfields"], list):
                    for bitfield in register["bitfields"]:
                        if not isinstance(bitfield, dict):
                            continue

                        # Skip bitfields that only have width (unnamed/reserved)
                        if set(bitfield.keys()) == {"width"}:
                            continue

                        bf_name = bitfield.get("name", "unnamed")
                        bf_access = bitfield.get("access")

                        # If bitfield has explicit access, check it
                        if bf_access is not None:
                            if is_writable_access(bf_access):
                                bf_key = f"{reg_name}.{bf_name}"
                                errors[f"write_access_mismatch_{bf_key}"] = (
                                    f"Register '{reg_name}' has non-writable access '{reg_access}' "
                                    f"but bitfield '{bf_name}' has writable access '{bf_access}'"
                                )
                        # If bitfield doesn't specify access, it inherits from register (correct behavior)

    return errors


def validate_lock_functional_consistency(data: dict) -> dict:
    """Validate functional consistency of lock fields.

    Validates that lock configurations are functionally consistent across register definitions.
    This includes checking access permissions, lock register existence, and bitfield alignment.

    :param data: Register configuration data containing groups of registers with lock definitions
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    # Build a map of register_id to register info for lock reference lookup
    register_map = {}
    cpu_name = data.get("cpu", "")

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "")
            reg_id = register.get("id", "")
            reg_access = register.get("access", "RW")

            # Store by both name and id for lookup
            if reg_name:
                register_map[reg_name] = {
                    "name": reg_name,
                    "access": reg_access,
                    "register": register,
                }
            if reg_id:
                register_map[reg_id] = {
                    "name": reg_name,
                    "access": reg_access,
                    "register": register,
                }

    def parse_lock_mask(mask_str: str) -> Optional[int]:
        """Parse lock mask string to integer.

        Converts a string representation of a lock mask to its integer equivalent.
        Supports both hexadecimal (with '0x' prefix) and decimal formats.

        :param mask_str: String representation of the lock mask (hexadecimal or decimal).
        :return: Integer value of the lock mask, or None if parsing fails or input is invalid.
        """
        if not isinstance(mask_str, str):
            return None
        try:
            if mask_str.lower().startswith("0x"):
                return int(mask_str, 16)
            return int(mask_str)
        except ValueError:
            return None

    def find_bit_position(mask_value: Optional[int]) -> list[int]:
        """Find the bit position(s) from a mask value.

        This method analyzes a bitmask and returns a list of all bit positions
        that are set to 1. Bit positions are counted from 0 (LSB).

        :param mask_value: The bitmask value to analyze for set bits.
        :return: List of bit positions (0-based) where bits are set to 1, empty list if mask is None or 0.
        """
        if mask_value is None or mask_value == 0:
            return []

        positions = []
        bit_pos = 0
        while mask_value > 0:
            if mask_value & 1:
                positions.append(bit_pos)
            mask_value >>= 1
            bit_pos += 1
        return positions

    def validate_lock_bitfield_exists(
        lock_register: dict, lock_type: str, mask_str: str, reg_name: str
    ) -> str:
        """Validate that lock bitfield exists at the correct position in lock register.

        This method validates that the specified lock register contains appropriate bitfields
        at the positions indicated by the lock mask. It checks bitfield positioning, naming
        conventions, and ensures all required bit positions are covered by valid lock-related
        bitfields.

        :param lock_register: Dictionary containing lock register definition with bitfields
        :param lock_type: Type of lock being validated (e.g., 'read', 'write')
        :param mask_str: String representation of the lock mask indicating bit positions
        :param reg_name: Name of the register being validated for error reporting
        :return: Empty string if validation passes, error message string if validation fails
        """
        if not isinstance(lock_register, dict) or "bitfields" not in lock_register:
            return f"Lock register for '{reg_name}' has no bitfields defined"

        mask_value = parse_lock_mask(mask_str)
        if mask_value is None:
            return f"Invalid {lock_type} mask '{mask_str}' for register '{reg_name}'"

        if mask_value == 0:
            return ""  # Mask of 0 means no lock, which is valid

        required_bit_positions = find_bit_position(mask_value)
        if not required_bit_positions:
            return ""

        # Calculate bitfield positions in the lock register
        bitfields = lock_register["bitfields"]
        current_bit_pos = 0
        found_positions = set()

        for bitfield in bitfields:
            if not isinstance(bitfield, dict) or "width" not in bitfield:
                continue

            bf_width = bitfield.get("width", 0)
            bf_name = bitfield.get("name", "")

            # Check if any required bit positions fall within this bitfield
            for req_pos in required_bit_positions:
                if current_bit_pos <= req_pos < current_bit_pos + bf_width:
                    found_positions.add(req_pos)

                    # Check if this bitfield is appropriately named for lock functionality
                    if bf_name and lock_type.lower() in bf_name.lower():
                        # Good - bitfield name suggests it's for locking
                        pass
                    elif bf_name and (
                        "lock" in bf_name.lower()
                        or "enable" in bf_name.lower()
                        or "write_protection" in bf_name.lower()
                    ):
                        # Acceptable - generic lock/enable bitfield
                        pass
                    elif (
                        lock_type.lower() == "write_lock"
                        and isinstance(bf_name, str)
                        and bf_name.lower().endswith("_wr")
                    ):
                        # Acceptable for write lock scenarios
                        pass
                    elif (
                        lock_type.lower() == "read_lock"
                        and isinstance(bf_name, str)
                        and bf_name.lower().endswith("_rd")
                    ):
                        # Acceptable for write lock scenarios
                        pass
                    elif set(bitfield.keys()) == {"width"}:
                        # Unnamed/reserved bitfield - might be acceptable
                        pass
                    else:
                        # Warning: bitfield doesn't seem to be lock-related
                        return (
                            f"Lock register bitfield '{bf_name}' at position {req_pos} "
                            f"doesn't appear to be lock-related for {lock_type} in register '{reg_name}'"
                        )

            current_bit_pos += bf_width

        # Check if all required bit positions were found
        missing_positions = set(required_bit_positions) - found_positions
        if missing_positions:
            return (
                f"Lock register for '{reg_name}' missing {lock_type} bitfields at bit positions "
                f"{sorted(missing_positions)} (mask: {mask_str})"
            )

        return ""

    # Validate lock functional consistency
    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_access = register.get("access", "RW")

            if "lock" in register:
                lock_info = register["lock"]

                if not isinstance(lock_info, dict):
                    continue

                # Check if register has WO access and uses read_lock
                if reg_access == "WO" and "read_lock_int" in lock_info:
                    read_lock_value = lock_info["read_lock_int"]

                    # Solve exceptions found on HW
                    if cpu_name.upper() in ["MIMXRT1189", "MIMXRT1181", "MIMXRT1182", "MIMXRT1187"]:
                        if re.match("OTFAD[1-9]_KEY.*", reg_name):
                            continue

                    # Check if read_lock is active (not "0")
                    if read_lock_value not in ["0", "0x0", "0x00"]:
                        errors[f"read_lock_wo_register_{reg_name}"] = (
                            f"Register '{reg_name}' has access 'WO' but uses read_lock_int '{read_lock_value}'. "
                            f"Read-lock cannot be used for write-only registers."
                        )

                # NEW: Validate that lock register exists and has correct bitfields
                lock_register_id = lock_info.get("register_id")
                if lock_register_id:
                    if lock_register_id not in register_map:
                        errors[f"lock_register_not_found_{reg_name}"] = (
                            f"Register '{reg_name}' references lock register '{lock_register_id}' "
                            f"which does not exist"
                        )
                    else:
                        lock_register_info = register_map[lock_register_id]
                        lock_register = lock_register_info["register"]
                        lock_reg_access = lock_register_info["access"]

                        # Check if lock register is writable
                        if lock_reg_access in ["RO", "none"]:
                            errors[f"lock_register_not_writable_{reg_name}"] = (
                                f"Register '{reg_name}' references lock register '{lock_register_id}' "
                                f"which has access '{lock_reg_access}' (not writable)"
                            )

                        # Validate each lock type bitfield exists
                        lock_types = [
                            ("write_lock_int", "write_lock"),
                            ("read_lock_int", "read_lock"),
                            ("operation_lock_int", "operation_lock"),
                        ]

                        for lock_field, lock_type in lock_types:
                            if lock_field in lock_info:
                                mask_str = lock_info[lock_field]
                                validation_error = validate_lock_bitfield_exists(
                                    lock_register, lock_type, mask_str, reg_name
                                )
                                if validation_error:
                                    errors[f"lock_bitfield_validation_{reg_name}_{lock_type}"] = (
                                        validation_error
                                    )

    return errors


def validate_calculated_reserved_default_value(data: dict) -> dict:
    """Validate calculated and reserved bitfield default value requirement.

    Validates that if any bitfield is calculated and any other bitfield is reserved
    or not writable, then the default value must be specified for the register.

    :param data: Register configuration data containing groups and registers.
    :return: Dictionary with validation errors where keys are error identifiers
             and values are error descriptions, empty dict if no errors found.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def is_bitfield_calculated(bitfield: dict) -> bool:
        """Check if bitfield is calculated.

        Determines whether the provided bitfield dictionary contains a 'calculated' key,
        indicating that the bitfield value is computed rather than directly set.

        :param bitfield: Dictionary representing a bitfield configuration.
        :return: True if bitfield is a dictionary containing 'calculated' key, False otherwise.
        """
        return isinstance(bitfield, dict) and "calculated" in bitfield

    def is_bitfield_reserved(bitfield: dict) -> bool:
        """Check if bitfield is reserved.

        Determines whether a bitfield dictionary represents a reserved field by checking
        multiple criteria: explicit is_reserved flag, unnamed fields with only width,
        or names containing "reserved".

        :param bitfield: Dictionary containing bitfield configuration data.
        :return: True if the bitfield is considered reserved, False otherwise.
        """
        if not isinstance(bitfield, dict):
            return False

        # Check explicit is_reserved flag
        if bitfield.get("is_reserved", False):
            return True

        # Check if bitfield only has width (unnamed/reserved bitfield)
        if set(bitfield.keys()) == {"width"}:
            return True

        # Check if name contains "reserved" (case insensitive)
        bf_name = bitfield.get("name", "")
        if bf_name and "reserved" in bf_name.lower():
            return True

        return False

    def is_bitfield_not_writable(bitfield: dict) -> bool:
        """Check if bitfield is not writable based on access."""
        if not isinstance(bitfield, dict):
            return False

        bf_access = bitfield.get("access")
        if bf_access is None:
            return False  # Inherits from register, check at register level

        # Non-writable access types
        non_writable_access = {"RO", "none"}
        return bf_access in non_writable_access

    def has_default_value(register: dict) -> bool:
        """Check if register or any of its bitfields has a default value."""
        if not isinstance(register, dict):
            return False

        # Check register-level default
        if "default" in register or "default_value_int" in register:
            return True

        # Check bitfield-level defaults
        if "bitfields" in register and isinstance(register["bitfields"], list):
            for bitfield in register["bitfields"]:
                if isinstance(bitfield, dict) and "default" in bitfield:
                    return True

        return False

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_access = register.get("access", "RW")

            if "bitfields" not in register or not isinstance(register["bitfields"], list):
                continue

            bitfields = register["bitfields"]
            if len(bitfields) <= 1:
                continue  # Need at least 2 bitfields for this rule to apply

            # Check conditions
            has_calculated_bitfield = False
            has_reserved_or_not_writable_bitfield = False

            for bitfield in bitfields:
                if not isinstance(bitfield, dict):
                    continue

                # Check if this bitfield is calculated
                if is_bitfield_calculated(bitfield):
                    has_calculated_bitfield = True

                # Check if this bitfield is reserved or not writable
                if is_bitfield_reserved(bitfield):
                    has_reserved_or_not_writable_bitfield = True
                elif is_bitfield_not_writable(bitfield):
                    has_reserved_or_not_writable_bitfield = True
                elif reg_access in ["RO", "none"]:
                    # If register is not writable, all bitfields inherit this
                    has_reserved_or_not_writable_bitfield = True

            # Apply the rule
            if has_calculated_bitfield and has_reserved_or_not_writable_bitfield:
                if not has_default_value(register):
                    errors[f"calculated_reserved_no_default_{reg_name}"] = (
                        f"Register '{reg_name}' has calculated bitfield(s) and reserved/non-writable bitfield(s) "
                        f"but no default value is specified"
                    )

    return errors


def validate_lock_bitfield_naming(data: dict) -> dict:
    """Validate bitfield names ending with lock suffixes.

    Checks bitfields ending with _LOCK, _LOCKS, or _RLOCK suffixes and validates
    that they have writable access permissions. Includes specific exceptions for
    certain lock bitfields that are not subject to these validation rules.

    :param data: Dictionary containing register groups with bitfield definitions.
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def is_lock_bit_with_exceptions(bf_name: str) -> bool:
        """Check if bitfield name is a lock bit subject to validation rules."""
        if not isinstance(bf_name, str):
            return False

        # Check if it's a lock bit
        is_lock_bit = (
            bf_name.endswith("_LOCK") or bf_name.endswith("_LOCKS") or bf_name.endswith("_RLOCK")
        )

        if not is_lock_bit:
            return False

        # Check exceptions - these are NOT subject to the lock rules
        exceptions = {
            "ROM_LOCK",  # RT11xx
            "DBG_EN_LOCK",
            "LOCK_CFG_LOCK",  # RT118x
            "DBG_OVER_USB_LOCK",  # RT7xx
            "GLOBAL_LOCK",  # KW45xx / K32W1xx
            "SYSTEM_LOCK",  # KW45xx / K32W1xx
        }

        # Also exclude _KEY_SEL_LOCK suffix
        if bf_name.endswith("_KEY_SEL_LOCK"):
            return False

        # If it's in exceptions, it's not subject to lock rules
        if bf_name in exceptions:
            return False

        # It's a lock bit and not an exception, so rules apply
        return True

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            register_name = register.get("name", "")

            if "bitfields" in register and isinstance(register["bitfields"], list):
                for bitfield in register["bitfields"]:
                    if not isinstance(bitfield, dict):
                        continue

                    # Skip bitfields that only have width
                    if set(bitfield.keys()) == {"width"}:
                        continue

                    bitfield_name = bitfield.get("name", "")

                    if bitfield_name and is_lock_bit_with_exceptions(bitfield_name):
                        # Add your specific validation logic here for lock bitfields
                        # Example: Check if lock bitfields are writable
                        bf_access = bitfield.get("access")

                        # If bitfield has explicit access, check it
                        if bf_access is not None:
                            if bf_access not in ["RW", "WO", "WRITE_CONST"]:
                                errors[
                                    f"lock_bitfield_not_writable_{register_name}.{bitfield_name}"
                                ] = (
                                    f"Lock bitfield '{bitfield_name}' in register '{register_name}' "
                                    f"has access '{bf_access}' but should be writable"
                                )
                        else:
                            # Bitfield inherits register access
                            reg_access = register.get("access", "RW")
                            if reg_access not in ["RW", "WO", "WRITE_CONST"]:
                                errors[
                                    f"lock_bitfield_inherited_not_writable_{register_name}.{bitfield_name}"
                                ] = (
                                    f"Lock bitfield '{bitfield_name}' in register '{register_name}' "
                                    f"inherits non-writable access '{reg_access}' but should be writable"
                                )

    return errors


def validate_calculated_register_constraints(data: dict) -> dict:
    """Validate constraints for calculated registers.

    This function validates that calculated registers follow specific rules:
    1. Register access must be WO (Write-Only) or RW (Read-Write)
    2. Register cannot be marked as reserved
    3. Register cannot contain any reserved bitfields

    :param data: Dictionary containing register groups and their register definitions
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def is_bitfield_reserved(bitfield: dict) -> bool:
        """Check if bitfield is reserved."""
        if not isinstance(bitfield, dict):
            return False

        # Check explicit is_reserved flag
        if bitfield.get("is_reserved", False):
            return True

        # Check if bitfield only has width (unnamed/reserved bitfield)
        if set(bitfield.keys()) == {"width"}:
            return True

        # Check if name contains "reserved" (case insensitive)
        bf_name = bitfield.get("name", "")
        if bf_name and "reserved" in bf_name.lower():
            return True

        return False

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")

            # Check if register is calculated
            if "calculated" not in register:
                continue

            calculated_info = register["calculated"]
            if not isinstance(calculated_info, dict):
                continue

            # This is a calculated register, apply the rules

            # Rule 1: Register access must be WO or RW
            reg_access = register.get("access", "RW")
            if reg_access not in ["WO", "RW"]:
                errors[f"calculated_invalid_access_{reg_name}"] = (
                    f"Calculated register '{reg_name}' has access '{reg_access}' "
                    f"but must be 'WO' or 'RW'"
                )

            # Rule 2: Register is not reserved
            is_reg_reserved = register.get("is_reserved", False)
            if is_reg_reserved:
                errors[f"calculated_register_reserved_{reg_name}"] = (
                    f"Calculated register '{reg_name}' is marked as reserved "
                    f"but calculated registers cannot be reserved"
                )

            # Rule 3: There is no bit-field reserved
            if "bitfields" in register and isinstance(register["bitfields"], list):
                for bitfield in register["bitfields"]:
                    if not isinstance(bitfield, dict):
                        continue

                    if is_bitfield_reserved(bitfield):
                        bf_name = bitfield.get("name", "unnamed")
                        errors[f"calculated_reserved_bitfield_{reg_name}.{bf_name}"] = (
                            f"Calculated register '{reg_name}' contains reserved bitfield '{bf_name}' "
                            f"but calculated registers cannot have reserved bitfields"
                        )

    return errors


def validate_reserved_register_constraints(data: dict) -> dict:
    """Validate constraints for reserved registers.

    This function validates that registers marked with is_reserved flag follow
    specific naming and configuration rules. Reserved registers must have names
    starting with "Reserved", use "none" for individual_write_lock, and contain
    only reserved bitfields.

    :param data: Dictionary containing register groups and their configurations
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def is_bitfield_reserved(bitfield: dict) -> bool:
        """Check if bitfield is reserved."""
        if not isinstance(bitfield, dict):
            return False

        # Check explicit is_reserved flag
        if bitfield.get("is_reserved", False):
            return True

        # Check if bitfield only has width (unnamed/reserved bitfield)
        if set(bitfield.keys()) == {"width"}:
            return True

        # Check if name contains "reserved" (case insensitive)
        bf_name = bitfield.get("name", "")
        if bf_name and "reserved" in bf_name.lower():
            return True

        return False

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")

            # Check if register is marked as reserved
            is_reg_reserved = register.get("is_reserved", False)
            if not is_reg_reserved:
                continue

            # This is a reserved register, apply the rules

            # Rule 1: Name must start with "Reserved" (case insensitive)
            if not reg_name.lower().startswith("reserved"):
                errors[f"reserved_invalid_name_{reg_name}"] = (
                    f"Reserved register '{reg_name}' name must start with 'Reserved' (case insensitive)"
                )

            # Rule 2: individual_write_lock must be "none"
            individual_write_lock = register.get("individual_write_lock", "none")
            if individual_write_lock != "none":
                errors[f"reserved_invalid_write_lock_{reg_name}"] = (
                    f"Reserved register '{reg_name}' has individual_write_lock '{individual_write_lock}' "
                    f"but must be 'none'"
                )

            # Rule 3: All bit-fields must be reserved
            if "bitfields" in register and isinstance(register["bitfields"], list):
                for i, bitfield in enumerate(register["bitfields"]):
                    if not isinstance(bitfield, dict):
                        continue

                    if not is_bitfield_reserved(bitfield):
                        bf_name = bitfield.get("name", f"bitfield_{i}")
                        errors[f"reserved_non_reserved_bitfield_{reg_name}.{bf_name}"] = (
                            f"Reserved register '{reg_name}' contains non-reserved bitfield '{bf_name}' "
                            f"but all bitfields in reserved registers must be reserved"
                        )

    return errors


def validate_enum_default_value_match(data: dict) -> dict:
    """Validate that enum values match default values.

    Validates that for each bitfield containing enum values, if a default value
    is specified for the register, there must be an enum value that matches
    the extracted bitfield portion of the register default value.

    :param data: Register configuration data containing groups, registers, and bitfields
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def parse_int_value(value_str: str) -> Optional[int]:
        """Parse integer value from string (hex or decimal)."""
        if not isinstance(value_str, str):
            return None

        value_str = value_str.strip()
        if value_str.startswith(("-", "+")):
            # Handle negative values
            sign = -1 if value_str.startswith("-") else 1
            value_str = value_str[1:]
        else:
            sign = 1
        if value_str.startswith("0x") or value_str.startswith("0X"):
            try:
                return sign * int(value_str, 16)
            except ValueError:
                return None
        return sign * int(value_str)

    def extract_bitfield_value_from_register_default(
        register_default: Optional[int], bitfield_offset: int, bitfield_width: int
    ) -> Optional[int]:
        """Extract bitfield value from register default value."""
        if register_default is None:
            return None

        # Create mask for the bitfield
        mask = (1 << bitfield_width) - 1

        # Extract the bitfield value
        bitfield_value = (register_default >> bitfield_offset) & mask

        return bitfield_value

    def calculate_bitfield_offset(bitfields: list, target_bitfield_index: int) -> int:
        """Calculate the bit offset of a bitfield within the register."""
        offset = 0
        for i, bf in enumerate(bitfields):
            if i == target_bitfield_index:
                return offset
            if isinstance(bf, dict) and "width" in bf:
                offset += bf["width"]
        return offset

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")

            # Check if register has a default value
            reg_default_str = register.get("default_value_int")
            if not reg_default_str or reg_default_str == "-1":
                continue

            reg_default_value = parse_int_value(reg_default_str)
            if reg_default_value is None:
                continue

            # Check bitfields
            if "bitfields" not in register or not isinstance(register["bitfields"], list):
                continue

            bitfields = register["bitfields"]

            for bf_index, bitfield in enumerate(bitfields):
                if not isinstance(bitfield, dict):
                    continue

                bf_name = bitfield.get("name", f"bitfield_{bf_index}")

                # Check if bitfield has enum values
                if "values" not in bitfield or not isinstance(bitfield["values"], list):
                    continue

                bf_width = bitfield.get("width")
                if not isinstance(bf_width, int) or bf_width <= 0:
                    continue

                # Calculate bitfield offset
                bf_offset = calculate_bitfield_offset(bitfields, bf_index)

                # Extract bitfield value from register default
                bf_default_value = extract_bitfield_value_from_register_default(
                    reg_default_value, bf_offset, bf_width
                )

                if bf_default_value is None:
                    continue

                # Check if any enum value matches the default
                enum_values = []
                found_match = False

                for enum_value in bitfield["values"]:
                    if not isinstance(enum_value, dict):
                        continue

                    enum_val_str = enum_value.get("value")
                    if not enum_val_str:
                        continue

                    enum_val_int = parse_int_value(enum_val_str)
                    if enum_val_int is not None:
                        enum_values.append(enum_val_int)
                        if enum_val_int == bf_default_value:
                            found_match = True
                            break

                # If no match found, report error
                if not found_match and enum_values:
                    errors[f"enum_default_mismatch_{reg_name}.{bf_name}"] = (
                        f"Register '{reg_name}', bitfield '{bf_name}' has default value {bf_default_value} "
                        f"(extracted from register default {reg_default_value:#x}) "
                        f"but no enum value matches. Available enum values: {enum_values}"
                    )

    return errors


def validate_register_and_bitfield_id_uniqueness(data: dict) -> dict:
    """Validate uniqueness of register IDs and bitfield IDs.

    This function checks for duplicate register IDs across all groups and duplicate
    bitfield IDs within each register. It also validates that bitfield IDs don't
    conflict with existing register IDs.

    :param data: Dictionary containing register groups with registers and bitfields structure.
    :return: Dictionary with error identifiers as keys and error descriptions as values,
             or empty dictionary if no validation errors found.
    """
    errors = {}

    if isinstance(data, dict) and "groups" in data:
        # Check register ID uniqueness across the whole file
        all_register_ids = []

        for group in data["groups"]:
            if "registers" in group:
                for register in group["registers"]:
                    register_name = register.get("name", "")
                    register_id = register.get("id", "")

                    # Only check IDs that are not empty
                    if register_id:
                        # Check if register ID is already used
                        if register_id in all_register_ids:
                            errors[f"duplicate_register_id_{register_id}"] = (
                                f"Duplicate register ID '{register_id}' in register '{register_name}'"
                            )
                        else:
                            all_register_ids.append(register_id)

                    # Check bitfield ID uniqueness within this register
                    if "bitfields" in register:
                        bitfield_ids = []

                        for bitfield in register["bitfields"]:
                            # Skip ID uniqueness check if the bitfield only has a width key
                            if set(bitfield.keys()) == {"width"}:
                                continue

                            bitfield_name = bitfield.get("name", "")
                            bitfield_id = bitfield.get("id", "")

                            # Only check IDs that are not empty
                            if bitfield_id:
                                bf_key = f"{register_name}.{bitfield_name}"

                                # Check if bitfield ID is already used in this register
                                if bitfield_id in bitfield_ids:
                                    errors[f"duplicate_bitfield_id_{bf_key}"] = (
                                        f"Register '{register_name}' has duplicate bitfield ID '{bitfield_id}' "
                                        f"in bitfield '{bitfield_name}'"
                                    )
                                else:
                                    bitfield_ids.append(bitfield_id)

                                # Check if bitfield ID conflicts with any register ID
                                if bitfield_id in all_register_ids:
                                    errors[f"bitfield_register_id_conflict_{bf_key}"] = (
                                        f"Bitfield '{bitfield_name}' in register '{register_name}'"
                                        f" has ID '{bitfield_id}' "
                                        "that conflicts with existing register ID"
                                    )

    return errors


def validate_id_naming_patterns(data: dict) -> dict:
    """Validate that register and bitfield IDs follow standard naming patterns.

    This function validates naming conventions for register and bitfield identifiers
    in the provided data structure. It checks against predefined patterns and ensures
    consistency between IDs and their corresponding offsets/positions.
    Standard patterns:
    - Register ID: {prefix}{hex_offset} (e.g., "field010", "fuse020")
    - Reserved Register ID: Reserved{hex_offset} (e.g., "Reserved00060")
    - Bitfield ID (single bit): {reg_id}-bit{bit_index} (e.g., "field000-bit0")
    - Bitfield ID (multi-bit): {reg_id}-bits{start}-{end} (e.g., "field000-bits0-31")

    :param data: Dictionary containing register groups with registers and bitfields structure.
    :return: Dictionary mapping error identifiers to error descriptions, empty if no errors found.
    """
    errors: dict[str, str] = {}

    # Allowed ID prefixes
    allowed_id_prefixes = ["field", "fuse"]

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    def validate_register_id(reg_id: str, reg_name: str, offset_int: str, is_reserved: bool) -> str:
        """Validate register ID pattern and return error message if invalid."""
        if not reg_id:
            return ""  # Empty ID is allowed

        if is_reserved:
            # Reserved register pattern: Reserved{hex_offset}
            reserved_pattern = r"^Reserved ?[0-9A-Fa-f]+$"
            if not re.match(reserved_pattern, reg_id):
                return (
                    f"Reserved register '{reg_name}' has invalid ID '{reg_id}', "
                    f"expected pattern: Reserved{offset_int}"
                )

            # Check if the hex part matches the offset
            dec_part = reg_id.replace("Reserved", "")
            try:
                if offset_int:
                    expected_offset = (
                        int(offset_int, 16) if offset_int.startswith("0x") else int(offset_int, 16)
                    )
                    actual_offset = int(dec_part, 10)
                    if expected_offset != actual_offset:
                        return (
                            f"Reserved register '{reg_name}' ID '{reg_id}' hex part "
                            f"doesn't match offset '{offset_int}'"
                        )
            except (ValueError, TypeError):
                pass  # Skip offset validation if parsing fails

        else:
            # Standard register pattern: {prefix}{hex_offset}
            found_valid_prefix = False
            for prefix in allowed_id_prefixes:
                pattern = f"^{prefix}[0-9A-Fa-f]+$"
                if re.match(pattern, reg_id):
                    found_valid_prefix = True

                    # Check if the hex part matches the offset
                    dec_part = reg_id.replace(prefix, "")
                    try:
                        if offset_int:
                            expected_offset = (
                                int(offset_int, 16)
                                if offset_int.startswith("0x")
                                else int(offset_int, 16)
                            )
                            actual_offset = int(dec_part, 10)
                            if expected_offset != actual_offset:
                                return (
                                    f"Register '{reg_name}' ID '{reg_id}' hex "
                                    f"art doesn't match offset '{offset_int}'"
                                )
                    except (ValueError, TypeError):
                        pass  # Skip offset validation if parsing fails
                    break

            if not found_valid_prefix:
                return (
                    f"Register '{reg_name}' has invalid ID '{reg_id}', "
                    f"expected pattern: {{{'|'.join(allowed_id_prefixes)}}}{offset_int}"
                )

        return ""

    def validate_bitfield_id(
        bf_id: str, bf_name: str, bf_pos: int, reg_id: str, reg_name: str, bf_width: int
    ) -> str:
        """Validate bitfield ID pattern and return error message if invalid."""
        if not bf_id:
            return ""  # Empty ID is allowed

        if not reg_id:
            return f"Bitfield '{bf_name}' in register '{reg_name}' has ID but register has no ID"

        # Bitfield patterns:
        # Single bit: {reg_id}-bit{bit_index}
        # Multi-bit: {reg_id}-bits{start}-{end}

        single_bit_pattern = f"^{re.escape(reg_id)}-bit-?(?P<bit>[0-9]+)$"
        multi_bit_pattern = f"^{re.escape(reg_id)}-bits-?(?P<start_bit>[0-9]+)-(?P<end_bit>[0-9]+)$"

        if bf_width == 1:
            # Should be single bit pattern
            match = re.match(single_bit_pattern, bf_id)
            if not match:
                return (
                    f"Single-bit bitfield '{bf_name}' in register '{reg_name}' has invalid ID "
                    f"'{bf_id}', expected pattern: {reg_id}-bit{{index}}"
                )
            if int(match.group("bit")) != bf_pos:  # check here test to bit value
                return (
                    f"Single-bit bitfield '{bf_name}' in register '{reg_name}' has incorrect "
                    f"bit index. Expected bit {bf_pos}, got {match.group('bit')}"
                )
        else:
            # Should be multi-bit pattern
            match = re.match(multi_bit_pattern, bf_id)
            if not match:
                return (
                    f"Multi-bit bitfield '{bf_name}' in register '{reg_name}' has invalid ID "
                    f"'{bf_id}', expected pattern: {reg_id}-bits{{start}}-{{end}}"
                )

            # Validate the bit range makes sense
            try:
                start_bit = int(match.group("start_bit"))
                end_bit = int(match.group("end_bit"))
                calculated_width = abs(end_bit - start_bit) + 1

                if bf_pos != start_bit:
                    return (
                        f"Bitfield '{bf_name}' in register '{reg_name}' has incorrect start bit. "
                        f"Expected {bf_pos}, got {start_bit}"
                    )
                if calculated_width != bf_width:
                    return (
                        f"Bitfield '{bf_name}' in register '{reg_name}' ID '{bf_id}' bit range "
                        f"({start_bit}-{end_bit}) doesn't match width {bf_width}"
                    )

            except (ValueError, IndexError):
                return f"Bitfield '{bf_name}' in register '{reg_name}' has malformed ID '{bf_id}'"

        return ""

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")
            reg_id = register.get("id", "")
            offset_int = register.get("index_int", "")
            is_reserved = register.get("is_reserved", False)

            # Validate register ID
            reg_error = validate_register_id(reg_id, reg_name, offset_int, is_reserved)
            if reg_error:
                errors[f"invalid_register_id_{reg_name}"] = reg_error
            bf_pos = 0
            # Validate bitfield IDs
            if "bitfields" in register and isinstance(register["bitfields"], list):
                for bitfield in register["bitfields"]:
                    if not isinstance(bitfield, dict):
                        continue

                    # Skip bitfields that only have width (unnamed/reserved)
                    if set(bitfield.keys()) == {"width"}:
                        bf_width = bitfield["width"]
                        bf_pos += bf_width
                        continue

                    bf_name = bitfield.get("name", "unnamed")
                    bf_id = bitfield.get("id", "")
                    bf_width = bitfield.get("width", 0)
                    bf_error = validate_bitfield_id(
                        bf_id, bf_name, bf_pos, reg_id, reg_name, bf_width
                    )
                    if bf_error:
                        errors[f"invalid_bitfield_id_{reg_name}.{bf_name}"] = bf_error
                    bf_pos += bf_width

    return errors


def validate_bitfield_enum_no_reserved_values(data: dict) -> dict:
    """Validate that bitfield enum values don't contain "RESERVED".

    This function checks all bitfield enum values and their deprecated names
    to ensure they don't contain the word "reserved" (case insensitive).

    :param data: Register data dictionary containing groups with registers and bitfields.
    :return: Dictionary with validation errors where keys are error identifiers and
        values are error descriptions. Empty dictionary if no errors found.
    """
    errors: dict[str, str] = {}

    if not isinstance(data, dict) or "groups" not in data:
        return errors

    for group in data["groups"]:
        if not isinstance(group, dict) or "registers" not in group:
            continue

        for register in group["registers"]:
            if not isinstance(register, dict):
                continue

            reg_name = register.get("name", "unnamed")

            if "bitfields" not in register or not isinstance(register["bitfields"], list):
                continue

            for bitfield in register["bitfields"]:
                if not isinstance(bitfield, dict):
                    continue

                # Skip bitfields that only have width (unnamed/reserved)
                if set(bitfield.keys()) == {"width"}:
                    continue

                bf_name = bitfield.get("name", "unnamed")

                # Check if bitfield has enum values
                if "values" not in bitfield or not isinstance(bitfield["values"], list):
                    continue

                for enum_value in bitfield["values"]:
                    if not isinstance(enum_value, dict):
                        continue

                    value_name = enum_value.get("name", "")

                    # Check if value name contains "reserved" (case insensitive)
                    if value_name and "reserved" in value_name.lower():
                        val_key = f"{reg_name}.{bf_name}.{value_name}"
                        errors[f"enum_reserved_value_{val_key}"] = (
                            f"Register '{reg_name}', bitfield '{bf_name}' has enum value named '{value_name}' "
                            f"which contains 'reserved' and is not allowed"
                        )

                    # Also check deprecated_names for "reserved"
                    if "deprecated_names" in enum_value and isinstance(
                        enum_value["deprecated_names"], list
                    ):
                        for deprecated_name in enum_value["deprecated_names"]:
                            if (
                                isinstance(deprecated_name, str)
                                and "reserved" in deprecated_name.lower()
                            ):
                                val_key = f"{reg_name}.{bf_name}.{deprecated_name}"
                                errors[f"enum_reserved_deprecated_{val_key}"] = (
                                    f"Register '{reg_name}', bitfield '{bf_name}' has deprecated "
                                    f"enum value named '{deprecated_name}' "
                                    "which contains 'reserved' and is not allowed"
                                )

    return errors


def get_device_folders(base_path: str) -> list:
    """Get all folder names in the given base path for test parametrization.

    The method scans the specified directory for subdirectories and returns their paths
    relative to the base directory. Some MCU/MPU names are excluded based on internal exceptions.

    :param base_path: Path to the directory containing device folders.
    :return: List of folder paths that can be used for parametrization, sorted alphabetically.
    """

    base_dir = Path(__file__).parent / base_path

    if not base_dir.exists():
        return []

    # Get all directories (folders) in the base path
    folders = [
        os.path.join(base_path, folder.name) for folder in base_dir.iterdir() if folder.is_dir()
    ]

    # Sort for consistent test ordering
    return sorted(folders)


@pytest.mark.parametrize(
    "test_path",
    get_device_folders("../../spsdk/data/devices") + get_device_folders("../../spsdk/data/common"),
)
def test_data_files(test_path: str) -> None:
    """Test data JSON files with comprehensive validation.

    Validates all JSON files in the specified test path using a comprehensive set of
    validation functions. The method performs register and bitfield validation including
    name uniqueness, access rights consistency, default values, and various other
    constraints specific to SPSDK register definitions.

    :param test_path: Relative path to the directory containing JSON files to validate
    :raises RuntimeError: Error processing JSON file or test execution failure
    """
    # Get the current file's directory
    current_dir = Path(__file__).parent

    # Resolve the test path
    full_path = current_dir / test_path

    if not full_path.exists():
        pytest.skip(f"Test path {full_path} does not exist")

    # Find all JSON files
    json_files = list(full_path.glob("**/*.json"))

    # List of all validation functions
    list_of_tests = [
        validate_register_names_without_reserved,
        validate_bitfield_names_without_reserved,
        validate_register_width_and_bitfields,
        validate_default_value_within_register_mask,
        validate_register_and_bitfield_name_uniqueness,
        validate_register_and_bitfield_id_uniqueness,
        validate_register_and_bitfield_names_no_double_spaces,
        validate_shadow_register_requirements,
        validate_access_rights_consistency,
        validate_write_access_rights_consistency,
        validate_lock_functional_consistency,
        validate_calculated_reserved_default_value,
        validate_lock_bitfield_naming,
        validate_calculated_register_constraints,
        validate_reserved_register_constraints,
        validate_enum_default_value_match,
        validate_id_naming_patterns,
        validate_bitfield_enum_no_reserved_values,
    ]

    # Final error log: {file_name: {test_name: {identifier: error_description}}}
    final_error_log = {}

    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

        except json.JSONDecodeError as e:

            final_error_log[str(json_file)] = {
                "json_parsing": {"file": f"JSON parsing error - {str(e)}"}
            }
            continue
        except Exception as exc:
            raise RuntimeError(f"Error processing file {json_file}: {exc}") from exc

        file_errors = {}

        for test_func in list_of_tests:
            try:
                # Each test returns: {identifier: error_description} or {} if no errors
                test_result = test_func(data)

                if test_result:  # If dict is not empty (has errors)
                    file_errors[test_func.__name__] = test_result

            except Exception as e:
                # Handle test function exceptions
                file_errors[test_func.__name__] = {"test_execution": f"Test execution error: {e}"}

        # Only add to final log if file has errors
        if file_errors:
            final_error_log[str(json_file)] = file_errors

    # Format error message for assertion
    if final_error_log:
        error_messages = []
        error_cnt = 0
        for file_path, file_tests in final_error_log.items():
            error_messages.append(f"\nFile: {file_path}")
            for test_name, test_errors in file_tests.items():
                error_messages.append(f"\n  Test: {test_name}")
                for identifier, error_desc in test_errors.items():
                    error_messages.append(f"\n    {identifier}: {error_desc}")
                    error_cnt += 1

        assert False, (
            "Validation failures found:"
            + "".join(error_messages)
            + f"\n\nTotal errors: {error_cnt}"
        )

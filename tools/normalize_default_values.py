#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK JSON configuration file default value normalizer.

This module provides utilities for normalizing default_value_int fields across
SPSDK JSON configuration files to ensure consistency between register-level
and bitfield-level default values. The normalizer processes JSON files to
compare and validate default values, consolidate them at the register level,
remove redundant bitfield-level defaults, and report inconsistencies.
"""

import glob
import json
import os
import sys
from typing import Any

from spsdk.utils.misc import value_to_int


class DefaultValueNormalizer:
    """JSON configuration normalizer for SPSDK register definitions.

    This class processes JSON files containing register and bitfield definitions,
    normalizing default_value_int fields to ensure consistency across SPSDK
    configuration files. It handles fuses files and other JSON configurations,
    performing validation and standardization of default values, register widths,
    and bitfield offsets.
    """

    def __init__(self, root_dir: str = ".") -> None:
        """Initialize the normalizer with the root directory to search.

        :param root_dir: Root directory to search for JSON files
        """
        self.root_dir = root_dir
        self.modified_files: set[str] = set()
        self.error_found = False

    def find_json_files(self) -> tuple[list[str], list[str]]:
        """Find all JSON files in the repository.

        Searches through the repository directory structure to locate JSON files,
        categorizing them into fuses configuration files and other JSON files.
        Excludes files in .git directories and JSON schema files.

        :return: Tuple containing two lists - first list contains paths to fuses*.json files,
                 second list contains paths to other JSON files (excluding schema files).
        """
        fuses_files: list[str] = []
        other_files: list[str] = []

        for root, _, _ in os.walk(self.root_dir):
            # Skip .git directory
            if ".git" in root.split(os.sep):
                continue

            # Find fuses*.json files
            for file_path in glob.glob(os.path.join(root, "fuses*.json")):
                fuses_files.append(file_path)

            # Find other *.json files (excluding schema files)
            for file_path in glob.glob(os.path.join(root, "*.json")):
                # Skip fuses files and schema files
                if (
                    not os.path.basename(file_path).startswith("fuses")
                    and "json_schemas" not in file_path
                ):
                    other_files.append(file_path)

        return fuses_files, other_files

    def process_register_defaults(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Process a register to normalize default_value_int fields.

        This method performs a two-step normalization process: first it normalizes
        default values by combining bitfield defaults and other operations, then it
        sanitizes any remaining reset_value_int fields in the register data.

        :param register: Register data dictionary containing field definitions and values.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 indicates if processing should continue and was_modified indicates if any
                 changes were made to the register data.
        """
        # First, normalize the default values (combine bitfield defaults, etc.)
        continue_processing, was_modified = self._normalize_default_values(
            register, file_path, register_name
        )
        if not continue_processing:
            return False, was_modified

        # Then, sanitize any remaining reset_value_int fields
        continue_processing, sub_modified = self._sanitize_reset_value_int(
            register, file_path, register_name
        )
        was_modified = was_modified or sub_modified

        return continue_processing, was_modified

    def _normalize_default_values(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Normalize default_value_int fields by combining bitfield defaults.

        This method processes register data to ensure consistency between register-level
        and bitfield-level default values. It handles cases where defaults exist in
        both locations or only in bitfields, and delegates to appropriate handler methods.

        :param register: Dictionary containing register configuration data including bitfields.
        :param file_path: Absolute or relative path to the JSON configuration file being processed.
        :param register_name: Name identifier of the register being normalized.
        :return: Tuple where first boolean indicates whether to continue processing and
            second boolean indicates if modifications were made.
        """
        was_modified = False

        # Check if register has bitfields
        if "bitfields" not in register or not register["bitfields"]:
            return True, was_modified

        register_default = register.get("default_value_int", register.get("reset_value_int"))

        # Collect all bitfield default values
        bitfield_defaults: dict[str, int] = {}
        for ix, bitfield in enumerate(register["bitfields"]):
            if "default_value_int" in bitfield or "reset_value_int" in bitfield:
                bitfield_defaults[bitfield.get("name", f"bitfield_{ix}")] = bitfield.get(
                    "default_value_int", bitfield["reset_value_int"]
                )

        # Case 1: default_value_int in both register and bitfields
        if register_default is not None and bitfield_defaults:
            return self._handle_defaults_in_both(
                register, register_default, bitfield_defaults, file_path, register_name
            )

        # Case 2: default_value_int only in bitfields
        if not register_default and bitfield_defaults:
            return self._handle_defaults_only_in_bitfields(register, file_path, register_name)

        return True, was_modified

    def _handle_defaults_in_both(
        self,
        register: dict[str, Any],
        register_default: Any,
        bitfield_defaults: dict[str, int],
        file_path: str,
        register_name: str,
    ) -> tuple[bool, bool]:
        """Handle case where default_value_int exists in both register and bitfields.

        Validates consistency between register and bitfield default values, extracts missing
        bitfield defaults from register default, and removes redundant bitfield defaults
        to avoid duplication.

        :param register: Register data dictionary containing bitfields and metadata.
        :param register_default: The register's default value (int or convertible to int).
        :param bitfield_defaults: Dictionary mapping bitfield names to their default values.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being validated.
        :return: Tuple of (continue_processing flag, modification status flag).
        """
        was_modified = False
        register_default = value_to_int(register_default)

        # Calculate combined bitfield default
        combined_default = 0
        # Alternative approach (calculating shift from preceding bitfields)
        current_shift = 0
        for bitfield in register["bitfields"]:
            # Use current_shift for this bitfield
            width = value_to_int(bitfield.get("width", 1))
            mask = (1 << width) - 1
            # If bitfield doesn't have default_value_int but register has one,
            # extract the default value from register_default using mask and shift
            if (
                register_default is not None
                and "default_value_int" not in bitfield
                and "reset_value_int" not in bitfield
            ):
                # Extract the default value for this bitfield from register_default
                bitfield_default = (register_default >> current_shift) & mask
                print(
                    f"   Info: For register '{register_name}', bitfield '{bitfield.get('name', 'unnamed')}': "
                    f"Using value {hex(bitfield_default)} extracted from register default {hex(register_default)}"
                )
            else:
                bitfield_default = (
                    value_to_int(
                        bitfield.get("default_value_int", bitfield.get("reset_value_int", 0))
                    )
                    & mask
                )
            combined_default |= bitfield_default << current_shift
            # Update shift for next bitfield
            current_shift += width

        # Compare register default with combined bitfield default
        if register_default != combined_default:
            print(f"❌ Error in {file_path}, register '{register_name}':")
            print(f"   Register default_value_int: {register_default}")
            print(f"   Combined bitfield default: {combined_default}")
            print(f"   Bitfield defaults: {bitfield_defaults}")
            return False, was_modified

        # Remove default_value_int from all bitfields
        for bitfield in register["bitfields"]:
            if "default_value_int" in bitfield:
                del bitfield["default_value_int"]
                was_modified = True
            if "reset_value_int" in bitfield:
                del bitfield["reset_value_int"]
                was_modified = True

        return True, was_modified

    def _handle_defaults_only_in_bitfields(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Handle case where default_value_int exists only in bitfields.

        This method calculates a combined default value from all bitfields within a register
        and moves it to the register level, then removes the individual default values
        from the bitfields to normalize the data structure.

        :param register: Register data dictionary containing bitfields and metadata.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 is always True and was_modified indicates if any changes were made.
        """
        was_modified = False

        # Calculate combined default value
        combined_default = 0
        # Alternative approach (calculating shift from preceding bitfields)
        current_shift = 0
        for bitfield in register["bitfields"]:
            # Use current_shift for this bitfield
            width = value_to_int(bitfield.get("width", 1))
            mask = (1 << width) - 1
            combined_default |= (
                value_to_int(bitfield.get("default_value_int", bitfield.get("reset_value_int", 0)))
                & mask
            ) << current_shift
            # Update shift for next bitfield
            current_shift += width

        # Add default_value_int to register
        register["default_value_int"] = hex(combined_default)
        was_modified = True

        # Remove default_value_int from all bitfields
        for bitfield in register["bitfields"]:
            if "default_value_int" in bitfield:
                del bitfield["default_value_int"]
                was_modified = True
            if "reset_value_int" in bitfield:
                del bitfield["reset_value_int"]
                was_modified = True

        return True, was_modified

    def _sanitize_reset_value_int(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Sanitize any remaining reset_value_int fields in the register.

        This method handles the conversion and validation of reset_value_int fields by either
        removing redundant values that match default_value_int or converting reset_value_int
        to default_value_int when no default exists. Reports errors for conflicting values.

        :param register: Register data dictionary containing field definitions.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being sanitized.
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 indicates if processing should continue and was_modified indicates if the
                 register data was changed.
        """
        was_modified = False

        # Check if both default_value_int and reset_value_int exist in register
        if "default_value_int" in register and "reset_value_int" in register:
            default_val = value_to_int(register["default_value_int"])
            reset_val = value_to_int(register["reset_value_int"])

            if default_val == reset_val:
                # Values are equal, remove the obsolete reset_value_int
                del register["reset_value_int"]
                was_modified = True
                print(
                    f"   Removed redundant reset_value_int in register '"
                    f"{register_name}' (matched default_value_int)"
                )
            else:
                # Values are different, report error for manual check
                print(f"❌ Error in {file_path}, register '{register_name}':")
                print(
                    f"   default_value_int ({hex(default_val)}) and reset_value_int "
                    f"({hex(reset_val)}) have different values"
                )
                print("   Manual correction needed to resolve this inconsistency")
                return False, was_modified
        # Convert reset_value_int to default_value_int if needed
        elif "reset_value_int" in register and "default_value_int" not in register:
            register["default_value_int"] = register["reset_value_int"]
            del register["reset_value_int"]
            was_modified = True
            print(
                f"   Converted reset_value_int to default_value_int in register '{register_name}'"
            )

        return True, was_modified

    def mark_reserved_registers(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Mark registers with 'reserved' in their name by adding 'is_reserved': True.

        The method identifies registers containing 'reserved' in their name (case insensitive)
        and ensures they have the 'is_reserved' field set to True. If the field doesn't exist,
        it's added. If it exists but has a different value, it's updated to True.

        :param register: Dictionary containing register configuration data.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple of (continue_processing flag, modification status flag).
        """
        was_modified = False

        # Check if register name contains 'reserved' (case insensitive)
        if "name" in register and "reserved" in register["name"].lower():
            # Check if is_reserved key doesn't exist
            if "is_reserved" not in register:
                register["is_reserved"] = True
                was_modified = True
                print(f"   Added 'is_reserved': True to register '{register_name}'")
            # If is_reserved exists but is not True, update it
            elif register["is_reserved"] is not True:
                register["is_reserved"] = True
                was_modified = True
                print(f"   Updated 'is_reserved' to True for register '{register_name}'")

        return True, was_modified

    def process_register_widths(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Process a register to normalize width fields, converting strings to integers.

        This method processes register data to ensure all width-related fields (reg_width and
        bitfield widths) are stored as integers rather than strings. It handles both the main
        register width and individual bitfield widths within the register.

        :param register: Dictionary containing register configuration data to be processed.
        :param file_path: Path to the JSON file being processed, used for error reporting.
        :param register_name: Name of the register being processed, used for logging and error messages.
        :raises ValueError: When string width values cannot be converted to integers.
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 indicates if processing should continue and was_modified indicates if any changes were made.
        """
        was_modified = False

        # Normalize register width
        if "reg_width" in register and isinstance(register["reg_width"], str):
            try:
                register["reg_width"] = int(register["reg_width"])
                print(f"   Converted register '{register_name}' reg_width from string to integer")
                was_modified = True
            except ValueError:
                print(
                    f"❌ Error in {file_path}: Could not convert reg_width '{register['reg_width']}' "
                    f"to integer in register '{register_name}'"
                )
                return False, was_modified

        # Normalize bitfield widths
        if "bitfields" in register:
            for bitfield in register["bitfields"]:
                if "width" in bitfield and isinstance(bitfield["width"], str):
                    try:
                        bitfield["width"] = int(bitfield["width"])
                        print(
                            f"   Converted bitfield '{bitfield.get('name', 'unnamed')}' width "
                            f"from string to integer in register '{register_name}'"
                        )
                        was_modified = True
                    except ValueError:
                        print(
                            f"❌ Error in {file_path}: Could not convert width '{bitfield['width']}'"
                            f" to integer in bitfield '{bitfield.get('name', 'unnamed')}' of register '{register_name}'"
                        )
                        return False, was_modified

        return True, was_modified

    def process_bitfield_offsets(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Process a register to remove bitfield offsets after validating they're correct.

        This method validates that existing bitfield offsets match the expected values
        based on bitfield widths, then removes all offset entries if validation passes.
        If validation fails, the register requires manual correction.

        :param register: Register data dictionary containing bitfields configuration
        :param file_path: Path to the JSON file being processed
        :param register_name: Name of the register being processed
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 indicates if processing should continue and was_modified indicates if the
                 register data was changed
        """
        was_modified = False

        # Check if register has bitfields
        if "bitfields" not in register or not register["bitfields"]:
            return True, was_modified

        # First, validate that offsets (if present) match the expected values based on widths
        expected_offset = 0
        for i, bitfield in enumerate(register["bitfields"]):
            # Skip unnamed bitfields (they should only have width)
            if "name" not in bitfield:
                expected_offset += value_to_int(bitfield.get("width", 1))
                continue

            # If offset exists, validate it
            if "offset" in bitfield:
                actual_offset = value_to_int(bitfield["offset"])
                if actual_offset != expected_offset:
                    print(f"❌ Error in {file_path}, register '{register_name}':")
                    print(
                        f"   Bitfield '{bitfield.get('name', f'bitfield_{i}')}' has offset {actual_offset}"
                    )
                    print(f"   Expected offset based on preceding bitfields: {expected_offset}")
                    print("   Manual correction needed before offsets can be removed")
                    return False, was_modified

            # Update expected offset for next bitfield
            expected_offset += value_to_int(bitfield.get("width", 1))

        # If validation passed, remove all offsets
        for bitfield in register["bitfields"]:
            if "offset" in bitfield:
                del bitfield["offset"]
                was_modified = True
                print(
                    f"   Removed 'offset' from bitfield '{bitfield.get('name', 'unnamed')}'"
                    f" in register '{register_name}'"
                )

        return True, was_modified

    def process_register_bitfield_values(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Process register bitfield values to normalize string-formatted numeric values.

        Converts string-formatted values in bitfield entries to their appropriate
        integer representation while preserving the original format (hexadecimal
        or decimal). This normalization removes unnecessary string quotations
        from numeric values in register bitfield definitions.

        :param register: Register data dictionary containing bitfield definitions.
        :param file_path: Path to the JSON file being processed for error reporting.
        :param register_name: Name of the register being processed for error reporting.
        :return: Tuple of (continue_processing, was_modified) where continue_processing
                 indicates if processing should continue and was_modified indicates
                 if any modifications were made to the register data.
        """
        was_modified = False

        # Check if register has bitfields
        if "bitfields" not in register or not register["bitfields"]:
            return True, was_modified

        # Process each bitfield
        for bitfield in register["bitfields"]:
            if "values" in bitfield and isinstance(bitfield["values"], list):
                for value_entry in bitfield["values"]:
                    if "value" in value_entry and isinstance(value_entry["value"], str):
                        try:
                            # Convert string value to integer but preserve format (hex or decimal)
                            original_value = value_entry["value"]
                            # Parse the value to ensure it's valid
                            int_value = value_to_int(value_entry["value"])

                            # Keep the original format (hex or decimal)
                            if original_value.lower().startswith("0x"):
                                # It's hex, keep it as hex
                                value_entry["value"] = int_value
                            else:
                                # It's decimal, keep it as decimal
                                value_entry["value"] = int_value

                            was_modified = True
                            print(
                                f"   Converted value '{original_value}' to non-string format in "
                                f"bitfield '{bitfield.get('name', 'unnamed')}' of register '{register_name}'"
                            )
                        except ValueError:
                            print(
                                f"❌ Error in {file_path}: Could not convert value '{value_entry['value']}' "
                                f"in bitfield '{bitfield.get('name', 'unnamed')}' of register '{register_name}'"
                            )
                            return False, was_modified

        return True, was_modified

    def process_unnamed_bitfields(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Process a register to normalize unnamed bitfields and reserved bitfields.

        This method processes bitfields within a register, keeping only the 'width' key for
        unnamed bitfields or bitfields with names containing "reserved" (case insensitive).
        All other keys are removed from such bitfields to normalize the data structure.
        Prints warnings to console when bitfields lack required 'width' key.

        :param register: Register data dictionary containing bitfields to process.
        :param file_path: Path to the JSON file being processed for warning messages.
        :param register_name: Name of the register being processed for logging purposes.
        :return: Tuple containing (continue_processing flag, modification status flag).
        """
        was_modified = False

        # Check if register has bitfields
        if "bitfields" not in register or not register["bitfields"]:
            return True, was_modified

        # Process each bitfield
        for bitfield in register["bitfields"]:
            # Check if bitfield doesn't have a name or has a name containing "reserved" (case insensitive)
            is_unnamed = "name" not in bitfield
            is_reserved = False
            if not is_unnamed and "name" in bitfield:
                is_reserved = "reserved" in bitfield["name"].lower()

            if is_unnamed or is_reserved:
                # Keep only the width key
                width = bitfield.get("width")
                if width is not None:
                    # Create a new dictionary with only the width
                    keys_to_remove = [key for key in bitfield.keys() if key != "width"]

                    # Only modify and print if there are keys to remove
                    if keys_to_remove:
                        for key in keys_to_remove:
                            del bitfield[key]
                        was_modified = True
                        if is_unnamed:
                            print(
                                f"   Simplified unnamed bitfield in register '{register_name}' "
                                f"to only keep the 'width' key"
                            )
                        else:
                            print(
                                f"   Simplified reserved bitfield '{bitfield.get('name')}'"
                                f" in register '{register_name}' to only keep the 'width' key"
                            )
                else:
                    if is_unnamed:
                        print(
                            f"⚠️ Warning in {file_path}: Unnamed bitfield in register '{register_name}' "
                            f"doesn't have a 'width' key"
                        )
                    else:
                        print(
                            f"⚠️ Warning in {file_path}: Reserved bitfield '{bitfield.get('name')}' "
                            f"in register '{register_name}' doesn't have a 'width' key"
                        )

        return True, was_modified

    def remove_no_yaml_comments(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Remove 'no_yaml_comments' key from registers and bitfields.

        This method processes a register dictionary and removes the 'no_yaml_comments'
        key from both the register level and any bitfields within the register. It
        provides console output indicating what was removed.

        :param register: Register data dictionary to process.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple containing (continue_processing flag, modification status flag).
        """
        was_modified = False

        # Remove from register level
        if "no_yaml_comments" in register:
            del register["no_yaml_comments"]
            was_modified = True
            print(f"   Removed 'no_yaml_comments' from register '{register_name}'")

        # Check if register has bitfields
        if "bitfields" in register and register["bitfields"]:
            # Process each bitfield
            for bitfield in register["bitfields"]:
                if "no_yaml_comments" in bitfield:
                    del bitfield["no_yaml_comments"]
                    was_modified = True
                    print(
                        f"   Removed 'no_yaml_comments' from bitfield '{bitfield.get('name', 'unnamed')}' "
                        f"in register '{register_name}'"
                    )

        return True, was_modified

    def remove_config_preprocess(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Remove 'config_processor' key from registers and bitfields.

        This method processes a register dictionary and removes any 'config_processor'
        keys found at both the register level and within individual bitfields. It provides
        console output indicating what was removed and tracks whether any modifications
        were made.

        :param register: Register data dictionary containing register configuration.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple containing (continue_processing flag, modification status flag).
        """
        was_modified = False

        # Remove from register level
        if "config_processor" in register:
            del register["config_processor"]
            was_modified = True
            print(f"   Removed 'config_processor' from register '{register_name}'")

        # Check if register has bitfields
        if "bitfields" in register and register["bitfields"]:
            # Process each bitfield
            for bitfield in register["bitfields"]:
                if "config_processor" in bitfield:
                    del bitfield["config_processor"]
                    was_modified = True
                    print(
                        f"   Removed 'config_processor' from bitfield '{bitfield.get('name', 'unnamed')}' "
                        f"in register '{register_name}'"
                    )

        return True, was_modified

    def remove_double_space(
        self, register: dict[str, Any], file_path: str, register_name: str
    ) -> tuple[bool, bool]:
        """Remove double spaces from register and bitfield names.

        The method processes register data to find and replace any double spaces with single spaces
        in the 'name' fields of both registers and their associated bitfields. Prints information
        about modifications made during processing.

        :param register: Register data dictionary containing register information and bitfields.
        :param file_path: Path to the JSON file being processed.
        :param register_name: Name of the register being processed.
        :return: Tuple containing (continue_processing, was_modified) where continue_processing
                 is always True and was_modified indicates if any changes were made.
        """
        was_modified = False
        double_space = "  "

        # Remove from register level
        if "name" in register and double_space in register["name"]:
            register["name"] = register["name"].replace(double_space, " ")
            was_modified = True
            print(f"   Replaced doublequote in 'name' for register '{register_name}'")

        # Check if register has bitfields
        if "bitfields" in register and register["bitfields"]:
            # Process each bitfield
            for bitfield in register["bitfields"]:
                if "name" in bitfield and double_space in bitfield.get("name"):
                    bitfield["name"] = bitfield["name"].replace(double_space, " ")
                    was_modified = True
                    print(
                        f"   Replaced doublequote in 'name' for bitfield '{bitfield['name']}' "
                        f"in register '{register_name}'"
                    )

        return True, was_modified

    def process_json_file(self, file_path: str) -> bool:
        """Process a JSON file to normalize default values and apply transformations.

        The method processes JSON files containing register definitions with groups structure,
        applying multiple normalization methods including default value processing, reserved
        register marking, width processing, bitfield offset handling, and cleanup operations.
        Modified files are automatically saved with proper formatting.

        :param file_path: Path to the JSON file to be processed.
        :raises json.JSONDecodeError: Invalid JSON format in the file.
        :raises Exception: Unexpected error during file processing or I/O operations.
        :return: True if processing was successful, False if an error was found.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            modified = False

            # Process groups (structure like in pfr_cfpa.json)
            if "groups" in data:
                for group_container in data["groups"]:
                    if "registers" in group_container:
                        # List of processing methods to apply to each register
                        processing_methods = [
                            self.process_register_defaults,
                            self.mark_reserved_registers,
                            self.process_register_widths,
                            self.process_bitfield_offsets,
                            self.process_register_bitfield_values,
                            self.process_unnamed_bitfields,
                            self.remove_no_yaml_comments,
                            self.remove_config_preprocess,
                            self.remove_double_space,
                        ]

                        for register in group_container["registers"]:
                            register_name = register.get("name", "unknown")

                            # Apply each processing method in sequence
                            for method in processing_methods:
                                continue_processing, was_modified = method(
                                    register, file_path, register_name
                                )
                                modified = modified or was_modified
                                if not continue_processing:
                                    return False

            # Save changes if modified
            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                    # Add newline at end of file
                    f.write("\n")
                self.modified_files.add(file_path)

            return True

        except json.JSONDecodeError as e:
            print(f"❌ Error parsing {file_path}: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error processing {file_path}: {e}")
            return False

    def process_all_files(self) -> bool:
        """Process all JSON files to normalize default_value_int fields.

        This method discovers all JSON files in the configured directory, categorizes them
        into fuses files and other files, then processes each file to normalize their
        default_value_int fields according to SPSDK standards.

        :return: True if all files were processed successfully, False otherwise.
        """
        fuses_files, other_files = self.find_json_files()

        print(f"Found {len(fuses_files)} fuses_*.json files")
        print(f"Found {len(other_files)} other *.json files")

        # Process all files
        for file_path in fuses_files + other_files:
            if not self.process_json_file(file_path):
                self.error_found = True
                return False

        return True


def main() -> None:
    """Main function to run the default value normalizer directly.

    Processes all files in the specified directory (or current directory if not provided)
    to normalize default values in configuration schemas. The function handles command-line
    arguments, executes the normalization process, and provides user feedback.

    :raises SystemExit: Always called with exit code 0 on success, 1 on failure.
    """
    root_dir = "." if len(sys.argv) <= 1 else sys.argv[1]
    normalizer = DefaultValueNormalizer(root_dir)

    success = normalizer.process_all_files()

    if normalizer.error_found:
        print("❌ Processing stopped due to inconsistent default values.")
        print("   Please fix the reported issues manually.")
        sys.exit(1)

    if normalizer.modified_files:
        print(f"✅ Successfully normalized {len(normalizer.modified_files)} files:")
        for file_path in sorted(normalizer.modified_files):
            print(f"   - {file_path}")
    else:
        print("✅ No files needed normalization.")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

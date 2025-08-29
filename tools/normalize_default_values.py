#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Default Value Normalizer for SPSDK JSON Files.

This script processes JSON files in the repository to normalize default_value_int fields:
1. If default_value_int exists in both register and bitfields:
   - Compares them and reports inconsistencies
   - If consistent, removes default_value_int from bitfields
2. If default_value_int exists only in bitfields:
   - Creates register-level default_value_int
   - Removes default_value_int from bitfields
3. If default_value_int exists only in register:
   - Leaves it as is

Usage:
    python normalize_default_values.py [root_directory]
"""

import glob
import json
import os
import sys
from typing import Any

from spsdk.utils.misc import value_to_int


class DefaultValueNormalizer:
    """Normalizer for default_value_int fields in JSON files."""

    def __init__(self, root_dir: str = ".") -> None:
        """Initialize the normalizer with the root directory to search.

        :param root_dir: Root directory to search for JSON files
        """
        self.root_dir = root_dir
        self.modified_files: set[str] = set()
        self.error_found = False

    def find_json_files(self) -> tuple[list[str], list[str]]:
        """Find all JSON files in the repository.

        :return:
            tuple: (fuses_files, other_files) - Lists of paths to JSON files
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param register_default: The register's default value
        :param bitfield_defaults: Dictionary of bitfield default values
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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
        """Mark registers with 'reserved' in their name by adding 'is_reserved': True if not already present.

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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
        """Process a register to normalize value fields in bitfield values, removing string quotations.

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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
        """Process a register to normalize unnamed bitfields and reserved bitfields, keeping only the width key.

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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
        """Remove 'config_processor' key from registers and bitfields.

        :param register: Register data
        :param file_path: Path to the JSON file
        :param register_name: Name of the register
        :return: Tuple containing (continue_processing, was_modified)
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
        """Process a JSON file to normalize default_value_int fields.

        :param file_path: Path to the JSON file
        :return: True if processing was successful, False if an error was found
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

        :return: True if all files were processed successfully, False otherwise
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
    """Main function to run the normalizer directly."""
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

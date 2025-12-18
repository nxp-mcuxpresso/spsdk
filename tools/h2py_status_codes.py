#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script to check error codes.

Check if all status error codes from input .h are present in error_codes.py
If some entries are missing suggest onces to add.
"""

import re
import sys
from pathlib import Path

import click

THIS_DIR = Path(__file__).parent
ROOT_DIR = THIS_DIR.parent
MBOOT_ERROR_CODES_FILE = ROOT_DIR / "spsdk" / "mboot" / "error_codes.py"


def extract_error_codes_from_h_file(h_file_path: str) -> dict[int, str]:
    """Extract error codes from the C header file."""
    error_codes = {}

    with open(h_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern to match #define STATUS_... 0x...u
    pattern = r"#define\s+(STATUS_\w+)\s+(0x[0-9A-Fa-f]+)u?"
    matches = re.findall(pattern, content)

    for name, hex_value in matches:
        # Convert hex string to integer
        value = int(hex_value, 16)
        error_codes[value] = name

    return error_codes


def extract_error_codes_from_py_file(py_file_path: str) -> set[int]:
    """Extract error codes from the Python file."""
    error_codes = set()

    with open(py_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern to match enum entries with numeric values
    # Looking for patterns like: NAME = (12345, "...", "...")
    pattern = r'\w+\s*=\s*\((\d+|0x[0-9A-Fa-f]+),\s*"[^"]*",\s*"[^"]*"\)'
    matches = re.findall(pattern, content)

    for value_str in matches:
        value = int(value_str, 0)
        error_codes.add(value)

    return error_codes


@click.command(no_args_is_help=True)
@click.argument(
    "header_file",
    required=True,
    type=click.Path(exists=True, resolve_path=True),
)
@click.argument(
    "python_file",
    required=False,
    default=MBOOT_ERROR_CODES_FILE,
    type=click.Path(exists=True, resolve_path=True),
)
def main(header_file: str, python_file: str) -> None:
    """Check and report missing error status codes.

    Extract error status codes from .h file and compare with Python error codes file.
    If status code is not present in Python file, print missing entries.

    \b
    HEADER_FILE     path to .h file with status codes
    PYTHON_FILE     path to Python file with error codes (default is spsdk/mboot/error_codes.py)
    """
    # Extract error codes from both files
    h_error_codes = extract_error_codes_from_h_file(header_file)
    py_error_codes = extract_error_codes_from_py_file(python_file)

    print(f"Found {len(h_error_codes)} error codes in {header_file}")
    print(f"Found {len(py_error_codes)} error codes in {python_file}")

    # Find missing error codes
    missing_codes = []
    for value, c_name in h_error_codes.items():
        if value not in py_error_codes:
            missing_codes.append((value, c_name))

    if not missing_codes:
        print("\n✅ All error codes from the header file are present in the Python file!")
        return

    print(f"\n❌ Found {len(missing_codes)} missing error codes:")
    print("\nMissing error codes that should be added to the Python file:")
    print("=" * 80)

    # Sort by value for better organization
    missing_codes.sort(key=lambda x: x[0])

    # Calculate the maximum width for alignment and round up to nearest multiple of 4 (default tab width)
    format_align_width = max(len(code[1]) for code in missing_codes)
    format_align_width = ((format_align_width + 3) // 4) * 4

    for value, c_name in missing_codes:
        # Format as Python enum entry
        print(f'    {c_name:<{format_align_width}} = (0x{value:08X}, "{c_name}", "{c_name}")')

    print("=" * 80)
    print(
        f"\nCopy the above {len(missing_codes)} entries to the appropriate location in your StatusCode enum."
    )


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter

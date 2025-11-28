#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB31 test utilities for file operations.

This module provides common utility functions for reading files in various formats
used by SB31 (Secure Binary version 3.1) test cases.
"""

from os import path
from typing import Union


def read_file(data_dir: str, file_name: str, mode: str = "rb") -> Union[str, bytes]:
    """Read file from specified directory.

    Reads the content of a file located in the given directory using the specified mode.

    :param data_dir: Directory path where the file is located.
    :param file_name: Name of the file to read.
    :param mode: File opening mode (default is "rb" for binary read).
    :raises FileNotFoundError: If the specified file does not exist.
    :raises PermissionError: If there are insufficient permissions to read the file.
    :raises OSError: If an OS-level error occurs during file operations.
    :return: File content as string (text mode) or bytes (binary mode).
    """
    with open(path.join(data_dir, file_name), mode, encoding="utf-8") as f:
        return f.read()


def read_file_hex(data_dir: str, file_name: str, mode: str = "r") -> bytes:
    """Read file containing hexadecimal data and convert to bytes.

    The function opens a file from the specified directory, reads its content
    as hexadecimal string, and converts it to bytes object.

    :param data_dir: Directory path where the file is located.
    :param file_name: Name of the file to read.
    :param mode: File opening mode, defaults to "r".
    :raises FileNotFoundError: If the specified file does not exist.
    :raises ValueError: If the file content is not valid hexadecimal format.
    :return: Bytes object created from hexadecimal data in the file.
    """
    with open(path.join(data_dir, file_name), mode, encoding="utf-8") as f:
        return bytes.fromhex(f.read())

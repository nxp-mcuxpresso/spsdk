#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK miscellaneous testing utilities.

This module provides various helper utilities and mock classes used across
SPSDK test suites for common testing operations and debugging support.
"""

# name if data sub-directory with logs from output generation
from typing import Optional, TextIO

DEBUG_LOG_SUBDIR = "debug_logs"


def compare_bin_files(path: str, bin_data: bytes) -> None:
    """Compare generated binary content with expected content from file.

    If the content differs, the generated file is stored to disk with '.generated'
    suffix to allow analysis of the differences.

    :param path: Absolute path to the file with expected content.
    :param bin_data: Generated binary data to compare.
    :raises AssertionError: When binary content does not match expected content.
    """
    with open(path, "rb") as f:
        expected = f.read()
    if expected != bin_data:
        with open(path + ".generated", "wb") as f:
            f.write(bin_data)
        assert expected == bin_data, f'file does not match: "{path}"'


class GetPassMock:
    """Mock implementation for password input functionality.

    This class provides a test double for getpass operations, allowing
    predetermined passphrases to be returned instead of prompting for
    user input during testing scenarios.
    """

    def __init__(self, passphrase: Optional[str]) -> None:
        """Initialize the object with an optional passphrase.

        :param passphrase: Optional passphrase string for authentication or encryption purposes.
        """
        self.passphrase = passphrase

    def get_pass(
        self, prompt: Optional[str] = None, stream: Optional[TextIO] = None
    ) -> Optional[str]:
        """Get passphrase for authentication.

        Returns the stored passphrase that was previously set for this instance.

        :param prompt: Optional prompt message (not used in this implementation).
        :param stream: Optional text stream for input/output (not used in this implementation).
        :return: The stored passphrase string, or None if no passphrase was set.
        """
        return self.passphrase

    getpass = get_pass

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CLI testing utilities.

This module provides enhanced CLI testing functionality for SPSDK command-line
interfaces, extending Click's testing capabilities with additional features
and compatibility handling.
"""

import traceback
from typing import Any

import importlib_metadata
from click.testing import CliRunner as _CliRunner
from click.testing import Result
from packaging.version import Version

CLICK_RETURN_2_IF_NO_HELP = Version(importlib_metadata.version("click")) >= Version("8.2.0")
CLICK_HAS_MIX_STDERR = Version(importlib_metadata.version("click")) < Version("8.2.0")


class CliRunner(_CliRunner):
    """SPSDK CLI test runner with enhanced error reporting.

    This class extends Click's CliRunner to provide automatic exit code validation
    and detailed error reporting for SPSDK CLI command testing. It simplifies
    test assertions by automatically checking expected exit codes and provides
    comprehensive failure messages including stack traces and output details.
    """

    def invoke(self, *args: Any, expected_code: int = 0, **kwargs: Any) -> Result:
        """Invoke CLI command with expected exit code validation.

        This method wraps the parent invoke method and validates that the command
        exits with the expected code. Use expected_code=-1 to verify any non-zero
        exit code.

        :param args: Arguments to be passed to the parent invoke method.
        :param expected_code: Expected exit code (default: 0). Use -1 to expect any non-zero code.
        :param kwargs: Keyword arguments to be passed to the parent invoke method.
        :return: Result object from the CLI command execution.
        """
        result = super().invoke(*args, **kwargs)

        if expected_code == -1:
            assert result.exit_code != 0, self._build_error_message(result, expected_code)
        else:
            assert result.exit_code == expected_code, self._build_error_message(
                result, expected_code
            )
        return result

    def _build_error_message(self, result: Result, expected_code: int) -> str:
        """Build error message from CLI test result.

        Constructs a detailed error message containing expected vs actual exit codes,
        exception information, command output/stderr, and stack trace details for
        debugging failed CLI command executions.

        :param result: Click test result object containing execution details.
        :param expected_code: Expected exit code for the CLI command.
        :return: Formatted error message string with comprehensive failure details.
        """
        error_msg = f"Expected code: {expected_code}, Actual code: {result.exit_code} \n"
        if result.exception:
            error_msg += f"{result.exception}\n"
        # mix_stderr was removed in click 8.2
        error_msg += (
            result.output
            if (CLICK_HAS_MIX_STDERR and getattr(self, "mix_stderr", False))
            else result.stderr
        )
        if result.exc_info and result.exc_info[2]:
            extracted_list = traceback.extract_tb(result.exc_info[2])
            for item in traceback.StackSummary.from_list(extracted_list).format():
                error_msg += f"{item}"
        return error_msg

    @staticmethod
    def get_help_error_code(use_help_flag: bool) -> int:
        """Get error code for help message based on click version.

        This method determines the appropriate error code to return when displaying
        help messages, taking into account the Click library version and whether
        the help flag was explicitly used.

        :param use_help_flag: Whether the help flag was explicitly used by the user.
        :return: Error code (2 for older Click versions without help flag, 0 otherwise).
        """
        return 2 if not use_help_flag and CLICK_RETURN_2_IF_NO_HELP else 0

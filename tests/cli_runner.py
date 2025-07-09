#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import traceback

import importlib_metadata
from click.testing import CliRunner as _CliRunner
from click.testing import Result
from packaging.version import Version

CLICK_RETURN_2_IF_NO_HELP = Version(importlib_metadata.version("click")) >= Version("8.2.0")
CLICK_HAS_MIX_STDERR = Version(importlib_metadata.version("click")) < Version("8.2.0")


class CliRunner(_CliRunner):
    def invoke(self, *args, expected_code: int = 0, **kwargs):
        """
        :param args: Argument to be passed into parent invoke method
        :param kwargs: Keyword argument to be passed into parent invoke method
        :param expected_code: Expected code to be returned. -1 means everything else but 0
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
        """Build error message from the result."""
        error_msg = f"Expected code: {expected_code}, Actual code: {result.exit_code} \n"
        if result.exception:
            error_msg += f"{result.exception}\n"
        # mix_stderr was removed in click 8.2
        error_msg += result.output if (CLICK_HAS_MIX_STDERR and self.mix_stderr) else result.stderr
        if result.exc_info[2]:
            extracted_list = traceback.extract_tb(result.exc_info[2])
            for item in traceback.StackSummary.from_list(extracted_list).format():
                error_msg += f"{item}"
        return error_msg

    @staticmethod
    def get_help_error_code(use_help_flag: bool) -> int:
        """Get error code for help message based on click version."""
        return 2 if not use_help_flag and CLICK_RETURN_2_IF_NO_HELP else 0

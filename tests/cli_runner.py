#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import traceback

from click.testing import CliRunner as _CliRunner
from click.testing import Result


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
        error_msg += result.output if self.mix_stderr else result.stderr
        if result.exc_info[2]:
            extracted_list = traceback.extract_tb(result.exc_info[2])
            for item in traceback.StackSummary.from_list(extracted_list).format():
                error_msg += f"{item}"
        return error_msg

#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK UUU utility testing module.

This module contains unit tests for the SPSDK UUU (Universal Update Utility)
functionality, specifically testing argument replacement and processing
capabilities within the SPSDKUUU class.
"""

import io
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from libuuu.libuuu import UUUNotifyType

import spsdk.utils.progress_bar as progress_bar_module
from spsdk.uboot.spsdk_uuu import SPSDKUUU, SPSDKUUUState
from spsdk.utils.progress_bar import ESC_HIDE_CURSOR, ESC_SHOW_CURSOR


class TtyStringIO(io.StringIO):
    """StringIO that pretends to be a TTY."""

    def isatty(self) -> bool:
        """Report the stream as a terminal.

        :return: Always True.
        """
        return True


def test_replace_arguments() -> None:
    """Test the replace_arguments method of SPSDKUUU class.

    This test verifies that the replace_arguments method correctly substitutes
    placeholders in a string with actual file paths from the arguments list,
    handling both direct replacements and optional key fallbacks.

    :param: No parameters - this is a test function.
    """
    arguments_dict: dict[str, dict[str, Any]] = {
        "_flash.bin": {"description": "bootloader", "optional_key": None},
        "_image": {
            "description": "image burn to emmc, default is the same as bootloader",
            "optional_key": "_flash.bin",
        },
    }
    arguments = ["some/path/bootable_image/flash.bin"]
    input_string = "This is a test string with _flash.bin and _image."
    result = SPSDKUUU.replace_arguments(input_string, arguments_dict, arguments)
    assert (
        result
        == "This is a test string with some/path/bootable_image/flash.bin and some/path/bootable_image/flash.bin."
    )


def test_replace_arguments_with_backslashes() -> None:
    """Test replacement of arguments containing backslashes in file paths.

    Verifies that the SPSDKUUU.replace_arguments method correctly handles Windows-style
    file paths with backslashes and converts them to forward slashes in the output.
    The test ensures that both direct argument replacement and optional key fallback
    work properly with backslash-containing paths.

    :raises AssertionError: If the argument replacement does not produce expected result.
    """
    arguments_dict: dict[str, dict[str, Any]] = {
        "_flash.bin": {"description": "bootloader", "optional_key": None},
        "_image": {
            "description": "image burn to emmc, default is the same as bootloader",
            "optional_key": "_flash.bin",
        },
    }
    arguments = [r"some\path\bootable_image\flash.bin"]
    input_string = "This is a test string with _flash.bin and _image."
    result = SPSDKUUU.replace_arguments(input_string, arguments_dict, arguments)
    assert (
        result
        == "This is a test string with some/path/bootable_image/flash.bin and some/path/bootable_image/flash.bin."
    )


def test_progress_bar_flag_is_propagated_to_state() -> None:
    """Verify that the progress_bar argument really disables the progress bar.

    The state object exposes the flag as progress_bar_enabled; a mismatched
    attribute name would silently keep the progress bar always enabled.
    """
    original = SPSDKUUU._state.progress_bar_enabled
    try:
        SPSDKUUU(progress_bar=False)
        assert SPSDKUUU._state.progress_bar_enabled is False
        SPSDKUUU(progress_bar=True)
        assert SPSDKUUU._state.progress_bar_enabled is True
    finally:
        SPSDKUUU._state.progress_bar_enabled = original


def _notify(notify_type: UUUNotifyType, total: int = 0, text: bytes = b"") -> SimpleNamespace:
    """Build a minimal duck-typed UUU notification structure.

    :param notify_type: Type of the notification.
    :param total: Value reported in the response total field.
    :param text: Value reported in the response string field.
    :return: Object accepted by SPSDKUUUState.update.
    """
    return SimpleNamespace(
        type=notify_type,
        timestamp=0,
        response=SimpleNamespace(total=total, str=text, status=0),
    )


def test_transfer_notifications_restore_cursor() -> None:
    """Cursor hidden while rendering transfer progress must be restored.

    Reproduces the reported defect where the terminal cursor stayed invisible
    after nxpuuu finished, because finish_progress() was never called.
    """
    stream = TtyStringIO()
    with (
        patch.object(sys, "stdout", stream),
        patch.object(progress_bar_module, "_hidden_cursor_count", 0),
    ):
        state = SPSDKUUUState(progress_bar_enabled=True)
        state.update(_notify(UUUNotifyType.NOTIFY_CMD_START, text=b"SDPS: boot -f flash.bin"))
        state.update(_notify(UUUNotifyType.NOTIFY_TRANS_SIZE, total=100))
        state.update(_notify(UUUNotifyType.NOTIFY_TRANS_POS, total=50))

        assert ESC_HIDE_CURSOR in stream.getvalue()
        assert ESC_SHOW_CURSOR not in stream.getvalue()

        state.finish_progress()
        assert ESC_SHOW_CURSOR in stream.getvalue()


def test_finish_progress_without_transfer_is_noop() -> None:
    """finish_progress() must stay silent when no progress bar was drawn."""
    stream = TtyStringIO()
    with (
        patch.object(sys, "stdout", stream),
        patch.object(progress_bar_module, "_hidden_cursor_count", 0),
    ):
        SPSDKUUUState(progress_bar_enabled=True).finish_progress()
        assert stream.getvalue() == ""

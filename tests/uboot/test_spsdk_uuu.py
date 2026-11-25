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
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from libuuu.libuuu import UUUNotifyType

import spsdk.utils.progress_bar as progress_bar_module
from spsdk.apps.nxpuuu import main as nxpuuu_main
from spsdk.uboot.spsdk_uuu import SPSDKUUU, SPSDKUUUState
from spsdk.utils.family import FamilyRevision
from spsdk.utils.progress_bar import ESC_HIDE_CURSOR, ESC_SHOW_CURSOR
from tests.cli_runner import CliRunner


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


@pytest.mark.parametrize("family", ["mimx943", "mimx9596"])
@pytest.mark.parametrize("image_path", ["images/imx-boot.bin", r"images\imx-boot.bin"])
def test_get_spl_script(family: str, image_path: str) -> None:
    """Substitute the image filename in every boot stage without changing the sequence.

    :param family: Device family using the shared SPL script.
    :param image_path: Bootloader image path with POSIX or Windows separators.
    """
    script = SPSDKUUU().get_uuu_script("spl", FamilyRevision(family), [image_path])
    commands = [
        line for line in script.splitlines() if line and not line.startswith(("#", "uuu_version"))
    ]
    assert "_flash.bin" not in script
    assert commands == [
        "SDP: boot -f images/imx-boot.bin",
        "SDPS[-t 10000]: boot -f images/imx-boot.bin",
        "SDPU: delay 1000",
        "SDPU: write -f images/imx-boot.bin -offset 0x57c00",
        "SDPU: jump",
        "SDPU: done",
        "SDPV: delay 1000",
        "SDPV: write -f images/imx-boot.bin -skipspl",
        "SDPV: jump",
        "SDPV: done",
    ]


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


def _invoke_write(cli_runner: CliRunner, args: list[str]) -> tuple[MagicMock, MagicMock]:
    """Invoke nxpuuu write with mocked UUU execution.

    :param cli_runner: CLI runner fixture.
    :param args: Arguments passed after the write command.
    :return: Mocks of the auto_detect_file and run_script methods.
    """
    with (
        patch.object(SPSDKUUU, "auto_detect_file", return_value=0) as auto_detect,
        patch.object(SPSDKUUU, "run_script", return_value=0) as run_script,
        patch.object(SPSDKUUU, "wait_uuu_finish", return_value=0),
    ):
        cli_runner.invoke(nxpuuu_main, ["write", "-f", "mimx943", *args])
    return auto_detect, run_script


def test_write_without_boot_device_uses_spl(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Load a bootloader image using the SPL script when no boot device is specified.

    :param cli_runner: CLI runner fixture.
    :param tmp_path: Temporary directory for the bootloader image.
    """
    image = tmp_path / "imx-boot.bin"
    image.write_bytes(bytes(range(256)))
    auto_detect, run_script = _invoke_write(cli_runner, [str(image)])
    auto_detect.assert_not_called()
    run_script.assert_called_once_with(
        SPSDKUUU().get_uuu_script("spl", FamilyRevision("mimx943"), [str(image)])
    )


@pytest.mark.parametrize("name", ["burn.uuu", "images.zip", "images.sdcard", "images"])
def test_write_without_boot_device_auto_detects(
    cli_runner: CliRunner, tmp_path: Path, name: str
) -> None:
    """Pass UUU scripts, archives and directories to the UUU auto-detection.

    :param cli_runner: CLI runner fixture.
    :param tmp_path: Temporary directory for the input.
    :param name: Name of the input file or directory.
    """
    path = tmp_path / name
    if name == "images":
        path.mkdir()
    else:
        path.write_text("uuu_version 1.2.39\nSDPS: boot -f imx-boot.bin\n")
    auto_detect, run_script = _invoke_write(cli_runner, [str(path)])
    auto_detect.assert_called_once_with(str(path))
    run_script.assert_not_called()


def test_write_with_boot_device_uses_selected_script(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Use the selected boot device script when the boot device is specified.

    :param cli_runner: CLI runner fixture.
    :param tmp_path: Temporary directory for the bootloader image.
    """
    image = tmp_path / "imx-boot.bin"
    image.write_bytes(b"\x00" * 16)
    auto_detect, run_script = _invoke_write(cli_runner, ["-b", "emmc", str(image)])
    auto_detect.assert_not_called()
    run_script.assert_called_once_with(
        SPSDKUUU().get_uuu_script("emmc", FamilyRevision("mimx943"), [str(image)])
    )


@pytest.mark.parametrize(
    "family, rom_stage",
    [
        ("mimx8ulp", True),
        ("mimx9131", True),
        ("mimx9352", True),
        ("mimx8qxp", False),
        ("mimx9596", False),
        ("mimx943", False),
    ],
)
def test_spl_script_per_family(family: str, rom_stage: bool) -> None:
    """Use the SPL script matching the way SPL loads U-Boot on the family.

    SPL of i.MX 8ULP, 91 and 93 reads U-Boot through the ROM API from the SDPS stream, so the
    script must finish after the SDPS stage instead of waiting for an SPL SDP device.

    :param family: Target family.
    :param rom_stage: True if the whole image is loaded in the ROM SDPS stage.
    """
    script = SPSDKUUU().get_uuu_script("spl", FamilyRevision(family), ["imx-boot.bin"])
    commands = [line for line in script.splitlines() if line and not line.startswith("#")]
    assert "SDPS[-t 10000]: boot -f imx-boot.bin" in commands
    assert ("SDPS: done" in commands) == rom_stage
    assert any(cmd.startswith("SDPV:") for cmd in commands) != rom_stage

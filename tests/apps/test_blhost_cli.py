#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Comprehensive pytest tests for blhost CLI application.

Tests cover all commands and subcommands using --help invocations and
hardware-free commands (get-families) to maximize code coverage without
requiring real MCU hardware.

Note: blhost's spsdk_mboot_interface decorator checks sys.argv for '--help'
to skip the hardware interface requirement. Tests must patch sys.argv accordingly.
"""

import contextlib
import os
import sys
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from spsdk.apps.blhost import main
from spsdk.apps.blhost_helper import MIN_ERASE_PROGRESS_LENGTH, get_erase_chunk_size
from spsdk.utils.misc import write_file
from tests.cli_runner import CliRunner

# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------


def test_blhost_help(cli_runner: CliRunner) -> None:
    """Test top-level --help output."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# All top-level commands via --help (hardware-free via sys.argv patch)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "batch",
        "call",
        "configure-memory",
        "efuse-program-once",
        "efuse-read-once",
        "execute",
        "flash-erase-region",
        "flash-erase-all",
        "flash-erase-all-unsecure",
        "flash-image",
        "flash-program-once",
        "flash-read-once",
        "flash-security-disable",
        "flash-read-resource",
        "fill-memory",
        "fuse-program",
        "fuse-read",
        "list-memory",
        "load-image",
        "get-property",
        "set-property",
        "read-memory",
        "receive-sb-file",
        "reliable-update",
        "reset",
        "write-memory",
        "generate-key-blob",
        "program-aeskey",
        "update-life-cycle",
        "ele-message",
    ],
)
def test_top_level_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each top-level command responds to --help.

    sys.argv is patched because spsdk_mboot_interface inspects sys.argv for '--help'
    to decide whether to skip the hardware interface requirement.
    """
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# get-families (GetFamiliesCommand — hardware required, only --help tested)
# ---------------------------------------------------------------------------


def test_get_families_help(cli_runner: CliRunner) -> None:
    """Test get-families --help."""
    args = ["get-families", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# key-provisioning group
# ---------------------------------------------------------------------------


def test_key_provisioning_help(cli_runner: CliRunner) -> None:
    """Test key-provisioning group --help."""
    args = ["key-provisioning", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "enroll",
        "set_user_key",
        "set_key",
        "write_key_nonvolatile",
        "read_key_nonvolatile",
        "write_key_store",
        "read_key_store",
    ],
)
def test_key_provisioning_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test that each key-provisioning subcommand responds to --help."""
    args = ["key-provisioning", subcommand, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# trust-provisioning group
# ---------------------------------------------------------------------------


def test_trust_provisioning_help(cli_runner: CliRunner) -> None:
    """Test trust-provisioning group --help."""
    args = ["trust-provisioning", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "hsm_store_key",
        "hsm_gen_key",
        "hsm_enc_blk",
        "hsm_enc_sign",
        "oem_gen_master_share",
        "oem_set_master_share",
        "oem_get_cust_cert_dice_puk",
        "wpc_get_id",
        "nxp_get_id",
        "wpc_insert_cert",
        "wpc_sign_csr",
        "dsc_hsm_create_session",
        "dsc_hsm_enc_blk",
        "dsc_hsm_enc_sign",
        "oem_get_cust_dice_response",
        "prove_genuinity",
        "isp_set_wrap_data",
        "el2go_close_device",
    ],
)
def test_trust_provisioning_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test that each trust-provisioning subcommand responds to --help."""
    args = ["trust-provisioning", subcommand, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# Error paths — missing interface (no sys.argv patch — let it fail naturally)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "reset",
        "read-memory",
        "write-memory",
        "flash-erase-all",
        "get-property",
    ],
)
def test_command_missing_interface_fails(cli_runner: CliRunner, command: str) -> None:
    """Test that commands fail without a hardware interface specified."""
    result = cli_runner.invoke(main, [command], expected_code=-1)
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Error paths — missing required arguments
# ---------------------------------------------------------------------------


def test_efuse_program_once_missing_args(cli_runner: CliRunner) -> None:
    """Test efuse-program-once fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["efuse-program-once"], expected_code=-1)
    assert result.exit_code != 0


def test_flash_erase_region_missing_args(cli_runner: CliRunner) -> None:
    """Test flash-erase-region fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["flash-erase-region"], expected_code=-1)
    assert result.exit_code != 0


def test_fill_memory_missing_args(cli_runner: CliRunner) -> None:
    """Test fill-memory fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["fill-memory"], expected_code=-1)
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# trust-provisioning prove_genuinity — mode selection (ecdsa vs hybrid)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode_arg, expected_mocked_method, other_method",
    [
        (None, "tp_prove_genuinity", "tp_prove_genuinity_hybrid"),
        ("ecdsa", "tp_prove_genuinity", "tp_prove_genuinity_hybrid"),
        ("hybrid", "tp_prove_genuinity_hybrid", "tp_prove_genuinity"),
    ],
)
def test_prove_genuinity_mode_selects_correct_mcuboot_method(
    cli_runner: CliRunner, mode_arg: str | None, expected_mocked_method: str, other_method: str
) -> None:
    """Test that --mode selects the correct McuBoot prove-genuinity method.

    No --mode (default), --mode ecdsa must call tp_prove_genuinity.
    --mode hybrid must call tp_prove_genuinity_hybrid.
    """
    args = ["trust-provisioning", "prove_genuinity", "0x1000", "0x100"]
    if mode_arg is not None:
        args += ["--mode", mode_arg]

    with (
        patch(
            "spsdk.apps.utils.common_cli_options.load_interface_config",
            return_value=MagicMock(IDENTIFIER="usb", get_scan_args=dict),
        ),
        patch(
            "spsdk.apps.utils.common_cli_options.MbootProtocolBase.get_interface_class"
        ) as get_cls,
        patch("spsdk.apps.blhost.McuBoot") as mock_mboot_class,
    ):
        get_cls.return_value.scan_single.return_value = MagicMock()
        mock_mboot = MagicMock()
        mock_mboot.__enter__.return_value = mock_mboot
        mock_mboot.status_code = 0
        getattr(mock_mboot, expected_mocked_method).return_value = 0x100
        mock_mboot_class.return_value = mock_mboot

        result = cli_runner.invoke(main, args)

    assert result.exit_code == 0
    getattr(mock_mboot, expected_mocked_method).assert_called_once_with(
        address=0x1000, buffer_size=0x100
    )
    getattr(mock_mboot, other_method).assert_not_called()


@contextlib.contextmanager
def _mocked_flash_image_mboot(sector_size: int = 0x1000) -> Iterator[MagicMock]:
    """Provide a mocked McuBoot instance for flash-image tests.

    :param sector_size: Flash sector size reported by the simulated target.
    :return: Mocked McuBoot instance used by the flash-image command.
    """
    with (
        patch(
            "spsdk.apps.utils.common_cli_options.load_interface_config",
            return_value=MagicMock(IDENTIFIER="usb", get_scan_args=dict),
        ),
        patch(
            "spsdk.apps.utils.common_cli_options.MbootProtocolBase.get_interface_class"
        ) as get_cls,
        patch("spsdk.apps.blhost.McuBoot") as mock_mboot_class,
    ):
        get_cls.return_value.scan_single.return_value = MagicMock()
        mock_mboot = MagicMock()
        mock_mboot.__enter__.return_value = mock_mboot
        mock_mboot.status_code = 0
        mock_mboot.get_property.return_value = [sector_size]
        mock_mboot.interface.device.timeout = 5000
        mock_mboot_class.return_value = mock_mboot
        yield mock_mboot


def test_flash_image_erase_only_does_not_write(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that --erase-only erases the image regions but writes no data."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image, "--erase-only"]

    with _mocked_flash_image_mboot() as mock_mboot:
        cli_runner.invoke(main, args)

    mock_mboot.flash_erase_region.assert_called_once_with(address=0, length=0x1000, mem_id=0)
    mock_mboot.write_memory.assert_not_called()


def test_flash_image_erase_only_with_memory_id(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that --erase-only honors the memory ID and the external memory sector size."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image, "none", "9", "--erase-only"]

    with _mocked_flash_image_mboot() as mock_mboot:
        # external memory attributes reporting a 64 kiB sector size
        mock_mboot.get_property.return_value = [0x08, 0, 0, 0, 0x10000, 0]
        cli_runner.invoke(main, args)

    mock_mboot.flash_erase_region.assert_called_once_with(address=0, length=0x10000, mem_id=9)
    mock_mboot.write_memory.assert_not_called()


def test_flash_image_erase_uses_target_sector_size(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that the erase region is aligned to the sector size reported by the target."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image, "erase"]

    with _mocked_flash_image_mboot(sector_size=0x8000) as mock_mboot:
        cli_runner.invoke(main, args)

    mock_mboot.flash_erase_region.assert_called_once_with(address=0, length=0x8000, mem_id=0)
    mock_mboot.write_memory.assert_called_once()


def test_flash_image_erase_alignment_override(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that --erase-alignment overrides the value read from the target."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image, "erase", "--erase-alignment", "0x10000"]

    with _mocked_flash_image_mboot(sector_size=0x1000) as mock_mboot:
        cli_runner.invoke(main, args)

    mock_mboot.get_property.assert_not_called()
    mock_mboot.flash_erase_region.assert_called_once_with(address=0, length=0x10000, mem_id=0)


def test_flash_image_no_erase(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that the image is written without erasing when erase is not requested."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image]

    with _mocked_flash_image_mboot() as mock_mboot:
        cli_runner.invoke(main, args)

    mock_mboot.flash_erase_region.assert_not_called()
    mock_mboot.write_memory.assert_called_once()


def test_flash_image_erase_only_failure_reports_error(cli_runner: CliRunner, data_dir: str) -> None:
    """Test that a failing erase operation is reported and no data is written."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["flash-image", image, "--erase-only"]

    with _mocked_flash_image_mboot() as mock_mboot:
        mock_mboot.status_code = 10205  # Memory Not Configured
        cli_runner.invoke(main, args, expected_code=1)

    mock_mboot.flash_erase_region.assert_called_once()
    mock_mboot.write_memory.assert_not_called()


def test_flash_image_erase_large_image_reports_progress(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test that erasing a large region is split into several commands reporting progress."""
    image = os.path.join(tmpdir, "large.bin")
    # an image large enough to be erased by several chunks
    length = 16 * MIN_ERASE_PROGRESS_LENGTH
    write_file(bytes(length), image, mode="wb")
    args = ["flash-image", image, "--erase-only"]

    with _mocked_flash_image_mboot(sector_size=0x1000) as mock_mboot:
        cli_runner.invoke(main, args)

    chunk = get_erase_chunk_size(length, 0x1000)
    assert mock_mboot.flash_erase_region.call_count == -(-length // chunk)
    # the erased chunks cover the whole region exactly once
    erased = [
        (call.kwargs["address"], call.kwargs["length"])
        for call in mock_mboot.flash_erase_region.call_args_list
    ]
    assert erased[0][0] == 0
    assert sum(item[1] for item in erased) == length
    for previous, current in zip(erased, erased[1:]):
        assert current[0] == previous[0] + previous[1]
    mock_mboot.write_memory.assert_not_called()


def test_flash_image_erase_progress_suppressed_in_json_mode(
    cli_runner: CliRunner, data_dir: str
) -> None:
    """Test that the erase still works when the progress bar is suppressed."""
    image = os.path.join(data_dir, "zeros.bin")
    args = ["-j", "flash-image", image, "--erase-only"]

    with _mocked_flash_image_mboot() as mock_mboot:
        cli_runner.invoke(main, args)

    mock_mboot.flash_erase_region.assert_called_once_with(address=0, length=0x1000, mem_id=0)
    mock_mboot.write_memory.assert_not_called()

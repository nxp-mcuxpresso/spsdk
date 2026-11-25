#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK NXP Fuses CLI functionality.

This module contains comprehensive test cases for the nxpfuses command-line
interface, covering fuse operations like reading, writing, and configuration
management across NXP MCU devices.
"""

import os
import sys
from typing import Any
from unittest.mock import patch

import pytest
from yaml import safe_dump

from spsdk.apps import nxpfuses
from spsdk.exceptions import SPSDKConnectionError
from spsdk.fuses.fuses import Fuses, SPSDKFuseOperationFailure
from spsdk.utils.family import FamilyRevision
from spsdk.utils.interfaces.protocol.protocol_base import (
    SpsdkMultipleDevicesFoundError,
    SpsdkNoDeviceFoundError,
)
from spsdk.utils.misc import load_configuration, load_file, write_file
from tests.cli_runner import CliRunner
from tests.fuses.fuses.fuses_test_operator import TestBlhostFuseOperator


def mock_fuses_operator(*args: Any, **kwargs: Any) -> TestBlhostFuseOperator:
    """Create a mock fuses operator for testing purposes.

    This function serves as a factory method to instantiate a TestBlhostFuseOperator
    with the specified family revision for use in unit tests.

    :param args: Variable length argument list (unused).
    :param kwargs: Keyword arguments containing configuration parameters.
    :raises AssertionError: If the 'family' parameter is not a FamilyRevision instance.
    :return: Configured TestBlhostFuseOperator instance for the specified family.
    """
    fam = kwargs.get("family")
    assert isinstance(fam, FamilyRevision)
    return TestBlhostFuseOperator(fam)


@pytest.mark.parametrize(
    "family",
    Fuses.get_supported_families(),
)
def test_nxpfuses_get_template(tmpdir: str, cli_runner: CliRunner, family: FamilyRevision) -> None:
    """Test nxpfuses get-template CLI command functionality.

    Verifies that the get-template command generates a valid YAML template file
    for the specified family and that the template contains the correct family name.

    :param tmpdir: Temporary directory path for test files.
    :param cli_runner: CLI runner instance for invoking commands.
    :param family: Family revision object containing the target family information.
    :raises AssertionError: If template file is not created or contains incorrect family name.
    """
    template = os.path.join(tmpdir, "template.yaml")
    cmd = f"get-template -f {family.name} --output {template}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(template)
    assert load_configuration(template)["family"] == family.name


def test_nxpfuses_fuses_script(tmpdir: str, cli_runner: CliRunner, data_dir: str) -> None:
    """Test the nxpfuses fuses-script command functionality.

    This test verifies that the fuses-script command can generate a proper fuses programming
    script from a configuration file, and that the generated script contains the expected
    content and structure.

    :param tmpdir: Temporary directory path for output files.
    :param cli_runner: CLI runner fixture for invoking commands.
    :param data_dir: Directory path containing test data files.
    """
    fuses_script = os.path.join(tmpdir, "fuses.txt")
    cmd = f"fuses-script -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} -o {fuses_script}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(fuses_script)
    fuses_script_content = load_file(fuses_script)
    assert isinstance(fuses_script_content, str)
    assert "BLHOST fuses programming script" in fuses_script_content
    assert fuses_script_content.count("efuse-program-once") == 15


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
def test_nxpfuses_fuses_write_single(cli_runner: CliRunner) -> None:
    """Test nxpfuses CLI write-single command functionality.

    This test verifies that the write-single command correctly processes arguments
    and executes the expected fuse write operation with proper parameters.

    :param cli_runner: CLI test runner fixture for invoking command line operations.
    """
    # This may eventually cause some conflicts when multiple tests run concurrently
    TestBlhostFuseOperator.ACTIONS = []
    cmd = "write-single -f mimxrt798s -n BOOT_CFG0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS
    write_action = TestBlhostFuseOperator.ACTIONS[-1]
    assert write_action.action_type == "write"
    assert write_action.fuse_index == 0x88
    assert write_action.value == 0x5


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_write(cli_runner: CliRunner, data_dir: str) -> None:
    """Test nxpfuses CLI write command functionality.

    This test verifies that the nxpfuses write command properly processes a configuration
    file and generates the expected fuse write operations. It checks that the correct
    number of write actions are created and validates the sequence of operations.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Path to test data directory containing configuration files.
    """
    # This may eventually cause some conflicts when multiple tests run concurrently
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"write -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS
    write_actions = [fuse for fuse in TestBlhostFuseOperator.ACTIONS if fuse.action_type == "write"]
    assert len(write_actions) == 15  # 12x RKTH + 2x XSPI0_IPED_CTX +1x LOCK_CFG0
    assert write_actions[-1].fuse_index == 0  # Last fuse is always lock fuse


@pytest.mark.parametrize(
    "name",
    ["XSPI0_IPED_CTX1", 0x91, "fuse145"],
)
@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_print_single(
    cli_runner: CliRunner, data_dir: str, caplog: Any, name: str | int
) -> None:
    """Test printing a single fuse using the nxpfuses CLI command.

    This test verifies that the nxpfuses print command correctly handles printing
    a single fuse by name or index, validates the blhost operator actions,
    and checks the formatted output contains expected fuse information.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param caplog: Pytest fixture for capturing log output.
    :param name: Fuse name or index to print.
    """
    caplog.set_level(100_000)
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"print -f mimxrt798s -n {name}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS[-1].action_type == "read"
    assert TestBlhostFuseOperator.ACTIONS[-1].fuse_index == 0x91
    assert "Name:        XSPI0_IPED_CTX1" in result.output
    assert "OTP index:   0x91" in result.output
    assert "Value:       0x00000000" in result.output
    assert "Locks:       No locks" in result.output


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_get_config(
    cli_runner: CliRunner, data_dir: str, caplog: Any, tmpdir: str
) -> None:
    """Test nxpfuses CLI get-config command functionality.

    This test verifies the get-config command can generate configuration files,
    save them to specified output paths, and handle diff-only mode to show
    only modified fuse registers.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param caplog: Pytest fixture for capturing log messages.
    :param tmpdir: Temporary directory path for test file operations.
    """
    out = os.path.join(tmpdir, "config.yaml")
    cmd = f"get-config -f mimxrt798s -o {out}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert "The fuses configuration has been saved" in result.output
    assert os.path.isfile(out)
    assert load_configuration(out)["family"] == "mimxrt798s"
    cmd = "write-single -f mimxrt798s -n BOOT_CFG0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    cmd = f"get-config -f mimxrt798s -o {out} --diff-only"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    cfg = load_configuration(out)
    assert len(cfg["registers"]) == 1
    assert next(iter(cfg["registers"])) == "BOOT_CFG0"


def _invoke_via_safe_main(args: list) -> int:
    """Invoke `nxpfuses` through `safe_main()` to get real exit codes.

    `click`'s `CliRunner` invokes the `main` group directly, bypassing the
    `@catch_spsdk_error` decorator applied on `safe_main()`, which is where
    `SPSDKAppError`/`SPSDKError` get translated into process exit codes.
    This helper reproduces that behavior for exact exit-code assertions.

    :param args: CLI arguments, e.g. ["verify", "-c", "config.yaml"].
    :return: Process exit code as it would be returned by `safe_main()`.
    """
    with patch.object(sys, "argv", ["nxpfuses", *args]):
        try:
            nxpfuses.safe_main()
        except SystemExit as exc:
            return int(exc.code) if exc.code is not None else 0
    return 0


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_verify_pass(cli_runner: CliRunner, data_dir: str) -> None:
    """Test nxpfuses CLI verify command returns exit code 0 (PASS) on full match.

    The device values are set up to exactly match the configuration file,
    so the verification must report an overall PASS status and exit code 0.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    """
    # LOCK_CFG0 otp_index=0x0, XSPI0_IPED_CTX1 otp_index=0x91, XSPI0_IPED_CTX2 otp_index=0x92
    TestBlhostFuseOperator.RETURN_VALUES = {0x0: 0x7, 0x91: 0, 0x92: 0}
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"verify -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split(), expected_code=0)
    assert "status: PASS" in result.output
    assert "Overall verification status: PASS" in result.output


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_verify_mismatch(capsys: pytest.CaptureFixture, data_dir: str) -> None:
    """Test nxpfuses CLI verify command exits with code 4 (FAIL) on mismatch.

    The LOCK_CFG0 fuse value read back from the device differs from the
    expected configuration, so the overall status must be FAIL and the
    process must exit with the dedicated mismatch exit code.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param data_dir: Directory path containing test data files.
    """
    TestBlhostFuseOperator.RETURN_VALUES = {0x0: 0x1, 0x91: 0, 0x92: 0}
    TestBlhostFuseOperator.ACTIONS = []
    exit_code = _invoke_via_safe_main(
        ["verify", "-c", os.path.join(data_dir, "mimxrt798s_config_0.yaml")]
    )
    captured = capsys.readouterr()
    assert exit_code == 4
    assert "status: FAIL" in captured.out
    assert "Overall verification status: FAIL" in captured.out


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_verify_partial(capsys: pytest.CaptureFixture, data_dir: str) -> None:
    """Test nxpfuses CLI verify command exits with code 5 (PARTIAL).

    One of the fuses raises SPSDKFuseOperationFailure on read, simulating a
    fuse that cannot be verified (e.g. due to access rights). Since there is
    no actual mismatch, the overall status must be PARTIAL.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param data_dir: Directory path containing test data files.
    """
    TestBlhostFuseOperator.RETURN_VALUES = {0x0: 0x7, 0x92: 0}
    TestBlhostFuseOperator.ACTIONS = []
    orig_read_fuse = TestBlhostFuseOperator.read_fuse

    def read_fuse_with_failure(self: TestBlhostFuseOperator, index: int, length: int) -> int:
        if index == 0x91:
            raise SPSDKFuseOperationFailure("simulated read failure")
        return orig_read_fuse(self, index, length)

    with patch.object(TestBlhostFuseOperator, "read_fuse", read_fuse_with_failure):
        exit_code = _invoke_via_safe_main(
            ["verify", "-c", os.path.join(data_dir, "mimxrt798s_config_0.yaml")]
        )
    captured = capsys.readouterr()
    assert exit_code == 5
    assert "status: PARTIAL" in captured.out
    assert "Overall verification status: PARTIAL" in captured.out
    assert "NOT_VERIFIABLE" in captured.out


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_verify_comm_error(capsys: pytest.CaptureFixture, data_dir: str) -> None:
    """Test nxpfuses CLI verify command exits with code 6 on comm error.

    When the device communication fails with SPSDKConnectionError, the
    verify command must translate it into the dedicated communication
    error exit code instead of a generic SPSDK error exit code.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param data_dir: Directory path containing test data files.
    """
    TestBlhostFuseOperator.RETURN_VALUES = {}
    TestBlhostFuseOperator.ACTIONS = []

    def read_fuse_connection_error(self: TestBlhostFuseOperator, index: int, length: int) -> int:
        raise SPSDKConnectionError("device disconnected")

    with patch.object(TestBlhostFuseOperator, "read_fuse", read_fuse_connection_error):
        exit_code = _invoke_via_safe_main(
            ["verify", "-c", os.path.join(data_dir, "mimxrt798s_config_0.yaml")]
        )
    captured = capsys.readouterr()
    assert exit_code == 6
    assert "Device communication failed" in captured.err


@pytest.mark.parametrize(
    "exception",
    [
        SpsdkNoDeviceFoundError("usb", "0x1fc9:0x0021"),
        SpsdkMultipleDevicesFoundError("usb", "0x1fc9:0x0021"),
        SPSDKConnectionError("cannot open"),
    ],
)
def test_nxpfuses_verify_device_not_available(
    capsys: pytest.CaptureFixture, data_dir: str, exception: Exception
) -> None:
    """Test nxpfuses CLI verify exits with code 6 when the device cannot be opened.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param data_dir: Directory path containing test data files.
    :param exception: Exception raised while creating the fuse operator.
    """
    with patch("spsdk.apps.nxpfuses.get_fuse_operator", side_effect=exception):
        exit_code = _invoke_via_safe_main(
            ["verify", "-c", os.path.join(data_dir, "mimxrt798s_config_0.yaml")]
        )
    captured = capsys.readouterr()
    assert exit_code == 6
    assert "Device communication failed" in captured.err


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_verify_output_file(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test nxpfuses CLI verify command writes the report to a file with -o.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for test file operations.
    """
    TestBlhostFuseOperator.RETURN_VALUES = {0x0: 0x7, 0x91: 0, 0x92: 0}
    TestBlhostFuseOperator.ACTIONS = []
    out = os.path.join(tmpdir, "verify_report.yaml")
    cmd = f"verify -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} -o {out}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split(), expected_code=0)
    assert os.path.isfile(out)
    report_content = load_file(out)
    assert isinstance(report_content, str)
    assert "status: PASS" in report_content
    assert "has been saved into" in result.output


def test_nxpfuses_compare_identical(
    capsys: pytest.CaptureFixture, mock_test_database: Any, tmpdir: str
) -> None:
    """Test compare ignores field order and equivalent value formatting.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param mock_test_database: Mocked test database fixture for testing.
    :param tmpdir: Temporary directory path for test files.
    """
    old_path = os.path.join(tmpdir, "old.yaml")
    new_path = os.path.join(tmpdir, "new.yaml")
    write_file(
        safe_dump(
            {
                "family": "dev2",
                "revision": "latest",
                "registers": {"REG1": {"BITFIELD1": "ENABLED", "BITFIELD2": "DISABLED"}},
            }
        ),
        old_path,
    )
    write_file(
        safe_dump(
            {
                "registers": {"REG1": {"BITFIELD2": 0, "BITFIELD1": 1}},
                "revision": "latest",
                "family": "dev2",
            }
        ),
        new_path,
    )

    exit_code = _invoke_via_safe_main(["compare", old_path, new_path])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "status: IDENTICAL" in captured.out
    assert "Overall comparison status: IDENTICAL" in captured.out


def test_nxpfuses_compare_difference(
    capsys: pytest.CaptureFixture, mock_test_database: Any, tmpdir: str
) -> None:
    """Test compare returns a CI-friendly exit code and field-level report.

    :param capsys: Pytest fixture to capture stdout/stderr output.
    :param mock_test_database: Mocked test database fixture for testing.
    :param tmpdir: Temporary directory path for test files.
    """
    old_path = os.path.join(tmpdir, "old.yaml")
    new_path = os.path.join(tmpdir, "new.yaml")
    output_path = os.path.join(tmpdir, "report.yaml")
    base = {
        "family": "dev2",
        "revision": "latest",
        "registers": {"REG1": {"BITFIELD1": "DISABLED"}},
    }
    changed = {
        "family": "dev2",
        "revision": "latest",
        "registers": {"REG1": {"BITFIELD1": "ENABLED"}},
    }
    write_file(safe_dump(base), old_path)
    write_file(safe_dump(changed), new_path)

    exit_code = _invoke_via_safe_main(["compare", old_path, new_path, "--output", output_path])
    captured = capsys.readouterr()
    report = load_file(output_path)

    assert exit_code == 4
    assert "Overall comparison status: DIFFERENT" in captured.out
    assert "REG1.BITFIELD1" in report
    assert "old: DISABLED" in report
    assert "new: ENABLED" in report

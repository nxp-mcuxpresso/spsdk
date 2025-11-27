#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK BLHost CLI application test suite.

This module contains comprehensive tests for the BLHost command-line interface,
covering device communication, memory operations, and security features.
The tests validate BLHost functionality including device properties, flash and eFuse
operations, Trust Provisioning commands, batch processing, and various communication
protocols. Mock objects simulate device responses to enable testing without hardware.
"""

import os
from typing import Any
from unittest.mock import patch

import spsdk
from spsdk.apps import blhost
from spsdk.utils.misc import load_binary
from spsdk.utils.serial_buspal_proxy import SerialBuspalProxy
from spsdk.utils.serial_proxy import SerialProxy
from tests.cli_runner import CliRunner, Result

# fmt: off
data_responses: dict[bytes, bytes] = {
    # ack
    b"\x5a\xa1": b"",
    # ping
    b"\x5a\xa6": b"\x5a\xa7\x00\x03\x01\x50\x00\x00\xfb\x40",
    # get-property
    b"\x5a\xa4\x0c\x00\x4b\x33\x07\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x65\x1c\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x4b",
    # get-property 0xA
    b"\x5a\xa4\x0c\x00\xe4\xe5\x07\x00\x00\x02\x0a\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x2d\xc6\xa7\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00",
    # set-property 10 1
    b"\x5a\xa4\x0c\x00\x67\x8d\x0c\x00\x00\x02\x0a\x00\x00\x00\x01\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\xe0\xf7\xa0\x00\x00\x02\x00\x00\x00\x00\x0c\x00\x00\x00",
    # efuse-read-one
    b"\x5a\xa4\x0c\x00\x14\x27\x0f\x00\x00\x02\x64\x00\x00\x00\x04\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x10\x00\xc5\xbf\xaf\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00",
    # efuse-read-one 0x98 with unknown error code 0xbeef (48,879)
    b"\x5a\xa4\x0c\x00\x2e\x7b\x0f\x00\x00\x02\x98\x00\x00\x00\x04\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x36\xc2\xaf\x00\x00\x02\xef\xbe\x00\x00\x00\x00\x00\x00",
    # use get-property 13 (reserved) as a vehicle to emulate no response from target
    b"\x5a\xa4\x0c\x00\xfc\x22\x07\x00\x00\x02\x0d\x00\x00\x00\x00\x00\x00\x00":
        b"",
    # get-property 0xff - unknown property
    b"\x5a\xa4\x0c\x00\xd7\xe0\x07\x00\x00\x02\xff\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x08\x00\x92\x68\xa7\x00\x00\x01\x3c\x28\x00\x00",
    # flash-read-once 1 4
    b"\x5a\xa4\x0c\x00\x12\xe2\x0f\x00\x00\x02\x01\x00\x00\x00\x04\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x10\x00\x3f\x6f\xaf\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x78\x56\x34\x12",
    # flash-program-once 1 4 12345678
    b"\x5a\xa4\x10\x00\x0b\x8a\x0e\x00\x00\x03\x01\x00\x00\x00\x04\x00\x00\x00\x78\x56\x34\x12":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x88\x1a\xa0\x00\x00\x02\x00\x00\x00\x00\x0e\x00\x00\x00",
    # flash-security-disable 0102030405060708
    b"\x5a\xa4\x0c\x00\x43\x7b\x06\x00\x00\x02\x04\x03\x02\x01\x08\x07\x06\x05":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x4d\xd5\xa0\x00\x00\x02\x10\x27\x00\x00\x06\x00\x00\x00",
    # flash-erase-all-unsecure
    b"\x5a\xa4\x04\x00\xf6\x61\x0d\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x52\xcb\xa0\x00\x00\x02\x10\x27\x00\x00\x0d\x00\x00\x00",
    # flash-erase-all 0x0
    b"\x5a\xa4\x08\x00\x0c\x22\x01\x00\x00\x01\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x66\xce\xa0\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00",
    # flash-erase-region 0x8000000 0x0
    b"\x5a\xa4\x10\x00\x41\xee\x02\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\xba\x55\xa0\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00",
    # flash-read-resource 1 4 1
    b"\x5a\xa4\x10\x00\x71\xde\x10\x00\x00\x03\x01\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00":
        (b"\x5a\xa1"
         b"\x5a\xa4\x0c\x00\x3a\x9d\xb0\x01\x00\x02\x00\x00\x00\x00\x04\x00\x00\x00"
         b"\x5a\xa5\x04\x00\x11\xe0\x00\x00\x00\x00"
         b"\x5a\xa4\x0c\x00\x75\xa3\xa0\x00\x00\x02\x00\x00\x00\x00\x10\x00\x00\x00"),
    # reliable-update 0xfe000
    b"\x5a\xa4\x08\x00\xc2\x67\x12\x00\x00\x01\x00\xe0\x0f\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x1b\x04\xa0\x00\x00\x02\x10\x27\x00\x00\x12\x00\x00\x00",
    # fuse-read 0x1 8
    b"\x5a\xa4\x10\x00\xed\xd1\x17\x00\x00\x03\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x5e\xb8\xa0\x00\x00\x02\x10\x27\x00\x00\x17\x00\x00\x00",
    # fuse-program 3 {{12345678}} 0
    b"\x5a\xa4\x0c\x00\x37\xa2\x07\x00\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\xa9\x87\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x01\x00\x00",
    b"\x5a\xa4\x10\x00\x01\x80\x14\x01\x00\x03\x03\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x82\x23\xa0\x00\x00\x02\x10\x27\x00\x00\x14\x00\x00\x00",
    # flash-image {os.path.join(data_dir, 'evkmimxrt685_led_blinky_ext_flash.srec')} erase 3
    b"\x5a\xa4\x10\x00\x46\xc2\x02\x00\x00\x03\x00\x10\x00\x08\x00\x58\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x89\x42\xa0\x00\x00\x02\xdd\x27\x00\x00\x02\x00\x00\x00",
    # trust-provisioning hsm_gen_key MFWISK 0 0x20008000 48 0x20009000 64
    b"\x5a\xa4\x20\x00\x53\x2e\x16\x00\x00\x07\x03\x00\x00\x00\xa5\xc3\x00\x00\x00\x00\x00\x00\x00\x80\x00\x20\x30\x00\x00\x00\x00\x90\x00\x20\x40\x00\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x10\x00\x43\x02\xb6\x00\x00\x03\x00\x00\x00\x00\x30\x00\x00\x00\x40\x00\x00\x00",
    # trust-provisioning hsm_store_key 5 1 0x2000B000 32 0x2000C000 48
    b"\x5a\xa4\x20\x00\x08\xf7\x16\x00\x00\x07\x04\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\x00\xb0\x00\x20\x20\x00\x00\x00\x00\xc0\x00\x20\x30\x00\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x10\x00\x5f\xd2\xb6\x00\x00\x03\x00\x00\x00\x00\x61\x00\x10\x10\x30\x00\x00\x00",
    # trust-provisioning hsm_enc_blk 0x2000A000 48 16 0x2000C000 60 1 0x2000D000 256
    b"\x5a\xa4\x28\x00\x8e\xae\x16\x00\x00\x09\x05\x00\x00\x00\x00\xa0\x00\x20\x30\x00\x00\x00\x10\x00\x00\x00\x00\xc0\x00\x20\x3c\x00\x00\x00\x01\x00\x00\x00\x00\xd0\x00\x20\x00\x01\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x08\x00\x49\x5e\xb6\x00\x00\x01\x00\x00\x00\x00",
    # trust-provisioning hsm_enc_sign 0x20008000 48 0x2000F000 220 0x20010000 64
    b"\x5a\xa4\x20\x00\xe7\x20\x16\x00\x00\x07\x06\x00\x00\x00\x00\x80\x00\x20\x30\x00\x00\x00\x00\xf0\x00\x20\xdc\x00\x00\x00\x00\x00\x01\x20\x40\x00\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x0c\x00\x20\xea\xb6\x00\x00\x02\x00\x00\x00\x00\x40\x00\x00\x00",
    # trust-provisioning oem_gen_master_share 0x20008000 0x10 0x20009000 0x1000 0x2000A000 0x1000 0x2000B000 0x1000
    b"\x5a\xa4\x28\x00\x34\x07\x16\x00\x00\x09\x00\x00\x00\x00\x00\x80\x00\x20\x10\x00\x00\x00\x00\x90\x00\x20\x00\x10\x00\x00\x00\xa0\x00\x20\x00\x10\x00\x00\x00\xb0\x00\x20\x00\x10\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x14\x00\xe6\x12\xb6\x00\x00\x04\x00\x00\x00\x00\x30\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00", # pylint: disable=line-too-long
    # trust-provisioning oem_set_master_share 0x20008000 16 0x20009000 64
    b"\x5a\xa4\x18\x00\x02\xfe\x16\x00\x00\x05\x01\x00\x00\x00\x00\x80\x00\x20\x10\x00\x00\x00\x00\x90\x00\x20\x40\x00\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x08\x00\x49\x5e\xb6\x00\x00\x01\x00\x00\x00\x00",
    # trust-provisioning oem_get_cust_cert_dice_puk 0x30015000 0x20 0x30016000 0x40
    b"\x5a\xa4\x18\x00\x01\xca\x16\x00\x00\x05\x02\x00\x00\x00\x00\x50\x01\x30\x20\x00\x00\x00\x00\x60\x01\x30\x40\x00\x00\x00": # pylint: disable=line-too-long
        b"\x5a\xa1\x5a\xa4\x0c\x00\x20\xea\xb6\x00\x00\x02\x00\x00\x00\x00\x40\x00\x00\x00",
}


data_responses_buspal_i2c = {
    # reset mode
    b"\x00": b"\x42\x42\x49\x4f\x31",
    # i2c mode
    b"\x02": b"\x49\x32\x43\x31",
    # set i2c address to 16
    b"\x70\x10": b"\x01",
    # Set I2C speed to 100bps
    b"\x60\x64\x00\x00\x00": b"\x01",
    # ping
    b"\x08\x02\x00\x00\x00\x5a\xa6": [
        b"\x01",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa7",
        b"\x01",
        b"\x00\x03\x01\x50\x00\x00\xfb\x40",
    ],
    # get-property
    b"\x08\x12\x00\x00\x00\x5a\xa4\x0c\x00\x4b\x33\x07\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00": [
        b"\x01",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa1",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa4",
        b"\x01",
        b"\x0c\x00",
        b"\x01",
        b"\x65\x1c",
        b"\x01",
        b"\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x4b",
    ],
    # get-property response
    b"\x08\x02\x00\x00\x00\x5a\xa1": b"\x01",
}


data_responses_buspal_spi = {
    # reset mode
    b"\x00": b"\x42\x42\x49\x4f\x31",
    # spi mode
    b"\x01": b"\x53\x50\x49\x31",
    # set spi config
    b"\x86": b"\x01",
    # set spi speed to 5bps
    b"\x60\x05\x00\x00\x00": b"\x01",
    # ping
    b"\x04\x02\x00\x00\x00\x5a\xa6": [
        b"\x01",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa7",
        b"\x01",
        b"\x00\x03\x01\x50\x00\x00\xfb\x40",
    ],
    # get-property
    b"\x04\x12\x00\x00\x00\x5a\xa4\x0c\x00\x4b\x33\x07\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00": [
        b"\x01",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa1",
        b"\x01",
        b"\x5a",
        b"\x01",
        b"\xa4",
        b"\x01",
        b"\x0c\x00",
        b"\x01",
        b"\x65\x1c",
        b"\x01",
        b"\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x4b",
    ],
    # get-property response
    b"\x04\x02\x00\x00\x00\x5a\xa1": b"\x01",
}

# fmt: on


def test_version(cli_runner: CliRunner) -> None:
    """Test that blhost CLI displays correct version information.

    Verifies that the --version flag outputs the current SPSDK version string
    in the command line interface response.

    :param cli_runner: Click CLI test runner for invoking command line interfaces
    """
    result = cli_runner.invoke(blhost.main, ["--version"])
    assert spsdk.__version__ in result.output


def run_blhost_proxy(
    cli_runner: CliRunner,
    caplog: Any,
    cmd: Any,
    expect_exit_code: int = 0,
    ignore_ack: bool = False,
) -> Result:
    """Run blhost CLI command through a proxy for testing.

    This function executes blhost CLI commands using a mocked serial interface
    for testing purposes. It handles logging configuration and sets up a serial
    proxy to simulate device communication.

    :param cli_runner: Click CLI test runner instance.
    :param caplog: Pytest logging capture fixture.
    :param cmd: Command arguments to pass to blhost CLI.
    :param expect_exit_code: Expected exit code from the CLI command.
    :param ignore_ack: Whether to ignore ACK responses in the proxy.
    :return: CLI command execution result.
    """
    # There's a problem with logging under CliRunner
    # https://github.com/pytest-dev/pytest/issues/3344
    # caplog is set to disable all logging output
    # Comment the following line to see logging info, however there will be an failure
    caplog.set_level(100_000)
    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial",
        SerialProxy.init_proxy(data_responses, ignore_ack=ignore_ack),
    ):
        result = cli_runner.invoke(blhost.main, cmd, expected_code=expect_exit_code)
    return result


def test_get_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test get-property command functionality.

    Verifies that the get-property command with parameter "1" executes successfully
    and returns the expected version information in the output.

    :param cli_runner: Click CLI runner for testing command line interfaces
    :param caplog: Pytest fixture for capturing log output during test execution
    """
    cmd = ["-p", "super-com", "get-property", "1"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Current Version = K3.0.0" in result.output


def test_buspal_i2c_get_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test buspal I2C get property command functionality.

    This test verifies that the blhost CLI can successfully execute a get-property
    command using the I2C buspal interface. It mocks the serial device connection
    and validates that the command returns the expected version information.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param caplog: Pytest fixture for capturing log messages.
    """
    caplog.set_level(100_000)
    cmd = ["-b", "i2c", "-p", "super-com", "get-property", "1"]
    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial",
        SerialBuspalProxy.init_buspal_proxy("i2c", data_responses_buspal_i2c),  # type: ignore
    ):
        result = cli_runner.invoke(blhost.main, cmd)
        assert result.exit_code == 0
        assert "Current Version = K3.0.0" in result.output


def test_buspal_spi_get_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test buspal SPI interface get-property command functionality.

    This test verifies that the blhost CLI can successfully communicate with a device
    using the buspal SPI interface to retrieve property information. It mocks the
    serial communication and validates that the expected version information is
    returned in the command output.

    :param cli_runner: Click CLI test runner for invoking command line interfaces
    :param caplog: Pytest fixture for capturing and controlling log output during tests
    """
    caplog.set_level(100_000)
    cmd = ["-b", "spi,5", "-p", "super-com", "get-property", "1"]
    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial",
        SerialBuspalProxy.init_buspal_proxy("spi", data_responses_buspal_spi),  # type: ignore
    ):
        result = cli_runner.invoke(blhost.main, cmd)
        assert "Current Version = K3.0.0" in result.output


def test_get_property_hex_input(cli_runner: CliRunner, caplog: Any) -> None:
    """Test get-property command with hexadecimal input parameter.

    Verifies that the blhost get-property command correctly processes hexadecimal
    input (0xA) and returns expected success response with proper formatting.

    :param cli_runner: Click CLI test runner for command execution.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = ["-p", "super-com", "get-property", "0xA"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 1 (0x1)" in result.output
    assert "Verify Writes = ON" in result.output


def test_set_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test set-property command functionality.

    Verifies that the blhost set-property command executes successfully
    and returns the expected success response when setting a property
    value through the command line interface.

    :param cli_runner: Click CLI runner for executing command line operations
    :param caplog: Pytest fixture for capturing log output during test execution
    """
    cmd = ["-p", "super-com", "set-property", "10", "1"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_efuse_read_once(cli_runner: CliRunner, caplog: Any) -> None:
    """Test efuse read-once command functionality.

    Verifies that the efuse-read-once blhost command executes correctly
    and returns expected response format with proper status codes.

    :param cli_runner: Click CLI test runner for command execution.
    :param caplog: Pytest fixture for capturing log output.
    """
    cmd = ["-p", "super-com", "efuse-read-once", "100"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Response word 2 = 0 (0x0)" in result.output
    assert "Response status = 0 (0x0) Success." in result.output


def test_efuse_read_once_unknown_error(cli_runner: CliRunner, caplog: Any) -> None:
    """Test efuse read once command with unknown error response.

    Verifies that the blhost efuse-read-once command properly handles and reports
    unknown error codes from the target device, ensuring appropriate error messaging
    is displayed to the user.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = ["-p", "super-com", "efuse-read-once", "0x98"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response word 1 = 4 (0x4)" not in result.output
    assert "Unknown error code" in result.output


def test_no_response(cli_runner: CliRunner, caplog: Any) -> None:
    """Test that blhost handles no response from target device correctly.

    This test uses get-property command with reserved property ID 13 to simulate
    a scenario where the target device doesn't respond, and verifies that the
    appropriate error message is displayed.

    :param cli_runner: Click CLI runner for executing commands in tests.
    :param caplog: Pytest fixture for capturing log output.
    """
    # use get-property 13 (reserved) as a vehicle to emulate no response from target
    cmd = ["-p", "super-com", "get-property", "13"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert (
        "Response status = 10004 (0x2714) No response packet from target device." in result.output
    )


def test_unknown_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test unknown property retrieval via blhost CLI.

    Verifies that the blhost CLI properly handles requests for unknown properties
    by returning the appropriate error status code and message.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    """
    # get-property 0xff
    cmd = ["-p", "super-com", "get-property", "0xff"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10300 (0x283c) Unknown Property." in result.output


def test_flash_read_once(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash read once command functionality.

    Verifies that the blhost flash-read-once command executes successfully
    and returns expected response values including status and word data.

    :param cli_runner: Click CLI test runner for command execution.
    :param caplog: Pytest fixture for capturing log output.
    """
    cmd = ["-p", "super-com", "flash-read-once", "1", "4"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Response word 2 = 305419896 (0x12345678)" in result.output


def test_flash_program_once(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash program once command functionality.

    Verifies that the blhost flash-program-once command executes successfully
    and returns the expected success response when programming OTP memory.

    :param cli_runner: Click CLI test runner for executing commands
    :param caplog: Pytest fixture for capturing log output
    """
    cmd = ["-p", "super-com", "flash-program-once", "1", "4", "12345678"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_flash_security_disable(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash security disable command with invalid parameters.

    This test verifies that the flash-security-disable command properly handles
    invalid scenarios and returns the expected error response when executed
    through the blhost CLI interface.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = ["-p", "super-com", "flash-security-disable", "0102030405060708"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_flash_erase_all_unsecure(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash erase all unsecure command with invalid port.

    This test verifies that the flash-erase-all-unsecure command properly handles
    an invalid communication port and returns the expected error response.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    """
    cmd = ["-p", "super-com", "flash-erase-all-unsecure"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_flash_erase_all(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash erase all command functionality.

    Verifies that the flash-erase-all command executes successfully through the blhost CLI
    and returns the expected success response status.

    :param cli_runner: Click CLI runner for executing command line interface commands
    :param caplog: Pytest fixture for capturing log output during test execution
    """
    cmd = ["-p", "super-com", "flash-erase-all", "0x0"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_flash_erase_region(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash erase region command functionality.

    Verifies that the blhost flash-erase-region command executes successfully
    and returns the expected success response when erasing a flash region.

    :param cli_runner: Click CLI test runner for command execution.
    :param caplog: Pytest fixture for capturing log output.
    """
    cmd = ["-p", "super-com", "flash-erase-region", "0x8000000", "0x0"]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def run_flash_read_resource(cli_runner: CliRunner, caplog: Any, cmd: Any) -> Result:
    """Run flash read resource command and verify expected output.

    Executes a blhost flash read resource command through the CLI runner and validates
    that the operation completes successfully with expected response messages.

    :param cli_runner: Click CLI runner instance for executing commands.
    :param caplog: Pytest log capture fixture for capturing log messages.
    :param cmd: Command arguments to execute with blhost.
    :return: CLI execution result containing output and exit code.
    """
    result = run_blhost_proxy(cli_runner, caplog, cmd, ignore_ack=True)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Read 4 of 4 bytes." in result.output
    return result


def test_flash_read_resource(cli_runner: CliRunner, caplog: Any) -> None:
    """Test flash read resource command functionality.

    Verifies that the flash-read-resource command executes correctly with specified
    parameters and produces expected output containing hexadecimal data.

    :param cli_runner: Click CLI runner instance for executing commands
    :param caplog: Pytest fixture for capturing log output
    """
    cmd = ["-p", "super-com", "flash-read-resource", "1", "4", "1"]
    result = run_flash_read_resource(cli_runner, caplog, cmd)
    assert "00 00 00 00" in result.output


def test_flash_read_resource_to_file(cli_runner: CliRunner, caplog: Any, tmpdir: str) -> None:
    """Test flash read resource command with file output.

    Verifies that the flash-read-resource command correctly reads data from flash
    memory and writes it to a specified output file. The test checks both that
    the file is created and contains the expected data.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    :param tmpdir: Temporary directory path for test file creation.
    """
    test_file = f"{tmpdir}/read.bin"
    cmd = ["-p", "super-com", "flash-read-resource", "1", "4", "1", test_file]
    run_flash_read_resource(cli_runner, caplog, cmd)
    assert os.path.isfile(test_file)
    assert load_binary(test_file) == bytes(4)


def test_reliable_update(cli_runner: CliRunner, caplog: Any) -> None:
    """Test reliable update command with invalid port configuration.

    This test verifies that the reliable-update command properly handles
    communication errors when using an invalid port, ensuring the command
    fails with the expected error response.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output during test execution.
    :raises AssertionError: If the expected error message is not found in output.
    """
    cmd = ["-p", "super-com", "reliable-update", "0xfe000"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_fuse_read(cli_runner: CliRunner, caplog: Any) -> None:
    """Test fuse read command with invalid parameters.

    Verifies that the fuse-read command properly handles invalid scenarios
    and returns the expected error response with status code 10000 (Unknown Command).

    :param cli_runner: Click CLI runner for executing command line interface.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = ["-p", "super-com", "fuse-read", "0x1", "8"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_fuse_program(cli_runner: CliRunner, caplog: Any) -> None:
    """Test the fuse-program command with invalid parameters.

    This test verifies that the fuse-program command properly handles invalid
    input and returns the expected error response when executed with test parameters.

    :param cli_runner: Click CLI runner fixture for testing command line interfaces
    :param caplog: Pytest fixture for capturing log output during test execution
    """
    cmd = ["-p", "super-com", "fuse-program", "3", "{{12345678}}", "0"]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_flash_image_memory_not_configured(
    cli_runner: CliRunner, caplog: Any, data_dir: str
) -> None:
    """Test flash image command when memory is not configured.

    This test verifies that the blhost flash-image command properly handles
    the case when the target memory is not configured, expecting a specific
    error response with status code 10205.

    :param cli_runner: Click CLI runner for executing commands in tests.
    :param caplog: Pytest fixture for capturing log output during test execution.
    :param data_dir: Path to the directory containing test data files.
    :raises AssertionError: If the expected error message is not found in output.
    """
    cmd = [
        "-p",
        "super-com",
        "flash-image",
        os.path.join(data_dir, "evkmimxrt685_led_blinky_ext_flash.srec"),
        "erase",
        "3",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Response status = 10205 (0x27dd) Memory Not Configured." in result.output


def test_tp_hsm_gen_key(cli_runner: CliRunner, caplog: Any) -> None:
    """Test trust provisioning HSM key generation command.

    This test verifies the blhost trust-provisioning hsm_gen_key command functionality
    by executing it with MFWISK key type and checking that the response contains
    expected success status, response words, and key blob information.

    :param cli_runner: Click CLI runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "hsm_gen_key",
        "MFWISK",
        "0",
        "0x20008000",
        "48",
        "0x20009000",
        "64",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 48 (0x30)" in result.output
    assert "Response word 2 = 64 (0x40)" in result.output
    assert "Output data size/value(s) is(are):" in result.output
    assert "Key Blob size: 48 (0x30)" in result.output
    assert "ECDSA Puk size: 64 (0x40)" in result.output


def test_tp_store_key(cli_runner: CliRunner, caplog: Any) -> None:
    """Test trust provisioning HSM store key command functionality.

    This test verifies that the blhost trust-provisioning hsm_store_key command
    executes successfully and returns the expected response format including
    status, response words, key header, and key blob size information.

    :param cli_runner: Click CLI runner for executing command line interface.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "hsm_store_key",
        "5",
        "1",
        "0x2000B000",
        "32",
        "0x2000C000",
        "48",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 269484129 (0x10100061)" in result.output
    assert "Response word 2 = 48 (0x30)" in result.output
    assert "Output data size/value(s) is(are):" in result.output
    assert "Key Header: 269484129 (0x10100061)" in result.output
    assert "Key Blob size: 48 (0x30)" in result.output


def test_tp_hsm_enc_blk(cli_runner: CliRunner, caplog: Any) -> None:
    """Test trust provisioning HSM encryption block command.

    Tests the blhost trust-provisioning hsm_enc_blk command with specific memory addresses,
    sizes, and encryption parameters to verify proper HSM encryption block functionality.

    :param cli_runner: Click CLI runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    :raises AssertionError: If the command does not return success status.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "hsm_enc_blk",
        "0x2000A000",
        "48",
        "16",
        "0x2000C000",
        "60",
        "1",
        "0x2000D000",
        "256",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_tp_hsm_enc_sign(cli_runner: CliRunner, caplog: Any) -> None:
    """Test trust provisioning HSM encryption and signing command.

    This test verifies the blhost trust-provisioning hsm_enc_sign command functionality
    by executing it with specific memory addresses and sizes, then validating the
    expected success response and output data.

    :param cli_runner: Click CLI runner for executing commands in tests.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "hsm_enc_sign",
        "0x20008000",
        "48",
        "0x2000F000",
        "220",
        "0x20010000",
        "64",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 64 (0x40)" in result.output
    assert "Output data size/value(s) is(are):" in result.output
    assert "Signature size: 64 (0x40)" in result.output


def test_tp_oem_gen_master_share(cli_runner: CliRunner, caplog: Any) -> None:
    """Test trust provisioning OEM generate master share command.

    This test verifies the blhost trust-provisioning oem_gen_master_share command
    functionality by executing it with specific memory addresses and sizes, then
    validating the expected response status, response words, and output data sizes.

    :param cli_runner: Click CLI runner for executing commands in tests.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "oem_gen_master_share",
        "0x20008000",
        "0x10",
        "0x20009000",
        "0x1000",
        "0x2000A000",
        "0x1000",
        "0x2000B000",
        "0x1000",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 48 (0x30)" in result.output
    assert "Response word 2 = 64 (0x40)" in result.output
    assert "Response word 3 = 64 (0x40)" in result.output
    assert "Output data size/value(s) is(are):" in result.output
    assert "OEM Share size: 48 (0x30)" in result.output
    assert "OEM Master Share size: 64 (0x40)" in result.output
    assert "Cust Cert Puk size: 64 (0x40)" in result.output


def test_tp_oem_set_master_share(cli_runner: CliRunner, caplog: Any) -> None:
    """Test OEM set master share command via blhost CLI.

    This test verifies that the trust-provisioning oem_set_master_share command
    executes successfully through the blhost CLI interface with the specified
    memory addresses and sizes.

    :param cli_runner: Click CLI runner for executing command line interfaces.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "oem_set_master_share",
        "0x20008000",
        "16",
        "0x20009000",
        "64",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_oem_get_cust_cert_dice_puk(cli_runner: CliRunner, caplog: Any) -> None:
    """Test OEM get customer certificate DICE public key command.

    This test verifies the blhost trust-provisioning oem_get_cust_cert_dice_puk command
    functionality by executing it with specific memory addresses and sizes, then
    validating the expected success response and output format.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output during test execution.
    """
    cmd = [
        "-p",
        "super-com",
        "trust-provisioning",
        "oem_get_cust_cert_dice_puk",
        "0x30015000",
        "0x20",
        "0x30016000",
        "0x40",
    ]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 64 (0x40)" in result.output
    assert "Output data size/value(s) is(are):" in result.output
    assert "Cust Cert Dice Puk size: 64 (0x40)" in result.output


def test_batch(cli_runner: CliRunner, caplog: Any, data_dir: str) -> None:
    """Test batch command execution with command file.

    This test verifies that the blhost batch command can successfully execute
    multiple commands from a batch command file (.bcf) and that all commands
    complete with success status.

    :param cli_runner: Click CLI test runner for executing commands.
    :param caplog: Pytest fixture for capturing log output.
    :param data_dir: Path to test data directory containing batch command file.
    """
    command_file = os.path.join(data_dir, "blhost_commands.bcf")
    cmd = ["-p", "super-com", "batch", command_file]
    result = run_blhost_proxy(cli_runner, caplog, cmd)
    # we expect 3 successful command execution
    assert result.output.count("Response status = 0 (0x0) Success.") == 3


def test_batch_error(cli_runner: CliRunner, caplog: Any, data_dir: str) -> None:
    """Test batch command execution with invalid commands file.

    This test verifies that the blhost CLI properly handles and reports errors
    when processing a batch file containing invalid or unknown commands.

    :param cli_runner: Click CLI test runner for executing commands
    :param caplog: Pytest fixture for capturing log output
    :param data_dir: Path to test data directory containing batch command files
    :raises AssertionError: If the expected error message is not found in exception
    """
    command_file = os.path.join(data_dir, "bad_blhost_commands.bcf")
    cmd = ["-p", "super-com", "batch", command_file]
    result = run_blhost_proxy(cli_runner, caplog, cmd, expect_exit_code=1)
    assert "Unknown command" in str(result.exception)


def test_blhost_help(cli_runner: CliRunner, caplog: Any) -> None:
    """Test blhost CLI help command functionality.

    Verifies that the blhost CLI tool displays the correct help message when invoked
    with the --help flag. The test ensures the help output contains the expected
    utility description.

    :param cli_runner: Click CLI test runner for invoking command line interfaces.
    :param caplog: Pytest logging capture fixture for controlling log levels.
    """
    caplog.set_level(100_000)
    cmd = ["--help"]
    result = cli_runner.invoke(blhost.main, cmd)
    assert "Utility for communication with the bootloader on target" in str(result.output)

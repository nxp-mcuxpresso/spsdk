#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing the BLHost application."""
import os
from unittest.mock import patch

from click.testing import CliRunner

import spsdk
from spsdk.apps import blhost
from spsdk.utils.misc import load_binary
from spsdk.utils.serial_proxy import SerialProxy

# fmt: off
data_responses = {
    # ack
    b"\x5a\xa1": b"",
    # ping
    b"\x5a\xa6": b"\x5a\xa7\x00\x03\x01\x50\x00\x00\xfb\x40",
    # get-property
    b"\x5a\xa4\x0c\x00\x4b\x33\x07\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x65\x1c\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x4b",
    # set-property 10 1
    b"\x5a\xa4\x0c\x00\x67\x8d\x0c\x00\x00\x02\x0a\x00\x00\x00\x01\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\xe0\xf7\xa0\x00\x00\x02\x00\x00\x00\x00\x0c\x00\x00\x00",
    # efuse-read-one
    b"\x5a\xa4\x0c\x00\x14\x27\x0f\x00\x00\x02\x64\x00\x00\x00\x04\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x10\x00\xc5\xbf\xaf\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00",
    # efuse-read-one 0x98 with unknown error code 0xbeef (48,879)
    b"\x5a\xa4\x0c\x00\x2e\x7b\x0f\x00\x00\x02\x98\x00\x00\x00\x04\x00\x00\x00":
        b"\x5a\xa1\x5a\xa4\x0c\x00\x36\xc2\xaf\x00\x00\x02\xef\xbe\x00\x00\x00\x00\x00\x00",
    # use get-property 99 as a vehicle to emulate no response from target
    b"\x5a\xa4\x0c\x00\x55\x31\x07\x00\x00\x02\x63\x00\x00\x00\x00\x00\x00\x00":
        b"",
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
}
# fmt: on


def test_version():
    runner = CliRunner()
    result = runner.invoke(blhost.main, ["--version"])
    assert result.exit_code == 0
    assert spsdk.__version__ in result.output


def run_blhost_proxy(caplog, cmd, expect_exit_code: int = 0, ignore_ack: bool = False):
    # There's a problem with logging under CliRunner
    # https://github.com/pytest-dev/pytest/issues/3344
    # caplog is set to disable all loging output
    # Comment the folowing line to see logging info, however there will be an failure
    caplog.set_level(100_000)
    runner = CliRunner()
    with patch(
        "spsdk.mboot.interfaces.uart.Serial",
        SerialProxy.init_proxy(data_responses, ignore_ack=ignore_ack),
    ):
        result = runner.invoke(blhost.main, cmd.split())
        assert result.exit_code == expect_exit_code
    return result


def test_get_property(caplog):
    cmd = "-p super-com get-property 1"
    result = run_blhost_proxy(caplog, cmd)
    assert "Current Version = K3.0.0" in result.output


def test_set_property(caplog):
    cmd = "-p super-com set-property 10 1"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_efuse_read_once(caplog):
    cmd = "-p super-com efuse-read-once 100"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Response word 2 = 0 (0x0)" in result.output


def test_efuse_read_once_unknown_error(caplog):
    cmd = "-p super-com efuse-read-once 0x98"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response word 1 = 4 (0x4)" not in result.output
    assert "Unknown error code" in result.output


def test_no_response(caplog):
    # use get-property 99 as a vehicle to emulate no response from target
    cmd = "-p super-com get-property 99"
    result = run_blhost_proxy(caplog, cmd)
    assert (
        "Response status = 10004 (0x2714) No response packet from target device." in result.output
    )


def test_flash_read_once(caplog):
    cmd = "-p super-com flash-read-once 1 4"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Response word 2 = 305419896 (0x12345678)" in result.output


def test_flash_program_once(caplog):
    cmd = "-p super-com flash-program-once 1 4 12345678"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 0 (0x0) Success." in result.output


def test_flash_security_disable(caplog):
    cmd = "-p super-com flash-security-disable 0102030405060708"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_flash_erase_all_unsecure(caplog):
    cmd = "-p super-com flash-erase-all-unsecure"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def run_flash_read_resource(caplog, cmd):
    result = run_blhost_proxy(caplog, cmd, ignore_ack=True)
    assert "Response status = 0 (0x0) Success." in result.output
    assert "Response word 1 = 4 (0x4)" in result.output
    assert "Read 4 of 4 bytes." in result.output
    return result


def test_flash_read_resource(caplog):
    cmd = "-p super-com flash-read-resource 1 4 1"
    result = run_flash_read_resource(caplog, cmd)
    assert "00 00 00 00" in result.output


def test_flash_read_resource_to_file(caplog, tmpdir):
    test_file = f"{tmpdir}/read.bin"
    cmd = f"-p super-com flash-read-resource 1 4 1 {test_file}"
    run_flash_read_resource(caplog, cmd)
    assert os.path.isfile(test_file)
    assert load_binary(test_file) == bytes(4)


def test_reliable_update(caplog):
    cmd = "-p super-com reliable-update 0xfe000"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_fuse_read(caplog):
    cmd = "-p super-com fuse-read 0x1 8"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_fuse_program(caplog):
    cmd = "-p super-com fuse-program 3 {{12345678}} 0"
    result = run_blhost_proxy(caplog, cmd)
    assert "Response status = 10000 (0x2710) Unknown Command." in result.output


def test_flash_image_memory_not_configured(caplog, data_dir):
    cmd = f"-p super-com flash-image {os.path.join(data_dir, 'evkmimxrt685_led_blinky_ext_flash.srec')} erase 3"
    result = run_blhost_proxy(caplog, cmd, expect_exit_code=1)
    assert "Response status = 10205 (0x27dd) Memory Not Configured." in result.output

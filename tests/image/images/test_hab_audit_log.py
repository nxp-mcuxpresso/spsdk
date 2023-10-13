#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from unittest.mock import patch

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab_audit_log import (
    CpuData,
    check_reserved_regions,
    get_hab_enum_description,
    get_hab_log_info,
    hab_audit_xip_app,
    parse_hab_log,
)

# from spsdk.utils.serial_proxy import SerialProxy
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.easy_enum import Enum
from spsdk.utils.interfaces.device.serial_device import SerialDevice

# responses from rt1020 for mcu emulating
from spsdk.utils.serial_proxy import SimpleReadSerialProxy
from tools.clr import ROOT_DIR

HAB_AUDIT_PATH = os.path.join(ROOT_DIR, "examples", "data", "hab_audit")


class TestEnum(Enum):
    TEST = (0xA5, "Test descr")


def test_get_hab_enum_descr():
    """Test `get_hab_enum_descr`"""
    # test known value
    t = get_hab_enum_description(TestEnum, 0xA5)
    assert t == "Test descr  (0xa5)"

    # test unknown value
    t = get_hab_enum_description(TestEnum, 0xFF)
    assert t == "0xff = Unknown value"


def test_parse_hab_log():
    """Test `parse_hab_log` function."""
    lines = parse_hab_log(0xF0, 0xCC, 0xAA, b"")
    assert lines
    lines = parse_hab_log(51, 240, 102, b"\xdb\x00\x08\x43\x33\x22\x0a\x00")
    assert lines
    lines = parse_hab_log(51, 240, 102, b"\xdb\x00\x08\x43\x33\x22\x0a\x00" + b"\x00" * 60)
    assert lines


def test_parse_hab_log_invalid():
    """Test `parse_hab_log` function - raises exception"""
    with pytest.raises(SPSDKError):
        parse_hab_log(51, 240, 102, b"\xdb\x00\x01\x43\x33\x22\x0a\x00")


def test_hab_audit_xip_app_simple(data_dir):
    """Test `hab_audit_log` function."""
    import os
    import re

    captured_log = os.path.join(data_dir, "cpu_data", "rt1020", "hab_audit_log_data.txt")
    with open(captured_log) as f:
        text_data = f.read()

    matches = re.finditer("<(?P<data>[ 0-9a-z]*)>", text_data, re.MULTILINE)

    bin_data = bytes()
    for match in matches:
        found = match.group("data")
        bin_data += bytes(int(value, 16) for value in found.split(" "))

    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial",
        SimpleReadSerialProxy.init_data_proxy(bin_data),
    ):
        with McuBoot((MbootUARTInterface(SerialDevice(port="totally-legit-port")))) as mboot:
            # test valid use case
            log = hab_audit_xip_app(CpuData.MIMXRT1020, mboot, True, HAB_AUDIT_PATH)
            assert log[:4] != b"\xFF" * 4


def test_hab_audit_xip_app_invalid(data_dir):
    with pytest.raises(SPSDKError, match="Flashloader is not running"):
        hab_audit_xip_app(
            CpuData.MIMXRT1020, mboot=None, read_log_only=True, hab_audit_path=HAB_AUDIT_PATH
        )
    import os
    import re

    captured_log = os.path.join(data_dir, "cpu_data", "rt1020", "hab_audit_log_data.txt")
    with open(captured_log) as f:
        text_data = f.read()
    bin_data = bytes()
    matches = re.finditer("<(?P<data>[ 0-9a-z]*)>", text_data, re.MULTILINE)
    for match in matches:
        found = match.group("data")
        bin_data += bytes(int(value, 16) for value in found.split(" "))
    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial",
        SimpleReadSerialProxy.init_data_proxy(bin_data),
    ):
        with McuBoot(MbootUARTInterface(SerialDevice(port="totally-legit-port"))) as mboot:
            with pytest.raises(
                SPSDKError, match="Can not read the log, because given cpu data were not provided."
            ):
                hab_audit_xip_app(None, mboot, read_log_only=True, hab_audit_path=HAB_AUDIT_PATH)


def test_get_hab_log_info():
    """Test `get_hab_log_info` function."""
    # checks the situation when hab log is valid
    assert get_hab_log_info(b"\xAA\xBB\xCC\xDD")
    # checks the situation when hab log is empty
    assert not get_hab_log_info(None)
    # checks the situation when flashloader is not accessible
    assert not get_hab_log_info(b"\xFF\xFF\xFF\xFF")


def test_check_reserved_regions():
    """Test `check_reserved_region` function."""
    # checks the situation when parameter with reserved regions is empty
    assert check_reserved_regions(0x20200000, None)
    # checks the situation when hab log address is not in conflict
    assert check_reserved_regions(0x20200000, [0x20100000, 0x20190000])
    # checks the situation when hab log address is in conflict
    assert not check_reserved_regions(0x20200000, [0x20190000, 0x20230000])

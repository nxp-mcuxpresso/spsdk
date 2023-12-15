#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test for TPHOST target adapter for BLHOST."""
import pytest

from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.tp.adapters.tptarget_blhost import TpBlHostIntfDescription, TpTargetBlHost
from spsdk.tp.exceptions import SPSDKTpTargetError
from spsdk.utils.interfaces.device.serial_device import SerialDevice
from spsdk.utils.interfaces.device.usb_device import UsbDevice


def test_non_existing_device():
    """Test to validate right functionality for nonexisting device in target description."""
    tblh_descr = TpBlHostIntfDescription(
        "Virtual BLHOST", "Virtual BLHOST device for testing without device", None
    )
    with pytest.raises(SPSDKTpTargetError):
        TpTargetBlHost(tblh_descr, "N/A")


def test_descr_usb():
    """Test to Description for As Dict for USB device."""
    tblh_descr = TpBlHostIntfDescription(
        "Virtual BLHOST USB", "Virtual BLHOST device for testing USB device", None
    )
    tblh_descr.interface = MbootUSBInterface(UsbDevice())

    usb_dict = tblh_descr.as_dict()
    assert usb_dict["pid_vid"] == "0x0000:0x0000"


def test_descr_uart():
    """Test to Description for As Dict for UART device."""
    tblh_descr = TpBlHostIntfDescription(
        "Virtual BLHOST UART", "Virtual BLHOST device for testing UART device", None
    )
    tblh_descr.interface = MbootUARTInterface(
        SerialDevice(baudrate=MbootUARTInterface.default_baudrate)
    )

    uart_dict = tblh_descr.as_dict()
    assert uart_dict["port"] is None
    assert uart_dict["baudrate"] == 57600


def test_settings_parse():
    """Test help function to parse settings."""
    sett = TpTargetBlHost._get_settings()
    assert sett["usb"] is None
    assert sett["port"] is None
    assert sett["baudrate"] is None
    assert sett["timeout"] == 50


def test_settings_parse_filled():
    """Test help function to parse settings."""
    input_sett = {}
    input_sett["blhost_usb"] = "USB"
    input_sett["blhost_port"] = "PORT"
    input_sett["blhost_baudrate"] = "0x20"
    input_sett["blhost_timeout"] = 1

    sett = TpTargetBlHost._get_settings(input_sett)
    assert sett["usb"] == "USB"
    assert sett["port"] == "PORT"
    assert sett["baudrate"] == 32
    assert sett["timeout"] == 1


def test_basic(trgt_blhost: TpTargetBlHost):
    """Basic test with open and close functionality for adapter."""
    trgt_blhost.open()
    trgt_blhost.close()


def test_reset(trgt_blhost_ready):
    """The test tries the reset target functionality."""
    trgt_blhost_ready.reset_device()


def test_reset_fail0(trgt_blhost_ready: TpTargetBlHost):
    """The test tries the reset target functionality fails condition."""
    trgt_blhost_ready.mboot._interface.device.fail_step = 1
    with pytest.raises(SPSDKTpTargetError):
        trgt_blhost_ready.reset_device()
    trgt_blhost_ready.mboot._interface.device.fail_step = None


def test_load_sb(trgt_blhost_ready: TpTargetBlHost):
    """The test tries the load SB file into target."""
    trgt_blhost_ready.load_sb_file(bytes(1024), 50)


def test_prove_genuinity_challenge(trgt_blhost_ready: TpTargetBlHost):
    """The test tries the prove challenge into target."""
    assert isinstance(trgt_blhost_ready.prove_genuinity_challenge(bytes(1024), 50), bytes)


def test_set_wrapped_data(trgt_blhost_ready: TpTargetBlHost):
    """The test tries the set wrapped data to target."""
    trgt_blhost_ready.set_wrapped_data(bytes(1024), 50)


def test_get_help():
    """The test ask for help string."""
    help = TpTargetBlHost.get_help()
    assert isinstance(help, str)
    assert len(help) > 1

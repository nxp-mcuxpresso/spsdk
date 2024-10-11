#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from typing import Optional, Union
from unittest.mock import patch

from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError, SPSDKConnectionError
from spsdk.sdp.commands import CmdPacket
from spsdk.sdp.exceptions import SdpConnectionError
from spsdk.sdp.sdps import SDPS, RomInfo
from spsdk.utils.interfaces.commands import CmdResponseBase
from spsdk.utils.interfaces.device.base import DeviceBase

data = b"\xAD" * 100
cmd_pack = b"BLTC\x01\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class VirtualDevice(DeviceBase):
    def __init__(self):
        self._is_opened = False
        self.cmd_index = 0
        self._timeout = 0

    @property
    def is_opened(self):
        return self._is_opened

    def open(self):
        self._is_opened = True

    def close(self):
        self._is_opened = False

    def read(self, length: int):
        pass

    def write(self, data):
        if self.cmd_index == 0:
            assert data == cmd_pack
            self.cmd_index += 1
        else:
            assert data == data

    def __str__(self):
        return "VirtualDevice"

    @property
    def timeout(self) -> int:
        return self._timeout

    @timeout.setter
    def timeout(self, value) -> None:
        self._timeout = value


class VirtualSDPInterface:
    def __init__(self, device: VirtualDevice) -> None:
        self.device = device

    def open(self) -> None:
        """Open the interface."""
        self.device.open()

    def close(self) -> None:
        """Close the interface."""
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return self.device.is_opened

    @classmethod
    def scan(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> list[Self]:
        """Scan method."""
        pass  # not used

    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        return self.device.read(length or 0)

    def write_data(self, data):
        self.device.write(data)

    def write_command(self, packet: CmdPacket):
        data = packet.to_bytes(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self.device.write(data)

    def configure(self, config):
        assert "hid_ep1" in config
        assert "pack_size" in config


def test_open_close():
    """Test SDPS is closed by default."""
    spds = SDPS(VirtualSDPInterface(VirtualDevice()), "mx93")
    assert not spds.is_opened
    spds.open()
    assert spds.is_opened
    spds.open()
    # TODO: analyze caplog, there should be no new records
    assert spds.is_opened


@patch("spsdk.sdp.sdps.SDPS.rom_info", RomInfo(False, False, 1024))
def test_sdps_send_data():
    """Test send data"""
    with SDPS(VirtualSDPInterface(VirtualDevice()), "mx93") as sdps:
        assert sdps.is_opened
        sdps.write_file(data)
    assert sdps.is_opened is False


class VirtualDeviceException(VirtualDevice):
    def write(self, data):
        raise SPSDKConnectionError()

    def __str__(self):
        return "VirtualDeviceException"


def test_sdps_exception():
    """Test connection error"""
    try:
        sdps = SDPS(VirtualSDPInterface(VirtualDeviceException()), "mx8ulp")
        sdps.write_file(data)
        assert False
    except SdpConnectionError:
        assert True
    except Exception:
        assert False

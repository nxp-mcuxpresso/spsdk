#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from struct import pack
from typing import Optional

import pytest
from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError
from spsdk.sdp.commands import CmdResponse, CommandTag, ResponseValue
from spsdk.sdp.error_codes import StatusCode
from spsdk.sdp.exceptions import SdpError
from spsdk.sdp.sdp import SDP, CmdPacket
from spsdk.utils.interfaces.device.base import DeviceBase


class VirtualDevice(DeviceBase):
    def __init__(self, respond_sequence):
        self.respond_sequence = respond_sequence
        self._timeout = 0

    @property
    def is_opened(self):
        return True

    def open(self):
        pass

    def close(self):
        pass

    def read(self, length: int):
        return self.respond_sequence.pop(0)

    def write(self, data):
        pass

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

    def read(self, length: Optional[int] = None):
        return self.device.read(length or 0)

    def write_data(self, data):
        self.device.write(data)

    def write_command(self, packet: CmdPacket):
        data = packet.to_bytes()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self.device.write(data)


def test_sdp_hab_locked():
    """Test send data returns TRUE if HAB locked"""
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[
                    CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag)),
                    CmdResponse(True, pack(">I", ResponseValue.HAB_SUCCESS.tag)),
                ]
            )
        )
    )
    assert sdp.is_opened
    assert sdp._send_data(CmdPacket(CommandTag.READ_REGISTER, 0, 0, 0), b"")
    assert sdp.hab_status == StatusCode.HAB_IS_LOCKED
    assert sdp.status_code == StatusCode.SUCCESS


def test_sdp_read_hab_locked():
    """Test `read` returns None if HAB locked"""
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[
                    CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag)),
                    CmdResponse(False, b"0000"),
                    CmdResponse(True, pack(">I", ResponseValue.HAB_SUCCESS.tag)),
                ]
            )
        )
    )
    assert sdp.is_opened
    assert sdp.read(0x20000000, 4)
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.hab_status == ResponseValue.LOCKED


def test_sdp_jump_and_run_hab_locked():
    """Test `jump_and_run` returns False if HAB locked (even the operation works)"""
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag))]
            )
        )
    )
    assert sdp.is_opened
    assert sdp.jump_and_run(0x20000000)
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.hab_status == ResponseValue.LOCKED


def test_sdp_send_data_errors():
    error_response = [
        CmdResponse(True, pack(">I", ResponseValue.UNLOCKED.tag)),
        CmdResponse(True, pack(">I", 0x12345678)),
    ]

    sdp = SDP(VirtualSDPInterface(VirtualDevice(respond_sequence=error_response.copy())))

    sdp._interface.device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_DCD, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_DCD_FAILURE

    sdp._interface.device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_CSF, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_CSF_FAILURE

    sdp._interface.device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_FILE, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_IMAGE_FAILURE

    sdp._interface.device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_DCD, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_DCD_FAILURE


def test_sdp_read_args_errors():
    sdp = SDP(VirtualSDPInterface(VirtualDevice([])))
    with pytest.raises(SdpError, match="Invalid data format"):
        sdp.read_safe(address=0, length=2, data_format=2)

    with pytest.raises(SdpError, match="not aligned"):
        sdp.read_safe(address=2, length=2, data_format=32)

    with pytest.raises(SdpError, match="Invalid data format"):
        sdp.write_safe(address=0, value=2, count=1, data_format=2)

    with pytest.raises(SdpError, match="not aligned"):
        sdp.write_safe(address=2, value=2, count=1, data_format=32)

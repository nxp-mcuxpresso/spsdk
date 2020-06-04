#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from struct import pack

from spsdk.sdp.commands import ResponseValue, CmdResponse
from spsdk.sdp.error_codes import StatusCode
from spsdk.sdp.interfaces.base import Interface
from spsdk.sdp.sdp import SDP, CmdPacket


class VirtualDeviceHabLocked(Interface):
    @property
    def is_opened(self):
        return True

    def open(self):
        pass

    def close(self):
        pass

    def read(self, timeout=1000):
        return CmdResponse(True, pack('>I', ResponseValue.LOCKED))

    def write(self, packet):
        pass

    def info(self):
        return 'VirtualDevice'


def test_sdp_hab_locked():
    """Test send data returns TRUE if HAB locked"""
    sdp = SDP(VirtualDeviceHabLocked())
    assert sdp.is_opened
    assert sdp._send_data(CmdPacket(0, 0, 0, 0), b'')
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.response_value == ResponseValue.LOCKED


def test_sdp_read_hab_locked():
    """Test `read` returns None if HAB locked"""
    sdp = SDP(VirtualDeviceHabLocked())
    assert sdp.is_opened
    assert sdp.read(0x20000000, 4) is None
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.response_value == ResponseValue.LOCKED


def test_sdp_jump_and_run_hab_locked():
    """Test `jump_and_run` returns False if HAB locked (even the operation works)"""
    sdp = SDP(VirtualDeviceHabLocked())
    assert sdp.is_opened
    assert sdp.jump_and_run(0x20000000) is False
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.response_value == ResponseValue.LOCKED

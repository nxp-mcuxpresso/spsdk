#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from spsdk.sdp.interfaces.base import Interface
from spsdk.sdp.sdps import SDPS
from spsdk.sdp import SdpConnectionError


data = b'\xAD' * 100
cmd_pack= b'BLTC\x01\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


class VirtualDevice(Interface):

    def __init__(self):
        self._is_opened = False
        self.cmd_index = 0

    @property
    def is_opened(self):
        return self._is_opened

    def open(self):
        self._is_opened = True

    def close(self):
        self._is_opened = False

    def read(self, timeout=1000):
        pass

    def conf(self, config):
        assert 'hid_ep1' in config
        assert 'pack_size' in config

    def write(self, packet):
        if self.cmd_index == 0:
            assert packet == cmd_pack
            self.cmd_index += 1
        else:
            assert packet == data

    def info(self):
        return 'VirtualDevice'


def test_open_close():
    """Test SDPS is closed by default."""
    spds = SDPS(VirtualDevice(), 'MX28')
    assert not spds.is_opened
    spds.open()
    assert spds.is_opened
    spds.open()
    #TODO: analyze caplog, there should be no new records
    assert spds.is_opened


def test_sdps_send_data():
    """Test send data"""
    with SDPS(VirtualDevice(), 'MX28') as sdps:
        assert sdps.is_opened
        sdps.write_file(data)
    assert sdps.is_opened is False


class VirtualDeviceException(VirtualDevice):

    def write(self, packet):
        raise Exception()

    def info(self):
        return 'VirtualDeviceException'


def test_sdps_exception():
    """Test connection error"""
    try:
        sdps = SDPS(VirtualDeviceException(), 'MX815')
        sdps.write_file(data)
        assert False
    except SdpConnectionError:
        assert True
    except Exception:
        assert False

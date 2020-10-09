#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing the BLHost application."""

import logging
from unittest.mock import patch

import click
from click.testing import CliRunner

import spsdk
from spsdk.apps import blhost
from spsdk.mboot.interfaces import Interface
from spsdk.utils.serial_proxy import SerialProxy


data_responses = {
    # ack
    b'\x5a\xa1': b'',
    # ping
    b'\x5a\xa6': b'\x5a\xa7\x00\x03\x01\x50\x00\x00\xfb\x40',
    # get-property
    b'\x5a\xa4\x0c\x00\x4b\x33\x07\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00':
        b'\x5a\xa1\x5a\xa4\x0c\x00\x65\x1c\xa7\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x4b',
    # efuse-read-one
    b'\x5a\xa4\x0c\x00\x14\x27\x0f\x00\x00\x02\x64\x00\x00\x00\x04\x00\x00\x00':
        b'\x5a\xa1\x5a\xa4\x10\x00\xc5\xbf\xaf\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'       
}

def test_version():
    runner = CliRunner()
    result = runner.invoke(blhost.main, ['--version'])
    assert result.exit_code == 0
    assert spsdk.__version__ in result.output


def test_get_property(caplog):
    # There's a problem with logging under CliRunner
    # https://github.com/pytest-dev/pytest/issues/3344
    # caplog is set to disable all loging output
    # Comment the folowing line to see logging info, however there will be an failure
    caplog.set_level(100_000)
    runner = CliRunner()
    cmd = '-p super-com get-property 1'
    with patch('spsdk.mboot.interfaces.uart.Serial', SerialProxy.init_proxy(data_responses)):
        result = runner.invoke(blhost.main, cmd.split())
        assert result.exit_code == 0
        assert 'Current Version = K3.0.0' in result.output


def test_efuse_read_once(caplog):
    caplog.set_level(100_000)
    runner = CliRunner()
    cmd = '-p super-com efuse-read-once 100'
    with patch('spsdk.mboot.interfaces.uart.Serial', SerialProxy.init_proxy(data_responses)):
        result = runner.invoke(blhost.main, cmd.split())
        assert result.exit_code == 0
        assert 'Response word 1 = 4 (0x4)' in result.output
        assert 'Response word 2 = 0 (0x0)' in result.output

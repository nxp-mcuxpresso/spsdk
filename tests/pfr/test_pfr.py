#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import json

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from spsdk.pfr import CFPA, CMPA
from spsdk.utils.misc import load_file


def test_generate_cmpa(data_dir):
    config = json.loads(load_file(data_dir, 'cmpa_96mhz.json'))
    binary = load_file(data_dir, 'CMPA_96MHz.bin', mode='rb')
    key = load_pem_private_key(
        load_file(data_dir, 'selfsign_privatekey_rsa2048.pem', mode='rb'),
        password=None, backend=default_backend())

    cmpa = CMPA('lpc55s6x', keys=[key.public_key()], user_config=config['settings'])
    assert binary == cmpa.export(add_seal=False, compute_inverses=True)


def test_generate_cfpa(data_dir):
    config = json.loads(load_file(data_dir, 'cfpa_test.json'))
    binary = load_file(data_dir, 'CFPA_test.bin', mode='rb')

    cfpa = CFPA('lpc55s6x', user_config=config['settings'])
    data = cfpa.export(add_seal=True, compute_inverses=False)
    assert binary == data


def test_supported_devices():
    cfpa_devices = CFPA.devices()
    cmpa_devices = CMPA.devices()

    assert sorted(cmpa_devices) == sorted(cfpa_devices)


def test_seal_cfpa():
    cfpa = CFPA('lpc55s6x')

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1e0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1e0:] == CFPA.MARK * 8


def test_seal_cmpa_n4analog():
    cfpa = CFPA('lpc55s3x')

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1e0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1ec:0x1f0] == CFPA.MARK


def test_basic_cmpa():
    cmpa = CMPA('lpc55s6x')
    with pytest.raises(AssertionError):
        cmpa.export()


def test_config_cfpa():
    cfpa = CFPA('lpc55s6x')
    config = cfpa.generate_config()
    config2 = cfpa.generate_config(exclude_computed=False)

    assert config != config2

    cfpa2 = CFPA('lpc55s6x', user_config=config2)
    out = cfpa2.parse(bytes(512), exclude_computed=False)

    assert out == config2


def test_config_cmpa():
    cmpa = CMPA('lpc55s6x')
    config = cmpa.generate_config()
    config2 = cmpa.generate_config(exclude_computed=False)

    assert config != config2

    cmpa2 = CMPA('lpc55s6x', user_config=config2)
    out = cmpa2.parse(bytes(512), exclude_computed=False)

    assert out == config2


def test_address():
    cmpa = CMPA('lpc55s6x')
    assert '0x9_E400' == cmpa.get_address(remove_underscore=False)
    assert '0x9E400' == cmpa.get_address(remove_underscore=True)

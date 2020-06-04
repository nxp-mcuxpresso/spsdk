#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import json
from binascii import hexlify
from os import path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from spsdk.image import CFPA, CMPA


def read_file(data_dir, file_name, mode='r'):
    with open(path.join(data_dir, file_name), mode) as f:
        return f.read()


def test_generate_cmpa(data_dir):
    config = json.loads(read_file(data_dir, 'cmpa_96mhz.json'))
    binary = read_file(data_dir, 'CMPA_96MHz.bin', 'rb')
    key = load_pem_private_key(
        read_file(data_dir, 'selfsign_privatekey_rsa2048.pem', 'rb'),
        password=None, backend=default_backend())

    cmpa = CMPA('lpc55xx', keys=[key.public_key()], user_config=config)
    assert binary == cmpa.export(add_hash=False, compute_inverses=True)


def test_generate_cfpa(data_dir):
    config = json.loads(read_file(data_dir, 'cfpa_test.json'))
    binary = read_file(data_dir, 'CFPA_test.bin', 'rb')

    cfpa = CFPA('lpc55xx', user_config=config)
    data = cfpa.export(add_hash=True, compute_inverses=False)
    assert binary == data


def test_supported_devices():
    cfpa_devices = CFPA.devices()
    cmpa_devices = CMPA.devices()

    assert sorted(cmpa_devices) == sorted(cfpa_devices)


def test_hash_cmpa():

    cfpa = CFPA('lpc55xx')

    data = cfpa.export(add_hash=False)
    assert len(data) == 512
    assert data[0x1e0:] == bytes(32)

    data = cfpa.export(add_hash=True)
    assert len(data) == 512
    sha = hexlify(data[0x1e0:])
    assert sha == b'4b48f21a4b7a02bfbec19ef880a967a02334a3cdcef8ae83de2ef327ba8bc5dd'


def test_basic_cmpa():
    cmpa = CMPA('lpc55xx')
    with pytest.raises(AssertionError):
        cmpa.export()


def test_config_cfpa():

    cfpa = CFPA('lpc55xx')
    config = cfpa.generate_config()
    config2 = cfpa.generate_config(exclude_computed=False)

    assert config != config2

    cfpa2 = CFPA('lpc55xx', user_config=config2)
    out = cfpa2.parse(bytes(512), exclude_computed=False)

    assert out == config2


def test_config_cmpa():

    cmpa = CMPA('lpc55xx')
    config = cmpa.generate_config()
    config2 = cmpa.generate_config(exclude_computed=False)

    assert config != config2

    cmpa2 = CMPA('lpc55xx', user_config=config2)
    out = cmpa2.parse(bytes(512), exclude_computed=False)

    assert out == config2

def test_address():
    cmpa = CMPA('lpc55xx')
    assert '0x9_E400' == cmpa.get_address(remove_underscore=False)
    assert '0x9E400' == cmpa.get_address(remove_underscore=True)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.utils.crypto.cert_blocks import CertBlockHeader
from spsdk.utils.crypto import Certificate, CertBlockV2


@pytest.fixture(scope="module")
def data_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def test_cert_block_header():
    header = CertBlockHeader()
    assert header.version == '1.0'
    assert header.flags == 0
    assert header.build_number == 0
    assert header.image_length == 0
    assert header.cert_count == 0
    assert header.cert_table_length == 0

    data = header.export()
    assert len(data) == CertBlockHeader.SIZE

    header_parsed = CertBlockHeader.parse(data)
    assert header == header_parsed


def test_cert_block_basic():
    cb = CertBlockV2()
    # test default values
    assert cb.image_length == 0
    assert cb.alignment == 16
    assert cb.rkh_index is None
    # test setters
    cb.image_length = 1
    cb.alignment = 1
    assert cb.alignment == 1
    assert cb.image_length == 1
    assert cb.header.image_length == 1
    # invalid root key index
    with pytest.raises(AssertionError):
        cb.set_root_key_hash(4, bytes([0] * 32))
    # invalid root key size
    with pytest.raises(AssertionError):
        cb.set_root_key_hash(0, bytes())


def test_cert_block(data_dir):
    with open(os.path.join(data_dir, 'selfsign_2048_v3.der.crt'), 'rb') as f:
        cert_data = f.read()

    cert_obj = Certificate(cert_data)

    cb = CertBlockV2()
    cb.set_root_key_hash(0, cert_obj.public_key_hash)
    cb.add_certificate(cert_data)
    assert cb.rkh_index == 0
    cb.export()

    # test RKHT
    assert cb.rkht.hex() == 'db31d46c717711a8231cbc38b1de8a6e8657e1f733e04c2ee4b62fcea59149fa'
    fuses = cb.rkht_fuses
    assert len(fuses) == 8
    assert fuses[0] == 1825845723

    # test exception if child certificate in chain is not signed by parent certificate
    with open(os.path.join(data_dir, 'ca0_v3.der.crt'), 'rb') as f:
        ca0_cert_data = f.read()
    ca0_cert = Certificate(ca0_cert_data)
    with pytest.raises(ValueError):
        cb.add_certificate(ca0_cert)

    # test exception if no certificate specified
    cb = CertBlockV2()
    cb.set_root_key_hash(0, cert_obj.public_key_hash)
    with pytest.raises(ValueError):
        cb.export()

    # test exception last certificate is set as CA
    cb = CertBlockV2()
    cb.set_root_key_hash(0, ca0_cert.public_key_hash)
    cb.add_certificate(ca0_cert)
    with pytest.raises(ValueError):
        cb.export()

    # test exception if hash does not match any certificate
    cb = CertBlockV2()
    cb.set_root_key_hash(0, ca0_cert.public_key_hash)
    cb.add_certificate(cert_data)
    with pytest.raises(ValueError):
        cb.export()

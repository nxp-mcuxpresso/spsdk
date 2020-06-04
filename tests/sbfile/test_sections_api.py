#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.sbfile.commands import CmdErase, CmdLoad, CmdReset
from spsdk.sbfile.sections import BootSectionV2, CertSectionV2
from spsdk.utils.crypto import CertBlockV2, Certificate,crypto_backend, Counter


def test_boot_section_v2():
    boot_section = BootSectionV2(
        0,
        CmdErase(address=0, length=100000),
        CmdLoad(address=0, data=b'0123456789'),
        CmdReset())

    assert boot_section.uid == 0
    assert not boot_section.is_last
    assert boot_section.hmac_count == 1
    assert boot_section.raw_size == 144

    dek = crypto_backend().random_bytes(32)
    mac = crypto_backend().random_bytes(32)
    nonce = crypto_backend().random_bytes(16)
    data = boot_section.export(dek, mac, Counter(nonce))
    assert data
    assert BootSectionV2.parse(data, 0, False, dek, mac, Counter(nonce))

    with pytest.raises(Exception):
        assert BootSectionV2.parse(data, 0, False, dek, crypto_backend().random_bytes(32), Counter(nonce))


def _create_cert_block_v2(data_dir: str) -> CertBlockV2:
    with open(os.path.join(data_dir, 'selfsign_v3.der.crt'), 'rb') as f:
        cert_data = f.read()

    cb = CertBlockV2()
    cert_obj = Certificate(cert_data)
    cb.set_root_key_hash(0, cert_obj.public_key_hash)
    cb.add_certificate(cert_obj)
    return cb


def test_certificate_section_v2(data_dir: str) -> None:
    with pytest.raises(AssertionError):
        CertSectionV2(None)

    cs = CertSectionV2(_create_cert_block_v2(data_dir))
    dek = crypto_backend().random_bytes(32)
    mac = crypto_backend().random_bytes(32)
    nonce = crypto_backend().random_bytes(16)
    data = cs.export(dek, mac, Counter(nonce))
    assert data
    assert CertSectionV2.parse(data, 0, dek, mac, Counter(nonce))

    with pytest.raises(Exception):
        CertSectionV2.parse(data, 0, dek, crypto_backend().random_bytes(32), Counter(nonce))


def test_certificate_block_v2(data_dir):
    _create_cert_block_v2(data_dir)

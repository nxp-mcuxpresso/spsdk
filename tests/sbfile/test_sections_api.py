#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import Counter
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.commands import CmdErase, CmdLoad, CmdReset
from spsdk.sbfile.sb2.sections import BootSectionV2, CertSectionV2
from spsdk.utils.crypto.cert_blocks import CertBlockV1


def test_boot_section_v2():
    boot_section = BootSectionV2(
        0, CmdErase(address=0, length=100000), CmdLoad(address=0, data=b"0123456789"), CmdReset()
    )

    assert boot_section.uid == 0
    assert not boot_section.is_last
    assert boot_section.hmac_count == 1
    assert boot_section.raw_size == 144

    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    data = boot_section.export(dek, mac, Counter(nonce))
    assert data
    assert BootSectionV2.parse(data, 0, False, dek, mac, Counter(nonce))

    with pytest.raises(SPSDKError, match="Invalid type of dek, should be bytes"):
        BootSectionV2.parse(
            data=data, offset=0, plain_sect=False, dek=4, mac=mac, counter=Counter(nonce)
        )

    with pytest.raises(SPSDKError, match="Invalid type of mac, should be bytes"):
        BootSectionV2.parse(
            data=data, offset=0, plain_sect=False, dek=dek, mac=4, counter=Counter(nonce)
        )

    with pytest.raises(SPSDKError, match="Invalid type of counter"):
        BootSectionV2.parse(data=data, offset=0, plain_sect=False, dek=dek, mac=mac, counter=5)

    with pytest.raises(SPSDKError):
        assert BootSectionV2.parse(data, 0, False, dek, random_bytes(32), Counter(nonce))


def test_boot_section_v2_invalid_export():
    boot_section = BootSectionV2(
        0, CmdErase(address=0, length=100000), CmdLoad(address=0, data=b"0123456789"), CmdReset()
    )
    dek = 32
    mac = 4
    nonce = random_bytes(16)
    with pytest.raises(SPSDKError, match="Invalid type of dek, should be bytes"):
        boot_section.export(dek, mac, Counter(nonce))
    dek = random_bytes(32)
    with pytest.raises(SPSDKError, match="Invalid type of mac, should be bytes"):
        boot_section.export(dek, mac, Counter(nonce))
    counter = 5
    mac = random_bytes(32)
    with pytest.raises(SPSDKError, match="Invalid type of counter"):
        boot_section.export(dek, mac, counter)


def test_boot_section_v2_raw_size():
    b_section = BootSectionV2(uid=2)
    b_section.HMAC_SIZE = 3
    assert b_section.raw_size == 32


def test_boot_section_v2_hmac_count():
    b_section = BootSectionV2(uid=2, hmac_count=0)
    assert b_section.uid == 2


def _create_cert_block_v1(data_dir: str) -> CertBlockV1:
    cb = CertBlockV1()
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_v3.der.crt"))
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    return cb


def test_certificate_section_v2(data_dir: str) -> None:
    with pytest.raises(AssertionError):
        CertSectionV2(None)

    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    data = cs.export(dek, mac, Counter(nonce))
    assert data
    assert CertSectionV2.parse(data, 0, dek, mac, Counter(nonce))

    with pytest.raises(SPSDKError):
        CertSectionV2.parse(data, 0, dek, random_bytes(32), Counter(nonce))


def test_invalid_export_cert_section_v2(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(16)
    mac = random_bytes(16)
    nonce = random_bytes(16)
    cs.HMAC_SIZE = 137
    with pytest.raises(SPSDKError, match="Invalid size"):
        cs.export(dek, mac, Counter(nonce))


def test_certificate_block_v2(data_dir):
    _create_cert_block_v1(data_dir)


def test_invalid_parse_cert_section_v2(data_dir):
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, dek="6")
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, mac="6")
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, counter="6")


def test_invalid_header_hmac(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    invalid_data = valid_data
    invalid_data = bytearray(invalid_data)
    invalid_data[0:32] = bytearray(32)
    with pytest.raises(SPSDKError, match="HMAC"):
        CertSectionV2.parse(invalid_data, 0, dek, mac, Counter(nonce))


def test_invalid_header_tag(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.tag += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="TAG"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))


def test_invalid_header_flag(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.flags += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="FLAGS"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))


def test_invalid_header_flag2(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.address += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="Mark"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))


def test_cert_section(data_dir):
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    assert "CertSectionV2: Length=1296" == repr(cs)

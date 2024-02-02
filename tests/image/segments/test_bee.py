#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from typing import Optional

import pytest

from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.image.bee import (
    BeeBaseClass,
    BeeFacRegion,
    BeeKIB,
    BeeProtectRegionBlock,
    BeeRegionHeader,
)
from spsdk.image.segments import SegBEE
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum


def verify_base_class_features(inst: BeeBaseClass, decrypt_key: Optional[bytes] = None) -> None:
    """Shared code to test base features of the base class.

    :param inst: instance to be tested
    :param decrypt_key: optional key used to decrypt data; None if data not encrypted
    """
    # check `__str__()` can be invoked without any problem
    assert str(inst)
    # check `update` can be invoked without any problem
    inst.update()
    # check `validate` can be invoked without any problem, and instance is configured properly
    inst.validate()
    # test size property and `_size()` class method returns the same number
    expected_size = inst.size
    assert inst.__class__.get_size() == expected_size
    # check export
    data = inst.export()
    assert (data is not None) and (len(data) == expected_size)
    # parse data back into instance
    cls = inst.__class__
    inst2 = (
        cls.parse((b"?" + data)[1:], sw_key=decrypt_key)
        if decrypt_key
        else cls.parse((b"?" + data)[1:])
    )
    # verify the parsed instance is same as original instance
    assert inst2 is not None
    assert inst == inst2
    # verify ValueError exception by parser if input data are too short
    with pytest.raises(SPSDKError):
        cls.parse(b"\x00")


def test_bee_fac_region() -> None:
    """Test BeeFacRegion class."""
    fac = BeeFacRegion(0x11111000, 0x1000, 3)
    assert fac.start_addr == 0x11111000
    assert fac.end_addr == 0x11112000
    assert fac.protected_level == 3
    verify_base_class_features(fac)
    # test invalid params:
    # - address is not aligned
    with pytest.raises(SPSDKError, match="Invalid configuration of the instance"):
        BeeFacRegion(1, 1, 3)
    # - length == 0
    with pytest.raises(SPSDKError, match="Invalid start/end address"):
        BeeFacRegion(0x2000, 0, 3)
    # # - invalid mode
    with pytest.raises(SPSDKError, match="Invalid protected level"):
        BeeFacRegion(0x1000, 0x2000, -1)


def test_bee_protect_region_block() -> None:
    """Test BeeProtectRegionBlock class."""
    prdb = BeeProtectRegionBlock()
    assert prdb.fac_count == 0
    # verify assertion if FAC are not specified
    with pytest.raises(SPSDKError):
        prdb.validate()
    with pytest.raises(SPSDKError):
        prdb.export()
    # test with FAC regions
    prdb.add_fac(BeeFacRegion(0x00000000, 0x01000000, 0))
    prdb.add_fac(BeeFacRegion(0x10000000, 0x01000000, 1))
    verify_base_class_features(prdb)
    prdb.add_fac(BeeFacRegion(0x20000000, 0x01000000, 2))
    prdb.add_fac(BeeFacRegion(0xF0000000, 0x01000000, 3))
    assert prdb.fac_count == 4
    verify_base_class_features(prdb)
    # parse invalid data
    with pytest.raises(SPSDKError):
        BeeProtectRegionBlock.parse(b"\x00" * 256)


def test_bee_invalid_validate():
    class TestBeeProtectRegionBlockAesMode(SpsdkEnum):
        TEST = (10, "TEST")

    prdb = BeeProtectRegionBlock()
    prdb._start_addr = 0xFFFFFFFFA
    with pytest.raises(SPSDKError, match="Invalid start address"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    prdb._end_addr = 0xFFFFFFFFA
    with pytest.raises(SPSDKError, match="Invalid start/end address"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    prdb.mode = TestBeeProtectRegionBlockAesMode.TEST
    with pytest.raises(SPSDKError, match="Only AES/CTR encryption mode supported now"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    prdb.counter = bytes(22)
    with pytest.raises(SPSDKError, match="Invalid counter"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    prdb.counter = b"\x01\x00\x00\x00" * 4
    with pytest.raises(SPSDKError, match="last four bytes must be zero"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    prdb.counter = bytes(16)
    with pytest.raises(SPSDKError, match="Invalid FAC regions"):
        prdb.validate()
    prdb = BeeProtectRegionBlock()
    with pytest.raises(SPSDKError, match="Incorrect length of binary block to be encrypted"):
        prdb.encrypt_block(key=bytes(16), start_addr=0x0, data=bytes(0x401))
    prdb = BeeProtectRegionBlock()
    with pytest.raises(SPSDKError, match="Invalid length of key"):
        prdb.encrypt_block(key=bytes(15), start_addr=0xAA, data=bytes(1024))


def test_bee_kib() -> None:
    """Test BeeKIB class"""
    kib = BeeKIB()
    verify_base_class_features(kib)


def test_bee_region_header() -> None:
    """Test BeeRegionHeader class"""
    sw_key = random_bytes(16)
    hdr = BeeRegionHeader(sw_key=sw_key)
    hdr.add_fac(BeeFacRegion(0x00000000, 0x00010000, 0))
    verify_base_class_features(hdr, decrypt_key=sw_key)
    hdr.add_fac(BeeFacRegion(0x10000000, 0x00010000, 1))
    hdr.add_fac(BeeFacRegion(0x20000000, 0x00010000, 2))
    hdr.add_fac(BeeFacRegion(0xF0000000, 0x00010000, 3))
    verify_base_class_features(hdr, decrypt_key=sw_key)


def test_bee_region_header_fuses() -> None:
    """Test function BeeRegionHeader.sw_key_fuses()"""
    hdr = BeeRegionHeader(sw_key=bytes.fromhex("11223344556677889900AABBCCDDEEFF"))
    fuses = hdr.sw_key_fuses()
    assert len(fuses) == 4
    assert fuses[0] == 0xCCDDEEFF
    assert fuses[1] == 0x9900AABB
    assert fuses[2] == 0x55667788
    assert fuses[3] == 0x11223344


def test_seg_bee() -> None:
    """Test SegBEE class - BEE segment of the bootable image"""
    # empty segment
    seg = SegBEE([])
    assert str(seg)
    assert seg.export() == b""
    assert seg.size == 0
    seg.validate()
    # single region
    sw_key = random_bytes(16)
    hdr = BeeRegionHeader(sw_key=sw_key)
    hdr.add_fac(BeeFacRegion(0x00000000, 0x00010000, 0))
    seg.add_region(hdr)
    assert str(seg)
    seg.validate()
    data = seg.export()
    assert (data is not None) and (len(data) == seg.size)
    parsed_seg = SegBEE.parse((b"\xFF" + data)[1:], [sw_key])
    assert seg == parsed_seg
    # two regions
    sw_key2 = random_bytes(16)
    hdr2 = BeeRegionHeader(sw_key=sw_key2)
    hdr2.add_fac(BeeFacRegion(0x10000000, 0x00010000, 1))
    hdr2.add_fac(BeeFacRegion(0x20000000, 0x00010000, 2))
    seg.add_region(hdr2)
    assert str(seg)
    seg.validate()
    data = seg.export()
    assert (data is not None) and (len(data) == seg.size)
    parsed_seg = SegBEE.parse((b"\xFF" + data)[1:], [sw_key, sw_key2])
    assert seg == parsed_seg
    # total number of FACs exceeded
    hdr.add_fac(BeeFacRegion(0xF0000000, 0x00010000, 3))
    with pytest.raises(SPSDKError):
        seg.validate()


def test_invalid_bee_fac_region_parse():
    with pytest.raises(SPSDKError):
        BeeFacRegion.parse(b"1" * 1024)


def test_invalid_bee_protected_block_parse(data_dir):
    """Test for unsupported version"""
    valid_data = bytearray(load_binary(f"{data_dir}/bee-data.bin"))

    invalid_version = valid_data
    invalid_version[8:12] = bytes(0) * 4
    with pytest.raises(SPSDKError):
        BeeProtectRegionBlock.parse(invalid_version + bytes(4))

    """Test for reserved area"""
    invalid_reserved = valid_data
    invalid_version[8:12] = b"\x00\x00\x01\x56"
    invalid_reserved[78] = 0xFF
    with pytest.raises(SPSDKError):
        BeeProtectRegionBlock.parse(invalid_reserved + bytes(4))


def test_seg_bee_invalid_encrypt_data() -> None:
    seg = SegBEE([])
    with pytest.raises(SPSDKError, match="Invalid start address"):
        seg.encrypt_data(start_addr=0xFFFFFFFFFFFFFFFFFFFF, data=bytes(16))

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK BEE (Bus Encryption Engine) module tests.

This module contains comprehensive test cases for the BEE functionality in SPSDK,
including tests for BEE regions, protection blocks, key information blocks (KIB),
and various BEE-related data structures used in secure boot and encryption.
"""

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
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum


def verify_base_class_features(inst: BeeBaseClass, decrypt_key: Optional[bytes] = None) -> None:
    """Verify base features of BeeBaseClass instances.

    This method performs comprehensive testing of BeeBaseClass instances including
    string representation, update/validate operations, size consistency, export/parse
    roundtrip, and error handling for invalid data.

    :param inst: BeeBaseClass instance to be tested
    :param decrypt_key: Optional decryption key for encrypted data; None if data is not encrypted
    :raises SPSDKError: When parsing fails with insufficient input data
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
    cls = type(inst)
    inst2 = (
        cls.parse((b"?" + data)[1:], sw_key=decrypt_key)  # type: ignore[attr-defined]
        if decrypt_key
        else cls.parse((b"?" + data)[1:])  # type: ignore[attr-defined]
    )
    # verify the parsed instance is same as original instance
    assert inst2 is not None
    assert inst == inst2
    # verify ValueError exception by parser if input data are too short
    with pytest.raises(SPSDKError):
        cls.parse(b"\x00")  # type: ignore[attr-defined]


def test_bee_fac_region() -> None:
    """Test BeeFacRegion class functionality and validation.

    Validates the BeeFacRegion class constructor with valid parameters and verifies
    that proper exceptions are raised for invalid configurations including
    unaligned addresses, zero length, and invalid protection levels.

    :raises SPSDKError: When BeeFacRegion is created with invalid parameters.
    """
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
    """Test BeeProtectRegionBlock class functionality.

    Validates the BeeProtectRegionBlock class by testing:
    - Initial state with zero FAC count
    - Error handling when FAC regions are not specified
    - Adding multiple FAC regions and verifying count
    - Base class feature verification
    - Parsing invalid data and error handling

    :raises SPSDKError: When validation fails, export fails without FAC regions, or parsing invalid data.
    """
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


def test_bee_invalid_validate() -> None:
    """Test BEE protect region block validation with invalid configurations.

    This test verifies that the BeeProtectRegionBlock validation properly detects
    and raises appropriate errors for various invalid configurations including:
    - Invalid start/end addresses
    - Unsupported encryption modes
    - Invalid counter values and formats
    - Invalid FAC regions
    - Incorrect data block lengths and key sizes
    """

    class TestBeeProtectRegionBlockAesMode(SpsdkEnum):
        """Test enumeration for BEE protect region block AES modes.

        This enumeration defines test values for validating BEE (Bus Encryption Engine)
        protect region block AES mode configurations in unit tests.
        """

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
    prdb.mode = TestBeeProtectRegionBlockAesMode.TEST  # type: ignore[assignment]
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
    """Test BeeKIB class functionality.

    Verifies that the BeeKIB class implements all required base class features
    and methods correctly.
    """
    kib = BeeKIB()
    verify_base_class_features(kib)


def test_bee_region_header() -> None:
    """Test BeeRegionHeader class functionality.

    This test verifies the BeeRegionHeader class by creating an instance with a random
    software key, adding multiple FAC (Flash Access Control) regions, and validating
    the base class features after each addition. The test covers scenarios with 1 to 4
    FAC regions to ensure proper functionality across different configurations.

    :raises AssertionError: If any verification of base class features fails.
    """
    sw_key = random_bytes(16)
    hdr = BeeRegionHeader(sw_key=sw_key)
    hdr.add_fac(BeeFacRegion(0x00000000, 0x00010000, 0))
    verify_base_class_features(hdr, decrypt_key=sw_key)
    hdr.add_fac(BeeFacRegion(0x10000000, 0x00010000, 1))
    hdr.add_fac(BeeFacRegion(0x20000000, 0x00010000, 2))
    hdr.add_fac(BeeFacRegion(0xF0000000, 0x00010000, 3))
    verify_base_class_features(hdr, decrypt_key=sw_key)


def test_bee_region_header_fuses() -> None:
    """Test BeeRegionHeader software key fuses conversion functionality.

    Validates that the sw_key_fuses() method correctly converts a 16-byte software key
    into four 32-bit fuse values with proper byte order transformation.
    """
    hdr = BeeRegionHeader(sw_key=bytes.fromhex("11223344556677889900AABBCCDDEEFF"))
    fuses = hdr.sw_key_fuses()
    assert len(fuses) == 4
    assert fuses[0] == 0xCCDDEEFF
    assert fuses[1] == 0x9900AABB
    assert fuses[2] == 0x55667788
    assert fuses[3] == 0x11223344


def test_invalid_bee_fac_region_parse() -> None:
    """Test that BeeFacRegion.parse raises SPSDKError for invalid data.

    Verifies that parsing invalid data (1024 bytes of "1" characters) with
    BeeFacRegion.parse method properly raises an SPSDKError exception.

    :raises SPSDKError: When invalid data is provided to parse method.
    """
    with pytest.raises(SPSDKError):
        BeeFacRegion.parse(b"1" * 1024)


def test_invalid_bee_protected_block_parse(data_dir: str) -> None:
    """Test BeeProtectRegionBlock parsing with invalid data.

    Tests parsing behavior when provided with invalid BEE protected block data,
    including unsupported version numbers and invalid reserved area values.
    Verifies that appropriate SPSDKError exceptions are raised for malformed data.

    :param data_dir: Path to directory containing test data files
    :raises SPSDKError: When parsing invalid BEE protected block data
    """
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

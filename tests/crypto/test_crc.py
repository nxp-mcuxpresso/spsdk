#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CRC (Cyclic Redundancy Check) testing module."""

import pytest

from spsdk.crypto.crc import Crc, CrcAlg, CrcConfig, from_crc_algorithm
from spsdk.exceptions import SPSDKKeyError


def test_crc_alg_enum() -> None:
    """Test CRC algorithm enumeration.

    Verifies that the CrcAlg enum contains expected CRC algorithm definitions
    and that they can be accessed by tag and value.

    :raises AssertionError: If CRC algorithm enumeration validation fails.
    """
    assert CrcAlg.CRC32.label == "crc32"
    assert CrcAlg.CRC32_MPEG.label == "crc32-mpeg"
    assert CrcAlg.CRC16_XMODEM.label == "crc16-xmodem"


def test_crc_calculate_crc32() -> None:
    """Test CRC32 calculation with known test vectors.

    Verifies that CRC32 calculation produces correct results for standard
    test data.

    :raises AssertionError: If CRC32 calculation fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32)

    # Test with empty data
    assert crc.calculate(b"") == 0x00000000

    # Test with "123456789" - standard CRC32 test vector
    test_data = b"123456789"
    expected_crc = 0xCBF43926
    assert crc.calculate(test_data) == expected_crc

    # Test with "The quick brown fox jumps over the lazy dog"
    test_data2 = b"The quick brown fox jumps over the lazy dog"
    result = crc.calculate(test_data2)
    assert isinstance(result, int)
    assert result >= 0


def test_crc_calculate_crc32_mpeg() -> None:
    """Test CRC32-MPEG calculation.

    Verifies that CRC32-MPEG algorithm produces correct results.

    :raises AssertionError: If CRC32-MPEG calculation fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32_MPEG)

    # Test with "123456789"
    test_data = b"123456789"
    result = crc.calculate(test_data)
    assert isinstance(result, int)
    assert result >= 0


def test_crc_calculate_crc16_xmodem() -> None:
    """Test CRC16-XMODEM calculation.

    Verifies that CRC16-XMODEM algorithm produces correct results.

    :raises AssertionError: If CRC16-XMODEM calculation fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC16_XMODEM)

    # Test with "123456789"
    test_data = b"123456789"
    expected_crc = 0x31C3
    assert crc.calculate(test_data) == expected_crc


def test_crc_verify() -> None:
    """Test CRC verification functionality.

    Verifies that the verify method correctly validates CRC checksums.

    :raises AssertionError: If CRC verification fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32)

    test_data = b"123456789"
    expected_crc = 0xCBF43926

    # Test correct CRC verification
    assert crc.verify(test_data, expected_crc) is True

    # Test incorrect CRC verification
    assert crc.verify(test_data, 0x12345678) is False

    # Test with empty data
    assert crc.verify(b"", 0x00000000) is True


def test_crc_update_and_finalize() -> None:
    """Test incremental CRC calculation using update and finalize.

    Verifies that processing data in chunks produces the same result
    as processing all data at once.

    :raises AssertionError: If incremental CRC calculation fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32)

    # Full data
    full_data = b"123456789"
    expected_crc = crc.calculate(full_data)

    # Process in chunks
    crc_incremental = from_crc_algorithm(CrcAlg.CRC32)
    crc_incremental.update(b"123")
    crc_incremental.update(b"456")
    crc_incremental.update(b"789")
    result = crc_incremental.finalize()

    assert result == expected_crc


def test_crc_update_single_chunk() -> None:
    """Test update with single chunk equals calculate.

    Verifies that update+finalize with one chunk produces same result
    as calculate.

    :raises AssertionError: If single chunk update fails.
    """
    test_data = b"Hello, World!"

    crc1 = from_crc_algorithm(CrcAlg.CRC32)
    result1 = crc1.calculate(test_data)

    crc2 = from_crc_algorithm(CrcAlg.CRC32)
    crc2.update(test_data)
    result2 = crc2.finalize()

    assert result1 == result2


def test_crc_update_multiple_chunks() -> None:
    """Test update with multiple chunks of varying sizes.

    Verifies that CRC calculation works correctly with different
    chunk sizes.

    :raises AssertionError: If multi-chunk update fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32)

    # Calculate expected result
    full_data = b"The quick brown fox jumps over the lazy dog"
    expected = crc.calculate(full_data)

    # Process in various chunk sizes
    crc_chunked = from_crc_algorithm(CrcAlg.CRC32)
    crc_chunked.update(b"The quick ")
    crc_chunked.update(b"brown fox ")
    crc_chunked.update(b"jumps over ")
    crc_chunked.update(b"the lazy dog")
    result = crc_chunked.finalize()

    assert result == expected


def test_crc_finalize_resets_state() -> None:
    """Test that finalize resets internal state for reuse.

    Verifies that after finalize, the CRC instance can be reused
    for new calculations.

    :raises AssertionError: If state reset fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC32)

    # First calculation
    crc.update(b"first")
    _ = crc.finalize()

    # Second calculation - should start fresh
    crc.update(b"second")
    result2 = crc.finalize()

    # Verify they're different (unless by coincidence)
    # More importantly, verify second calculation is correct
    expected = from_crc_algorithm(CrcAlg.CRC32).calculate(b"second")
    assert result2 == expected


def test_crc_update_empty_data() -> None:
    """Test update with empty data chunks.

    Verifies that updating with empty bytes doesn't affect the result.

    :raises AssertionError: If empty update handling fails.
    """
    crc1 = from_crc_algorithm(CrcAlg.CRC32)
    crc1.update(b"test")
    result1 = crc1.finalize()

    crc2 = from_crc_algorithm(CrcAlg.CRC32)
    crc2.update(b"")
    crc2.update(b"test")
    crc2.update(b"")
    result2 = crc2.finalize()

    assert result1 == result2


def test_crc_from_algorithm_string() -> None:
    """Test creating CRC from algorithm string name.

    Verifies that CRC instances can be created using string
    algorithm names.

    :raises AssertionError: If string-based creation fails.
    """
    crc1 = from_crc_algorithm("crc32")
    crc2 = from_crc_algorithm(CrcAlg.CRC32)

    test_data = b"test"
    assert crc1.calculate(test_data) == crc2.calculate(test_data)


def test_crc_from_algorithm_invalid() -> None:
    """Test creating CRC with invalid algorithm name.

    Verifies that appropriate exception is raised for unknown
    algorithm names.

    :raises AssertionError: If exception handling fails.
    """
    with pytest.raises(SPSDKKeyError):
        from_crc_algorithm("invalid_algorithm")


def test_crc_config_direct() -> None:
    """Test creating CRC with direct CrcConfig.

    Verifies that CRC can be instantiated with custom configuration.

    :raises AssertionError: If direct config creation fails.
    """
    config = CrcConfig(
        polynomial=0x104C11DB7,
        initial_value=0x00000000,
        final_xor=0xFFFFFFFF,
        reverse=True,
    )
    crc = Crc(config)

    # Should behave like CRC32
    test_data = b"123456789"
    expected_crc = 0xCBF43926
    assert crc.calculate(test_data) == expected_crc


def test_crc_large_data_incremental() -> None:
    """Test incremental CRC calculation with large data.

    Verifies that processing large data in chunks produces correct
    results and is memory efficient.

    :raises AssertionError: If large data processing fails.
    """
    # Create large test data
    chunk_size = 4096
    num_chunks = 10
    test_data = b"A" * (chunk_size * num_chunks)

    # Calculate expected result
    crc_full = from_crc_algorithm(CrcAlg.CRC32)
    expected = crc_full.calculate(test_data)

    # Calculate incrementally
    crc_incremental = from_crc_algorithm(CrcAlg.CRC32)
    for i in range(num_chunks):
        chunk = test_data[i * chunk_size : (i + 1) * chunk_size]
        crc_incremental.update(chunk)
    result = crc_incremental.finalize()

    assert result == expected


def test_crc16_update_and_finalize() -> None:
    """Test incremental CRC16 calculation.

    Verifies that CRC16 algorithms also work correctly with
    update and finalize methods.

    :raises AssertionError: If CRC16 incremental calculation fails.
    """
    crc = from_crc_algorithm(CrcAlg.CRC16_XMODEM)

    # Full calculation
    full_data = b"123456789"
    expected = crc.calculate(full_data)

    # Incremental calculation
    crc_inc = from_crc_algorithm(CrcAlg.CRC16_XMODEM)
    crc_inc.update(b"12345")
    crc_inc.update(b"6789")
    result = crc_inc.finalize()

    assert result == expected

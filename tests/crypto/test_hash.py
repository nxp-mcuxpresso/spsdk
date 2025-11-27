#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK cryptographic hash functions test suite.

This module contains comprehensive tests for SPSDK's hash functionality,
including various hash algorithms, hash operations, and utility functions.
Test coverage includes hash algorithm enumeration, hash operations with
different data types and sizes, edge cases handling, and consistency verification.
"""

from binascii import unhexlify

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm, Hash, get_hash, get_hash_algorithm, get_hash_length


def test_hash() -> None:
    """Test SHA256 hash calculation functionality.

    Validates that the get_hash function correctly computes SHA256 hash
    by comparing the calculated hash of a known plain text input against
    the expected hash value.

    :raises AssertionError: If calculated hash does not match expected hash value.
    """
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_sha256 = unhexlify("41116FE4EFB90A050AABB83419E19BF2196A0E76AB8E3034C8D674042EE23621")
    calc_sha256 = get_hash(plain_text, EnumHashAlgorithm.SHA256)
    assert calc_sha256 == text_sha256


def test_all_hash_algorithms() -> None:
    """Test all supported hash algorithms with known test vectors.

    This test function validates the correctness of all hash algorithms supported
    by SPSDK by computing hashes of a known input string and comparing the results
    against pre-computed expected values. The test covers SHA1, SHA256, SHA384,
    SHA512, MD5, SHA3-256, SHA3-384, and SHA3-512 algorithms.

    :raises AssertionError: If any hash algorithm produces an unexpected result.
    """
    plain_text = b"The quick brown fox jumps over the lazy dog"

    # Expected hash values for the test string
    expected_hashes = {
        EnumHashAlgorithm.SHA1: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        EnumHashAlgorithm.SHA256: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        EnumHashAlgorithm.SHA384: "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
        EnumHashAlgorithm.SHA512: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
        EnumHashAlgorithm.MD5: "9e107d9d372bb6826bd81d3542a419d6",
        EnumHashAlgorithm.SHA3_256: "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        EnumHashAlgorithm.SHA3_384: "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
        EnumHashAlgorithm.SHA3_512: "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
    }

    for algorithm, expected_hex in expected_hashes.items():
        result = get_hash(plain_text, algorithm)
        expected = unhexlify(expected_hex)
        assert result == expected, f"Hash mismatch for {algorithm.name}"


def test_hash_class() -> None:
    """Test the Hash class functionality.

    Validates that the Hash class works correctly with different algorithms
    and produces the same results as the direct get_hash function. Tests
    both SHA256 (default) and SHA1 algorithms using incremental updates
    and finalization.
    """
    plain_text = b"test data"

    # Test with default SHA256
    hash_obj = Hash()
    hash_obj.update(plain_text)
    result1 = hash_obj.finalize()

    # Compare with direct get_hash function
    result2 = get_hash(plain_text, EnumHashAlgorithm.SHA256)
    assert result1 == result2

    # Test with different algorithm
    hash_obj_sha1 = Hash(EnumHashAlgorithm.SHA1)
    hash_obj_sha1.update(plain_text)
    result_sha1 = hash_obj_sha1.finalize()

    result_sha1_direct = get_hash(plain_text, EnumHashAlgorithm.SHA1)
    assert result_sha1 == result_sha1_direct


def test_hash_update_int() -> None:
    """Test the update_int method of Hash class.

    Verifies that the update_int method correctly processes both positive and negative
    integers by comparing results with manual byte conversion. Tests that negative
    integers are converted to their positive equivalent before hashing.
    """
    hash_obj = Hash(EnumHashAlgorithm.SHA256)

    # Test with positive integer
    test_value = 12345
    hash_obj.update_int(test_value)
    result1 = hash_obj.finalize()

    # Compare with manual conversion
    hash_obj2 = Hash(EnumHashAlgorithm.SHA256)
    hash_obj2.update(test_value.to_bytes(length=2, byteorder="big"))
    result2 = hash_obj2.finalize()

    assert result1 == result2

    # Test with negative integer (should be converted to positive)
    hash_obj3 = Hash(EnumHashAlgorithm.SHA256)
    hash_obj3.update_int(-12345)
    result3 = hash_obj3.finalize()

    assert result1 == result3  # Should be same as positive value


def test_hash_multiple_updates() -> None:
    """Test hash functionality with multiple update calls.

    Verifies that hash computation produces identical results whether data is
    processed in a single update call or split across multiple update calls.
    This ensures the Hash class correctly maintains internal state between
    update operations.

    :raises AssertionError: When hash results from single and multiple updates don't match.
    """
    data1 = b"Hello "
    data2 = b"World"
    combined_data = data1 + data2

    # Single update
    result1 = get_hash(combined_data, EnumHashAlgorithm.SHA256)

    # Multiple updates
    hash_obj = Hash(EnumHashAlgorithm.SHA256)
    hash_obj.update(data1)
    hash_obj.update(data2)
    result2 = hash_obj.finalize()

    assert result1 == result2


def test_get_hash_length() -> None:
    """Test get_hash_length function for all supported hash algorithms.

    Validates that get_hash_length returns correct byte lengths for each hash algorithm
    in EnumHashAlgorithm. Also verifies the returned length matches actual hash output
    by computing hashes and comparing their byte lengths.

    :raises AssertionError: If hash length doesn't match expected value or actual hash output length.
    """
    expected_lengths = {
        EnumHashAlgorithm.SHA1: 20,
        EnumHashAlgorithm.SHA256: 32,
        EnumHashAlgorithm.SHA384: 48,
        EnumHashAlgorithm.SHA512: 64,
        EnumHashAlgorithm.MD5: 16,
        EnumHashAlgorithm.SHA3_256: 32,
        EnumHashAlgorithm.SHA3_384: 48,
        EnumHashAlgorithm.SHA3_512: 64,
    }

    for algorithm, expected_length in expected_lengths.items():
        actual_length = get_hash_length(algorithm)
        assert actual_length == expected_length, f"Length mismatch for {algorithm.name}"

        # Verify with actual hash output
        test_data = b"test"
        hash_result = get_hash(test_data, algorithm)
        assert len(hash_result) == expected_length


def test_get_hash_algorithm() -> None:
    """Test the get_hash_algorithm function with valid hash algorithms.

    Verifies that the get_hash_algorithm function correctly returns hash algorithm
    objects for SHA1, SHA256, and SHA384 algorithms, and that the returned objects
    have the expected digest_size attribute.
    """
    # Test valid algorithms
    for algorithm in [EnumHashAlgorithm.SHA1, EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]:
        hash_algo = get_hash_algorithm(algorithm)
        assert hash_algo is not None
        assert hasattr(hash_algo, "digest_size")


def test_empty_data_hash() -> None:
    """Test hashing empty data with various hash algorithms.

    Validates that the get_hash function correctly handles empty byte data
    across different hash algorithms (SHA1, SHA256, SHA384, SHA512, MD5).
    Verifies that the returned hash has the expected length for each algorithm
    and is not None.

    :raises AssertionError: If hash result length doesn't match expected length or result is None.
    """
    empty_data = b""

    # Test with different algorithms
    algorithms_to_test = [
        EnumHashAlgorithm.SHA1,
        EnumHashAlgorithm.SHA256,
        EnumHashAlgorithm.SHA384,
        EnumHashAlgorithm.SHA512,
        EnumHashAlgorithm.MD5,
    ]

    for algorithm in algorithms_to_test:
        result = get_hash(empty_data, algorithm)
        expected_length = get_hash_length(algorithm)
        assert len(result) == expected_length
        assert result is not None


def test_large_data_hash() -> None:
    """Test hashing functionality with large data sets.

    Validates that the hash function can properly handle large amounts of data
    (1MB) and returns correct SHA256 hash output with expected length.
    """
    # Create 1MB of test data
    large_data = b"A" * (1024 * 1024)

    result = get_hash(large_data, EnumHashAlgorithm.SHA256)
    assert len(result) == 32
    assert result is not None


@pytest.mark.parametrize(
    "algorithm",
    [
        EnumHashAlgorithm.SHA1,
        EnumHashAlgorithm.SHA256,
        EnumHashAlgorithm.SHA384,
        EnumHashAlgorithm.SHA512,
        EnumHashAlgorithm.MD5,
        EnumHashAlgorithm.SHA3_256,
        EnumHashAlgorithm.SHA3_384,
        EnumHashAlgorithm.SHA3_512,
    ],
)
def test_hash_consistency(algorithm: EnumHashAlgorithm) -> None:
    """Test that the same input always produces the same hash.

    Verifies the consistency of hash algorithms by ensuring that identical input
    data produces identical hash outputs across multiple invocations.

    :param algorithm: The hash algorithm to test for consistency.
    :raises AssertionError: If hash results are inconsistent or length is incorrect.
    """
    test_data = b"consistency test data"

    result1 = get_hash(test_data, algorithm)
    result2 = get_hash(test_data, algorithm)

    assert result1 == result2
    assert len(result1) == get_hash_length(algorithm)


def test_hash_different_inputs() -> None:
    """Test that different inputs produce different hashes.

    Validates that the get_hash function generates distinct hash values when
    provided with different input data using the same hash algorithm. Also
    verifies that the output hash length is consistent and matches the
    expected length for SHA256 (32 bytes).
    """
    data1 = b"input1"
    data2 = b"input2"

    hash1 = get_hash(data1, EnumHashAlgorithm.SHA256)
    hash2 = get_hash(data2, EnumHashAlgorithm.SHA256)

    assert hash1 != hash2
    assert len(hash1) == len(hash2) == 32

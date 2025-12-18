#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK ELE HSE message implementation tests.

This module contains unit tests for HSE-specific EdgeLock Enclave (ELE)
message functionality, focusing on boot data image signing operations
and message encoding/decoding validation.
"""

import os

import pytest

from spsdk.crypto.keys import PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc, PublicKeyRsa
from spsdk.ele.ele_message_hse import (
    EleMessageHse,
    EleMessageHseBootDataImageSign,
    KeyImportPayload,
)
from spsdk.exceptions import SPSDKValueError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.image.hse.key_info import (
    HseAesBlockModeMask,
    HseEccCurveId,
    HseKeyFlags,
    HseSmrFlags,
    KeyInfo,
)
from spsdk.utils.family import FamilyRevision


# Mock implementation of EleMessageHse for testing
class MockEleMessageHse(EleMessageHse):
    """Mock ELE HSE message implementation for testing purposes.

    This class provides a test double for EleMessageHse with predefined
    command values and service descriptors to support unit testing of
    ELE HSE message handling functionality.

    :cvar CMD: Mock command identifier set to 1.
    :cvar CMD_DESCRIPTOR_FORMAT: Command descriptor format using little-endian uint32.
    """

    CMD = 1
    CMD_DESCRIPTOR_FORMAT = "<I"  # LITTLE_ENDIAN + UINT32

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Returns a fixed 4-byte service descriptor used for testing purposes.

        :return: Service descriptor as 4 zero bytes.
        """
        return b"\x00\x00\x00\x00"


def test_ele_message_hse_boot_data_image_sign_init_invalid_tag_len() -> None:
    """Test ELE message HSE boot data image sign initialization with invalid tag length.

    Verifies that creating an EleMessageHseBootDataImageSign instance with an invalid
    tag length (20) raises SPSDKValueError with appropriate error message.

    :raises SPSDKValueError: When tag length is invalid (expected behavior).
    """
    with pytest.raises(SPSDKValueError, match="Invalid tag length"):
        EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=20)


def test_ele_message_hse_boot_data_image_sign_decode_response_data_tag_len_16() -> None:
    """Test ELE HSE boot data image sign message response decoding with 16-byte tag length.

    Verifies that the decode_response_data method correctly processes response data
    when tag_len is set to 16 bytes. In this configuration, only GMAC data is expected
    in the response, and the initial_vector should remain None.

    :raises AssertionError: If the decoded response data doesn't match expected values.
    """
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=16)

    # Mock response data for tag_len=16 (just GMAC)
    gmac = bytes([i for i in range(16)])
    response = gmac

    msg.decode_response_data(response)

    assert msg.initial_vector is None
    assert msg.gmac_value == gmac


def test_ele_message_hse_boot_data_image_sign_decode_response_data_tag_len_28() -> None:
    """Test ELE HSE boot data image sign message response decoding with 28-byte tag length.

    Verifies that the decode_response_data method correctly parses response data
    when tag_len is set to 28 bytes, extracting the 12-byte initialization vector
    and 16-byte GMAC value from the combined response.
    """
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=28)

    # Mock response data for tag_len=28 (IV + GMAC)
    iv = bytes([i for i in range(12)])
    gmac = bytes([i for i in range(16)])
    response = iv + gmac

    msg.decode_response_data(response)

    assert msg.initial_vector == iv
    assert msg.gmac_value == gmac


def test_ele_message_hse_boot_data_image_sign_decode_response_data_invalid_tag_len() -> None:
    """Test ELE message HSE boot data image sign decode response with invalid tag length.

    Verifies that decode_response_data method properly validates tag_len parameter
    and raises appropriate exception when an unsupported tag length is provided.

    :raises SPSDKValueError: When tag_len is set to unsupported value (20 instead of 16).
    """
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=16)
    msg.tag_len = 20
    with pytest.raises(SPSDKValueError, match="Unsupported tag length"):
        msg.decode_response_data(b"\x00" * 20)


def test_ele_message_hse_boot_data_image_sign_response_info() -> None:
    """Test response_info method of EleMessageHseBootDataImageSign.

    This test verifies that the response_info method correctly formats output
    based on tag length. Tests both scenarios: tag_len=16 (no IV) and
    tag_len=28 (with IV), ensuring proper inclusion/exclusion of Initial Vector
    information in the response.
    """
    # Test with tag_len=16 (no IV)
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=16)
    msg.gmac_value = bytes([i for i in range(16)])

    info = msg.response_info()
    assert "Image Signature:" in info
    assert "GMAC:" in info
    assert "Initial Vector:" not in info

    # Test with tag_len=28 (with IV)
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=28)
    msg.initial_vector = bytes([i for i in range(12)])
    msg.gmac_value = bytes([i for i in range(16)])

    info = msg.response_info()
    assert "Image Signature:" in info
    assert "GMAC:" in info
    assert "Initial Vector:" in info


@pytest.fixture
def family() -> FamilyRevision:
    """Return a family revision for testing."""
    return FamilyRevision("mcxe31b")


@pytest.fixture
def aes_key_info(family: FamilyRevision) -> KeyInfo:
    """Create an AES key info for testing."""
    return KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT | HseKeyFlags.USAGE_DECRYPT,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0,
        key_bit_len=HseKeyBits.KEY256_BITS,
        specific_data={
            "aesBlockModeMask": HseAesBlockModeMask.BLOCK_MODE_CBC
            | HseAesBlockModeMask.BLOCK_MODE_GCM
        },
    )


@pytest.fixture
def ecc_key_info(family: FamilyRevision) -> KeyInfo:
    """Create an ECC key info for testing."""
    return KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_SIGN | HseKeyFlags.USAGE_VERIFY,
        key_type=KeyType.ECC_PAIR,
        smr_flags=HseSmrFlags.SMR_0,
        key_bit_len=HseKeyBits.KEY256_BITS,
        specific_data={"eccCurveId": HseEccCurveId.SEC_SECP256R1.value},
    )


@pytest.fixture
def rsa_key_info(family: FamilyRevision) -> KeyInfo:
    """Create an RSA key info for testing."""
    return KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_SIGN | HseKeyFlags.USAGE_VERIFY,
        key_type=KeyType.RSA_PAIR,
        smr_flags=HseSmrFlags.SMR_0,
        key_bit_len=HseKeyBits.KEY2048_BITS,
        specific_data={"pubExponentSize": 3},
    )


def test_key_import_payload_init_with_aes_key(aes_key_info: KeyInfo) -> None:
    """Test initializing KeyImportPayload with an AES key."""
    # Create a 256-bit AES key
    aes_key = bytes(32)  # 32 bytes = 256 bits

    # Initialize payload
    payload = KeyImportPayload(key_info=aes_key_info, key=aes_key)

    # Check key data
    assert payload.key_data[0] is None
    assert payload.key_data[1] is None
    assert payload.key_data[2] == aes_key

    # Check key lengths
    assert payload.key_lengths[0] is None
    assert payload.key_lengths[1] is None
    assert payload.key_lengths[2] == 32

    # Check key offsets
    assert payload.key_offsets[0] is None
    assert payload.key_offsets[1] is None
    assert payload.key_offsets[2] == aes_key_info.size

    # Check total size
    assert payload.size == aes_key_info.size + 32


def test_key_import_payload_init_with_invalid_aes_key(aes_key_info: KeyInfo) -> None:
    """Test initializing KeyImportPayload with an invalid AES key."""
    # Create an invalid AES key (wrong size)
    invalid_aes_key = bytes(20)  # Not a valid AES key size

    # Should raise an error
    with pytest.raises(SPSDKValueError, match="Invalid AES key length"):
        KeyImportPayload(key_info=aes_key_info, key=invalid_aes_key)


def test_key_import_payload_init_with_ecc_public_key(
    tests_root_dir: str, ecc_key_info: KeyInfo
) -> None:
    """Test initializing KeyImportPayload with an ECC public key."""
    # Create an ECC public key
    public_key = PublicKeyEcc.load(
        os.path.join(tests_root_dir, "_data/keys/ecc256/srk3_ecc256.pub")
    )

    # Initialize payload
    payload = KeyImportPayload(key_info=ecc_key_info, key=public_key)

    # Check key data
    assert payload.key_data[0] is not None  # X || Y coordinates
    assert payload.key_data[1] is None
    assert payload.key_data[2] is None

    # Check key lengths
    assert payload.key_lengths[0] == 64  # 32 bytes X + 32 bytes Y
    assert payload.key_lengths[1] is None
    assert payload.key_lengths[2] is None

    # Check key offsets
    assert payload.key_offsets[0] == ecc_key_info.size
    assert payload.key_offsets[1] is None
    assert payload.key_offsets[2] is None

    # Check total size
    assert payload.size == ecc_key_info.size + 64


def test_key_import_payload_init_with_ecc_private_key(
    tests_root_dir: str, ecc_key_info: KeyInfo
) -> None:
    """Test initializing KeyImportPayload with an ECC private key."""
    # Create an ECC private key
    private_key = PrivateKeyEcc.load(
        os.path.join(tests_root_dir, "_data/keys/ecc256/srk3_ecc256.pem")
    )

    # Initialize payload
    payload = KeyImportPayload(key_info=ecc_key_info, key=private_key)

    # Check key data
    assert payload.key_data[0] is not None  # X || Y coordinates
    assert payload.key_data[1] is None
    assert payload.key_data[2] is not None  # Private scalar

    # Check key lengths
    assert payload.key_lengths[0] == 64  # 32 bytes X + 32 bytes Y
    assert payload.key_lengths[1] is None
    assert payload.key_lengths[2] == 32  # 32 bytes private scalar

    # Check key offsets
    assert payload.key_offsets[0] == ecc_key_info.size
    assert payload.key_offsets[1] is None
    assert payload.key_offsets[2] == ecc_key_info.size + 64

    # Check total size
    assert payload.size == ecc_key_info.size + 64 + 32


def test_key_import_payload_init_with_rsa_public_key(
    tests_root_dir: str, rsa_key_info: KeyInfo
) -> None:
    """Test initializing KeyImportPayload with an RSA public key."""
    # Create an RSA public key
    public_key = PublicKeyRsa.load(
        os.path.join(tests_root_dir, "_data/keys/rsa2048/srk3_rsa2048.pub")
    )
    # Initialize payload
    payload = KeyImportPayload(key_info=rsa_key_info, key=public_key)

    # Check key data
    assert payload.key_data[0] is not None  # Modulus
    assert payload.key_data[1] is not None  # Public exponent
    assert payload.key_data[2] is None

    # Check key lengths
    assert payload.key_lengths[0] == 256  # 2048-bit modulus
    assert payload.key_lengths[1] == 3  # Public exponent (typically 3 bytes for 0x010001)
    assert payload.key_lengths[2] is None

    # Check key offsets
    assert payload.key_offsets[0] == rsa_key_info.size
    assert payload.key_offsets[1] == rsa_key_info.size + 256
    assert payload.key_offsets[2] is None

    # Check total size
    assert payload.size == rsa_key_info.size + 256 + 3


def test_key_import_payload_init_with_rsa_private_key(
    tests_root_dir: str, rsa_key_info: KeyInfo
) -> None:
    """Test initializing KeyImportPayload with an RSA private key."""
    # Create an RSA private key
    private_key = PrivateKeyRsa.load(
        os.path.join(tests_root_dir, "_data/keys/rsa2048/srk3_rsa2048.pem")
    )
    # Initialize payload
    payload = KeyImportPayload(key_info=rsa_key_info, key=private_key)

    # Check key data
    assert payload.key_data[0] is not None  # Modulus
    assert payload.key_data[1] is not None  # Public exponent
    assert payload.key_data[2] is not None  # Private exponent

    # Check key lengths
    assert isinstance(payload.key_lengths[0], int)
    assert payload.key_lengths[0] == 256  # 2048-bit modulus
    assert isinstance(payload.key_lengths[1], int)
    assert payload.key_lengths[1] > 0  # Public exponent
    assert isinstance(payload.key_lengths[2], int)
    assert payload.key_lengths[2] == 256  # 2048-bit private exponent

    # Check key offsets
    assert isinstance(payload.key_offsets[0], int)
    assert payload.key_offsets[0] == rsa_key_info.size
    assert isinstance(payload.key_offsets[1], int)
    assert payload.key_offsets[1] == rsa_key_info.size + 256
    assert isinstance(payload.key_offsets[2], int)
    assert payload.key_offsets[2] == rsa_key_info.size + 256 + payload.key_lengths[1]


def test_key_import_payload_export(aes_key_info: KeyInfo) -> None:
    """Test exporting KeyImportPayload to binary."""
    # Create a 256-bit AES key
    aes_key = bytes(32)  # 32 bytes = 256 bits

    # Initialize payload
    payload = KeyImportPayload(key_info=aes_key_info, key=aes_key)

    # Export to binary
    exported_data = payload.export()

    # Check exported data
    assert len(exported_data) == payload.size
    assert exported_data[: aes_key_info.size] == aes_key_info.export()
    assert exported_data[aes_key_info.size :] == aes_key


def test_key_import_payload_with_raw_bytes_no_key_type() -> None:
    """Test KeyImportPayload with raw bytes but no key type."""
    # Create a key without specifying key_type
    key = bytes(32)

    # Should raise an error when converting
    with pytest.raises(SPSDKValueError, match="Key type must be specified"):
        KeyImportPayload.convert_key(key)

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

import pytest

from spsdk.ele.ele_message_hse import EleMessageHse, EleMessageHseBootDataImageSign
from spsdk.exceptions import SPSDKValueError


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

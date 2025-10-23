#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for HSE-specific ELE message implementation."""

import pytest

from spsdk.ele.ele_message_hse import (
    EleMessageHse,
    EleMessageHseBootDataImageSign,

)
from spsdk.exceptions import SPSDKValueError, SPSDKParsingError


# Mock implementation of EleMessageHse for testing
class MockEleMessageHse(EleMessageHse):
    """Mock implementation of EleMessageHse for testing."""

    CMD = 1
    CMD_DESCRIPTOR_FORMAT = "<I"  # LITTLE_ENDIAN + UINT32

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor."""
        return b"\x00\x00\x00\x00"


def test_ele_message_hse_boot_data_image_sign_init_invalid_tag_len():
    """Test initialization with invalid tag length."""
    with pytest.raises(SPSDKValueError, match="Invalid tag length"):
        EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=20)


def test_ele_message_hse_boot_data_image_sign_decode_response_data_tag_len_16():
    """Test decode_response_data with tag_len=16."""
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=16)

    # Mock response data for tag_len=16 (just GMAC)
    gmac = bytes([i for i in range(16)])
    response = gmac

    msg.decode_response_data(response)

    assert msg.initial_vector is None
    assert msg.gmac_value == gmac


def test_ele_message_hse_boot_data_image_sign_decode_response_data_tag_len_28():
    """Test decode_response_data with tag_len=28."""
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=28)

    # Mock response data for tag_len=28 (IV + GMAC)
    iv = bytes([i for i in range(12)])
    gmac = bytes([i for i in range(16)])
    response = iv + gmac

    msg.decode_response_data(response)

    assert msg.initial_vector == iv
    assert msg.gmac_value == gmac


def test_ele_message_hse_boot_data_image_sign_decode_response_data_invalid_tag_len():
    """Test decode_response_data with invalid tag_len."""
    msg = EleMessageHseBootDataImageSign(img_addr=0x12345678, tag_len=16)
    msg.tag_len = 20
    with pytest.raises(SPSDKValueError, match="Unsupported tag length"):
        msg.decode_response_data(b"\x00" * 20)


def test_ele_message_hse_boot_data_image_sign_response_info():
    """Test response_info method of EleMessageHseBootDataImageSign."""
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

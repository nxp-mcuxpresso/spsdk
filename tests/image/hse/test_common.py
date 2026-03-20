#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the HSE common module."""

import pytest

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.hse.common import (
    AuthScheme,
    AuthSchemeEnum,
    CipherAlgo,
    CmacScheme,
    EcdsaSignScheme,
    EddsaSignScheme,
    GmacScheme,
    HashAlgo,
    HmacScheme,
    RsaPkcs1v15Scheme,
    RsaPssSignScheme,
    XcbcMacScheme,
)
from spsdk.utils.config import Config


def test_ecdsa_scheme_init() -> None:
    """Test basic initialization of EcdsaScheme."""
    scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    assert scheme.hash_algo == HashAlgo.SHA256
    assert scheme.AUTH_SCH == AuthSchemeEnum.ECDSA


def test_ecdsa_scheme_invalid_hash() -> None:
    """Test EcdsaScheme validation with NULL hash."""
    with pytest.raises(SPSDKValueError, match="Hash algorithm cannot be NULL for ECDSA"):
        EcdsaSignScheme(hash_algo=HashAlgo.NULL)


def test_ecdsa_scheme_export_parse() -> None:
    """Test exporting and parsing EcdsaScheme."""
    original = EcdsaSignScheme(hash_algo=HashAlgo.SHA384)

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, EcdsaSignScheme)
    assert parsed.hash_algo == original.hash_algo


def test_ecdsa_scheme_config_roundtrip() -> None:
    """Test round-trip from EcdsaScheme to config and back."""
    original = EcdsaSignScheme(hash_algo=HashAlgo.SHA512)

    # Get config
    config_dict = original.get_config()
    config = Config(config_dict["ecdsa"])

    # Load from config
    parsed = EcdsaSignScheme.load_from_config(config)

    # Verify fields match
    assert parsed.hash_algo == original.hash_algo


def test_ecdsa_scheme_string_representation() -> None:
    """Test string representation of EcdsaScheme."""
    scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    str_repr = str(scheme)
    assert "ECDSA" in str_repr
    assert "SHA256" in str_repr


def test_eddsa_scheme_init() -> None:
    """Test basic initialization of EddsaSignScheme."""
    scheme = EddsaSignScheme(
        pre_hash_eddsa=True,
        context_length=16,
        context_addr=0x00500000,
    )

    assert scheme.pre_hash_eddsa is True
    assert scheme.context_length == 16
    assert scheme.context_addr == 0x00500000


def test_eddsa_scheme_invalid_context_length() -> None:
    """Test EddsaSignScheme validation with invalid context length."""
    with pytest.raises(SPSDKValueError, match="context_length must be between 0 and 255"):
        EddsaSignScheme(
            pre_hash_eddsa=False,
            context_length=256,  # Invalid
            context_addr=0x00500000,
        )


def test_eddsa_scheme_missing_context_addr() -> None:
    """Test EddsaSignScheme validation with missing context address."""
    with pytest.raises(
        SPSDKValueError, match="p_context must be provided when context_length is non-zero"
    ):
        EddsaSignScheme(
            pre_hash_eddsa=False,
            context_length=16,
            context_addr=0,  # Missing
        )


def test_eddsa_scheme_export_parse() -> None:
    """Test exporting and parsing EddsaSignScheme."""
    original = EddsaSignScheme(
        pre_hash_eddsa=True,
        context_length=8,
        context_addr=0x00500000,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, EddsaSignScheme)
    assert parsed.pre_hash_eddsa == original.pre_hash_eddsa
    assert parsed.context_length == original.context_length
    assert parsed.context_addr == original.context_addr


def test_rsa_pss_scheme_init() -> None:
    """Test basic initialization of RsaPssSignScheme."""
    scheme = RsaPssSignScheme(
        hash_algo=HashAlgo.SHA256,
        salt_length=32,
    )

    assert scheme.hash_algo == HashAlgo.SHA256
    assert scheme.salt_length == 32


def test_rsa_pss_scheme_invalid_hash() -> None:
    """Test RsaPssSignScheme validation with NULL hash."""
    with pytest.raises(SPSDKValueError, match="Hash algorithm cannot be NULL for RSA PSS"):
        RsaPssSignScheme(hash_algo=HashAlgo.NULL, salt_length=32)


def test_rsa_pss_scheme_invalid_salt_length() -> None:
    """Test RsaPssSignScheme validation with negative salt length."""
    with pytest.raises(SPSDKValueError, match="salt_length must be a non-negative integer"):
        RsaPssSignScheme(hash_algo=HashAlgo.SHA256, salt_length=-1)


def test_rsa_pss_scheme_export_parse() -> None:
    """Test exporting and parsing RsaPssSignScheme."""
    original = RsaPssSignScheme(
        hash_algo=HashAlgo.SHA384,
        salt_length=48,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, RsaPssSignScheme)
    assert parsed.hash_algo == original.hash_algo
    assert parsed.salt_length == original.salt_length


def test_rsa_pkcs1v15_scheme_init() -> None:
    """Test basic initialization of RsaPkcs1v15Scheme."""
    scheme = RsaPkcs1v15Scheme(hash_algo=HashAlgo.SHA256)

    assert scheme.hash_algo == HashAlgo.SHA256


def test_rsa_pkcs1v15_scheme_invalid_hash() -> None:
    """Test RsaPkcs1v15Scheme validation with NULL hash."""
    with pytest.raises(SPSDKValueError, match="Hash algorithm cannot be NULL for RSA PKCS1v15"):
        RsaPkcs1v15Scheme(hash_algo=HashAlgo.NULL)


def test_rsa_pkcs1v15_scheme_export_parse() -> None:
    """Test exporting and parsing RsaPkcs1v15Scheme."""
    original = RsaPkcs1v15Scheme(hash_algo=HashAlgo.SHA512)

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, RsaPkcs1v15Scheme)
    assert parsed.hash_algo == original.hash_algo


def test_cmac_scheme_init() -> None:
    """Test basic initialization of CmacScheme."""
    scheme = CmacScheme(cipher_algo=CipherAlgo.AES)

    assert scheme.cipher_algo == CipherAlgo.AES


def test_cmac_scheme_invalid_cipher() -> None:
    """Test CmacScheme validation with non-AES cipher."""
    with pytest.raises(SPSDKValueError, match="Only AES cipher algorithm is supported for CMAC"):
        CmacScheme(cipher_algo=CipherAlgo.NULL)


def test_cmac_scheme_export_parse() -> None:
    """Test exporting and parsing CmacScheme."""
    original = CmacScheme(cipher_algo=CipherAlgo.AES)

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, CmacScheme)
    assert parsed.cipher_algo == original.cipher_algo


def test_hmac_scheme_init() -> None:
    """Test basic initialization of HmacScheme."""
    scheme = HmacScheme(hash_algo=HashAlgo.SHA256)

    assert scheme.hash_algo == HashAlgo.SHA256


def test_hmac_scheme_export_parse() -> None:
    """Test exporting and parsing HmacScheme."""
    original = HmacScheme(hash_algo=HashAlgo.SHA384)

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, HmacScheme)
    assert parsed.hash_algo == original.hash_algo


def test_gmac_scheme_init() -> None:
    """Test basic initialization of GmacScheme."""
    scheme = GmacScheme(iv_length=12, iv_addr=0x00500000)

    assert scheme.iv_length == 12
    assert scheme.iv_addr == 0x00500000


def test_gmac_scheme_invalid_iv_length() -> None:
    """Test GmacScheme validation with invalid IV length."""
    with pytest.raises(SPSDKValueError, match="iv_length must be a positive integer"):
        GmacScheme(iv_length=0, iv_addr=0x00500000)


def test_gmac_scheme_invalid_iv_addr() -> None:
    """Test GmacScheme validation with invalid IV address."""
    with pytest.raises(SPSDKValueError, match="iv_addr must be a non-zero address"):
        GmacScheme(iv_length=12, iv_addr=0)


def test_gmac_scheme_export_parse() -> None:
    """Test exporting and parsing GmacScheme."""
    original = GmacScheme(iv_length=16, iv_addr=0x00600000)

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type and fields match
    assert isinstance(parsed, GmacScheme)
    assert parsed.iv_length == original.iv_length
    assert parsed.iv_addr == original.iv_addr


def test_xcbc_mac_scheme_init() -> None:
    """Test basic initialization of XcbcMacScheme."""
    scheme = XcbcMacScheme()

    assert scheme.AUTH_SCH == AuthSchemeEnum.XCBC_MAC


def test_xcbc_mac_scheme_export_parse() -> None:
    """Test exporting and parsing XcbcMacScheme."""
    original = XcbcMacScheme()

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = AuthScheme.parse(exported_data)

    # Verify it's the correct type
    assert isinstance(parsed, XcbcMacScheme)


def test_auth_scheme_registry() -> None:
    """Test that all authentication schemes are registered."""
    schemes = AuthScheme.auth_schemes()

    assert AuthSchemeEnum.ECDSA in schemes
    assert AuthSchemeEnum.EDDSA in schemes
    assert AuthSchemeEnum.RSASSA_PSS in schemes
    assert AuthSchemeEnum.RSASSA_PKCS1_V15 in schemes
    assert AuthSchemeEnum.CMAC in schemes
    assert AuthSchemeEnum.HMAC in schemes
    assert AuthSchemeEnum.GMAC in schemes
    assert AuthSchemeEnum.XCBC_MAC in schemes


def test_auth_scheme_parse_invalid_type() -> None:
    """Test parsing with invalid authentication scheme type."""
    # Create data with invalid scheme type (0xFF)
    invalid_data = b"\xff\x00\x00\x00\x00\x00\x00\x00"

    with pytest.raises(SPSDKParsingError, match="Invalid authentication scheme type"):
        AuthScheme.parse(invalid_data)


def test_auth_scheme_parse_insufficient_data() -> None:
    """Test parsing with insufficient data."""
    with pytest.raises(
        SPSDKParsingError, match="Insufficient data for authentication scheme header"
    ):
        AuthScheme.parse(b"\x80\x00")


def test_auth_scheme_is_mac_scheme() -> None:
    """Test is_mac_scheme property."""
    mac_scheme = CmacScheme(cipher_algo=CipherAlgo.AES)
    sig_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    assert mac_scheme.is_mac_scheme is True
    assert mac_scheme.is_signature_scheme is False

    assert sig_scheme.is_mac_scheme is False
    assert sig_scheme.is_signature_scheme is True

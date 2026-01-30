#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the HSE SMR (Secure Memory Region) module."""

import os
from typing import Any, Dict, Type

import pytest
import yaml

from spsdk.apps.utils.common_cli_options import Optional
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.hse.common import KeyCatalogId, KeyHandle
from spsdk.image.hse.smr import (
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
    SmrConfigFlags,
    SmrDecrypt,
    SmrEntry,
    XcbcMacScheme,
    prepare_auth_tag_addr_tuple,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file
from spsdk.utils.schema_validator import CommentedConfig


@pytest.fixture
def family() -> FamilyRevision:
    """Return a family revision for testing."""
    return FamilyRevision("mcxe31b")


@pytest.fixture
def key_handle() -> KeyHandle:
    """Return a key handle for testing."""
    return KeyHandle(KeyCatalogId.NVM, 0, 0)


@pytest.fixture
def smr_decrypt(key_handle: KeyHandle) -> SmrDecrypt:
    """Return SMR decrypt parameters for testing."""
    return SmrDecrypt(
        decrypt_key_handle=key_handle,
        gmac_tag_addr=0x00500000,
        aad_length=64,
        aad_addr=0x00600000,
    )


@pytest.fixture
def smr_entry_config() -> Dict[str, Any]:
    """Return a basic SMR entry configuration for testing."""
    return {
        "family": "mcxe31b",
        "smrSrcAddr": 0x00400000,
        "smrSize": 0x10000,
        "smrDest": 0x20000000,
        "configFlags": "QSPI_FLASH",
        "checkPeriod": 0,
        "authKeyHandle": {
            "catalogId": "NVM",
            "groupIdx": 0,
            "slotIdx": 0,
        },
        "authScheme": {
            "ecdsa": {
                "hashAlgo": "SHA256",
            }
        },
        "instAuthTagAddrs": [0x00700000, 0x00700100],
        "versionOffset": 0,
    }


def test_smr_decrypt_init(key_handle: KeyHandle) -> None:
    """Test basic initialization of SmrDecrypt."""
    smr_decrypt = SmrDecrypt(
        decrypt_key_handle=key_handle,
        gmac_tag_addr=0x00500000,
        aad_length=64,
        aad_addr=0x00600000,
    )

    assert smr_decrypt.decrypt_key_handle == key_handle
    assert smr_decrypt.gmac_tag_addr == 0x00500000
    assert smr_decrypt.aad_length == 64
    assert smr_decrypt.aad_addr == 0x00600000


def test_smr_decrypt_invalid_aad_length(key_handle: KeyHandle) -> None:
    """Test SmrDecrypt validation with invalid AAD length."""
    with pytest.raises(SPSDKValueError, match="aad_length must be 0, 64, or 128 bytes"):
        SmrDecrypt(
            decrypt_key_handle=key_handle,
            gmac_tag_addr=0x00500000,
            aad_length=32,  # Invalid
            aad_addr=0x00600000,
        )


def test_smr_decrypt_missing_aad_addr(key_handle: KeyHandle) -> None:
    """Test SmrDecrypt validation with missing AAD address."""
    with pytest.raises(
        SPSDKValueError, match="aad_addr must be provided when aad_length is non-zero"
    ):
        SmrDecrypt(
            decrypt_key_handle=key_handle,
            gmac_tag_addr=0x00500000,
            aad_length=64,
            aad_addr=0,  # Missing
        )


def test_smr_decrypt_export_parse(key_handle: KeyHandle) -> None:
    """Test exporting and parsing SmrDecrypt."""
    original = SmrDecrypt(
        decrypt_key_handle=key_handle,
        gmac_tag_addr=0x00500000,
        aad_length=128,
        aad_addr=0x00600000,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = SmrDecrypt.parse(exported_data)

    # Verify all fields match
    assert isinstance(parsed.decrypt_key_handle, KeyHandle)
    assert isinstance(original.decrypt_key_handle, KeyHandle)
    assert parsed.decrypt_key_handle.handle == original.decrypt_key_handle.handle
    assert parsed.gmac_tag_addr == original.gmac_tag_addr
    assert parsed.aad_length == original.aad_length
    assert parsed.aad_addr == original.aad_addr


def test_smr_decrypt_parse_insufficient_data() -> None:
    """Test parsing SmrDecrypt with insufficient data."""
    with pytest.raises(SPSDKParsingError, match="Insufficient data for SMR decrypt parameters"):
        SmrDecrypt.parse(b"\x00\x01\x02\x03")


def test_smr_decrypt_get_size() -> None:
    """Test SmrDecrypt.get_size() method."""
    size = SmrDecrypt.get_size()
    # Size should be: 4 (key handle) + 4 (gmac_tag_addr) + 1 (aad_length) + 3 (reserved) + 4 (aad_addr)
    assert size == 16


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


def test_smr_entry_init(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test basic initialization of SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0,
    )

    assert smr_entry.family == family
    assert smr_entry.auth_scheme == auth_scheme
    assert smr_entry.smr_src_addr == 0x00400000
    assert smr_entry.smr_size == 0x10000
    assert smr_entry.smr_dest == 0x20000000
    assert smr_entry.auth_key_handle == key_handle
    assert smr_entry.config_flags == SmrConfigFlags.QSPI_FLASH
    assert smr_entry.check_period == 0
    assert smr_entry.inst_auth_tag_addrs == (0x00700000, 0x00700100)
    assert smr_entry.version_offset == 0


def test_smr_entry_export_parse(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test exporting and parsing SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    original = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0x100,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = SmrEntry.parse(exported_data, family)

    # Verify all fields match
    assert parsed.smr_src_addr == original.smr_src_addr
    assert parsed.smr_size == original.smr_size
    assert parsed.smr_dest == original.smr_dest
    assert parsed.config_flags == original.config_flags
    assert parsed.check_period == original.check_period
    assert parsed.auth_key_handle.handle == original.auth_key_handle.handle
    assert isinstance(parsed.auth_scheme, EcdsaSignScheme)
    assert isinstance(original.auth_scheme, EcdsaSignScheme)
    assert parsed.auth_scheme.hash_algo == original.auth_scheme.hash_algo
    assert parsed.inst_auth_tag_addrs == original.inst_auth_tag_addrs
    assert parsed.version_offset == original.version_offset


def test_smr_entry_with_decryption(
    family: FamilyRevision, key_handle: KeyHandle, smr_decrypt: SmrDecrypt
) -> None:
    """Test SmrEntry with decryption parameters."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    original = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
        smr_decrypt=smr_decrypt,
    )

    # Export to binary
    exported_data = original.export()

    # Parse from binary
    parsed = SmrEntry.parse(exported_data, family)

    # Verify decryption parameters
    assert isinstance(smr_decrypt.decrypt_key_handle, KeyHandle)
    assert isinstance(parsed.smr_decrypt.decrypt_key_handle, KeyHandle)
    assert parsed.smr_decrypt.decrypt_key_handle.handle == smr_decrypt.decrypt_key_handle.handle
    assert parsed.smr_decrypt.gmac_tag_addr == smr_decrypt.gmac_tag_addr
    assert parsed.smr_decrypt.aad_length == smr_decrypt.aad_length
    assert parsed.smr_decrypt.aad_addr == smr_decrypt.aad_addr


def test_smr_entry_parse_insufficient_data() -> None:
    """Test parsing SmrEntry with insufficient data."""
    family = FamilyRevision("mcxe31b")

    with pytest.raises(SPSDKParsingError, match="Insufficient data for SMR entry"):
        SmrEntry.parse(b"\x00\x01\x02\x03", family)


def test_smr_entry_parse_invalid_config_flags(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with invalid configuration flags."""
    # Create minimal valid data with invalid config flags (0xFF)
    data = b"\x00" * 12  # smr_src_addr, smr_size, smr_dest
    data += b"\xff"  # Invalid config_flags
    data += b"\x00" * 3  # reserved
    data += b"\x00" * 4  # check_period
    data += b"\x00" * 100  # Rest of the data

    with pytest.raises(SPSDKParsingError, match="Invalid SMR configuration flags"):
        SmrEntry.parse(data, family)


def test_smr_entry_load_from_config(smr_entry_config: dict) -> None:
    """Test loading SmrEntry from configuration."""
    config = Config(smr_entry_config)
    smr_entry = SmrEntry.load_from_config(config)

    assert smr_entry.family.name == "mcxe31b"
    assert smr_entry.smr_src_addr == 0x00400000
    assert smr_entry.smr_size == 0x10000
    assert smr_entry.smr_dest == 0x20000000
    assert smr_entry.config_flags == SmrConfigFlags.QSPI_FLASH
    assert smr_entry.check_period == 0
    assert smr_entry.auth_key_handle.catalog_id == KeyCatalogId.NVM
    assert smr_entry.auth_key_handle.group_idx == 0
    assert smr_entry.auth_key_handle.slot_idx == 0
    assert isinstance(smr_entry.auth_scheme, EcdsaSignScheme)
    assert smr_entry.inst_auth_tag_addrs == (0x00700000, 0x00700100)
    assert smr_entry.version_offset == 0


def test_smr_entry_load_from_config_with_decryption() -> None:
    """Test loading SmrEntry from configuration with decryption."""
    config_dict = {
        "family": "mcxe31b",
        "smrSrcAddr": 0x00400000,
        "smrSize": 0x10000,
        "smrDest": 0x20000000,
        "configFlags": "QSPI_FLASH",
        "checkPeriod": 0,
        "authKeyHandle": {
            "catalogId": "NVM",
            "groupIdx": 0,
            "slotIdx": 0,
        },
        "authScheme": {
            "ecdsa": {
                "hashAlgo": "SHA256",
            }
        },
        "smrDecrypt": {
            "decryptKeyHandle": {
                "catalogId": "NVM",
                "groupIdx": 1,
                "slotIdx": 0,
            },
            "gmacTagAddr": 0x00500000,
            "aadLength": 64,
            "aadAddr": 0x00600000,
        },
        "versionOffset": 0x100,
    }

    config = Config(config_dict)
    smr_entry = SmrEntry.load_from_config(config)

    assert smr_entry.smr_decrypt is not None
    assert isinstance(smr_entry.smr_decrypt.decrypt_key_handle, KeyHandle)
    assert smr_entry.smr_decrypt.decrypt_key_handle.catalog_id == KeyCatalogId.NVM
    assert smr_entry.smr_decrypt.decrypt_key_handle.group_idx == 1
    assert smr_entry.smr_decrypt.gmac_tag_addr == 0x00500000
    assert smr_entry.smr_decrypt.aad_length == 64
    assert smr_entry.smr_decrypt.aad_addr == 0x00600000
    assert smr_entry.version_offset == 0x100


def test_smr_entry_load_from_config_invalid_auth_scheme() -> None:
    """Test loading SmrEntry with invalid authentication scheme."""
    config_dict = {
        "family": "mcxe31b",
        "smrSrcAddr": 0x00400000,
        "smrSize": 0x10000,
        "smrDest": 0x20000000,
        "configFlags": "QSPI_FLASH",
        "checkPeriod": 0,
        "authKeyHandle": {
            "catalogId": "NVM",
            "groupIdx": 0,
            "slotIdx": 0,
        },
        "authScheme": {
            "invalid_scheme": {
                "someParam": "value",
            }
        },
    }

    config = Config(config_dict)

    with pytest.raises(SPSDKValueError, match="No valid authentication scheme found"):
        SmrEntry.load_from_config(config)


def test_smr_entry_get_config(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test getting configuration from SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0x100,
    )

    config = smr_entry.get_config()

    assert config["family"] == "mcxe31b"
    assert config["smrSrcAddr"] == "0x00400000"
    assert config["smrSize"] == "0x00010000"
    assert config["smrDest"] == "0x20000000"
    assert config["configFlags"] == "QSPI_FLASH"
    assert config["checkPeriod"] == 0
    assert config["authKeyHandle"]["catalogId"] == "NVM"
    assert config["authKeyHandle"]["groupIdx"] == 0
    assert config["authKeyHandle"]["slotIdx"] == 0
    assert "ecdsa" in config["authScheme"]
    assert config["authScheme"]["ecdsa"]["hashAlgo"] == "SHA256"
    assert config["instAuthTagAddrs"] == ["0x00700000", "0x00700100"]
    assert config["versionOffset"] == "0x00000100"


def test_smr_entry_config_roundtrip(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test round-trip from SmrEntry to config and back."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    original = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0x100,
    )

    # Get config
    config_dict = original.get_config()
    config = Config(config_dict)

    # Load from config
    parsed = SmrEntry.load_from_config(config)

    # Verify fields match
    assert parsed.smr_src_addr == original.smr_src_addr
    assert parsed.smr_size == original.smr_size
    assert parsed.smr_dest == original.smr_dest
    assert parsed.config_flags == original.config_flags
    assert parsed.check_period == original.check_period
    assert parsed.auth_key_handle.handle == original.auth_key_handle.handle
    assert isinstance(parsed.auth_scheme, EcdsaSignScheme)
    assert isinstance(original.auth_scheme, EcdsaSignScheme)
    assert parsed.auth_scheme.hash_algo == original.auth_scheme.hash_algo
    assert parsed.inst_auth_tag_addrs == original.inst_auth_tag_addrs
    assert parsed.version_offset == original.version_offset


def test_smr_entry_string_representation(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test string representation of SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=100,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0x100,
    )

    str_repr = str(smr_entry)

    assert "HSE Secure Memory Region Entry:" in str_repr
    assert "Source Address: 0x00400000" in str_repr
    assert "Size: 0x00010000" in str_repr
    assert "Destination Address: 0x20000000" in str_repr
    assert "QSPI_FLASH" in str_repr
    assert "Periodic Verification: Every 10000ms" in str_repr
    assert "ECDSA" in str_repr
    assert "Installation Auth Tag[0]: 0x00700000" in str_repr
    assert "Installation Auth Tag[1]: 0x00700100" in str_repr
    assert "Version Offset: 0x00000100" in str_repr


def test_smr_entry_string_representation_no_dest(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test string representation of SmrEntry without destination."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0,  # No destination
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    str_repr = str(smr_entry)

    assert "Destination Address: Not used (in-place verification)" in str_repr
    assert "Periodic Verification: Disabled" in str_repr
    assert "Version Offset: Not used" in str_repr


def test_smr_entry_string_representation_with_decryption(
    family: FamilyRevision, key_handle: KeyHandle, smr_decrypt: SmrDecrypt
) -> None:
    """Test string representation of SmrEntry with decryption."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
        smr_decrypt=smr_decrypt,
    )

    str_repr = str(smr_entry)

    assert "SMR Decryption: Enabled" in str_repr
    assert "GMAC Tag Address: 0x00500000" in str_repr
    assert "AAD Length: 64 bytes" in str_repr
    assert "AAD Address: 0x00600000" in str_repr


def test_smr_entry_verify_valid(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test verification of valid SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,  # Aligned to 16 bytes
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0x100,  # Aligned to 4 bytes
    )

    verifier = smr_entry.verify()

    # Should have no errors
    assert verifier.has_errors is False


def test_smr_entry_verify_invalid_src_addr(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test verification with invalid source address."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0,  # Invalid
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    verifier = smr_entry.verify()

    # Should have error about source address
    assert verifier.has_errors is True


def test_smr_entry_verify_invalid_size(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test verification with invalid size."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0,  # Invalid
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    verifier = smr_entry.verify()

    # Should have error about size
    assert verifier.has_errors is True


def test_smr_entry_verify_misaligned_dest(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test verification with misaligned destination address."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000001,  # Not aligned to 16 bytes
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    verifier = smr_entry.verify()

    # Should have error about alignment
    assert verifier.has_errors is True


def test_smr_entry_verify_invalid_check_period(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test verification with invalid check period."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0xFFFFFFFF,  # Invalid
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    verifier = smr_entry.verify()

    # Should have error about check period
    assert verifier.has_errors is True


def test_smr_entry_verify_check_period_without_dest(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test verification with check period but no destination."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0,  # No destination
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=100,  # Non-zero check period
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    verifier = smr_entry.verify()

    # Should have error about check period configuration
    assert verifier.has_errors is True


def test_smr_entry_verify_invalid_version_offset(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test verification with invalid version offset."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0x20000,  # Out of range
    )

    verifier = smr_entry.verify()

    # Should have error about version offset
    assert verifier.has_errors is True


def test_smr_entry_verify_misaligned_version_offset(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test verification with misaligned version offset."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0x101,  # Not aligned to 4 bytes
    )

    verifier = smr_entry.verify()

    # Should have error about version offset alignment
    assert verifier.has_errors is True


def test_smr_entry_template(family: FamilyRevision, tmp_path: str) -> None:
    """Test generating a template configuration."""
    template = SmrEntry.get_config_template(family)

    # Verify template is valid YAML
    template_dict = yaml.safe_load(template)

    # Check required fields are present
    assert "family" in template_dict
    assert "smrSrcAddr" in template_dict
    assert "smrSize" in template_dict
    assert "authKeyHandle" in template_dict
    assert "authScheme" in template_dict

    # Verify all possible auth schemes are present in the template
    auth_scheme = template_dict["authScheme"]
    possible_schemes = [
        "ecdsa",
        "eddsa",
        "rsassa_pss",
        "rsassa_pkcs1_v15",
        "cmac",
        "gmac",
        "xcbc_mac",
        "hmac",
    ]

    for scheme in possible_schemes:
        assert scheme in auth_scheme, f"Auth scheme '{scheme}' should be present in template"

    # create a modified version with only one auth scheme active (ECDSA)
    template_dict["authScheme"] = {"ecdsa": {"hashAlgo": "SHA256"}}
    # Save template to file
    yaml_data = CommentedConfig(
        main_title=("SME entry configuration:"),
        schemas=SmrEntry.get_validation_schemas(family),
    ).get_config(template_dict)
    template_file = os.path.join(tmp_path, "smr_entry_template.yaml")
    write_file(yaml_data, template_file)

    # Load template as config
    config = Config.create_from_file(template_file)

    # Verify schema validation
    schemas = SmrEntry.get_validation_schemas(family)
    config.check(schemas)


def test_smr_entry_with_different_auth_schemes(
    family: FamilyRevision, key_handle: KeyHandle
) -> None:
    """Test SmrEntry with different authentication schemes."""
    auth_schemes = [
        EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
        EddsaSignScheme(pre_hash_eddsa=False, context_length=0, context_addr=0),
        RsaPssSignScheme(hash_algo=HashAlgo.SHA384, salt_length=48),
        RsaPkcs1v15Scheme(hash_algo=HashAlgo.SHA512),
        CmacScheme(cipher_algo=CipherAlgo.AES),
        HmacScheme(hash_algo=HashAlgo.SHA256),
        GmacScheme(iv_length=12, iv_addr=0x00500000),
        XcbcMacScheme(),
    ]

    for auth_scheme in auth_schemes:
        smr_entry = SmrEntry(
            family=family,
            auth_scheme=auth_scheme,
            smr_src_addr=0x00400000,
            smr_size=0x10000,
            smr_dest=0x20000000,
            auth_key_handle=key_handle,
            config_flags=SmrConfigFlags.QSPI_FLASH,
            check_period=0,
            inst_auth_tag=(0, 0),
            version_offset=0,
        )

        # Export and parse
        exported_data = smr_entry.export()
        parsed = SmrEntry.parse(exported_data, family)

        # Verify auth scheme type matches
        assert type(parsed.auth_scheme) is type(auth_scheme)


def test_smr_entry_parse_missing_key_handle(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with missing key handle data."""
    # Create data with basic fields but not enough for key handle
    data = b"\x00" * 20  # Basic fields only

    with pytest.raises(SPSDKParsingError, match="Invalid key handle data length"):
        SmrEntry.parse(data, family)


def test_smr_entry_parse_missing_auth_scheme(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with missing authentication scheme data."""
    # Create data with basic fields and key handle but not auth scheme
    data = b"\x00" * 24  # Basic fields + key handle

    with pytest.raises(SPSDKParsingError, match="Insufficient data for authentication scheme"):
        SmrEntry.parse(data, family)


def test_smr_entry_parse_missing_inst_auth_tag(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with missing installation auth tag data."""
    # Create data with basic fields, key handle, and auth scheme but not inst_auth_tag
    data = b"\x00" * 20  # Basic fields
    data += b"\x00" * 4  # Key handle
    data += b"\x80\x00\x00\x00"  # Auth scheme header (ECDSA)
    data += b"\x04\x00\x00\x00"  # Auth scheme data (SHA256)
    # Missing inst_auth_tag

    with pytest.raises(
        SPSDKParsingError, match="Insufficient data for installation authentication tags"
    ):
        SmrEntry.parse(data, family)


def test_smr_entry_parse_missing_smr_decrypt(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with missing SMR decrypt data."""
    # Create data with all fields except SMR decrypt
    data = b"\x00" * 20  # Basic fields
    data += b"\x00" * 4  # Key handle
    data += b"\x80\x00\x00\x00"  # Auth scheme header (ECDSA)
    data += b"\x04\x00\x00\x00"  # Auth scheme data (SHA256)
    data += b"\x00" * 8  # inst_auth_tag
    # Missing smr_decrypt

    with pytest.raises(SPSDKParsingError, match="Insufficient data for SMR decrypt parameters"):
        SmrEntry.parse(data, family)


def test_smr_entry_parse_missing_version_offset(family: FamilyRevision) -> None:
    """Test parsing SmrEntry with missing version offset data."""
    # Create data with all fields except version offset
    data = b"\x00" * 20  # Basic fields
    data += b"\x00" * 4  # Key handle
    data += b"\x80\x00\x00\x00"  # Auth scheme header (ECDSA)
    data += b"\x04\x00\x00\x00"  # Auth scheme data (SHA256)
    data += b"\x00" * 8  # inst_auth_tag
    data += b"\x00" * 16  # smr_decrypt
    # Missing version_offset

    with pytest.raises(SPSDKParsingError, match="Insufficient data for version offset"):
        SmrEntry.parse(data, family)


def test_smr_entry_with_all_config_flags(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test SmrEntry with different configuration flags."""
    config_flags_list = [
        SmrConfigFlags.QSPI_FLASH,
        SmrConfigFlags.SD_FLASH,
        SmrConfigFlags.MMC_FLASH,
        SmrConfigFlags.INSTALL_AUTH,
        SmrConfigFlags.AUTH_AAD,
    ]

    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    for config_flag in config_flags_list:
        smr_entry = SmrEntry(
            family=family,
            auth_scheme=auth_scheme,
            smr_src_addr=0x00400000,
            smr_size=0x10000,
            smr_dest=0x20000000,
            auth_key_handle=key_handle,
            config_flags=config_flag,
            check_period=0,
            inst_auth_tag=(0, 0),
            version_offset=0,
        )

        # Export and parse
        exported_data = smr_entry.export()
        parsed = SmrEntry.parse(exported_data, family)

        # Verify config flag matches
        assert parsed.config_flags == config_flag


def test_smr_entry_repr(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test __repr__ method of SmrEntry."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=100,
        inst_auth_tag=(0x00700000, 0x00700100),
        version_offset=0x100,
    )

    repr_str = repr(smr_entry)

    assert "SmrEntry(" in repr_str
    assert "family=" in repr_str
    assert "smr_src_addr=0x00400000" in repr_str
    assert "smr_size=0x00010000" in repr_str
    assert "smr_dest=0x20000000" in repr_str
    assert "QSPI_FLASH" in repr_str
    assert "check_period=100" in repr_str
    assert "ECDSA" in repr_str
    assert "version_offset=256" in repr_str


def test_smr_entry_binary_size_consistency(family: FamilyRevision, key_handle: KeyHandle) -> None:
    """Test that exported binary size is consistent."""
    auth_scheme = EcdsaSignScheme(hash_algo=HashAlgo.SHA256)

    smr_entry = SmrEntry(
        family=family,
        auth_scheme=auth_scheme,
        smr_src_addr=0x00400000,
        smr_size=0x10000,
        smr_dest=0x20000000,
        auth_key_handle=key_handle,
        config_flags=SmrConfigFlags.QSPI_FLASH,
        check_period=0,
        inst_auth_tag=(0, 0),
        version_offset=0,
    )

    exported_data = smr_entry.export()

    # Expected size:
    # 20 bytes (basic fields)
    # 4 bytes (key handle)
    # 8 bytes (auth scheme: 4 header + 4 ECDSA data)
    # 8 bytes (inst_auth_tag)
    # 16 bytes (smr_decrypt)
    # 4 bytes (version_offset)
    # Total: 60 bytes
    expected_size = 60

    assert len(exported_data) == expected_size


def test_auth_scheme_size_methods() -> None:
    """Test size methods for all authentication schemes."""
    schemes = [
        EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
        EddsaSignScheme(pre_hash_eddsa=False, context_length=0, context_addr=0),
        RsaPssSignScheme(hash_algo=HashAlgo.SHA384, salt_length=48),
        RsaPkcs1v15Scheme(hash_algo=HashAlgo.SHA512),
        CmacScheme(cipher_algo=CipherAlgo.AES),
        HmacScheme(hash_algo=HashAlgo.SHA256),
        GmacScheme(iv_length=12, iv_addr=0x00500000),
        XcbcMacScheme(),
    ]

    for scheme in schemes:
        # Instance size should match class size
        assert scheme.size == scheme.get_size()

        # Exported data should match size
        exported = scheme.export()
        assert len(exported) == scheme.size


def test_smr_entry_validation_schemas(family: FamilyRevision) -> None:
    """Test that validation schemas are properly defined."""
    schemas = SmrEntry.get_validation_schemas(family)

    # Should have at least 2 schemas (family + smr)
    assert len(schemas) >= 2

    # First schema should be family schema
    assert "family" in schemas[0]["properties"]

    # Second schema should be SMR schema
    assert "smrSrcAddr" in schemas[1]["properties"]
    assert "smrSize" in schemas[1]["properties"]
    assert "authKeyHandle" in schemas[1]["properties"]
    assert "authScheme" in schemas[1]["properties"]


@pytest.mark.parametrize(
    "auth_scheme, auth_tag_addr, auth_tag_length, expected_result, expected_exception",
    [
        # ECDSA with two addresses
        (
            EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
            (0x00100000, 0x00200000),
            (32, 32),
            (0x00100000, 0x00200000),
            None,
        ),
        # ECDSA with one address (second calculated)
        (
            EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
            (0x00100000,),
            (64,),
            (0x00100000, 0x00100040),  # 0x00100000 + 64
            None,
        ),
        # EdDSA with two addresses
        (
            EddsaSignScheme(pre_hash_eddsa=False, context_length=0, context_addr=0),
            (0x00300000, 0x00400000),
            (64, 64),
            (0x00300000, 0x00400000),
            None,
        ),
        # EdDSA with one address (second calculated)
        (
            EddsaSignScheme(pre_hash_eddsa=True, context_length=16, context_addr=0x00500000),
            (0x00600000,),
            (128,),
            (0x00600000, 0x00600080),  # 0x00600000 + 128
            None,
        ),
        # RSA PSS with one address
        (
            RsaPssSignScheme(hash_algo=HashAlgo.SHA256, salt_length=32),
            (0x00700000,),
            (256,),
            (0x00700000, 0),
            None,
        ),
        # RSA PKCS1v15 with one address
        (
            RsaPkcs1v15Scheme(hash_algo=HashAlgo.SHA384),
            (0x00800000,),
            (512,),
            (0x00800000, 0),
            None,
        ),
        # CMAC with one address
        (
            CmacScheme(cipher_algo=CipherAlgo.AES),
            (0x00900000,),
            (16,),
            (0x00900000, 0),
            None,
        ),
        # HMAC with one address
        (
            HmacScheme(hash_algo=HashAlgo.SHA256),
            (0x00A00000,),
            (32,),
            (0x00A00000, 0),
            None,
        ),
        # GMAC with one address
        (
            GmacScheme(iv_length=12, iv_addr=0x00500000),
            (0x00B00000,),
            (16,),
            (0x00B00000, 0),
            None,
        ),
        # XCBC-MAC with one address
        (
            XcbcMacScheme(),
            (0x00C00000,),
            (16,),
            (0x00C00000, 0),
            None,
        ),
        # Error cases
        # Empty auth_tag_addr
        (
            EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
            (),
            (32,),
            None,
            SPSDKValueError,
        ),
        # Empty auth_tag_length
        (
            EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
            (0x00100000,),
            (),
            None,
            SPSDKValueError,
        ),
        # ECDSA with too many addresses
        (
            EcdsaSignScheme(hash_algo=HashAlgo.SHA256),
            (0x00100000, 0x00200000, 0x00300000),
            (32, 32, 32),
            None,
            SPSDKError,
        ),
        # RSA with too many addresses
        (
            RsaPssSignScheme(hash_algo=HashAlgo.SHA256, salt_length=32),
            (0x00100000, 0x00200000),
            (256, 256),
            None,
            SPSDKError,
        ),
    ],
)
def test_prepare_auth_tag_addr_tuple(
    auth_scheme: AuthScheme,
    auth_tag_addr: tuple,
    auth_tag_length: tuple,
    expected_result: Optional[tuple],
    expected_exception: Optional[Type[Exception]],
) -> None:
    """Test prepare_auth_tag_addr_tuple with various authentication schemes and parameters.

    This test covers all supported authentication schemes (ECDSA, EdDSA, RSA variants,
    MAC schemes) with valid inputs, as well as error cases with invalid parameters.
    """
    if expected_exception:
        with pytest.raises(expected_exception):
            prepare_auth_tag_addr_tuple(auth_scheme, auth_tag_addr, auth_tag_length)
    else:
        result = prepare_auth_tag_addr_tuple(auth_scheme, auth_tag_addr, auth_tag_length)
        assert result == expected_result

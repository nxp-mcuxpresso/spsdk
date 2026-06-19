#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for AHAB blob module."""

import struct
from pathlib import Path

import pytest

from spsdk.ele.ele_constants import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_blob import AhabBlob, AhabBlobOffline
from spsdk.image.ahab.ahab_data import DebugEnable, KeyblobLifeCycle
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

VALID_KEYBLOB_128 = (
    b"\x00H\x00\x81\x01\x10\x03\x00\xfe\xda\x04v\xb3s\xcb\x8bE"
    + b"\xdc\x06(I\x8a\xd3\xe0\xf0\x86\xbf\xdc\xea\xeds-H\xb8"
    + b"\x94v\xe7\xc7\xae\x07\xca\xce;\x93Z\xcd\x0ff\x0c\xec{"
    + b'\xa6KMg\x97\x0e\xb3](]b"\xdd`\x16\xdb\xe5\x94*\x01\xea'
)

FAMILY = FamilyRevision("mimxrt1189")
CMK = bytes(range(32))
SRKH0 = bytes(64)
SRKH1 = bytes(64)
DEK_256 = bytes(range(32))
BLOB_KEY_256 = bytes(range(32, 64))


# ---------------------------------------------------------------------------
# AhabBlob basic construction and properties
# ---------------------------------------------------------------------------


def test_ahab_blob_default_init() -> None:
    """Test AhabBlob initializes with default parameters."""
    blob = AhabBlob()
    assert blob.flags == AhabBlob.FLAGS_DFLT
    assert blob.mode == 0
    assert blob.algorithm == KeyBlobEncryptionAlgorithm.AES_CBC
    assert blob._size == 0
    assert blob.dek_keyblob == b""


def test_ahab_blob_custom_init() -> None:
    """Test AhabBlob initializes correctly with custom parameters."""
    dek = bytes(16)
    keyblob = bytes(48 + 16)
    blob = AhabBlob(
        flags=0x81,
        size=128,
        algorithm=KeyBlobEncryptionAlgorithm.AES_CBC,
        mode=0,
        dek=dek,
        dek_keyblob=keyblob,
        key_identifier=0xABCD,
    )
    assert blob.flags == 0x81
    assert blob._size == 128
    assert blob.dek == dek
    assert blob.dek_keyblob == keyblob
    assert blob.key_identifier == 0xABCD


def test_ahab_blob_repr() -> None:
    """Test AhabBlob __repr__ returns expected string."""
    blob = AhabBlob()
    assert repr(blob) == "AHAB Blob"


def test_ahab_blob_str() -> None:
    """Test AhabBlob __str__ includes key fields."""
    blob = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(48 + 16))
    text = str(blob)
    assert "AHAB Blob" in text
    assert "Algorithm" in text
    assert "Key Size" in text


def test_ahab_blob_str_no_keyblob() -> None:
    """Test AhabBlob __str__ when dek_keyblob is empty."""
    blob = AhabBlob()
    text = str(blob)
    assert "N/A" in text


def test_ahab_blob_equality() -> None:
    """Test AhabBlob equality comparison."""
    blob1 = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(48 + 16))
    blob2 = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(48 + 16))
    assert blob1 == blob2


def test_ahab_blob_inequality() -> None:
    """Test AhabBlob inequality when attributes differ."""
    blob1 = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(48 + 16))
    blob2 = AhabBlob(flags=0x01, size=128, dek_keyblob=bytes(48 + 16))
    assert blob1 != blob2
    assert blob1 != "not a blob"


def test_ahab_blob_len() -> None:
    """Test AhabBlob __len__ returns the correct length."""
    blob = AhabBlob(size=128, dek_keyblob=bytes(48 + 16))
    assert len(blob) == blob.length


def test_ahab_blob_compute_keyblob_size() -> None:
    """Test AhabBlob.compute_keyblob_size returns correct size."""
    assert AhabBlob.compute_keyblob_size(128) == 64
    assert AhabBlob.compute_keyblob_size(192) == 72
    assert AhabBlob.compute_keyblob_size(256) == 80


# ---------------------------------------------------------------------------
# AhabBlob export / parse round-trip
# ---------------------------------------------------------------------------


def test_ahab_blob_export_roundtrip() -> None:
    """Test that export → parse is a lossless round-trip."""
    keyblob = bytes(48 + 16)
    blob = AhabBlob(flags=0x80, size=128, dek_keyblob=keyblob)
    data = blob.export()
    parsed = AhabBlob.parse(data)
    assert parsed.flags == blob.flags
    assert parsed._size == blob._size
    assert parsed.dek_keyblob == blob.dek_keyblob
    assert parsed.export() == data


def test_ahab_blob_parse_known_binary() -> None:
    """Test parsing a known-good binary blob (128-bit, AES-CBC)."""
    blob = AhabBlob.parse(VALID_KEYBLOB_128)
    assert blob.algorithm == KeyBlobEncryptionAlgorithm.AES_CBC
    assert blob.mode == 0
    assert blob.flags == 1
    assert blob.export() == VALID_KEYBLOB_128


def test_ahab_blob_export_header() -> None:
    """Test that export_header produces a valid 8-byte header."""
    blob = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(48 + 16))
    header = blob.export_header()
    assert len(header) == AhabBlob.fixed_length()
    assert header[3] == AhabBlob.TAG  # tag byte


# ---------------------------------------------------------------------------
# AhabBlob verify
# ---------------------------------------------------------------------------


def test_ahab_blob_verify_success() -> None:
    """Test AhabBlob.verify() passes with valid DEK and keyblob."""
    blob = AhabBlob(
        flags=0x80,
        size=128,
        dek=bytes(16),
        dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)),
    )
    v = blob.verify()
    assert not v.has_errors


def test_ahab_blob_verify_no_dek() -> None:
    """Test AhabBlob.verify() warns when DEK is not provided."""
    blob = AhabBlob(
        flags=0x80,
        size=128,
        dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)),
    )
    v = blob.verify()
    # Should have a warning about missing DEK but no hard errors
    assert not v.has_errors


def test_ahab_blob_verify_wrong_dek_size() -> None:
    """Test AhabBlob.verify() errors when DEK size doesn't match key size."""
    blob = AhabBlob(
        flags=0x80,
        size=128,
        dek=bytes(32),  # 256-bit key for 128-bit size → mismatch
        dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)),
    )
    v = blob.verify()
    assert v.has_errors


def test_ahab_blob_verify_no_keyblob() -> None:
    """Test AhabBlob.verify() errors when dek_keyblob is empty."""
    blob = AhabBlob(flags=0x80, size=128)
    v = blob.verify()
    assert v.has_errors


def test_ahab_blob_verify_wrong_keyblob_size() -> None:
    """Test AhabBlob.verify() errors when keyblob size is wrong."""
    blob = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(10))
    v = blob.verify()
    assert v.has_errors


# ---------------------------------------------------------------------------
# AhabBlob get_config / load_from_config
# ---------------------------------------------------------------------------


def test_ahab_blob_get_config(tmp_path: Path) -> None:
    """Test AhabBlob.get_config() produces a valid Config object and writes file."""
    blob = AhabBlob(flags=0x80, size=128, dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)))
    cfg = blob.get_config(data_path=str(tmp_path), index=0)
    assert cfg["dek_key_size"] == 128
    assert cfg["dek_key"] == "N/A"
    assert "dek_keyblob" in cfg
    assert (tmp_path / "container0_dek_keyblob.bin").exists()


def test_ahab_blob_get_config_indexed(tmp_path: Path) -> None:
    """Test AhabBlob.get_config() uses the index in the filename."""
    blob = AhabBlob(flags=0x80, size=256, dek_keyblob=bytes(AhabBlob.compute_keyblob_size(256)))
    blob.get_config(data_path=str(tmp_path), index=3)
    assert (tmp_path / "container3_dek_keyblob.bin").exists()


def test_ahab_blob_load_from_config_without_keyblob() -> None:
    """Test AhabBlob.load_from_config() creates placeholder when keyblob absent."""
    cfg = Config({"dek_key_size": 128, "dek_key": bytes(16).hex()})
    blob = AhabBlob.load_from_config(cfg)
    assert blob._size == 128
    assert blob.flags == AhabBlob.FLAGS_DEK
    assert len(blob.dek_keyblob) == 48 + 16


def test_ahab_blob_load_from_config_with_keyblob(tmp_path: Path) -> None:
    """Test AhabBlob.load_from_config() parses existing keyblob file."""
    # Write a valid keyblob file
    keyblob_path = tmp_path / "keyblob.bin"
    keyblob_path.write_bytes(VALID_KEYBLOB_128)

    cfg = Config(
        {
            "dek_key_size": 128,
            "dek_key": bytes(16).hex(),
            "dek_keyblob": str(keyblob_path),
        }
    )
    blob = AhabBlob.load_from_config(cfg)
    assert blob._size == 128
    assert blob.algorithm == KeyBlobEncryptionAlgorithm.AES_CBC


# ---------------------------------------------------------------------------
# AhabBlob encrypt_data / decrypt_data
# ---------------------------------------------------------------------------


def test_ahab_blob_encrypt_decrypt_aes_cbc() -> None:
    """Test AES-CBC encryption and decryption round-trip via AhabBlob."""
    dek = bytes(16)
    blob = AhabBlob(size=128, dek=dek, dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)))
    iv = bytes(16)
    plaintext = bytes(32)
    encrypted = blob.encrypt_data(iv, plaintext)
    decrypted = blob.decrypt_data(iv, encrypted)
    assert decrypted == plaintext


def test_ahab_blob_encrypt_decrypt_sm4_cbc() -> None:
    """Test SM4-CBC encryption and decryption round-trip via AhabBlob."""
    dek = bytes(16)
    blob = AhabBlob(
        size=128,
        dek=dek,
        dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)),
        algorithm=KeyBlobEncryptionAlgorithm.SM4_CBC,
    )
    iv = bytes(16)
    plaintext = bytes(32)
    encrypted = blob.encrypt_data(iv, plaintext)
    decrypted = blob.decrypt_data(iv, encrypted)
    assert decrypted == plaintext


def test_ahab_blob_encrypt_no_dek_raises() -> None:
    """Test encrypt_data raises SPSDKError when no DEK is set."""
    blob = AhabBlob(size=128)
    with pytest.raises(SPSDKError, match="DEK"):
        blob.encrypt_data(bytes(16), bytes(32))


def test_ahab_blob_decrypt_no_dek_raises() -> None:
    """Test decrypt_data raises SPSDKError when no DEK is set."""
    blob = AhabBlob(size=128)
    with pytest.raises(SPSDKError, match="DEK"):
        blob.decrypt_data(bytes(16), bytes(32))


def test_ahab_blob_encrypt_unsupported_algorithm_raises() -> None:
    """Test encrypt_data raises SPSDKError for unsupported algorithm (AES_CTR)."""
    blob = AhabBlob(size=128, dek=bytes(16), dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)))
    blob.algorithm = KeyBlobEncryptionAlgorithm.AES_CTR
    with pytest.raises(SPSDKError, match="Unsupported"):
        blob.encrypt_data(bytes(16), bytes(32))


def test_ahab_blob_decrypt_unsupported_algorithm_raises() -> None:
    """Test decrypt_data raises SPSDKError for unsupported algorithm (AES_CTR)."""
    blob = AhabBlob(size=128, dek=bytes(16), dek_keyblob=bytes(AhabBlob.compute_keyblob_size(128)))
    blob.algorithm = KeyBlobEncryptionAlgorithm.AES_CTR
    with pytest.raises(SPSDKError, match="Unsupported"):
        blob.decrypt_data(bytes(16), bytes(32))


# ---------------------------------------------------------------------------
# AhabBlobOffline construction
# ---------------------------------------------------------------------------


def test_ahab_blob_offline_init() -> None:
    """Test AhabBlobOffline initializes correctly with required params."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
    )
    assert blob.family == FAMILY
    assert blob.customer_master_key == CMK
    assert blob._size == 256


def test_ahab_blob_offline_key_identifier_too_large_raises() -> None:
    """Test AhabBlobOffline raises SPSDKValueError for oversized key_identifier."""
    with pytest.raises(SPSDKValueError, match="4 bytes"):
        AhabBlobOffline(family=FAMILY, key_identifier=0x1_0000_0000)


def test_ahab_blob_offline_default_srkh() -> None:
    """Test AhabBlobOffline defaults srkh0/srkh1 to 64 zero bytes."""
    blob = AhabBlobOffline(family=FAMILY, customer_master_key=CMK)
    assert blob.srkh0 == bytes(64)
    assert blob.srkh1 == bytes(64)


# ---------------------------------------------------------------------------
# AhabBlobOffline key derivation methods
# ---------------------------------------------------------------------------


def test_ahab_blob_offline_derive_master_key() -> None:
    """Test derive_master_key returns 32 bytes deterministically."""
    blob = AhabBlobOffline(
        family=FAMILY,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
    )
    mk1 = blob.derive_master_key()
    mk2 = blob.derive_master_key()
    assert len(mk1) == 32
    assert mk1 == mk2


def test_ahab_blob_offline_derive_master_key_no_cmk_raises() -> None:
    """Test derive_master_key raises when no customer master key provided."""
    blob = AhabBlobOffline(family=FAMILY)
    with pytest.raises(SPSDKError, match="Customer master key"):
        blob.derive_master_key()


def test_ahab_blob_offline_derive_kek() -> None:
    """Test derive_kek returns 32 bytes."""
    blob = AhabBlobOffline(family=FAMILY, customer_master_key=CMK)
    master_key = blob.derive_master_key()
    kek = blob.derive_kek(master_key)
    assert len(kek) == 32


def test_ahab_blob_offline_generate_nonce() -> None:
    """Test generate_nonce returns 13-byte nonce with integrity byte."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        key_identifier=0x12345678,
    )
    nonce = blob.generate_nonce()
    assert len(nonce) == 13


def test_ahab_blob_offline_add_nonce_integrity_protection() -> None:
    """Test nonce integrity protection appends XOR checksum."""
    blob = AhabBlobOffline(family=FAMILY)
    nonce = bytes([0x01, 0x02, 0x04])  # XOR = 0x07
    protected = blob.add_nonce_integrity_protection(nonce)
    assert len(protected) == len(nonce) + 1
    assert protected[-1] == 0x01 ^ 0x02 ^ 0x04


def test_ahab_blob_offline_generate_dek() -> None:
    """Test generate_dek produces a random DEK of correct size."""
    blob = AhabBlobOffline(family=FAMILY, size=256)
    dek = blob.generate_dek()
    assert len(dek) == 32
    assert blob.dek == dek


def test_ahab_blob_offline_generate_blob_key() -> None:
    """Test generate_blob_key produces a 32-byte key."""
    blob = AhabBlobOffline(family=FAMILY)
    bk = blob.generate_blob_key()
    assert len(bk) == 32


# ---------------------------------------------------------------------------
# AhabBlobOffline export / parse / decrypt round-trip
# ---------------------------------------------------------------------------


def test_ahab_blob_offline_export_produces_correct_length() -> None:
    """Test AhabBlobOffline.export() produces the expected blob length."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        dek=DEK_256,
        blob_key=BLOB_KEY_256,
    )
    data = blob.export()
    # Header (8) + enc_blob_key (32) + enc_dek (DEK_size + 16 CCM tag)
    assert len(data) == 8 + 32 + 32 + 16


def test_ahab_blob_offline_export_no_cmk_raises() -> None:
    """Test AhabBlobOffline.export() raises when customer master key is missing."""
    blob = AhabBlobOffline(family=FAMILY, size=256)
    with pytest.raises(SPSDKError, match="Customer master key"):
        blob.export()


def test_ahab_blob_offline_parse_roundtrip() -> None:
    """Test AhabBlobOffline export → parse preserves flags and size."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        dek=DEK_256,
        blob_key=BLOB_KEY_256,
    )
    data = blob.export()
    parsed = AhabBlobOffline.parse(data, FAMILY)
    assert parsed.flags == blob.flags
    assert parsed._size == blob._size


def test_ahab_blob_offline_encrypt_decrypt_roundtrip() -> None:
    """Test that AhabBlobOffline encrypt → decrypt recovers the original DEK."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        dek=DEK_256,
        blob_key=BLOB_KEY_256,
    )
    data = blob.export()

    decryptor = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        key_identifier=blob.key_identifier,
    )
    recovered_dek = decryptor.decrypt_keyblob(data)
    assert recovered_dek == DEK_256


def test_ahab_blob_offline_decrypt_no_cmk_raises() -> None:
    """Test decrypt_keyblob raises SPSDKError when no customer master key."""
    blob = AhabBlobOffline(family=FAMILY, size=256)
    with pytest.raises(SPSDKError, match="Customer master key"):
        blob.decrypt_keyblob(bytes(88))


def test_ahab_blob_offline_decrypt_too_short_raises() -> None:
    """Test decrypt_keyblob raises when data is too short."""
    blob = AhabBlobOffline(family=FAMILY, size=256, customer_master_key=CMK)
    with pytest.raises(SPSDKValueError, match="too short"):
        blob.decrypt_keyblob(bytes(7))


def test_ahab_blob_offline_decrypt_wrong_tag_raises() -> None:
    """Test decrypt_keyblob raises when blob tag is not 0x81."""
    blob = AhabBlobOffline(family=FAMILY, size=256, customer_master_key=CMK)
    bad_data = bytes(88)  # tag byte [3] == 0x00
    with pytest.raises(SPSDKValueError, match="Invalid keyblob tag"):
        blob.decrypt_keyblob(bad_data)


def test_ahab_blob_offline_decrypt_length_mismatch_raises() -> None:
    """Test decrypt_keyblob raises when stated length doesn't match data length."""
    blob = AhabBlobOffline(family=FAMILY, size=256, customer_master_key=CMK)
    # Build header with tag=0x81, length=100, but actual data is 88 bytes
    bad_data = bytes([0x00]) + struct.pack("<H", 100) + bytes([0x81]) + bytes(84)
    with pytest.raises(SPSDKValueError, match="length mismatch"):
        blob.decrypt_keyblob(bad_data)


# ---------------------------------------------------------------------------
# AhabBlobOffline load_from_config
# ---------------------------------------------------------------------------


def test_ahab_blob_offline_load_from_config_minimal() -> None:
    """Test AhabBlobOffline.load_from_config() with minimal required fields."""
    cfg = Config(
        {
            "family": "mimxrt1189",
            "lifecycle": "oem_open",
            "debug": False,
            "key_id": 0,
            "cust_mk_sk": CMK.hex(),
            "srkh0": SRKH0.hex(),
            "srkh1": SRKH1.hex(),
            "dek_key_size": 256,
        }
    )
    blob = AhabBlobOffline.load_from_config(cfg)
    assert blob.customer_master_key == CMK
    assert blob._size == 256
    assert blob.lifecycle_state == KeyblobLifeCycle.OEM_OPEN
    assert blob.debug_enable == DebugEnable.NO


def test_ahab_blob_offline_load_from_config_with_dek_and_blob_key() -> None:
    """Test AhabBlobOffline.load_from_config() loads optional dek and blob_key."""
    cfg = Config(
        {
            "family": "mimxrt1189",
            "lifecycle": "oem_open",
            "debug": True,
            "key_id": 42,
            "cust_mk_sk": CMK.hex(),
            "srkh0": SRKH0.hex(),
            "srkh1": SRKH1.hex(),
            "dek": DEK_256.hex(),
            "blob_key": BLOB_KEY_256.hex(),
            "dek_key_size": 256,
        }
    )
    blob = AhabBlobOffline.load_from_config(cfg)
    assert blob.dek == DEK_256
    assert blob.blob_key == BLOB_KEY_256
    assert blob.debug_enable == DebugEnable.YES
    assert blob.key_identifier == 42


# ---------------------------------------------------------------------------
# AhabBlobOffline with different lifecycle states and debug settings
# ---------------------------------------------------------------------------


def test_ahab_blob_offline_different_lifecycle_states() -> None:
    """Test AhabBlobOffline nonce differs across lifecycle states."""
    nonces = set()
    for state in [
        KeyblobLifeCycle.OEM_OPEN,
        KeyblobLifeCycle.OEM_CLOSED,
    ]:
        blob = AhabBlobOffline(
            family=FAMILY,
            size=256,
            customer_master_key=CMK,
            lifecycle_state=state,
        )
        nonces.add(blob.generate_nonce().hex())
    assert len(nonces) == 2  # each lifecycle produces a unique nonce


def test_ahab_blob_offline_debug_enabled_changes_nonce() -> None:
    """Test that debug_enable flag changes the generated nonce."""
    blob_no_debug = AhabBlobOffline(
        family=FAMILY, size=256, customer_master_key=CMK, debug_enable=DebugEnable.NO
    )
    blob_debug = AhabBlobOffline(
        family=FAMILY, size=256, customer_master_key=CMK, debug_enable=DebugEnable.YES
    )
    assert blob_no_debug.generate_nonce() != blob_debug.generate_nonce()


def test_ahab_blob_offline_export_generates_dek_if_missing() -> None:
    """Test AhabBlobOffline.export() auto-generates DEK when not provided."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        blob_key=BLOB_KEY_256,
        # No dek provided
    )
    data = blob.export()
    assert blob.dek is not None
    assert len(blob.dek) == 32
    assert len(data) > 0


def test_ahab_blob_offline_export_generates_blob_key_if_missing() -> None:
    """Test AhabBlobOffline.export() auto-generates blob_key when not provided."""
    blob = AhabBlobOffline(
        family=FAMILY,
        size=256,
        customer_master_key=CMK,
        srkh0=SRKH0,
        srkh1=SRKH1,
        dek=DEK_256,
        # No blob_key provided
    )
    data = blob.export()
    assert blob.blob_key is not None
    assert len(blob.blob_key) == 32
    assert len(data) > 0

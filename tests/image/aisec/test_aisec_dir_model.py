#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of the AISEC dir-v5 container data model."""

import pytest

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.aisec.aisec_dir import AisecDirContainer, AisecMember
from spsdk.image.aisec.aisec_dir_blocks import (
    AisecAuthBlock,
    AisecBlockHeader,
    AisecDescriptor,
    AisecMemberEntry,
    AisecMetadata,
    AisecMmkBlock,
    check_member_names,
)
from spsdk.image.aisec.aisec_dir_types import (
    AUTH_BLOCK_SIZE,
    BLOCK_HEADER_SIZE,
    DESCRIPTOR_SIZE,
    MEMBER_ENTRY_FIXED_SIZE,
    METADATA_FIXED_PREFIX_SIZE,
    AisecBlockSize,
    AisecContainerFlag,
    AisecKeySize,
    AisecMemberType,
    AisecMode,
)
from spsdk.utils.family import FamilyRevision

SALT = bytes(range(1, 17))


def _metadata(entries: list[AisecMemberEntry]) -> AisecMetadata:
    return AisecMetadata(
        container_id=0x11223344,
        container_version=0x0102,
        enc_alg=0x02,
        enc_key_size=0x20,
        auth_alg=0x01,
        auth_key_size=0x10,
        container_salt=SALT,
        mmk_id=0x0A0B0C0D,
        mmk_size=0x20,
        kdf_alg=0x81,
        entries=entries,
    )


def test_descriptor_layout() -> None:
    desc = AisecDescriptor(
        flag=0x12,
        mode=0x02,
        length_header_bytes=0x01020304,
        authentication_block_offset=0x05060708,
        mmk_block_offset=0x090A0B0C,
    )
    data = desc.export()
    assert len(data) == DESCRIPTOR_SIZE
    assert data == bytes.fromhex("81051202" "01020304" "00000018" "05060708" "090a0b0c" "00000000")
    assert AisecDescriptor.parse(data) == desc


def test_descriptor_bad_tag() -> None:
    data = bytearray(AisecDescriptor(flag=0x12, mode=0).export())
    data[0] = 0x82
    with pytest.raises(SPSDKParsingError):
        AisecDescriptor.parse(bytes(data))


def test_member_entry_layout() -> None:
    entry = AisecMemberEntry(
        member_id=3,
        member_type=0x01,
        protection=0x02,
        block_size_enum=0x03,
        name="dir/model.dvm",
        member_offset=0x0102030405060708,
        member_size=0x1111,
        plain_size=0x1000,
        block_count=1,
        member_root_mac=bytes([0xAA] * 16),
    )
    data = entry.export()
    assert len(data) == MEMBER_ENTRY_FIXED_SIZE + len("dir/model.dvm")
    assert data[:6] == bytes.fromhex("000301020300")
    assert data[6:14] == bytes.fromhex("0102030405060708")
    assert data[50:52] == bytes.fromhex("000d")
    assert AisecMemberEntry.parse(data) == entry


def test_metadata_round_trip() -> None:
    entries = [
        AisecMemberEntry(0, 0, 1, 0, "config.json", plain_size=10, block_count=1),
        AisecMemberEntry(1, 1, 2, 3, "model.dvm", plain_size=20, block_count=1),
    ]
    meta = _metadata(entries)
    data = meta.export()
    assert len(data) == meta.size
    assert meta.size == METADATA_FIXED_PREFIX_SIZE + 2 * MEMBER_ENTRY_FIXED_SIZE + 20
    assert data[1:5] == meta.size.to_bytes(4, "big")
    assert data[11:13] == (2).to_bytes(2, "big")
    parsed = AisecMetadata.parse(data + b"trailing")
    assert parsed.entries == entries
    assert parsed.binding is True
    assert parsed.kdf == 0x01
    assert parsed.container_salt == SALT


def test_metadata_count_mismatch() -> None:
    meta = _metadata([AisecMemberEntry(0, 0, 1, 0, "a")])
    meta.member_count = 2
    with pytest.raises(SPSDKParsingError):
        AisecMetadata.parse(meta.export())
    meta.member_count = 0
    with pytest.raises(SPSDKParsingError):
        AisecMetadata.parse(meta.export())


def test_metadata_bad_salt() -> None:
    meta = _metadata([])
    meta.container_salt = bytes(15)
    with pytest.raises(SPSDKValueError):
        meta.export()


def test_auth_block() -> None:
    block = AisecAuthBlock(auth_data=bytes([0x55] * 16))
    data = block.export()
    assert len(data) == AUTH_BLOCK_SIZE
    assert data[:4] == bytes.fromhex("83001400")
    assert block.export_header() == data[:4]
    assert AisecAuthBlock.parse(data) == block


def test_mmk_block() -> None:
    block = AisecMmkBlock(blob=b"\x01\x02\x03")
    data = block.export()
    assert data == bytes.fromhex("84000700010203")
    assert AisecMmkBlock.parse(data + b"\xff") == block
    with pytest.raises(SPSDKValueError):
        AisecMmkBlock(blob=b"").export()
    with pytest.raises(SPSDKValueError):
        AisecMmkBlock(blob=bytes(0xFFFC)).export()
    with pytest.raises(SPSDKParsingError):
        AisecMmkBlock.parse(bytes.fromhex("84000400"))


def test_block_header() -> None:
    header = AisecBlockHeader(block_index=2, block_len=0x10000, block_mac=bytes([1] * 16))
    data = header.export()
    assert len(data) == BLOCK_HEADER_SIZE
    assert AisecBlockHeader.parse(data) == header


@pytest.mark.parametrize(
    "names,valid",
    [
        (["config.json", "tokenizer/vocab.txt", "model.dvm"], True),
        (["a", "a"], False),
        (["../a"], False),
        (["/a"], False),
        (["a\\b"], False),
        (["a\x00b"], False),
        (["a//b"], False),
        (["a", "a/b"], False),
        (["e\u0301"], False),
    ],
)
def test_check_member_names(names: list[str], valid: bool) -> None:
    assert (not check_member_names(names)) == valid


def test_enums() -> None:
    assert AisecBlockSize.B64K.size == 0x10000
    assert AisecBlockSize.B4M.size == 0x400000
    assert all(bs.size % 16 == 0 for bs in AisecBlockSize)
    assert AisecKeySize.from_size(24) == AisecKeySize.AES_192
    assert AisecContainerFlag.from_label("discrete").tag == 0x12
    assert AisecMode.from_label("ele_primitive_backend").tag == 0x02


def test_member_type_and_block_count() -> None:
    assert AisecMember("x/model.DVM", b"").member_type == AisecMemberType.DVM
    assert AisecMember("readme.txt", b"").member_type == AisecMemberType.RAW
    member = AisecMember("a", bytes(0x10001), block_size=AisecBlockSize.B64K)
    assert member.block_count == 2
    assert AisecMember("a", b"").block_count == 0


@pytest.mark.parametrize(
    "family",
    [
        "mimx9301",
        "mimx9302",
        "mimx9311",
        "mimx9312",
        "mimx9321",
        "mimx9322",
        "mimx9331",
        "mimx9332",
        "mimx9351",
        "mimx9352",
        "mimx9596",
    ],
)
def test_supported_families_and_template(family: str) -> None:
    families = AisecDirContainer.get_supported_families()
    assert FamilyRevision(family) in families
    template = AisecDirContainer.get_config_template(FamilyRevision(family))
    for key in ("container:", "crypto:", "keys:", "members:", "flow:", "mmk:"):
        assert key in template

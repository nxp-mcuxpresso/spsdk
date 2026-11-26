#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AISEC dir-v5 container wire-level blocks.

The dir-v5 format is big-endian and byte-packed (no natural alignment). Every block is
serialized field by field with explicit big-endian ``struct`` formats - the blocks are
never overlaid on memory. Wire values are stored as raw integers, so that a parsed
container with invalid values can still be represented and reported by verification.
"""

import fnmatch
import struct
import unicodedata
from dataclasses import dataclass, field

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.aisec.aisec_dir_types import (
    AISEC_DIR_VERSION,
    AISEC_LOAD_INFLUENCING_PATTERNS,
    AUTH_BLOCK_SIZE,
    BLOCK_HEADER_SIZE,
    CONTAINER_SALT_SIZE,
    DESCRIPTOR_SIZE,
    KDF_ALG_MASK,
    KDF_BINDING_FLAG,
    MAC_SIZE,
    MEMBER_ENTRY_FIXED_SIZE,
    METADATA_FIXED_PREFIX_SIZE,
    MMK_BLOCK_MAX_BLOB_SIZE,
    MMK_BLOCK_PREFIX_SIZE,
    TAG_AUTH_BLOCK,
    TAG_DESCRIPTOR,
    TAG_METADATA,
    TAG_MMK_BLOCK,
)


def _check_size(data: bytes, size: int, name: str) -> None:
    """Check that enough data is available for parsing.

    :param data: Input data.
    :param size: Required size in bytes.
    :param name: Name of the parsed block used in the error message.
    :raises SPSDKParsingError: Not enough data.
    """
    if len(data) < size:
        raise SPSDKParsingError(
            f"Not enough data to parse AISEC {name}: required {size} bytes, got {len(data)}"
        )


@dataclass
class AisecDescriptor:
    """Container descriptor (tag 0x81), fixed 24 bytes."""

    FORMAT = ">BBBBLLLL4s"

    flag: int
    mode: int
    length_header_bytes: int = 0
    container_metadata_offset: int = DESCRIPTOR_SIZE
    authentication_block_offset: int = 0
    mmk_block_offset: int = 0
    version: int = AISEC_DIR_VERSION
    tag: int = TAG_DESCRIPTOR
    rfu: bytes = bytes(4)

    def export(self) -> bytes:
        """Serialize the descriptor.

        :return: Binary descriptor.
        """
        return struct.pack(
            self.FORMAT,
            self.tag,
            self.version,
            self.flag,
            self.mode,
            self.length_header_bytes,
            self.container_metadata_offset,
            self.authentication_block_offset,
            self.mmk_block_offset,
            self.rfu,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the descriptor.

        :param data: Binary data starting with the descriptor.
        :raises SPSDKParsingError: Not enough data or invalid tag.
        :return: Parsed descriptor.
        """
        _check_size(data, DESCRIPTOR_SIZE, "container descriptor")
        tag, version, flag, mode, lhb, md_off, auth_off, mmk_off, rfu = struct.unpack_from(
            cls.FORMAT, data
        )
        if tag != TAG_DESCRIPTOR:
            raise SPSDKParsingError(
                f"Invalid AISEC container descriptor tag 0x{tag:02X}, "
                f"expected 0x{TAG_DESCRIPTOR:02X}"
            )
        return cls(
            flag=flag,
            mode=mode,
            length_header_bytes=lhb,
            container_metadata_offset=md_off,
            authentication_block_offset=auth_off,
            mmk_block_offset=mmk_off,
            version=version,
            tag=tag,
            rfu=rfu,
        )


@dataclass
class AisecMemberEntry:
    """Member entry, folded into the container metadata (52 bytes + name)."""

    FORMAT = ">HBBBBQQQL16sH"

    member_id: int
    member_type: int
    protection: int
    block_size_enum: int
    name: str
    member_offset: int = 0
    member_size: int = 0
    plain_size: int = 0
    block_count: int = 0
    member_root_mac: bytes = bytes(MAC_SIZE)
    rfu1: int = 0

    @property
    def name_bytes(self) -> bytes:
        """Member name encoded as UTF-8.

        :return: Encoded member name.
        """
        return self.name.encode("utf-8")

    @property
    def size(self) -> int:
        """Size of the serialized entry.

        :return: Entry size in bytes.
        """
        return MEMBER_ENTRY_FIXED_SIZE + len(self.name_bytes)

    def export(self) -> bytes:
        """Serialize the member entry.

        :return: Binary member entry.
        """
        name = self.name_bytes
        return (
            struct.pack(
                self.FORMAT,
                self.member_id,
                self.member_type,
                self.protection,
                self.block_size_enum,
                self.rfu1,
                self.member_offset,
                self.member_size,
                self.plain_size,
                self.block_count,
                self.member_root_mac,
                len(name),
            )
            + name
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the member entry.

        :param data: Binary data starting with the member entry.
        :raises SPSDKParsingError: Not enough data or invalid UTF-8 name.
        :return: Parsed member entry.
        """
        _check_size(data, MEMBER_ENTRY_FIXED_SIZE, "member entry")
        (
            member_id,
            member_type,
            protection,
            block_size_enum,
            rfu1,
            member_offset,
            member_size,
            plain_size,
            block_count,
            member_root_mac,
            name_len,
        ) = struct.unpack_from(cls.FORMAT, data)
        _check_size(data, MEMBER_ENTRY_FIXED_SIZE + name_len, "member entry name")
        raw_name = data[MEMBER_ENTRY_FIXED_SIZE : MEMBER_ENTRY_FIXED_SIZE + name_len]
        try:
            name = raw_name.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SPSDKParsingError(
                f"AISEC member {member_id} name is not valid UTF-8: {raw_name!r}"
            ) from exc
        return cls(
            member_id=member_id,
            member_type=member_type,
            protection=protection,
            block_size_enum=block_size_enum,
            name=name,
            member_offset=member_offset,
            member_size=member_size,
            plain_size=plain_size,
            block_count=block_count,
            member_root_mac=member_root_mac,
            rfu1=rfu1,
        )


@dataclass
class AisecMetadata:
    """Container metadata (tag 0x82): 40-byte fixed prefix + folded member entries."""

    FORMAT = ">BLLHHBBBB16sLBBB"

    container_id: int
    container_version: int
    enc_alg: int
    enc_key_size: int
    auth_alg: int
    auth_key_size: int
    container_salt: bytes
    mmk_id: int
    mmk_size: int
    kdf_alg: int
    entries: list[AisecMemberEntry] = field(default_factory=list)
    member_count: int | None = None
    total_len: int | None = None
    tag: int = TAG_METADATA
    rfu: int = 0

    @property
    def size(self) -> int:
        """Size of the serialized metadata including all member entries.

        :return: Metadata size in bytes.
        """
        return METADATA_FIXED_PREFIX_SIZE + sum(entry.size for entry in self.entries)

    @property
    def binding(self) -> bool:
        """Device binding flag (MSB of kdf_alg).

        :return: True if the container is device-bound.
        """
        return bool(self.kdf_alg & KDF_BINDING_FLAG)

    @property
    def kdf(self) -> int:
        """KDF algorithm value (LSBs of kdf_alg).

        :return: KDF algorithm enumeration value.
        """
        return self.kdf_alg & KDF_ALG_MASK

    def export(self) -> bytes:
        """Serialize the metadata.

        The member_count and total_len fields are computed from the entries unless
        they are explicitly set (used to construct malformed test vectors).

        :raises SPSDKValueError: Invalid container salt size.
        :return: Binary metadata.
        """
        if len(self.container_salt) != CONTAINER_SALT_SIZE:
            raise SPSDKValueError(
                f"AISEC container salt must be {CONTAINER_SALT_SIZE} bytes, "
                f"got {len(self.container_salt)}"
            )
        prefix = struct.pack(
            self.FORMAT,
            self.tag,
            self.size if self.total_len is None else self.total_len,
            self.container_id,
            self.container_version,
            len(self.entries) if self.member_count is None else self.member_count,
            self.enc_alg,
            self.enc_key_size,
            self.auth_alg,
            self.auth_key_size,
            self.container_salt,
            self.mmk_id,
            self.mmk_size,
            self.kdf_alg,
            self.rfu,
        )
        return prefix + b"".join(entry.export() for entry in self.entries)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the metadata including all member entries.

        The entries are parsed within the extent given by the block's own total_len.

        :param data: Binary data starting with the metadata block.
        :raises SPSDKParsingError: Not enough data, invalid tag or inconsistent entries.
        :return: Parsed metadata.
        """
        _check_size(data, METADATA_FIXED_PREFIX_SIZE, "container metadata")
        (
            tag,
            total_len,
            container_id,
            container_version,
            member_count,
            enc_alg,
            enc_key_size,
            auth_alg,
            auth_key_size,
            container_salt,
            mmk_id,
            mmk_size,
            kdf_alg,
            rfu,
        ) = struct.unpack_from(cls.FORMAT, data)
        if tag != TAG_METADATA:
            raise SPSDKParsingError(
                f"Invalid AISEC container metadata tag 0x{tag:02X}, expected 0x{TAG_METADATA:02X}"
            )
        if total_len < METADATA_FIXED_PREFIX_SIZE:
            raise SPSDKParsingError(f"Invalid AISEC container metadata total_len {total_len}")
        _check_size(data, total_len, "container metadata member entries")
        region = data[:total_len]
        entries: list[AisecMemberEntry] = []
        offset = METADATA_FIXED_PREFIX_SIZE
        for _ in range(member_count):
            if offset >= total_len:
                raise SPSDKParsingError(
                    f"AISEC member_count {member_count} exceeds entries present in metadata "
                    f"(found {len(entries)})"
                )
            entry = AisecMemberEntry.parse(region[offset:])
            entries.append(entry)
            offset += entry.size
        if offset != total_len:
            raise SPSDKParsingError(
                f"AISEC container metadata total_len {total_len} does not match the size of "
                f"{member_count} member entries ({offset})"
            )
        return cls(
            container_id=container_id,
            container_version=container_version,
            enc_alg=enc_alg,
            enc_key_size=enc_key_size,
            auth_alg=auth_alg,
            auth_key_size=auth_key_size,
            container_salt=container_salt,
            mmk_id=mmk_id,
            mmk_size=mmk_size,
            kdf_alg=kdf_alg,
            entries=entries,
            member_count=member_count,
            total_len=total_len,
            tag=tag,
            rfu=rfu,
        )


@dataclass
class AisecAuthBlock:
    """Authentication block (tag 0x83), fixed 20 bytes, carries the header CMAC."""

    FORMAT = ">BHB16s"

    auth_data: bytes = bytes(MAC_SIZE)
    total_len: int = AUTH_BLOCK_SIZE
    tag: int = TAG_AUTH_BLOCK
    rfu: int = 0

    def export_header(self) -> bytes:
        """Serialize the authentication block header covered by the header CMAC.

        :return: Binary header (tag, total_len, rfu).
        """
        return struct.pack(">BHB", self.tag, self.total_len, self.rfu)

    def export(self) -> bytes:
        """Serialize the authentication block.

        :raises SPSDKValueError: Invalid auth data size.
        :return: Binary authentication block.
        """
        if len(self.auth_data) != MAC_SIZE:
            raise SPSDKValueError(f"AISEC auth_data must be {MAC_SIZE} bytes")
        return self.export_header() + self.auth_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the authentication block.

        :param data: Binary data starting with the authentication block.
        :raises SPSDKParsingError: Not enough data or invalid tag.
        :return: Parsed authentication block.
        """
        _check_size(data, AUTH_BLOCK_SIZE, "authentication block")
        tag, total_len, rfu, auth_data = struct.unpack_from(cls.FORMAT, data)
        if tag != TAG_AUTH_BLOCK:
            raise SPSDKParsingError(
                f"Invalid AISEC authentication block tag 0x{tag:02X}, "
                f"expected 0x{TAG_AUTH_BLOCK:02X}"
            )
        return cls(auth_data=auth_data, total_len=total_len, tag=tag, rfu=rfu)


@dataclass
class AisecMmkBlock:
    """MMK block (tag 0x84) - opaque ELE/EL2GO provisioning blob (flag 0x11 only)."""

    FORMAT = ">BHB"

    blob: bytes
    tag: int = TAG_MMK_BLOCK
    rfu: int = 0

    @property
    def size(self) -> int:
        """Size of the serialized block.

        :return: Block size in bytes.
        """
        return MMK_BLOCK_PREFIX_SIZE + len(self.blob)

    @staticmethod
    def check_blob(blob: bytes) -> None:
        """Check that the provisioning blob fits into the MMK block.

        :param blob: Provisioning blob.
        :raises SPSDKValueError: Empty or too large provisioning blob.
        """
        if not blob:
            raise SPSDKValueError("AISEC provisioning blob must not be empty")
        if len(blob) > MMK_BLOCK_MAX_BLOB_SIZE:
            raise SPSDKValueError(
                f"AISEC provisioning blob is {len(blob)} bytes, the maximum is "
                f"{MMK_BLOCK_MAX_BLOB_SIZE} bytes"
            )

    def export(self) -> bytes:
        """Serialize the MMK block. The blob is carried verbatim.

        :raises SPSDKValueError: Empty or too large provisioning blob.
        :return: Binary MMK block.
        """
        self.check_blob(self.blob)
        return struct.pack(self.FORMAT, self.tag, self.size, self.rfu) + self.blob

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the MMK block, using its own total_len as the block extent.

        :param data: Binary data starting with the MMK block.
        :raises SPSDKParsingError: Not enough data, invalid tag or total_len.
        :return: Parsed MMK block.
        """
        _check_size(data, MMK_BLOCK_PREFIX_SIZE, "mmk block")
        tag, total_len, rfu = struct.unpack_from(cls.FORMAT, data)
        if tag != TAG_MMK_BLOCK:
            raise SPSDKParsingError(
                f"Invalid AISEC mmk block tag 0x{tag:02X}, expected 0x{TAG_MMK_BLOCK:02X}"
            )
        if total_len <= MMK_BLOCK_PREFIX_SIZE:
            raise SPSDKParsingError(f"Invalid AISEC mmk block total_len {total_len}")
        _check_size(data, total_len, "mmk block blob")
        return cls(blob=data[MMK_BLOCK_PREFIX_SIZE:total_len], tag=tag, rfu=rfu)


@dataclass
class AisecBlockHeader:
    """Inline header of one member payload block (24 bytes)."""

    FORMAT = ">LL16s"

    block_index: int
    block_len: int
    block_mac: bytes = bytes(MAC_SIZE)

    def export(self) -> bytes:
        """Serialize the block header.

        :return: Binary block header.
        """
        return struct.pack(self.FORMAT, self.block_index, self.block_len, self.block_mac)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the block header.

        :param data: Binary data starting with the block header.
        :return: Parsed block header.
        """
        _check_size(data, BLOCK_HEADER_SIZE, "block header")
        block_index, block_len, block_mac = struct.unpack_from(cls.FORMAT, data)
        return cls(block_index=block_index, block_len=block_len, block_mac=block_mac)


def check_member_names(names: list[str]) -> list[str]:
    """Check member names against the dir-v5 name safety rules.

    :param names: List of member names in container order.
    :return: List of problem descriptions; empty if all names are valid.
    """
    problems: list[str] = []
    seen: set[str] = set()
    normalized: set[str] = set()
    for name in names:
        if not name:
            problems.append("Empty member name")
            continue
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
            problems.append(f"Member name contains control or NUL character: {name!r}")
        if "\\" in name:
            problems.append(f"Member name contains backslash: {name!r}")
        if name.startswith("/"):
            problems.append(f"Member name is absolute: {name!r}")
        if any(part in ("", ".", "..") for part in name.split("/")):
            problems.append(f"Member name has empty, '.' or '..' component: {name!r}")
        nfc = unicodedata.normalize("NFC", name)
        if nfc != name:
            problems.append(f"Member name is not in Unicode NFC form: {name!r}")
        if name in seen:
            problems.append(f"Duplicate member name: {name!r}")
        elif nfc in normalized:
            problems.append(f"Member name collides with another name after NFC: {name!r}")
        seen.add(name)
        normalized.add(nfc)

    dir_prefixes = {"/".join(n.split("/")[:i]) for n in names for i in range(1, n.count("/") + 1)}
    for clash in sorted(set(names) & dir_prefixes):
        problems.append(f"Member name is both a file and a directory prefix: {clash!r}")
    return problems


def is_load_influencing(name: str) -> bool:
    """Check whether a member name identifies a load-influencing file.

    Load-influencing members (model weights, configuration, tokenizer, manifests) must
    never use protection 'none'. The test keys off the member name, not the member type.

    :param name: Member name.
    :return: True if the member is load-influencing.
    """
    basename = unicodedata.normalize("NFC", name).rsplit("/", 1)[-1].casefold()
    return any(fnmatch.fnmatchcase(basename, pat) for pat in AISEC_LOAD_INFLUENCING_PATTERNS)

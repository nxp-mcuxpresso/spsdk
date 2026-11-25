#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AISEC dir-v5 container decoder and verifier.

The decoder reads the wire structures field by field with explicit bounds checks. The
verifier applies the dir-v5 must-reject rules. The structural verification needs no key;
the header CMAC, block MACs and member root MACs are verified only when the MMK (and the
SRKH binding root for device-bound containers) is supplied.
"""

import struct
from dataclasses import dataclass, field

from typing_extensions import Self

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.aisec.aisec_dir_blocks import (
    AisecAuthBlock,
    AisecBlockHeader,
    AisecDescriptor,
    AisecMemberEntry,
    AisecMetadata,
    AisecMmkBlock,
    check_member_names,
    is_load_influencing,
)
from spsdk.image.aisec.aisec_dir_crypto import (
    block_mac,
    decrypt_block,
    derive_auth_key,
    derive_enc_key,
    kdf_base_context,
    member_root_mac,
)
from spsdk.image.aisec.aisec_dir_types import (
    AISEC_BLOCK_SIZES,
    AISEC_DIR_VERSION,
    AUTH_BLOCK_SIZE,
    BLOCK_HEADER_SIZE,
    DESCRIPTOR_SIZE,
    ELE_PERSISTENT_KEY_ID_MAX,
    ELE_PERSISTENT_KEY_ID_MIN,
    MAC_SIZE,
    MAX_MEMBER_COUNT,
    MMK_BLOCK_MAX_BLOB_SIZE,
    MMK_BLOCK_PREFIX_SIZE,
    SRKH_SIZE,
    TAG_MMK_BLOCK,
    AisecAuthAlg,
    AisecBlockSize,
    AisecContainerFlag,
    AisecEncAlg,
    AisecKdfAlg,
    AisecKeySize,
    AisecMemberType,
    AisecMode,
    AisecProtection,
)
from spsdk.utils.verifier import Verifier, VerifierResult

NOT_VERIFIED_NO_KEY = "not verified (no key)"


@dataclass
class AisecBlockRef:
    """Reference to one payload block of a member."""

    header: AisecBlockHeader
    data_offset: int


@dataclass
class AisecDecodedMember:
    """Decoded member entry with its payload block references."""

    entry: AisecMemberEntry
    blocks: list[AisecBlockRef] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def block_size(self) -> int | None:
        """Block size in bytes, None for an invalid block size enumeration.

        :return: Block size in bytes or None.
        """
        return AISEC_BLOCK_SIZES.get(self.entry.block_size_enum)


@dataclass
class AisecKeys:
    """Key material for the cryptographic verification and member decryption."""

    mmk: bytes
    srkh: bytes | None = None


@dataclass
class AisecDecodedContainer:
    """Decoded AISEC dir-v5 container binary."""

    data: bytes
    descriptor: AisecDescriptor
    metadata: AisecMetadata
    auth_block: AisecAuthBlock
    mmk_block: AisecMmkBlock | None
    members: list[AisecDecodedMember]

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Decode the container binary.

        Only the problems that prevent decoding raise an exception; all the other rule
        violations are reported by :meth:`verify`.

        :param data: Container binary.
        :raises SPSDKParsingError: The binary cannot be decoded.
        :return: Decoded container.
        """
        descriptor = AisecDescriptor.parse(data[:DESCRIPTOR_SIZE])
        for name, offset in (
            ("container_metadata_offset", descriptor.container_metadata_offset),
            ("authentication_block_offset", descriptor.authentication_block_offset),
            ("mmk_block_offset", descriptor.mmk_block_offset),
            ("length_header_bytes", descriptor.length_header_bytes),
        ):
            if offset > len(data):
                raise SPSDKParsingError(
                    f"AISEC {name} 0x{offset:X} is beyond the container end 0x{len(data):X}"
                )
        md_off = descriptor.container_metadata_offset
        if md_off + 5 > len(data):
            raise SPSDKParsingError("AISEC container metadata is truncated")
        (md_len,) = struct.unpack_from(">L", data, md_off + 1)
        metadata = AisecMetadata.parse(data[md_off : md_off + md_len])
        auth_off = descriptor.authentication_block_offset
        auth_block = AisecAuthBlock.parse(data[auth_off : auth_off + AUTH_BLOCK_SIZE])
        mmk_block = None
        if descriptor.flag == AisecContainerFlag.INTEGRATED.tag:
            mmk_off = descriptor.mmk_block_offset
            mmk_block = AisecMmkBlock.parse(
                data[mmk_off : mmk_off + MMK_BLOCK_PREFIX_SIZE + MMK_BLOCK_MAX_BLOB_SIZE]
            )
        members = [cls._decode_member(data, entry) for entry in metadata.entries]
        return cls(
            data=data,
            descriptor=descriptor,
            metadata=metadata,
            auth_block=auth_block,
            mmk_block=mmk_block,
            members=members,
        )

    @staticmethod
    def _decode_member(data: bytes, entry: AisecMemberEntry) -> AisecDecodedMember:
        """Walk the payload blocks of one member with bounds checks.

        :param data: Container binary.
        :param entry: Member entry.
        :return: Decoded member with the found structural problems.
        """
        member = AisecDecodedMember(entry=entry)
        end = entry.member_offset + entry.member_size
        if end > len(data):
            member.problems.append(
                f"payload 0x{entry.member_offset:X}+0x{entry.member_size:X} is beyond the "
                f"container end 0x{len(data):X}"
            )
            return member
        pos = entry.member_offset
        for index in range(entry.block_count):
            if pos + BLOCK_HEADER_SIZE > end:
                member.problems.append(f"block {index} header is beyond the member payload")
                return member
            header = AisecBlockHeader.parse(data[pos : pos + BLOCK_HEADER_SIZE])
            if header.block_index != index:
                member.problems.append(f"block {index} has block_index {header.block_index}")
            if member.block_size is not None and header.block_len > member.block_size:
                member.problems.append(
                    f"block {index} block_len {header.block_len} exceeds the block size "
                    f"{member.block_size}"
                )
                return member
            if pos + BLOCK_HEADER_SIZE + header.block_len > end:
                member.problems.append(f"block {index} data is beyond the member payload")
                return member
            member.blocks.append(AisecBlockRef(header, pos + BLOCK_HEADER_SIZE))
            pos += BLOCK_HEADER_SIZE + header.block_len
        if pos != end:
            member.problems.append(
                f"member_size {entry.member_size} does not match the size of the blocks "
                f"({pos - entry.member_offset})"
            )
        return member

    @property
    def flag(self) -> int:
        """Container custody flag value.

        :return: Flag value.
        """
        return self.descriptor.flag

    def block_data(self, block: AisecBlockRef) -> bytes:
        """Get the stored data of one payload block.

        :param block: Block reference.
        :return: Stored block data.
        """
        return self.data[block.data_offset : block.data_offset + block.header.block_len]

    # ------------------------------------------------------------------------------------
    # Structural verification
    # ------------------------------------------------------------------------------------
    def verify(self, keys: AisecKeys | None = None) -> Verifier:
        """Verify the container against the dir-v5 must-reject rules.

        :param keys: Optional key material enabling the MAC verification.
        :return: Verifier with the results.
        """
        ver = Verifier("AISEC dir-v5 container")
        ver.add_child(self._verify_descriptor())
        ver.add_child(self._verify_metadata())
        ver.add_child(self._verify_custody())
        ver.add_child(self._verify_member_area())
        for index, member in enumerate(self.members):
            ver.add_child(self._verify_member(index, member))
        ver.add_child(self._verify_authentication(keys))
        return ver

    def _verify_descriptor(self) -> Verifier:
        """Verify the container descriptor and the header layout.

        :return: Verifier with the results.
        """
        desc = self.descriptor
        ver = Verifier("Container descriptor")
        ver.add_record("Version", desc.version == AISEC_DIR_VERSION, f"0x{desc.version:02X}")
        ver.add_record_enum("Flag", desc.flag, AisecContainerFlag)
        ver.add_record_enum("Mode", desc.mode, AisecMode)
        if desc.mode == AisecMode.SW.tag:
            ver.add_record(
                "Production policy",
                VerifierResult.WARNING,
                "software backend is for testing and development only",
            )
        if desc.flag & 0x80 == 0 and AisecContainerFlag.contains(desc.flag):
            ver.add_record(
                "Lifecycle",
                VerifierResult.SUCCEEDED,
                "provisioning form - accepted by the on-device installer only",
                important=False,
            )
        ver.add_record(
            "Metadata offset",
            desc.container_metadata_offset == DESCRIPTOR_SIZE,
            desc.container_metadata_offset,
        )
        auth_off = desc.container_metadata_offset + (self.metadata.total_len or 0)
        ver.add_record(
            "Authentication block offset",
            desc.authentication_block_offset == auth_off,
            f"{desc.authentication_block_offset} (expected {auth_off})",
        )
        mmk_off = desc.authentication_block_offset + AUTH_BLOCK_SIZE
        ver.add_record(
            "MMK block offset",
            desc.mmk_block_offset == mmk_off,
            f"{desc.mmk_block_offset} (expected {mmk_off})",
        )
        ver.add_record(
            "Authentication block",
            self.auth_block.total_len == AUTH_BLOCK_SIZE,
            f"total_len {self.auth_block.total_len}",
        )
        return ver

    def _verify_metadata(self) -> Verifier:
        """Verify the global container metadata fields.

        :return: Verifier with the results.
        """
        md = self.metadata
        ver = Verifier("Container metadata")
        count = md.member_count or 0
        ver.add_record(
            "Member count", 0 < count <= MAX_MEMBER_COUNT and count == len(md.entries), count
        )
        ver.add_record_enum("Encryption algorithm", md.enc_alg, AisecEncAlg)
        ver.add_record_enum("Authentication algorithm", md.auth_alg, AisecAuthAlg)
        ver.add_record_enum("Encryption key size", md.enc_key_size, AisecKeySize)
        ver.add_record_enum("Authentication key size", md.auth_key_size, AisecKeySize)
        ver.add_record_enum("MMK size", md.mmk_size, AisecKeySize)
        ver.add_record_enum("KDF algorithm", md.kdf, AisecKdfAlg)
        ver.add_record("Device binding", VerifierResult.SUCCEEDED, md.binding, important=False)
        ver.add_record("Container salt", any(md.container_salt), md.container_salt.hex())
        ver.add_record("Container ID", VerifierResult.SUCCEEDED, f"0x{md.container_id:08X}")
        ver.add_record("Container version", VerifierResult.SUCCEEDED, md.container_version)
        return ver

    def _verify_custody(self) -> Verifier:
        """Verify the MMK custody rules driven by the container flag.

        :return: Verifier with the results.
        """
        desc, md = self.descriptor, self.metadata
        ver = Verifier("MMK custody")
        if desc.flag == AisecContainerFlag.INTEGRATED.tag:
            assert self.mmk_block is not None
            end = desc.mmk_block_offset + self.mmk_block.size
            ver.add_record(
                "Provisioning blob",
                bool(self.mmk_block.blob),
                f"{len(self.mmk_block.blob)} bytes",
            )
            ver.add_record(
                "Header length",
                desc.length_header_bytes == end,
                f"{desc.length_header_bytes} (expected {end})",
            )
            ver.add_record("MMK ID", VerifierResult.SUCCEEDED, f"0x{md.mmk_id:08X} (informational)")
            return ver
        stray = (
            desc.mmk_block_offset < len(self.data)
            and self.data[desc.mmk_block_offset] == TAG_MMK_BLOCK
        )
        ver.add_record(
            "MMK block absent",
            desc.mmk_block_offset == desc.length_header_bytes and not stray,
            f"mmk_block_offset {desc.mmk_block_offset}, length_header_bytes "
            f"{desc.length_header_bytes}",
        )
        id_ok = md.mmk_id != 0
        if desc.mode == AisecMode.ELE.tag:
            id_ok = ELE_PERSISTENT_KEY_ID_MIN <= md.mmk_id <= ELE_PERSISTENT_KEY_ID_MAX
        ver.add_record("MMK ID", id_ok, f"0x{md.mmk_id:08X}")
        if desc.flag == AisecContainerFlag.SEALED.tag:
            derived = max(md.enc_key_size, md.auth_key_size)
            ver.add_record(
                "MMK entropy",
                md.mmk_size >= derived,
                f"MMK {md.mmk_size} B, derived keys up to {derived} B",
            )
        return ver

    def _verify_member_area(self) -> Verifier:
        """Verify member names and the placement of member payloads.

        :return: Verifier with the results.
        """
        ver = Verifier("Member area")
        problems = check_member_names([m.entry.name for m in self.members])
        for problem in problems:
            ver.add_record("Member name", False, problem)
        if not problems:
            ver.add_record("Member names", True, f"{len(self.members)} valid names")
        ranges = sorted(
            (m.entry.member_offset, m.entry.member_offset + m.entry.member_size)
            for m in self.members
        )
        pos = self.descriptor.length_header_bytes
        gaps = False
        for start, end in ranges:
            if start < pos:
                ver.add_record(
                    "Payload ranges", False, f"payload at 0x{start:X} overlaps 0x{pos:X}"
                )
                return ver
            gaps |= start != pos
            pos = end
        ver.add_record("Payload ranges", True, "no overlap", important=False)
        if gaps or pos != len(self.data):
            ver.add_record(
                "Payload placement",
                VerifierResult.WARNING,
                "member area contains gaps or trailing data",
            )
        return ver

    def _verify_member(self, index: int, member: AisecDecodedMember) -> Verifier:
        """Verify one member entry and its payload structure.

        :param index: Position of the member in the member table.
        :param member: Decoded member.
        :return: Verifier with the results.
        """
        entry = member.entry
        ver = Verifier(f"Member {index}: {entry.name}")
        ver.add_record("Member ID", entry.member_id == index, entry.member_id)
        ver.add_record_enum("Protection", entry.protection, AisecProtection)
        ver.add_record_enum("Block size", entry.block_size_enum, AisecBlockSize)
        if not AisecMemberType.contains(entry.member_type):
            ver.add_record(
                "Member type",
                VerifierResult.WARNING,
                f"unknown informational type 0x{entry.member_type:02X}",
            )
        if member.block_size is not None:
            # computed on the u64 quotient, so a wrapped u32 block_count cannot match
            expected = -(-entry.plain_size // member.block_size)
            ver.add_record(
                "Block count",
                expected == entry.block_count,
                f"{entry.block_count} (expected {expected})",
            )
            if not member.problems and expected == entry.block_count:
                self._verify_block_lengths(ver, member)
        for problem in member.problems:
            ver.add_record("Payload structure", False, problem)
        if entry.protection == AisecProtection.NONE.tag:
            influencing = is_load_influencing(entry.name)
            ver.add_record(
                "Plaintext policy",
                not influencing,
                (
                    "protection 'none' is not allowed for a load-influencing member"
                    if influencing
                    else "inert member"
                ),
            )
            zero = bytes(MAC_SIZE)
            ver.add_record(
                "MACs must be zero",
                entry.member_root_mac == zero
                and all(b.header.block_mac == zero for b in member.blocks),
                "protection 'none'",
            )
        return ver

    @staticmethod
    def _verify_block_lengths(ver: Verifier, member: AisecDecodedMember) -> None:
        """Verify the block lengths of a member against its plain size.

        :param ver: Verifier to add the result to.
        :param member: Decoded member with a consistent block count.
        """
        assert member.block_size is not None
        last = len(member.blocks) - 1
        for index, block in enumerate(member.blocks):
            expected = (
                member.entry.plain_size - last * member.block_size
                if index == last
                else member.block_size
            )
            if block.header.block_len != expected:
                ver.add_record(
                    "Block lengths",
                    False,
                    f"block {index} block_len {block.header.block_len}, expected {expected}",
                )
                return
        ver.add_record("Block lengths", True, f"{len(member.blocks)} blocks", important=False)

    # ------------------------------------------------------------------------------------
    # Cryptographic verification and member extraction
    # ------------------------------------------------------------------------------------
    def _crypto_params(self) -> tuple[AisecKdfAlg, int, int] | None:
        """Get the KDF and key sizes if they are valid.

        :return: KDF, encryption key size and authentication key size or None.
        """
        md = self.metadata
        if not (
            AisecKdfAlg.contains(md.kdf)
            and AisecKeySize.contains(md.enc_key_size)
            and AisecKeySize.contains(md.auth_key_size)
        ):
            return None
        return AisecKdfAlg.from_tag(md.kdf), md.enc_key_size, md.auth_key_size

    def _base_context(self, keys: AisecKeys) -> bytes:
        """Get the KDF base context.

        :param keys: Key material.
        :raises SPSDKError: SRKH is required for a device-bound container.
        :return: KDF base context.
        """
        if not self.metadata.binding:
            return kdf_base_context(self.descriptor.mode)
        if keys.srkh is None:
            raise SPSDKError(
                f"The container is device-bound: the {SRKH_SIZE}-byte SRKH binding root is "
                "required"
            )
        return kdf_base_context(self.descriptor.mode, keys.srkh)

    def _verify_authentication(self, keys: AisecKeys | None) -> Verifier:
        """Verify the header CMAC, block MACs and member root MACs.

        :param keys: Optional key material.
        :return: Verifier with the results.
        """
        ver = Verifier("Authentication")
        params = self._crypto_params()
        if keys is None or params is None:
            reason = NOT_VERIFIED_NO_KEY if keys is None else "not verified (invalid parameters)"
            ver.add_record("Header CMAC", VerifierResult.WARNING, reason)
            ver.add_record("Member MACs", VerifierResult.WARNING, reason)
            return ver
        kdf, enc_size, auth_size = params
        self._verify_mmk_size(ver, keys.mmk, max(enc_size, auth_size))
        try:
            base_ctx = self._base_context(keys)
        except SPSDKError as exc:
            ver.add_record("Binding root", False, str(exc))
            return ver
        auth_key = derive_auth_key(kdf, keys.mmk, base_ctx, self.metadata.container_salt, auth_size)
        header_ok = cmac(auth_key, self._header_cmac_input()) == self.auth_block.auth_data
        ver.add_record("Header CMAC", header_ok, "header is authentic" if header_ok else "mismatch")
        if not header_ok:
            ver.add_record(
                "Member MACs", VerifierResult.WARNING, "not verified (header is not authentic)"
            )
            return ver
        for index, member in enumerate(self.members):
            problem = self._verify_member_macs(auth_key, index, member)
            ver.add_record(f"Member {index} MACs", problem is None, problem or "authentic")
        return ver

    def _verify_mmk_size(self, ver: Verifier, mmk: bytes, derived_size: int) -> None:
        """Verify the length of the supplied MMK.

        :param ver: Verifier to add the result to.
        :param mmk: Supplied MMK.
        :param derived_size: Largest derived key size.
        """
        ver.add_record(
            "MMK entropy",
            len(mmk) >= derived_size,
            f"MMK {len(mmk)} B, derived keys up to {derived_size} B",
        )
        if len(mmk) != self.metadata.mmk_size:
            sealed = self.flag == AisecContainerFlag.SEALED.tag
            ver.add_record(
                "MMK size",
                VerifierResult.ERROR if sealed else VerifierResult.WARNING,
                f"supplied MMK has {len(mmk)} B, container declares {self.metadata.mmk_size} B",
            )

    def _header_cmac_input(self) -> bytes:
        """Get the data covered by the header CMAC.

        :return: Descriptor, metadata and authentication block header.
        """
        md_off = self.descriptor.container_metadata_offset
        auth_off = self.descriptor.authentication_block_offset
        return (
            self.data[:DESCRIPTOR_SIZE]
            + self.data[md_off : md_off + (self.metadata.total_len or 0)]
            + self.data[auth_off : auth_off + AUTH_BLOCK_SIZE - MAC_SIZE]
        )

    def _verify_member_macs(
        self, auth_key: bytes, index: int, member: AisecDecodedMember
    ) -> str | None:
        """Verify the block MACs and the root MAC of one member.

        :param auth_key: AUTH_DKEY.
        :param index: Position of the member in the member table.
        :param member: Decoded member.
        :return: Problem description or None if the member is authentic.
        """
        entry = member.entry
        if entry.protection == AisecProtection.NONE.tag:
            return None
        if member.problems or len(member.blocks) != entry.block_count:
            return "not verified (invalid payload structure)"
        macs: list[bytes] = []
        for block_index, block in enumerate(member.blocks):
            expected = block_mac(auth_key, index, block_index, self.block_data(block))
            if expected != block.header.block_mac:
                return f"block {block_index} MAC mismatch"
            macs.append(expected)
        root = member_root_mac(
            auth_key, index, entry.member_type, entry.protection, entry.block_size_enum, macs
        )
        return None if root == entry.member_root_mac else "member_root_mac mismatch"

    def member_plaintext(self, index: int, keys: AisecKeys | None) -> bytes | None:
        """Get the plaintext of one member.

        :param index: Position of the member in the member table.
        :param keys: Optional key material, required for enc_auth members.
        :return: Member plaintext or None if it cannot be recovered without a key.
        """
        member = self.members[index]
        blocks = [self.block_data(block) for block in member.blocks]
        if member.entry.protection != AisecProtection.ENC_AUTH.tag or not blocks:
            return b"".join(blocks)
        params = self._crypto_params()
        if keys is None or params is None or member.block_size is None:
            return None
        kdf, enc_size, _ = params
        enc_key = derive_enc_key(
            kdf,
            keys.mmk,
            self._base_context(keys),
            self.metadata.container_salt,
            index,
            enc_size,
        )
        return b"".join(
            decrypt_block(enc_key, block_index, member.block_size, block)
            for block_index, block in enumerate(blocks)
        )


def verify_container_binary(data: bytes, keys: AisecKeys | None = None) -> Verifier:
    """Decode and verify an AISEC dir-v5 container binary.

    :param data: Container binary.
    :param keys: Optional key material enabling the MAC verification.
    :return: Verifier with the results; decoding failures are reported as errors.
    """
    try:
        decoded = AisecDecodedContainer.decode(data)
    except SPSDKError as exc:
        ver = Verifier("AISEC dir-v5 container")
        ver.add_record("Container structure", False, str(exc))
        return ver
    return decoded.verify(keys)

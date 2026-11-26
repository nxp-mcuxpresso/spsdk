#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AISEC dir-v5 container cryptography (frozen KDF and MAC constructions).

Key hierarchy::

    base_ctx     = SHA256(u8(mode))                          (no binding)
                 = SHA256(u8(mode) || SHA256(SRKH))          (binding)
    ctx_auth     = SHA256(base_ctx || container_salt)
    ctx_enc[m]   = SHA256(base_ctx || container_salt || u16(member_id))
    AUTH_DKEY    = KDF(MMK, label 0xF3 / info 'modelauthdkey', ctx_auth)
    ENC_DKEY[m]  = KDF(MMK, label 0xF2 / info 'modelencdkey', ctx_enc[m])

Member payload blocks are encrypt-then-MAC: AES-CTR with the IV derived from the block
index and the block size, followed by AES-CMAC over the block domain, the member id,
the block index, the block length and the stored block data.
"""

import struct
from dataclasses import dataclass, field

from spsdk.crypto.cmac import cmac
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.hkdf import hkdf
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt
from spsdk.exceptions import SPSDKValueError
from spsdk.image.aisec.aisec_dir_blocks import AisecBlockHeader
from spsdk.image.aisec.aisec_dir_types import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAC_DOMAIN,
    HKDF_INFO_AUTH,
    HKDF_INFO_ENC,
    KDF_LABEL_AUTH,
    KDF_LABEL_ENC,
    MAC_SIZE,
    SRKH_SIZE,
    AisecKdfAlg,
    AisecProtection,
)


def _sha256(data: bytes) -> bytes:
    """Compute SHA-256 digest.

    :param data: Input data.
    :return: 32-byte digest.
    """
    return get_hash(data, EnumHashAlgorithm.SHA256)


def sp800_108_cmac_counter(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """NIST SP 800-108 KDF in counter mode with AES-CMAC as PRF.

    Fixed input per iteration: u32(i) || label || 0x00 || context || u32(length * 8).

    :param key: Key derivation key.
    :param label: KDF label.
    :param context: KDF context.
    :param length: Requested output length in bytes.
    :return: Derived key material.
    """
    out = b""
    counter = 1
    while len(out) < length:
        fixed = (
            struct.pack(">I", counter) + label + b"\x00" + context + struct.pack(">I", length * 8)
        )
        out += cmac(key, fixed)
        counter += 1
    return out[:length]


def kdf_base_context(mode: int, srkh: bytes | None = None) -> bytes:
    """Compute the 32-byte KDF base context.

    :param mode: Execution backend (container_descriptor.mode).
    :param srkh: 32-byte SRKH binding root; None disables device binding. A 32 zero bytes
        root is legitimate (software backend).
    :raises SPSDKValueError: Invalid SRKH size.
    :return: Base context.
    """
    mode_byte = bytes([mode & 0xFF])
    if srkh is None:
        return _sha256(mode_byte)
    if len(srkh) != SRKH_SIZE:
        raise SPSDKValueError(f"AISEC SRKH binding root must be {SRKH_SIZE} bytes, got {len(srkh)}")
    return _sha256(mode_byte + _sha256(srkh))


def _derive(kdf: AisecKdfAlg, mmk: bytes, label: int, context: bytes, length: int) -> bytes:
    """Derive a key with the selected KDF.

    :param kdf: Key derivation function.
    :param mmk: Master model key.
    :param label: KDF label (SP 800-108); also selects the HKDF info.
    :param context: KDF context, used as HKDF salt.
    :param length: Output length in bytes.
    :return: Derived key.
    """
    if kdf == AisecKdfAlg.SP800_108_CMAC:
        return sp800_108_cmac_counter(mmk, bytes([label]), context, length)
    info = HKDF_INFO_ENC if label == KDF_LABEL_ENC else HKDF_INFO_AUTH
    return hkdf(salt=context, ikm=mmk, info=info, length=length)


def derive_auth_key(
    kdf: AisecKdfAlg, mmk: bytes, base_ctx: bytes, container_salt: bytes, length: int
) -> bytes:
    """Derive the container authentication key AUTH_DKEY.

    :param kdf: Key derivation function.
    :param mmk: Master model key.
    :param base_ctx: KDF base context.
    :param container_salt: 16-byte container salt.
    :param length: Key length in bytes.
    :return: AUTH_DKEY.
    """
    return _derive(kdf, mmk, KDF_LABEL_AUTH, _sha256(base_ctx + container_salt), length)


def derive_enc_key(
    kdf: AisecKdfAlg,
    mmk: bytes,
    base_ctx: bytes,
    container_salt: bytes,
    member_id: int,
    length: int,
) -> bytes:
    """Derive the per-member encryption key ENC_DKEY[member_id].

    :param kdf: Key derivation function.
    :param mmk: Master model key.
    :param base_ctx: KDF base context.
    :param container_salt: 16-byte container salt.
    :param member_id: Member identifier.
    :param length: Key length in bytes.
    :return: ENC_DKEY of the member.
    """
    ctx = _sha256(base_ctx + container_salt + struct.pack(">H", member_id))
    return _derive(kdf, mmk, KDF_LABEL_ENC, ctx, length)


def counter_iv(block_index: int, block_size: int) -> bytes:
    """Get the AES-CTR initial counter block of a payload block.

    The counter is the 128-bit big-endian value block_index * (block_size / 16), so the
    member keystream is continuous across blocks.

    :param block_index: Index of the block within the member.
    :param block_size: Member block size in bytes.
    :return: 16-byte initial counter block.
    """
    return ((block_index * (block_size // 16)) % (1 << 128)).to_bytes(16, "big")


def block_mac(auth_key: bytes, member_id: int, block_index: int, block_data: bytes) -> bytes:
    """Compute the MAC of one stored payload block.

    :param auth_key: AUTH_DKEY.
    :param member_id: Member identifier.
    :param block_index: Index of the block within the member.
    :param block_data: Stored (encrypted for enc_auth) block data.
    :return: 16-byte block MAC.
    """
    return cmac(
        auth_key,
        struct.pack(">BHII", BLOCK_MAC_DOMAIN, member_id, block_index, len(block_data))
        + block_data,
    )


def member_root_mac(
    auth_key: bytes,
    member_id: int,
    member_type: int,
    protection: int,
    block_size_enum: int,
    block_macs: list[bytes],
) -> bytes:
    """Compute the member root MAC over the explicit member field list.

    :param auth_key: AUTH_DKEY.
    :param member_id: Member identifier.
    :param member_type: Member type value.
    :param protection: Member protection value.
    :param block_size_enum: Member block size enumeration value.
    :param block_macs: MACs of all member blocks in order.
    :return: 16-byte member root MAC.
    """
    data = struct.pack(
        ">HBBBI", member_id, member_type, protection, block_size_enum, len(block_macs)
    ) + b"".join(block_macs)
    return cmac(auth_key, data)


@dataclass
class AisecMemberPayload:
    """Serialized payload of one member with its computed MACs."""

    data: bytes
    block_macs: list[bytes] = field(default_factory=list)
    root_mac: bytes = bytes(MAC_SIZE)


def build_member_payload(
    plain: bytes,
    member_id: int,
    member_type: int,
    protection: AisecProtection,
    block_size_enum: int,
    block_size: int,
    auth_key: bytes,
    enc_key: bytes | None = None,
) -> AisecMemberPayload:
    """Build the member payload: fixed-stride blocks, each with an inline block header.

    :param plain: Member plaintext.
    :param member_id: Member identifier.
    :param member_type: Member type value.
    :param protection: Member protection level.
    :param block_size_enum: Member block size enumeration value.
    :param block_size: Member block size in bytes.
    :param auth_key: AUTH_DKEY.
    :param enc_key: ENC_DKEY of the member, required for enc_auth members.
    :raises SPSDKValueError: Missing encryption key for an enc_auth member.
    :return: Member payload.
    """
    if protection == AisecProtection.ENC_AUTH and enc_key is None:
        raise SPSDKValueError(f"Missing encryption key for enc_auth AISEC member {member_id}")
    out = bytearray()
    macs: list[bytes] = []
    for block_index, offset in enumerate(range(0, len(plain), block_size)):
        chunk = plain[offset : offset + block_size]
        if protection == AisecProtection.ENC_AUTH:
            assert enc_key is not None
            chunk = aes_ctr_encrypt(enc_key, chunk, counter_iv(block_index, block_size))
        mac = (
            bytes(MAC_SIZE)
            if protection == AisecProtection.NONE
            else block_mac(auth_key, member_id, block_index, chunk)
        )
        out += AisecBlockHeader(block_index, len(chunk), mac).export() + chunk
        macs.append(mac)
    root = (
        bytes(MAC_SIZE)
        if protection == AisecProtection.NONE
        else member_root_mac(
            auth_key, member_id, member_type, protection.tag, block_size_enum, macs
        )
    )
    return AisecMemberPayload(data=bytes(out), block_macs=macs, root_mac=root)


def decrypt_block(enc_key: bytes, block_index: int, block_size: int, block_data: bytes) -> bytes:
    """Decrypt one stored enc_auth payload block.

    :param enc_key: ENC_DKEY of the member.
    :param block_index: Index of the block within the member.
    :param block_size: Member block size in bytes.
    :param block_data: Stored encrypted block data.
    :return: Block plaintext.
    """
    return aes_ctr_decrypt(enc_key, block_data, counter_iv(block_index, block_size))


def payload_size(plain_size: int, block_size: int) -> int:
    """Get the serialized member payload size.

    :param plain_size: Member plaintext size.
    :param block_size: Member block size in bytes.
    :return: Payload size including the inline block headers.
    """
    return plain_size + -(-plain_size // block_size) * BLOCK_HEADER_SIZE

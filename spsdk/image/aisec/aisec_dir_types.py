#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AISEC dir-v5 container enumerations and constants.

All values are taken from the authoritative AISEC dir schema (``aisec_schema_dir.yaml``).
"""

from spsdk.utils.spsdk_enum import SpsdkEnum

# Container format version (container_descriptor.version)
AISEC_DIR_VERSION = 0x05

# Block tags
TAG_DESCRIPTOR = 0x81
TAG_METADATA = 0x82
TAG_AUTH_BLOCK = 0x83
TAG_MMK_BLOCK = 0x84

# Fixed sizes
DESCRIPTOR_SIZE = 24
METADATA_FIXED_PREFIX_SIZE = 40
MEMBER_ENTRY_FIXED_SIZE = 52
AUTH_BLOCK_SIZE = 20
MMK_BLOCK_PREFIX_SIZE = 4
MMK_BLOCK_MAX_BLOB_SIZE = 0xFFFF - MMK_BLOCK_PREFIX_SIZE
BLOCK_HEADER_SIZE = 24
CONTAINER_SALT_SIZE = 16
MAC_SIZE = 16
SRKH_SIZE = 32
MAX_MEMBER_COUNT = 0xFFFF

# Cryptographic domain constants (frozen KDF construction)
BLOCK_MAC_DOMAIN = 0xB5
KDF_LABEL_ENC = 0xF2
KDF_LABEL_AUTH = 0xF3
HKDF_INFO_ENC = b"modelencdkey"
HKDF_INFO_AUTH = b"modelauthdkey"
KDF_BINDING_FLAG = 0x80
KDF_ALG_MASK = 0x7F

# ELE/HSM persistent key-id range for keystore-resolved MMK
ELE_PERSISTENT_KEY_ID_MIN = 0x00000001
ELE_PERSISTENT_KEY_ID_MAX = 0x3FFFFFFF

# Basename patterns (case-insensitive) of load-influencing members, which must never use
# protection 'none' (validation_rules.plaintext_member_policy - the list is a floor)
AISEC_LOAD_INFLUENCING_PATTERNS = (
    "*.dvm",
    "*.onnx",
    "*.tflite",
    "*.pte",
    "*.gguf",
    "*.safetensors",
    "*.bin",
    "*.pt",
    "*.pth",
    "*.so",
    "*.a",
    "*.elf",
    "*config*.json",
    "tokenizer*",
    "vocab*",
    "merges*",
    "*.model",
    "special_tokens_map.json",
    "*.index.json",
    "*.manifest",
    "*.list",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.ini",
)


class AisecContainerFlag(SpsdkEnum):
    """Container custody flag (container_descriptor.flag)."""

    INTEGRATED = (
        0x11,
        "integrated",
        "Integrated provisioning - MMK delivered by an opaque ELE/EL2GO provisioning blob",
    )
    DISCRETE = (
        0x12,
        "discrete",
        "Discrete provisioning - POST_MMK resolved from the keystore by mmk_id",
    )
    SEALED = (
        0x91,
        "sealed",
        "Installed, device-bound - DIE_MMK sealed in the keystore (on-device only)",
    )


# Flags that the host-side builder can produce
AISEC_BUILDABLE_FLAGS = (AisecContainerFlag.INTEGRATED, AisecContainerFlag.DISCRETE)


class AisecMode(SpsdkEnum):
    """Execution backend (container_descriptor.mode)."""

    SW = (0x00, "sw_primitive_backend", "Software backend (testing and development only)")
    OPTEE = (0x01, "optee_primitive_backend", "OP-TEE backend")
    ELE = (0x02, "ele_primitive_backend", "EdgeLock Secure Enclave backend")


class AisecProtection(SpsdkEnum):
    """Per-member protection level (member_entry.protection)."""

    NONE = (0x00, "none", "Plaintext, no integrity protection")
    AUTH_ONLY = (0x01, "auth_only", "Plaintext, AES-CMAC authenticated")
    ENC_AUTH = (0x02, "enc_auth", "AES-CTR encrypted and AES-CMAC authenticated")


class AisecMemberType(SpsdkEnum):
    """Informational member artifact type (member_entry.member_type)."""

    RAW = (0x00, "raw", "Raw data")
    DVM = (0x01, "dvm", "DVM model")
    ONNX = (0x02, "onnx", "ONNX model")
    TFLITE = (0x03, "tflite", "TensorFlow Lite model")
    EXECUTORCH_PTE = (0x04, "executorch_pte", "ExecuTorch PTE model")
    GGUF = (0x05, "gguf", "GGUF model")
    SAFETENSORS = (0x06, "safetensors", "Safetensors model")
    OTHER = (0xFF, "other", "Other artifact")


# Member type derived from the file extension
AISEC_MEMBER_TYPE_BY_EXT = {
    ".dvm": AisecMemberType.DVM,
    ".onnx": AisecMemberType.ONNX,
    ".tflite": AisecMemberType.TFLITE,
    ".pte": AisecMemberType.EXECUTORCH_PTE,
    ".gguf": AisecMemberType.GGUF,
    ".safetensors": AisecMemberType.SAFETENSORS,
}


class AisecEncAlg(SpsdkEnum):
    """Global encryption algorithm (container_metadata.enc_alg)."""

    AES_CTR = (0x02, "aes_ctr", "AES-CTR")


class AisecAuthAlg(SpsdkEnum):
    """Global authentication algorithm (container_metadata.auth_alg)."""

    AES_CMAC = (0x01, "aes_cmac", "AES-CMAC")


class AisecKeySize(SpsdkEnum):
    """Key size (container_metadata.enc_key_size/auth_key_size/mmk_size_enum)."""

    AES_128 = (0x10, "16", "128-bit key")
    AES_192 = (0x18, "24", "192-bit key")
    AES_256 = (0x20, "32", "256-bit key")

    @property
    def size(self) -> int:
        """Key size in bytes.

        :return: Key size in bytes.
        """
        return self.tag

    @classmethod
    def from_size(cls, size: int) -> "AisecKeySize":
        """Get key size enum from the size in bytes.

        :param size: Key size in bytes.
        :return: Key size enumeration member.
        """
        return cls.from_tag(size)


class AisecKdfAlg(SpsdkEnum):
    """Key derivation function (container_metadata.kdf_alg & 0x7F)."""

    SP800_108_CMAC = (0x01, "sp800_108_cmac", "NIST SP 800-108 counter mode with AES-CMAC")
    HKDF_SHA256 = (0x02, "hkdf_sha256", "HKDF with SHA-256 (RFC 5869)")


class AisecBlockSize(SpsdkEnum):
    """Per-member plaintext block size (member_entry.block_size_enum)."""

    B64K = (0x00, "b64k", "64 KiB blocks")
    B256K = (0x01, "b256k", "256 KiB blocks")
    B512K = (0x02, "b512k", "512 KiB blocks")
    B1M = (0x03, "b1m", "1 MiB blocks")
    B4M = (0x04, "b4m", "4 MiB blocks")

    @property
    def size(self) -> int:
        """Block size in bytes.

        :return: Block size in bytes.
        """
        return AISEC_BLOCK_SIZES[self.tag]


AISEC_BLOCK_SIZES = {
    0x00: 0x10000,
    0x01: 0x40000,
    0x02: 0x80000,
    0x03: 0x100000,
    0x04: 0x400000,
}

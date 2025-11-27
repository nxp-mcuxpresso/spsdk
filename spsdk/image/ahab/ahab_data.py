#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB data storage classes and various constants.

This module provides data structures, enumerations, and utility functions for working with
Advanced High Assurance Boot (AHAB) components. It includes definitions for target memories,
cryptographic algorithms, container tags, and configuration helpers required for secure boot
image creation.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Type, Union

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.database import DatabaseManager, Features
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.spsdk_enum import SpsdkEnum, SpsdkSoftEnum

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
INT32 = "l"
UINT64 = "Q"
RESERVED = 0
CONTAINER_ALIGNMENT = 8


class AhabTargetMemory(SpsdkEnum):
    """AHAB target memory enumeration for SPSDK operations.

    This enumeration defines the supported target memory types used in AHAB
    (Advanced High Assurance Boot) operations, including serial downloader,
    NOR flash, NAND flash variants, and standard memory configurations.
    """

    TARGET_MEMORY_SERIAL_DOWNLOADER = (0, "serial_downloader")
    TARGET_MEMORY_NOR = (1, "nor")
    TARGET_MEMORY_NAND_4K = (2, "nand_4k")
    TARGET_MEMORY_NAND_2K = (3, "nand_2k")
    TARGET_MEMORY_STANDARD = (4, "standard")
    TARGET_MEMORY_SD_EMMC = (5, "sd_emmc")


@dataclass
class TargetMemoryDescr:
    """Data class representing target memory configuration details."""

    memory_type: AhabTargetMemory = field(default=AhabTargetMemory.TARGET_MEMORY_STANDARD)
    image_offset_alignment: int = 1
    image_size_alignment: int = 1
    is_nand: bool = False
    force_no_gaps: bool = False


MEMORY_TARGET_DESCRIPTIONS = {
    AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER,
        image_offset_alignment=4,
        image_size_alignment=1,
        force_no_gaps=True,
    ),
    AhabTargetMemory.TARGET_MEMORY_NOR: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_NOR,
        image_offset_alignment=1024,
        image_size_alignment=1,
    ),
    AhabTargetMemory.TARGET_MEMORY_NAND_2K: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_NAND_2K,
        image_offset_alignment=2048,
        image_size_alignment=1,
        is_nand=True,
    ),
    AhabTargetMemory.TARGET_MEMORY_NAND_4K: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_NAND_4K,
        image_offset_alignment=4096,
        image_size_alignment=1,
        is_nand=True,
    ),
    AhabTargetMemory.TARGET_MEMORY_STANDARD: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_STANDARD,
        image_offset_alignment=1024,
        image_size_alignment=1,
    ),
    AhabTargetMemory.TARGET_MEMORY_SD_EMMC: TargetMemoryDescr(
        memory_type=AhabTargetMemory.TARGET_MEMORY_SD_EMMC,
        image_offset_alignment=1024,
        image_size_alignment=512,
    ),
}


class AHABTags(SpsdkEnum):
    """AHAB container tag definitions for secure boot operations.

    This enumeration defines standardized tags used in AHAB (Advanced High Assurance Boot)
    container structures for NXP secure boot implementations. Each tag identifies specific
    data blocks within AHAB containers including cryptographic elements, headers, and
    signature components.
    """

    SRK_TABLE_ARRAY = (0x5A, "SRK table array.")
    SRK_DATA = (0x5D, "SRK Data.")
    BLOB = (0x81, "Blob (Wrapped Data Encryption Key).")
    CONTAINER_HEADER_V1_WITH_V2 = (
        0x82,
        "Container header of container version 1 used with containers V2.",
    )
    CONTAINER_HEADER = (0x87, "Container header.")
    SIGNATURE_BLOCK = (0x90, "Signature block.")
    CERTIFICATE = (0xAF, "Certificate.")
    SRK_TABLE = (0xD7, "SRK table.")
    SIGNATURE = (0xD8, "Signature part of signature block.")
    SRK_RECORD = (0xE1, "SRK record.")


class AHABSignAlgorithm(SpsdkEnum):
    """AHAB signature algorithm enumeration.

    This enumeration defines the supported signature algorithms for AHAB
    (Advanced High Assurance Boot) image authentication and verification.
    """


class AHABSignAlgorithmV1(AHABSignAlgorithm):
    """AHAB signature algorithm enumeration for version 1.

    This class defines the supported cryptographic signature algorithms
    for AHAB (Advanced High Assurance Boot) version 1, including their
    numeric identifiers and descriptive names.

    :cvar RSA: RSA signature algorithm with PKCS#1 v1.5 padding
    :cvar RSA_PSS: RSA signature algorithm with PSS padding scheme
    :cvar ECDSA: Elliptic Curve Digital Signature Algorithm
    :cvar SM2: Chinese national cryptography standard signature algorithm
    """

    RSA = (0x21, "RSA", "Rivest–Shamir–Adleman")
    RSA_PSS = (0x22, "RSA_PSS", "Rivest–Shamir–Adleman with PSS padding")
    ECDSA = (0x27, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    SM2 = (0x28, "SM2", "Chinese national cryptography standard")


class AHABSignAlgorithmV2(AHABSignAlgorithm):
    """AHAB signature algorithm enumeration for version 2.

    This class defines the supported cryptographic signature algorithms for AHAB
    (Advanced High Assurance Boot) version 2, including traditional algorithms
    like RSA and ECDSA, as well as post-quantum cryptography standards.

    :cvar RSA: Rivesta-Shamira-Adleman signature algorithm
    :cvar RSA_PSS: RSA with Probabilistic Signature Scheme padding
    :cvar ECDSA: Elliptic Curve Digital Signature Algorithm
    :cvar SM2: Chinese national cryptography standard
    :cvar DILITHIUM: Post-quantum cryptography standard candidate
    :cvar ML_DSA: Module-Lattice-Based Digital Signature Algorithm
    """

    RSA = (0x21, "RSA", "Rivest–Shamir–Adleman")
    RSA_PSS = (0x22, "RSA_PSS", "Rivest–Shamir–Adleman with PSS padding")
    ECDSA = (0x27, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    SM2 = (0x28, "SM2", "Chinese national cryptography standard")
    DILITHIUM = (0xD1, "DILITHIUM", "Post quantum cryptography standard candidate")
    ML_DSA = (0xD2, "ML-DSA", "Post quantum cryptography standard candidate")


class AHABSignHashAlgorithm(SpsdkEnum):
    """AHAB signature hash algorithm enumeration.

    This enumeration defines the supported hash algorithms for AHAB (Advanced High Assurance Boot)
    signature operations in NXP secure boot implementations.
    """


class AHABSignHashAlgorithmV1(AHABSignHashAlgorithm):
    """AHAB signature hash algorithm enumeration for version 1.

    This class defines the supported cryptographic hash algorithms for AHAB
    (Advanced High Assurance Boot) signature operations in version 1 format.

    :cvar SHA256: SHA-256 hash algorithm identifier and metadata.
    :cvar SHA384: SHA-384 hash algorithm identifier and metadata.
    :cvar SHA512: SHA-512 hash algorithm identifier and metadata.
    :cvar SM3: SM3 hash algorithm identifier and metadata.
    """

    SHA256 = (0x00, "SHA256", "Secure Hash Algorithm 256")
    SHA384 = (0x01, "SHA384", "Secure Hash Algorithm 384")
    SHA512 = (0x02, "SHA512", "Secure Hash Algorithm 512")
    SM3 = (
        0x03,
        "SM3",
        "Cryptographic hash function used in the Chinese National Standard",
    )


class AHABSignHashAlgorithmV2(AHABSignHashAlgorithm):
    """AHAB signature hash algorithm enumeration for version 2.

    Extended enumeration of cryptographic hash algorithms supported by AHAB
    (Advanced High Assurance Boot) version 2, including traditional SHA variants,
    Chinese national standard SM3, SHA-3 family, and SHAKE algorithms.
    """

    SHA256 = (0x00, "SHA256", "Secure Hash Algorithm 256")
    SHA384 = (0x01, "SHA384", "Secure Hash Algorithm 384")
    SHA512 = (0x02, "SHA512", "Secure Hash Algorithm 512")
    SM3 = (
        0x03,
        "SM3",
        "Cryptographic hash function used in the Chinese National Standard",
    )
    SHA3_256 = (4, "SHA3_256", "Secure Hash Algorithm 3 - 256")
    SHA3_384 = (5, "SHA3_384", "Secure Hash Algorithm 3 - 384")
    SHA3_512 = (6, "SHA3_512", "Secure Hash Algorithm 3 - 512")
    SHAKE_128_256 = (
        8,
        "SHAKE_128_256",
        "Secure Hash Algorithm Shake 128 - with 256 bits output",
    )
    SHAKE_256_512 = (
        9,
        "SHAKE_256_512",
        "Secure Hash Algorithm Shake 256 - with 512 bits output",
    )


class FlagsSrkSet(SpsdkSoftEnum):
    """AHAB SRK Set flags enumeration.

    This enumeration defines the available SRK (Super Root Key) set flags used in AHAB
    (Advanced High Assurance Boot) image containers to indicate the signing authority
    and key set type for secure boot verification.
    """

    NONE = (0x00, "none", "Image is not signed")
    NXP = (0x01, "nxp", "Signed by NXP keys")
    OEM = (0x02, "oem", "Signed by OEM keys")
    DEVHSM = (0x05, "devhsm", "Device HSM key set")


class SignatureType(SpsdkEnum):
    """AHAB container signature type enumeration.

    This enumeration defines the available signature types that can be used
    in AHAB (Advanced High Assurance Boot) containers for secure boot operations.
    """

    SRK_TABLE = (
        0x0,
        "SRK table",
        "Signature type defined by SRK table (SRK table must be present)",
    )
    CMAC = (0x10, "CMAC", "CMAC signature")


class DummyEnum(SpsdkSoftEnum):
    """Dummy enumeration for AHAB core identifiers.

    This enumeration provides placeholder values for AHAB (Advanced High Assurance Boot)
    core identification when actual core IDs are not available or needed for testing
    purposes.
    """

    DUMMY = (0x00, "dummy")


class KeyImportSigningAlgorithm(SpsdkEnum):
    """AHAB Key Import Signing Algorithm enumeration.

    This enumeration defines the valid signing algorithms that can be used
    for key import operations in AHAB (Advanced High Assurance Boot) images.

    :cvar CMAC: Cipher-based Message Authentication Code algorithm.
    """

    CMAC = (0x01, "CMAC")


class KeyAlgorithm(SpsdkEnum):
    """EdgeLock Secure Enclave cryptographic algorithm enumeration.

    This enumeration defines all cryptographic algorithms supported by the EdgeLock Secure Enclave,
    including hash algorithms (MD5, SHA variants), MAC algorithms (HMAC, CMAC), cipher algorithms
    (ECB, CBC, CTR, CFB, OFB), AEAD algorithms (CCM, GCM, ChaCha20-Poly1305), and signature
    algorithms (ECDSA, RSA PKCS#1). Each algorithm is identified by its unique numeric identifier
    used in AHAB container operations.
    """

    # Hash Algorithms
    MD5 = (0x02000003, "MD5", "MD5 hash algorithm")
    SHA1 = (0x02000005, "SHA1", "SHA1 hash algorithm")
    SHA224 = (0x02000008, "SHA224", "SHA224 hash algorithm")
    SHA256 = (0x02000009, "SHA256", "SHA256 hash algorithm")
    SHA384 = (0x0200000A, "SHA384", "SHA384 hash algorithm")
    SHA512 = (0x0200000B, "SHA512", "SHA512 hash algorithm")
    SHA3_224 = (0x02000010, "SHA3_224", "SHA3-224 hash algorithm")
    SHA3_256 = (0x02000011, "SHA3_256", "SHA3-256 hash algorithm")
    SHA3_384 = (0x02000012, "SHA3_384", "SHA3-384 hash algorithm")
    SHA3_512 = (0x02000013, "SHA3_512", "SHA3-512 hash algorithm")
    SHAKE256 = (0x02000015, "SHAKE256", "SHAKE256 hash algorithm")

    # MAC Algorithms
    HMAC_SHA256 = (0x03800009, "HMAC SHA256", "HMAC SHA256 algorithm")
    HMAC_SHA384 = (0x0380000A, "HMAC SHA384", "HMAC SHA384 algorithm")
    CMAC = (0x03C00200, "CMAC", "CMAC algorithm")

    # Cipher Algorithms
    ECB_NO_PADDING = (0x04404400, "ECB NO PADDING", "ECB no padding cipher")
    CBC_NO_PADDING = (0x04404000, "CBC NO PADDING", "CBC no padding cipher")
    CTR = (0x04C01000, "CTR", "CTR cipher mode")
    CFB = (0x04C01100, "CFB", "CFB cipher mode")
    OFB = (0x04C01200, "OFB", "OFB cipher mode")
    ALL_CIPHER = (0x84C0FF00, "ALL CIPHER", "All supported cipher algorithms")

    # AEAD Algorithms
    CCM = (0x05500100, "CCM", "CCM AEAD algorithm")
    GCM = (0x05500200, "GCM", "GCM AEAD algorithm")
    CHACHA20_POLY1305 = (0x05100500, "CHACHA20_POLY1305", "ChaCha20-Poly1305 AEAD")
    ALL_AEAD = (0x8550FF00, "ALL AEAD", "All supported AEAD algorithms")

    # Signature Algorithms
    ECDSA_SHA224 = (0x06000608, "ECDSA SHA224", "ECDSA with SHA224")
    ECDSA_SHA256 = (0x06000609, "ECDSA SHA256", "ECDSA with SHA256")
    ECDSA_SHA384 = (0x0600060A, "ECDSA SHA384", "ECDSA with SHA384")
    ECDSA_SHA512 = (0x0600060B, "ECDSA SHA512", "ECDSA with SHA512")
    RSA_PKCS1_V15_SHA224 = (0x06000208, "RSA PKCS1 V1.5 SHA224", "RSA PKCS#1 v1.5 with SHA224")
    RSA_PKCS1_V15_SHA256 = (0x06000209, "RSA PKCS1 V1.5 SHA256", "RSA PKCS#1 v1.5 with SHA256")
    RSA_PKCS1_V15_SHA384 = (0x0600020A, "RSA PKCS1 V1.5 SHA384", "RSA PKCS#1 v1.5 with SHA384")
    RSA_PKCS1_V15_SHA512 = (0x0600020B, "RSA PKCS1 V1.5 SHA512", "RSA PKCS#1 v1.5 with SHA512")
    RSA_PKCS1_V15_SHA_ANY = (0x060002FF, "RSA PKCS1 V1.5 SHA ANY", "RSA PKCS#1 v1.5 with any SHA")
    RSA_PKCS1_PSS_MGF1_SHA224 = (
        0x06000308,
        "RSA PKCS1 PSS MGF1 SHA224",
        "RSA PKCS#1 PSS MGF1 with SHA224",
    )
    RSA_PKCS1_PSS_MGF1_SHA256 = (
        0x06000309,
        "RSA PKCS1 PSS MGF1 SHA256",
        "RSA PKCS#1 PSS MGF1 with SHA256",
    )
    RSA_PKCS1_PSS_MGF1_SHA384 = (
        0x0600030A,
        "RSA PKCS1 PSS MGF1 SHA384",
        "RSA PKCS#1 PSS MGF1 with SHA384",
    )
    RSA_PKCS1_PSS_MGF1_SHA512 = (
        0x0600030B,
        "RSA PKCS1 PSS MGF1 SHA512",
        "RSA PKCS#1 PSS MGF1 with SHA512",
    )
    RSA_PKCS1_PSS_MGF1_SHA_ANY = (
        0x060003FF,
        "RSA PKCS1 PSS MGF1 SHA ANY",
        "RSA PKCS#1 PSS MGF1 with any SHA",
    )
    RSA_PKCS1_ALL = (0x8600FF00, "RSA PKCS1 ALL", "All RSA PKCS#1 algorithms")
    ED25519PH = (0x0600090B, "ED25519PH", "Ed25519ph signature algorithm")
    ED448PH = (0x06000915, "ED448PH", "Ed448ph signature algorithm")
    PURE_EDDSA = (0x06000800, "PURE EDDSA", "Pure EdDSA signature algorithm")
    ALL_EDDSA = (0x86000800, "ALL EDDSA", "All EdDSA algorithms")

    # Public Key Attestation Algorithms
    CMAC_ATTESTATION = (0x83C00200, "CMAC ATTESTATION", "CMAC attestation algorithm")
    ECDSA_SHA224_ATTESTATION = (0x86000608, "ECDSA SHA224 ATTESTATION", "ECDSA SHA224 attestation")
    ECDSA_SHA256_ATTESTATION = (0x86000609, "ECDSA SHA256 ATTESTATION", "ECDSA SHA256 attestation")
    ECDSA_SHA384_ATTESTATION = (0x8600060A, "ECDSA SHA384 ATTESTATION", "ECDSA SHA384 attestation")
    ECDSA_SHA512_ATTESTATION = (0x8600060B, "ECDSA SHA512 ATTESTATION", "ECDSA SHA512 attestation")

    # Asymmetric Encryption/Decryption Algorithms
    RSA_PKCS1_V15_CRYPT = (0x07000200, "RSA PKCS1 V1.5 CRYPT", "RSA PKCS#1 v1.5 encryption")
    RSA_PKCS1_OAEP_SHA1 = (0x07000305, "RSA PKCS1 OAEP SHA1", "RSA PKCS#1 OAEP with SHA1")
    RSA_PKCS1_OAEP_SHA224 = (0x07000308, "RSA PKCS1 OAEP SHA224", "RSA PKCS#1 OAEP with SHA224")
    RSA_PKCS1_OAEP_SHA256 = (0x07000309, "RSA PKCS1 OAEP SHA256", "RSA PKCS#1 OAEP with SHA256")
    RSA_PKCS1_OAEP_SHA384 = (0x0700030A, "RSA PKCS1 OAEP SHA384", "RSA PKCS#1 OAEP with SHA384")
    RSA_PKCS1_OAEP_SHA512 = (0x0700030B, "RSA PKCS1 OAEP SHA512", "RSA PKCS#1 OAEP with SHA512")

    # Key Exchange Algorithms
    ECDH_HKDF_SHA256_KEY_IMPORT = (
        0x09020109,
        "ECDH HKDF SHA256 KEY IMPORT",
        "ECDH HKDF SHA256 for key import",
    )
    ECDH_HKDF_SHA384_KEY_IMPORT = (
        0x0902010A,
        "ECDH HKDF SHA384 KEY IMPORT",
        "ECDH HKDF SHA384 for key import",
    )
    ECDH_HKDF_SHA_ANY_KEY_IMPORT = (
        0x090201FF,
        "ECDH HKDF SHA ANY KEY IMPORT",
        "ECDH HKDF with any SHA for key import",
    )
    ECDH_HKDF_SHA256 = (0x89020109, "ECDH HKDF SHA256", "ECDH HKDF SHA256")
    ECDH_HKDF_SHA384 = (0x8902010A, "ECDH HKDF SHA384", "ECDH HKDF SHA384")
    ECDH_HKDF_SHA_ANY = (0x890201FF, "ECDH HKDF SHA ANY", "ECDH HKDF with any SHA")

    # Legacy aliases for backward compatibility
    HKDF_SHA256 = (
        0x09020109,
        "HKDF SHA256",
        "ECDH HKDF SHA256 for key import",
    )
    HKDF_SHA384 = (
        0x0902010A,
        "HKDF SHA384",
        "ECDH HKDF SHA384 for key import",
    )


class KeyDerivationAlgorithm(SpsdkEnum):
    """AHAB Key Derivation Algorithm enumeration.

    This enumeration defines the supported key derivation algorithms for AHAB
    (Advanced High Assurance Boot) operations, including HKDF variants with
    different SHA hash functions.
    """

    HKDF_SHA256 = (0x08000109, "HKDF SHA256", "HKDF SHA256 (HMAC two-step)")
    HKDF_SHA384 = (0x0800010A, "HKDF SHA384", "HKDF SHA384 (HMAC two-step)")


class KeyType(SpsdkEnum):
    """AHAB cryptographic key type enumeration.

    This enumeration defines the valid key types supported by the AHAB (Advanced High Assurance Boot)
    security subsystem, including symmetric keys (AES, HMAC), derived keys, OEM import keys, and
    asymmetric keys (ECC). Each key type specifies supported bit widths and cryptographic properties.
    """

    AES = (0x2400, "AES", "Possible bit widths: 128/192/256")
    HMAC = (0x1100, "HMAC", "Possible bit widths: 224/256/384/512")
    DERIVE = (0x1200, "Derived key", "Possible bit widths: 256/384")
    OEM_IMPORT_MK_SK = (0x9200, "OEM_IMPORT_MK_SK", "Possible bit widths: 128/192/256")
    ECC = (0x7112, "ECC NIST", "Possible bit widths: 128/192/256")


class LifeCycle(SpsdkEnum):
    """AHAB chip lifecycle enumeration.

    This enumeration defines the valid lifecycle states for AHAB (Advanced High Assurance Boot)
    enabled chips, representing different security and operational modes from development
    through production deployment.
    """

    CURRENT = (0x00, "CURRENT", "Current device lifecycle")
    OPEN = (0x01, "OPEN")
    CLOSED = (0x02, "CLOSED")
    OPEN_CLOSED = (0x03, "OPEN_CLOSED")
    LOCKED = (0x04, "LOCKED")


class LifeTime(SpsdkEnum):
    """EdgeLock Enclave lifetime enumeration for key and data persistence.

    This enumeration defines valid lifetime values for keys and data in EdgeLock
    Enclave systems, including standard lifetime options and specialized values
    for EdgeLock secure enclave key import and EdgeLock 2 GO operations.
    """

    VOLATILE = (0x00, "VOLATILE", "Standard volatile key")
    PERSISTENT = (0x01, "PERSISTENT", "Standard persistent key")
    PERMANENT = (0xFF, "PERMANENT", "Standard permanent key")

    ELE_KEY_IMPORT_VOLATILE = (
        0xC0020000,
        "ELE_KEY_IMPORT_VOLATILE",
        "EdgeLock® secure enclave Key import volatile key",
    )
    ELE_KEY_IMPORT_PERSISTENT = (
        0xC0020001,
        "ELE_KEY_IMPORT_PERSISTENT",
        "EdgeLock® secure enclave Key import persistent key",
    )
    ELE_KEY_IMPORT_PERMANENT = (
        0xC00200FF,
        "ELE_KEY_IMPORT_PERMANENT",
        "EdgeLock® secure enclave Key import permanent key",
    )

    EL2GO_KEY_IMPORT_VOLATILE = (
        0xE0000400,
        "EL2GO_KEY_IMPORT_VOLATILE",
        "EdgeLock® 2 GO Key Import volatile key",
    )
    EL2GO_KEY_IMPORT_PERSISTENT = (
        0xE0000401,
        "EL2GO_KEY_IMPORT_PERSISTENT",
        "EdgeLock® 2 GO Key Import persistent key",
    )
    EL2GO_KEY_IMPORT_PERMANENT = (
        0xE00004FF,
        "EL2GO_KEY_IMPORT_PERMANENT",
        "EdgeLock® 2 GO Key Import permanent key",
    )

    EL2GO_DATA_IMPORT_VOLATILE = (
        0xE0800400,
        "EL2GO_DATA_IMPORT_VOLATILE",
        "EdgeLock® 2 GO Data Import volatile",
    )
    EL2GO_DATA_IMPORT_PERSISTENT = (
        0xE0800401,
        "EL2GO_DATA_IMPORT_PERSISTENT",
        "EdgeLock® 2 GO Data Import persistent",
    )
    EL2GO_DATA_IMPORT_PERMANENT = (
        0xE08004FF,
        "EL2GO_DATA_IMPORT_PERMANENT",
        "EdgeLock® 2 GO Data Import permanent",
    )


class KeyUsage(SpsdkEnum):
    """AHAB key usage enumeration for cryptographic operations.

    This enumeration defines the valid key usage flags that specify what cryptographic
    operations are permitted for keys in the AHAB (Advanced High Assurance Boot) context.
    Each usage flag controls specific permissions such as encryption, decryption, signing,
    verification, and key derivation operations within the ELE (EdgeLock Enclave) security
    subsystem.
    """

    CACHE = (
        0x00000004,
        "Cache",
        (
            "Permission to cache the key in the ELE internal secure memory. "
            "This usage is set by default by ELE FW for all keys generated or imported."
        ),
    )
    ENCRYPT = (
        0x00000100,
        "Encrypt",
        (
            "Permission to encrypt a message with the key. It could be cipher encryption,"
            " AEAD encryption or asymmetric encryption operation."
        ),
    )
    DECRYPT = (
        0x00000200,
        "Decrypt",
        (
            "Permission to decrypt a message with the key. It could be cipher decryption,"
            " AEAD decryption or asymmetric decryption operation."
        ),
    )
    SIGN_MSG = (
        0x00000400,
        "Sign message",
        (
            "Permission to sign a message with the key. It could be a MAC generation or an "
            "asymmetric message signature operation."
        ),
    )
    VERIFY_MSG = (
        0x00000800,
        "Verify message",
        (
            "Permission to verify a message signature with the key. It could be a MAC "
            "verification or an asymmetric message signature verification operation."
        ),
    )
    SIGN_HASH = (
        0x00001000,
        "Sign hash",
        (
            "Permission to sign a hashed message with the key with an asymmetric signature "
            "operation. Setting this permission automatically sets the Sign Message usage."
        ),
    )
    VERIFY_HASH = (
        0x00002000,
        "Verify hash",
        (
            "Permission to verify a hashed message signature with the key with an asymmetric "
            "signature verification operation. Setting this permission automatically sets the Verify Message usage."
        ),
    )
    DERIVE = (0x00004000, "Derive", "Permission to derive other keys from this key.")


class WrappingAlgorithm(SpsdkEnum):
    """SPSDK enumeration for key import wrapping algorithms.

    This enumeration defines the supported cryptographic wrapping algorithms
    used for secure key import operations in AHAB (Advanced High Assurance Boot).
    """

    RFC3394 = (0x01, "RFC3394", "RFC 3394 wrapping")
    AES_CBC = (0x02, "AES_CBC", "AES-CBC wrapping (padding: ISO7816-4 padding)")


@dataclass
class AhabChipConfig:
    """AHAB chip configuration container.

    This class holds chip-specific configuration parameters for AHAB (Advanced High Assurance Boot)
    operations, including memory targets, core identifiers, image types, and container constraints.

    :cvar family: Target chip family and revision information.
    :cvar target_memory: Memory target type for AHAB operations.
    :cvar core_ids: Enumeration of supported core identifiers.
    :cvar image_types: Mapping of image type names to their enumeration classes.
    :cvar image_types_mapping: Mapping of image types to their numeric identifiers.
    :cvar containers_max_cnt: Maximum number of containers supported.
    :cvar images_max_cnt: Maximum number of images per container.
    :cvar container_types: List of supported container type identifiers.
    :cvar valid_offset_minimal_alignment: Minimum alignment requirement for offsets.
    :cvar container_image_size_alignment: Alignment requirement for container image sizes.
    :cvar allow_empty_hash: Whether empty hash values are permitted.
    :cvar iae_has_signed_offsets: Whether Image Array Entry uses signed offset values.
    """

    family: FamilyRevision = FamilyRevision("Unknown")
    target_memory: TargetMemoryDescr = field(
        default_factory=lambda: MEMORY_TARGET_DESCRIPTIONS[AhabTargetMemory.TARGET_MEMORY_STANDARD]
    )
    core_ids: Type[SpsdkSoftEnum] = DummyEnum
    image_types: dict[str, Type[SpsdkSoftEnum]] = field(default_factory=dict)
    image_types_mapping: dict[str, list[int]] = field(default_factory=dict)
    containers_max_cnt: int = 3
    images_max_cnt: int = 8
    container_types: list[int] = field(default_factory=list)
    valid_offset_minimal_alignment: int = 4
    allow_empty_hash: bool = False
    iae_has_signed_offsets: bool = False


@dataclass
class AhabChipContainerConfig:
    """AHAB chip container configuration holder.

    This class manages AHAB (Advanced High Assurance Boot) configuration data
    specific to chip containers, including SRK (Super Root Key) settings,
    container positioning, and security lock status.
    """

    base: AhabChipConfig = field(default_factory=AhabChipConfig)
    container_offset: int = 0
    used_srk_id: int = 0
    srk_revoke_keys: int = 0
    srk_set: FlagsSrkSet = FlagsSrkSet.NONE
    locked: bool = False


def load_images_types(
    db: Features, feature: str = DatabaseManager.AHAB, base_key: Optional[list[str]] = None
) -> dict[str, Type[SpsdkSoftEnum]]:
    """Load image types from the database.

    Retrieves image type definitions from the specified database feature and converts them into
    SpsdkSoftEnum types for use in AHAB image processing.

    :param db: Database instance to load image types from.
    :param feature: The database feature identifier to query for image types.
    :param base_key: Optional list of hierarchical keys to navigate to the image types section.
    :return: Dictionary mapping image type names to their corresponding SpsdkSoftEnum classes.
    """

    def make_key(key: str) -> Union[str, list[str]]:
        """Create a composite key from base key and provided key.

        The method combines a base key (if available) with the provided key to form
        a hierarchical key structure. If no base key exists, returns the original key.

        :param key: The key to be combined with base key.
        :return: Original key if no base key exists, otherwise list containing base key elements and the new key.
        """
        if base_key is None:
            return key
        ret = []
        ret.extend(base_key)
        ret.append(key)
        return ret

    db_image_types = db.get_dict(feature, make_key("image_types"))
    ret = {}
    for k, v in db_image_types.items():
        ret[k] = SpsdkSoftEnum.create_from_dict(f"AHABImageTypes_{k}", v)
    return ret


def create_chip_config(
    family: FamilyRevision,
    target_memory: str = AhabTargetMemory.TARGET_MEMORY_STANDARD.label,
    feature: str = DatabaseManager.AHAB,
    base_key: Optional[list[str]] = None,
) -> AhabChipConfig:
    """Create AHAB chip configuration structure.

    This method retrieves device-specific configuration parameters from the database
    and creates a complete AHAB chip configuration object with all necessary settings
    for image processing.

    :param family: Device family revision identifier
    :param target_memory: Target memory type for AHAB image, defaults to standard memory
    :param feature: Database feature identifier to query for configuration data
    :param base_key: Optional list of base keys for hierarchical database queries
    :raises SPSDKValueError: When invalid target memory type is provided
    :return: Complete AHAB chip configuration structure with device-specific settings
    """

    def make_key(key: str) -> Union[str, list[str]]:
        """Create a composite key from base key and provided key.

        The method combines a base key (if available) with the provided key to form
        a hierarchical key structure. If no base key exists, returns the original key.

        :param key: The key to be combined with base key.
        :return: Original key if no base key exists, otherwise list containing base key elements and the new key.
        """
        if base_key is None:
            return key
        ret = []
        ret.extend(base_key)
        ret.append(key)
        return ret

    if target_memory not in AhabTargetMemory.labels():
        raise SPSDKValueError(
            f"Invalid AHAB target memory [{target_memory}]."
            f" The list of supported images: [{','.join(AhabTargetMemory.labels())}]"
        )
    db = get_db(family)
    containers_max_cnt = db.get_int(feature, make_key("containers_max_cnt"))
    images_max_cnt = db.get_int(feature, make_key("oem_images_max_cnt"))
    core_ids = SpsdkSoftEnum.create_from_dict(
        "AHABCoreId", db.get_dict(feature, make_key("core_ids"))
    )
    image_types = load_images_types(db, feature=feature, base_key=base_key)
    image_types_mapping = db.get_dict(feature, make_key("image_types_mapping"))

    valid_offset_minimal_alignment = db.get_int(
        feature, make_key("valid_offset_minimal_alignment"), 4
    )

    container_types = db.get_list(feature, make_key("container_types"))
    allow_empty_hash = db.get_bool(feature, make_key("allow_empty_hash"))
    iae_has_signed_offsets = db.get_bool(feature, make_key("iae_has_signed_offsets"), False)
    return AhabChipConfig(
        family=family,
        target_memory=MEMORY_TARGET_DESCRIPTIONS[AhabTargetMemory.from_label(target_memory)],
        core_ids=core_ids,
        image_types=image_types,
        image_types_mapping=image_types_mapping,
        containers_max_cnt=containers_max_cnt,
        images_max_cnt=images_max_cnt,
        container_types=container_types,
        valid_offset_minimal_alignment=valid_offset_minimal_alignment,
        allow_empty_hash=allow_empty_hash,
        iae_has_signed_offsets=iae_has_signed_offsets,
    )

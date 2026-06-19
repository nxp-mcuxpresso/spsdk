#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK AHAB container encryption blob support.

This module provides functionality for handling encryption blobs used in
AHAB (Advanced High Assurance Boot) containers, enabling secure boot
operations for NXP MCUs.
"""

import logging
import os
from struct import pack, unpack
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.cmac import cmac
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from spsdk.ele.ele_constants import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import AHABTags, DebugEnable, KeyblobLifeCycle
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config, FamilyRevision
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import get_db, update_validation_schema_family
from spsdk.utils.misc import UINT8, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class AhabBlob(HeaderContainer):
    """AHAB Blob container for secure key management.

    Represents the encryption blob structure used in AHAB (Advanced High Assurance Boot) containers
    for secure data encryption and decryption operations. Contains metadata and wrapped key
    information following the AHAB blob format specification.
    Blob (DEK) content::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |    Mode      | Algorithm    |      Size      |     Flags      |
        +-----+--------------+--------------+----------------+----------------+
        |0x08 |                        Wrapped Key                            |
        +-----+--------------+--------------+----------------+----------------+

    :cvar TAG: AHAB blob tag identifier.
    :cvar VERSION: Blob format version.
    :cvar FLAGS_KEK_KEY: KEK (Key Encryption Key) flag value.
    :cvar FLAGS_DEK: DEK (Data Encryption Key) flag value.
    :cvar FLAGS_DFLT: Default flags configuration.
    :cvar SUPPORTED_KEY_SIZES: List of supported key sizes in bits.
    """

    TAG = AHABTags.BLOB.tag
    VERSION = 0x00
    FLAGS_KEK_KEY = 0x80  # KEK key flag
    FLAGS_DEK = 0x01  # DEK flag
    FLAGS_DFLT = FLAGS_KEK_KEY
    SUPPORTED_KEY_SIZES = [128, 192, 256]
    DIFF_ATTRIBUTES_VALUES = [
        "mode",
        "algorithm",
        "_size",
        "flags",
        "dek_keyblob",
        "key_identifier",
    ]

    class BlobKeySizes(SpsdkEnum):
        """AHAB Blob encryption key sizes enumeration.

        This enumeration defines the supported key sizes for AHAB (Advanced High Assurance Boot)
        blob encryption operations, including 128-bit, 192-bit, and 256-bit key lengths.
        """

        KEY_128 = (128, "Key size 128 bits")
        KEY_192 = (192, "Key size 192 bits")
        KEY_256 = (256, "Key size 256 bits")

    def __init__(
        self,
        flags: int = FLAGS_DFLT,
        size: int = 0,
        algorithm: KeyBlobEncryptionAlgorithm = KeyBlobEncryptionAlgorithm.AES_CBC,
        mode: int = 0,
        dek: Optional[bytes] = None,
        dek_keyblob: Optional[bytes] = None,
        key_identifier: int = 0,
    ) -> None:
        """Initialize AHAB key blob container.

        Creates a new AHAB key blob with specified encryption parameters and DEK configuration.
        The key blob is used for secure key storage and provisioning in AHAB containers.

        :param flags: Key blob configuration flags, defaults to FLAGS_DFLT
        :param size: DEK key size in bits, supported values are 128, 192, or 256
        :param algorithm: Encryption algorithm for key blob, defaults to AES_CBC
        :param mode: DEK blob mode configuration value
        :param dek: Data Encryption Key bytes, optional
        :param dek_keyblob: Encrypted DEK key blob data, optional
        :param key_identifier: Unique key identifier matching the one used for key blob generation
        """
        super().__init__(tag=self.TAG, length=56 + size // 8, version=self.VERSION)
        self.mode = mode
        self.algorithm = algorithm
        self._size = size
        self.flags = flags
        self.dek = dek
        self.dek_keyblob = dek_keyblob or b""
        self.key_identifier = key_identifier

    def __eq__(self, other: object) -> bool:
        """Check equality of two AhabBlob objects.

        Compares all attributes of the current AhabBlob instance with another object
        to determine if they are equal. The comparison includes parent class attributes
        as well as mode, algorithm, size, flags, dek_keyblob, and key_identifier.

        :param other: Object to compare with this AhabBlob instance.
        :return: True if objects are equal, False otherwise.
        """
        if isinstance(other, AhabBlob):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.mode == other.mode
                and self.algorithm == other.algorithm
                and self._size == other._size
                and self.flags == other.flags
                and self.dek_keyblob == other.dek_keyblob
                and self.key_identifier == other.key_identifier
            ):
                return True

        return False

    def __repr__(self) -> str:
        """Return string representation of AHAB Blob.

        :return: String representation of the AHAB Blob object.
        """
        return "AHAB Blob"

    def __str__(self) -> str:
        """Get string representation of AHAB Blob.

        Provides a formatted string containing all key properties of the AHAB Blob
        including mode, algorithm, key size, flags, key identifier, and DEK keyblob.

        :return: Formatted string representation of the AHAB Blob.
        """
        return (
            "AHAB Blob:\n"
            f"  Mode:               {self.mode}\n"
            f"  Algorithm:          {self.algorithm.label}\n"
            f"  Key Size:           {self._size}\n"
            f"  Flags:              {self.flags}\n"
            f"  Key identifier:     {hex(self.key_identifier)}\n"
            f"  DEK keyblob:        {self.dek_keyblob.hex() if self.dek_keyblob else 'N/A'}"
        )

    @staticmethod
    def compute_keyblob_size(key_size: int) -> int:
        """Compute Keyblob size.

        The method calculates the total size of a keyblob based on the AES key size,
        adding the fixed overhead of 48 bytes for keyblob structure.

        :param key_size: Input AES key size in bits
        :return: Keyblob size in bytes.
        """
        return (key_size // 8) + 48

    @classmethod
    def format(cls) -> str:
        """Get format of binary representation.

        Returns the format string that describes the binary layout of this class,
        including endianness, header fields, and specific data fields.

        :return: Format string for binary representation.
        """
        return (
            super().format()  # endianness, header: tag, length, version
            + UINT8  # mode
            + UINT8  # algorithm
            + UINT8  # size
            + UINT8  # flags
        )

    def __len__(self) -> int:
        """Get the total length of the AHAB blob.

        :return: Total length of the AHAB blob in bytes.
        """
        # return super()._total_length() + len(self.dek_keyblob)
        return self.length

    def export_header(self) -> bytes:
        """Export AHAB Blob header.

        Packs the header fields of the blob into their binary representation format.

        :return: Binary data representing the AHAB Blob header.
        """
        return pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self.flags,
            self._size // 8,
            self.algorithm.tag,
            self.mode,
        )

    def export(self) -> bytes:
        """Export Signature Block Blob.

        Packs the blob data into its binary representation format by combining
        the header fields and DEK keyblob data.

        :return: Binary data representing the Signature Block Blob.
        """
        return self.export_header() + self.dek_keyblob

    def verify(self) -> Verifier:
        """Verify container blob data.

        Checks the integrity and correctness of all blob components including headers,
        key size, algorithm, DEK key, and wrapped key.

        :return: Verifier object with verification results.
        """
        ret = Verifier("Blob", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_enum("Key size", self._size, self.BlobKeySizes)
        ret.add_record_bit_range("Mode", self.mode, 8)
        ret.add_record_enum("Algorithm", self.algorithm, KeyBlobEncryptionAlgorithm)
        if self.dek:
            if len(self.dek) != self._size // 8:
                ret.add_record("DEK key", VerifierResult.ERROR, "Invalid key size")
            else:
                ret.add_record("DEK key", VerifierResult.SUCCEEDED)
        else:
            ret.add_record("DEK key", VerifierResult.WARNING, "Not provided")

        if self.dek_keyblob:
            if len(self.dek_keyblob) != self.compute_keyblob_size(self._size):
                ret.add_record("Wrapped key", VerifierResult.ERROR, "Invalid key size")
            else:
                ret.add_record("Wrapped key", VerifierResult.SUCCEEDED)
        else:
            ret.add_record("Wrapped key", VerifierResult.ERROR, "Not provided")

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into an AhabBlob object.

        Extracts blob information from the provided binary data and creates
        a corresponding AhabBlob instance with parsed header and configuration.

        :param data: Binary data containing the Blob block to be parsed.
        :raises SPSDKParsingError: Invalid or corrupted binary data format.
        :return: AhabBlob object recreated from the binary data.
        """
        AhabBlob.check_container_head(data).validate()
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            size,
            algorithm,  # algorithm
            mode,  # mode
        ) = unpack(AhabBlob.format(), data[: AhabBlob.fixed_length()])

        dek_keyblob = data[AhabBlob.fixed_length() : container_length]

        blob = cls(
            size=size * 8,
            flags=flags,
            dek_keyblob=dek_keyblob,
            mode=mode,
            algorithm=KeyBlobEncryptionAlgorithm.from_tag(algorithm),
        )
        blob.length = container_length
        blob._parsed_header = HeaderContainerData.parse(binary=data)
        return blob

    def get_config(self, data_path: str = "./", index: int = 0) -> Config:
        """Create configuration of the AHAB Image Blob.

        Exports the current blob configuration into a Config object and saves
        related binary data to the specified path.

        :param data_path: Path where to store the data files of configuration.
        :param index: Container index used for filename generation.
        :return: Configuration object with blob settings.
        """
        ret_cfg = Config()
        assert isinstance(self.dek_keyblob, bytes)
        filename = f"container{index}_dek_keyblob.bin"
        write_file(self.export(), os.path.join(data_path, filename), "wb")
        ret_cfg["dek_key_size"] = self._size
        ret_cfg["dek_key"] = "N/A"
        ret_cfg["dek_keyblob"] = filename
        ret_cfg["key_identifier"] = self.key_identifier

        return ret_cfg

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Convert configuration options into an AHAB image signature block blob object.

        Processes the given configuration and creates a properly configured AhabBlob instance.
        If DEK keyblob is not specified in configuration, creates empty keyblob placeholder.

        :param config: Blob configuration containing key size, DEK key, and other blob parameters
        :raises SPSDKValueError: If configuration contains invalid DEK KeyBlob data
        :return: Initialized AhabBlob object
        """
        dek_size = config.get_int("dek_key_size", 128)
        dek = config.load_symmetric_key("dek_key", expected_size=dek_size // 8)
        key_identifier = config.get_int("key_identifier", 0)

        if "dek_keyblob" not in config:
            logger.warning(
                "The keyblob has not been specified. The empty keyblob placeholder has been used in container."
            )
            # Create empty DEK keyblob as a placeholder
            return cls(
                size=dek_size,
                flags=AhabBlob.FLAGS_DEK,
                dek_keyblob=bytes(48 + dek_size // 8),
                dek=dek,
                key_identifier=key_identifier,
                mode=0,
                algorithm=KeyBlobEncryptionAlgorithm.AES_CBC,
            )

        dek_keyblob = config.load_symmetric_key(
            "dek_keyblob", cls.compute_keyblob_size(dek_size) + 8
        )

        keyblob = cls.parse(dek_keyblob)
        keyblob.dek = dek
        keyblob.key_identifier = key_identifier

        return keyblob

    def encrypt_data(self, iv: bytes, data: bytes) -> bytes:
        """Encrypt data using the DEK.

        Uses the appropriate encryption algorithm based on the blob's algorithm setting.

        :param iv: Initial vector 128 bits length.
        :param data: Data to encrypt.
        :raises SPSDKError: Missing DEK or unsupported algorithm.
        :return: Encrypted data.
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        encryption_methods = {
            KeyBlobEncryptionAlgorithm.AES_CBC: aes_cbc_encrypt,
            KeyBlobEncryptionAlgorithm.SM4_CBC: sm4_cbc_encrypt,
        }

        if not encryption_methods.get(self.algorithm):
            raise SPSDKError(f"Unsupported encryption algorithm: {self.algorithm}")
        return encryption_methods[self.algorithm](self.dek, data, iv)

    def decrypt_data(self, iv: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using the DEK.

        Uses the appropriate decryption algorithm based on the blob's algorithm setting.

        :param iv: Initial vector 128 bits length.
        :param encrypted_data: Data to decrypt.
        :raises SPSDKError: Missing DEK or unsupported algorithm.
        :return: Decrypted plain data.
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        decryption_methods = {
            KeyBlobEncryptionAlgorithm.AES_CBC: aes_cbc_decrypt,
            KeyBlobEncryptionAlgorithm.SM4_CBC: sm4_cbc_decrypt,
        }

        if not decryption_methods.get(self.algorithm):
            raise SPSDKError(f"Unsupported encryption algorithm: {self.algorithm}")
        return decryption_methods[self.algorithm](self.dek, encrypted_data, iv)

    def get_encryption_algorithm_info(self) -> str:
        """Get encryption algorithm information.

        Returns a formatted string containing the encryption algorithm and key size
        used by this AHAB blob for data encryption operations.

        :return: String with encryption algorithm name and key size in format "ALGORITHM-KEY_SIZE".
        """
        return f"{self.algorithm.label}-{self._size}"


class AhabBlobOffline(FeatureBaseClass, AhabBlob):
    """AHAB Blob generator for offline key wrapping and blob creation.

    This class extends AhabBlob to provide offline generation capabilities for AHAB key blobs,
    supporting both common key and die individual key strategies. It implements the complete
    key derivation and wrapping process.

    The blob generation process follows these steps:
    1. Derive master key using CKDF
    2. Derive KEK from master key
    3. Generate blob key (256-bit) and DEK
    4. Generate nonce with integrity protection
    5. Encrypt DEK with blob key (AES-CCM)
    6. Encrypt blob key with KEK (AES-ECB)
    7. Combine header, encrypted blob key, encrypted DEK, and tag
    """

    FEATURE = DatabaseManager.AHAB
    SUB_FEATURE = "offline_keyblob"

    def __init__(
        self,
        family: FamilyRevision,
        flags: int = AhabBlob.FLAGS_DFLT,
        size: int = 256,
        algorithm: KeyBlobEncryptionAlgorithm = KeyBlobEncryptionAlgorithm.AES_CBC,
        mode: int = 0,
        dek: Optional[bytes] = None,
        dek_keyblob: Optional[bytes] = None,
        key_identifier: int = 0,
        customer_master_key: Optional[bytes] = None,
        lifecycle_state: KeyblobLifeCycle = KeyblobLifeCycle.OEM_OPEN,
        debug_enable: DebugEnable = DebugEnable.NO,
        srkh0: Optional[bytes] = None,
        srkh1: Optional[bytes] = None,
        blob_key: Optional[bytes] = None,
    ) -> None:
        """Initialize AHAB blob generator.

        :param flags: Key blob configuration flags
        :param size: DEK key size in bits (128, 192, or 256)
        :param algorithm: Encryption algorithm for key blob
        :param mode: DEK blob mode configuration value
        :param dek: Data Encryption Key bytes, will be generated if not provided
        :param dek_keyblob: Encrypted DEK key blob data
        :param key_identifier: Unique key identifier (4 bytes)
        :param customer_master_key: Customer master key CUST_MK_SK (256-bit)
        :param lifecycle_state: Life cycle state for nonce generation
        :param debug_enable: Debug enable flag for nonce generation
        :param srkh0: Classic SRK hash (64 bytes)
        :param srkh1: PQC SRK hash (64 bytes)
        :param blob_key: Blob key for encryption, will be generated if not provided
        """
        super().__init__(
            flags=flags,
            size=size,
            algorithm=algorithm,
            mode=mode,
            dek=dek,
            dek_keyblob=dek_keyblob,
            key_identifier=key_identifier,
        )
        self.family = family
        self.customer_master_key = customer_master_key
        self.lifecycle_state = lifecycle_state
        self.debug_enable = debug_enable
        self.srkh0 = srkh0 or b"\x00" * 64
        self.srkh1 = srkh1 or b"\x00" * 64
        self.blob_key = blob_key

        self.db = get_db(family)
        self.product_string = self.db.get_str(
            DatabaseManager.AHAB, "offline_keyblob_constant", "2660 S110A0"
        )
        # convert product string to bytes
        self.product_string_bytes = self.product_string.encode(encoding="ascii")

        # Validate key identifier fits in 4 bytes
        if key_identifier > 0xFFFFFFFF:
            raise SPSDKValueError("Key identifier must fit in 4 bytes")

    def derive_master_key(self) -> bytes:
        """Derive master key using CKDF implementation.

        This implements the exact CKDF from the reference implementation.

        :return: Derived master key (32 bytes)
        :raises SPSDKError: If required parameters are missing
        """
        if not self.customer_master_key:
            raise SPSDKError("Customer master key is required for key derivation")

        logger.debug(f"Customer master key: {self.customer_master_key.hex()}")
        # Build common derivation data
        common_derivation_data = b"\x64"  # Fixed prefix
        common_derivation_data += self.product_string_bytes
        common_derivation_data += self.srkh0
        common_derivation_data += self.srkh1
        common_derivation_data += self.lifecycle_state.tag.to_bytes(length=4, byteorder="little")
        common_derivation_data += bytes(12)  # 12 zero bytes
        common_derivation_data += (0x100).to_bytes(length=4, byteorder="big")  # Length field

        # Generate MAC using CMAC-AES
        mac = b""
        for i in range(1, 3):  # Two iterations
            derivation_data = common_derivation_data + i.to_bytes(length=4, byteorder="big")

            mac_block = cmac(self.customer_master_key, derivation_data)
            mac += mac_block

        return mac[:32]  # Return first 32 bytes as master key

    def derive_kek(self, master_key: bytes) -> bytes:
        """Derive KEK (Key Encryption Key) from master key.

        :param master_key: Master key derived from customer master key
        :return: Derived KEK (32 bytes)
        """
        # Build common derivation data for KEK
        common_derivation_data = b"\x6a"  # Different prefix for KEK
        common_derivation_data += self.product_string_bytes
        common_derivation_data += bytes(12)  # 12 zero bytes
        common_derivation_data += (0x100).to_bytes(length=4, byteorder="big")  # Length field

        # Generate MAC using CMAC-AES
        mac = b""
        for i in range(1, 3):  # Two iterations
            derivation_data = common_derivation_data + i.to_bytes(length=4, byteorder="big")
            mac_block = cmac(master_key, derivation_data)
            mac += mac_block

        return mac[:32]  # Return first 32 bytes as KEK

    def add_nonce_integrity_protection(self, nonce: bytes) -> bytes:
        """Add integrity protection to nonce.

        :param nonce: Input nonce
        :return: Nonce with integrity protection (checksum)
        """
        checksum = 0
        for byte_val in nonce:
            checksum ^= byte_val
        return nonce + checksum.to_bytes(1, "little")

    def generate_nonce(self) -> bytes:
        """Generate nonce for AES-CCM encryption following reference implementation.

        Nonce format (13 bytes before integrity protection):
        Byte 0: Life Cycle State
        Byte 1: Mode (from header)
        Byte 2: Flags (from header)
        Byte 3: Debug Enable
        Byte 4: Flags (from header) - repeated
        Byte 5: Size (from header)
        Byte 6: Algorithm (from header)
        Byte 7: Reserved (0x00)
        Bytes 8-11: Key ID (4 bytes, little-endian)
        Byte 12: Integrity checksum (XOR of all previous bytes)

        :return: 13-byte nonce with integrity protection
        """
        # Build nonce components from header values
        lc = self.lifecycle_state.tag.to_bytes(1, "big")
        mode = self.mode.to_bytes(1, "big")
        flags = self.flags.to_bytes(1, "big")
        debug = self.debug_enable.tag.to_bytes(1, "big")
        size = (self._size // 8).to_bytes(1, "big")
        algorithm = self.algorithm.tag.to_bytes(1, "big")
        reserved = b"\x00"
        key_id = self.key_identifier.to_bytes(4, "little")

        # Combine: LC + mode + flags + debug + flags + size + algorithm + reserved + key_id
        iv = lc + mode + flags + debug + flags + size + algorithm + reserved + key_id

        # Add integrity protection (XOR checksum as 13th byte)
        return self.add_nonce_integrity_protection(iv)

    def generate_blob_key(self) -> bytes:
        """Generate a random 256-bit blob key.

        :return: 32-byte blob key
        """
        return random_bytes(32)

    def generate_dek(self) -> bytes:
        """Generate a random DEK of the specified size.

        :return: DEK of size specified in self._size
        """
        dek = random_bytes(self._size // 8)
        self.dek = dek
        return dek

    def export(self) -> bytes:
        """Generate the complete encrypted keyblob.

        1. Derive master key using CKDF
        2. Derive KEK from master key
        3. Generate blob key and DEK if not provided
        4. Generate nonce with integrity protection
        5. Encrypt DEK with blob key (AES-CCM)
        6. Encrypt blob key with KEK (AES-ECB)
        7. Create header and combine all components

        :return: Complete encrypted keyblob with header
        """
        logger.debug("Starting keyblob generation process")

        if not self.customer_master_key:
            raise SPSDKError("Customer master key is required for blob generation")

        logger.debug(f"Using lifecycle state: {self.lifecycle_state.label}")
        logger.debug(f"Debug enable: {self.debug_enable.label}")
        logger.debug(f"Key identifier: 0x{self.key_identifier:08x}")
        logger.debug(f"DEK size: {self._size} bits")

        # Step 1: Derive master key
        logger.debug("Step 1: Deriving master key using CKDF")
        master_key = self.derive_master_key()
        logger.debug(f"Master key derived: {len(master_key)} bytes")
        logger.debug(f"Master key: {master_key.hex()}")

        # Step 2: Derive KEK
        logger.debug("Step 2: Deriving KEK from master key")
        kek = self.derive_kek(master_key)
        logger.debug(f"KEK derived: {len(kek)} bytes")
        logger.debug(f"KEK: {kek.hex()}")

        # Step 3: Generate components if not provided
        if not self.blob_key:
            logger.debug("Step 3a: Generating blob key (not provided)")
            self.blob_key = self.generate_blob_key()
            logger.debug("Blob key generated")
        else:
            logger.debug("Step 3a: Using provided blob key")

        if not self.dek:
            logger.debug("Step 3b: Generating DEK (not provided)")
            self.generate_dek()
            logger.debug("DEK generated")
        else:
            logger.debug("Step 3b: Using provided DEK")

        # Step 4: Generate nonce
        logger.debug("Step 4: Generating nonce with integrity protection")
        iv = self.generate_nonce()
        logger.debug(f"Nonce generated: {len(iv)} bytes - {iv.hex()}")

        # Step 5: Encrypt DEK with blob key (AES-CCM)
        logger.debug("Step 5: Encrypting DEK with blob key using AES-CCM")
        assert self.dek, "Dek not provided"
        enc_dek = aes_ccm_encrypt(self.blob_key, self.dek, iv)
        logger.debug(f"Encrypted DEK: {len(enc_dek)} bytes")

        # Step 6: Encrypt blob key with KEK (AES-ECB)
        logger.debug("Step 6: Encrypting blob key with KEK using AES-ECB")
        enc_blob_key = aes_ecb_encrypt(kek, self.blob_key)
        logger.debug(f"Encrypted blob key: {len(enc_blob_key)} bytes")

        # Step 7: Create header and combine
        logger.debug("Step 7: Creating header and combining components")
        header = self.export_header()
        logger.debug(f"Header created: {header.hex()}")

        # Combine all components
        keyblob_with_header = header + enc_blob_key + enc_dek

        # Store the keyblob data (without header for AHAB blob compatibility)
        self.dek_keyblob = enc_blob_key + enc_dek
        self.length = len(keyblob_with_header)

        logger.debug("Keyblob generation completed successfully")
        return keyblob_with_header

    def decrypt_keyblob(self, keyblob_with_header: bytes) -> bytes:
        """Decrypt the keyblob to extract the original DEK.

        This reverses the encryption process to verify the blob or extract the DEK.

        :param keyblob_with_header: Complete keyblob with header
        :return: Decrypted DEK
        """
        if not self.customer_master_key:
            raise SPSDKError("Customer master key is required for blob decryption")

        # Parse header
        if len(keyblob_with_header) < 8:
            raise SPSDKValueError("Keyblob too short to contain valid header")

        # Extract header components
        header = keyblob_with_header[:8]
        # version = header[0]
        total_length = unpack("<H", header[1:3])[0]  # Little-endian 2-byte length
        tag = header[3]
        # usage = header[4:8]

        # Validate header
        if tag != 0x81:
            raise SPSDKValueError(f"Invalid keyblob tag: 0x{tag:02x}, expected 0x81")

        if len(keyblob_with_header) != total_length:
            raise SPSDKValueError(
                f"Keyblob length mismatch: got {len(keyblob_with_header)}, expected {total_length}"
            )

        # Extract encrypted components
        payload = keyblob_with_header[8:]
        enc_blob_key = payload[:32]  # First 32 bytes are encrypted blob key
        enc_dek = payload[32:]  # Remaining bytes are encrypted DEK

        # Step 1: Derive master key
        master_key = self.derive_master_key()

        # Step 2: Derive KEK
        kek = self.derive_kek(master_key)

        # Step 3: Decrypt blob key with KEK (AES-ECB)
        blob_key = aes_ecb_decrypt(kek, enc_blob_key)

        # Step 4: Generate nonce for decryption
        iv = self.generate_nonce()

        # Step 5: Decrypt DEK with blob key (AES-CCM)
        decrypted_dek = aes_ccm_decrypt(blob_key, enc_dek, iv, b"")

        return decrypted_dek

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load AHAB blob generator from configuration matching reference implementation.

        Expected configuration format:
        {
            "family": "xxx",
            "revision" "a0"
            "lifecycle": "oem_open",
            "debug": false,
            "key_id": 12345,
            "cust_mk_sk": "hex_string_or_path",
            "srkh0": "hex_string_or_path",
            "srkh1": "hex_string_or_path",
            "dek": "hex_string_or_path",
            "dek_key_size": 256,
            "flags": 0x81
            "mode": 0
            "algorithm": AES_CBC
        }

        :param config: Configuration containing blob generation parameters
        :return: Configured AhabBlobGenerator instance
        """
        # Load basic configuration
        family = config.get_family()
        lifecycle = config.get_str("lifecycle", "oem_open").lower()
        debug_enable = config.get_bool("debug", False)
        key_identifier = config.get_int("key_id", 0)
        dek_size = config.get_int("dek_key_size", 256)
        algorithm = KeyBlobEncryptionAlgorithm.from_label(config.get_str("algorithm", "AES_CBC"))
        flags = config.get_int("flags", 0x4)
        mode = config.get_int("mode", 0)

        lifecycle_state = KeyblobLifeCycle.from_label(lifecycle)
        debug_enable_state = DebugEnable.YES if debug_enable else DebugEnable.NO

        # Load keys
        customer_master_key = config.load_symmetric_key("cust_mk_sk", expected_size=32)
        srkh0 = config.load_symmetric_key("srkh0", expected_size=64)
        srkh1 = config.load_symmetric_key("srkh1", expected_size=64)
        if "dek" not in config:
            dek = None
        else:
            dek = config.load_symmetric_key("dek", expected_size=dek_size // 8)

        if "blob_key" not in config:
            blob_key = None
        else:
            blob_key = config.load_symmetric_key("blob_key", expected_size=32)

        # Create generator instance
        generator = cls(
            family=family,
            flags=flags,
            size=dek_size,
            algorithm=algorithm,
            mode=mode,
            key_identifier=key_identifier,
            customer_master_key=customer_master_key,
            lifecycle_state=lifecycle_state,
            debug_enable=debug_enable_state,
            srkh0=srkh0,
            srkh1=srkh1,
            dek=dek,
            blob_key=blob_key,
        )

        return generator

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[Any]:
        """Get validation schemas for AHAB blob configuration."""
        sch_cfg = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)
        sch_family = DatabaseManager().db.get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg["ahab_blob"]]

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse binary data into an AhabBlobGenerator object.

        Extracts blob information from the provided binary data and creates
        a corresponding AhabBlobGenerator instance with parsed header and configuration.
        This method extends the base AhabBlob.parse() to include family-specific parameters.

        :param data: Binary data containing the Blob block to be parsed.
        :param family: Family and revision information for the target device.
        :raises SPSDKParsingError: Invalid or corrupted binary data format.
        :return: AhabBlobGenerator object recreated from the binary data.
        """
        # First parse using parent class to get basic blob structure
        AhabBlob.check_container_head(data).validate()
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            size,
            algorithm,
            mode,
        ) = unpack(AhabBlobOffline.format(), data[: AhabBlobOffline.fixed_length()])

        dek_keyblob = data[AhabBlobOffline.fixed_length() : container_length]

        # Create AhabBlobGenerator instance with parsed data
        blob_generator = cls(
            family=family,
            size=size * 8,
            flags=flags,
            dek_keyblob=dek_keyblob,
            mode=mode,
            algorithm=KeyBlobEncryptionAlgorithm.from_tag(algorithm),
        )
        blob_generator.length = container_length
        blob_generator._parsed_header = HeaderContainerData.parse(binary=data)

        return blob_generator

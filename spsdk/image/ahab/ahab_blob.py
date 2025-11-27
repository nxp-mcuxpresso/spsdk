#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
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
from typing import Optional

from typing_extensions import Self

from spsdk.crypto.symmetric import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from spsdk.ele.ele_constants import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import UINT8, AHABTags
from spsdk.utils.config import Config
from spsdk.utils.misc import write_file
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

    def export(self) -> bytes:
        """Export Signature Block Blob.

        Packs the blob data into its binary representation format by combining
        the header fields and DEK keyblob data.

        :return: Binary data representing the Signature Block Blob.
        """
        blob = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.flags,
                self._size // 8,
                self.algorithm.tag,
                self.mode,
            )
            + self.dek_keyblob
        )

        return blob

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

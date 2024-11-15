#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container encryption blob support."""


import logging
import os
from struct import pack, unpack
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.symmetric import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from spsdk.ele.ele_constants import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import UINT8, AHABTags
from spsdk.utils.misc import load_hex_string, value_to_int, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class AhabBlob(HeaderContainer):
    """The Blob object used in Signature Container.

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

    """

    TAG = AHABTags.BLOB.tag
    VERSION = 0x00
    FLAGS_KEK_KEY = 0x80  # KEK key flag
    FLAGS_DEK = 0x01  # DEK flag
    FLAGS_DFLT = FLAGS_KEK_KEY
    SUPPORTED_KEY_SIZES = [128, 192, 256]

    class BlobKeySizes(SpsdkEnum):
        """AHAB Blob key sizes."""

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
        """Class object initializer.

        :param flags: Keyblob flags
        :param size: key size [128,192,256]
        :param dek: DEK key
        :param mode: DEK BLOB mode
        :param algorithm: Encryption algorithm
        :param dek_keyblob: DEK keyblob
        :param key_identifier: Key identifier. Must be same as it was used for keyblob generation
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
        return "AHAB Blob"

    def __str__(self) -> str:
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

        :param key_size: Input AES key size in bits
        :return: Keyblob size in bytes.
        """
        return (key_size // 8) + 48

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness, header: tag, length, version
            + UINT8  # mode
            + UINT8  # algorithm
            + UINT8  # size
            + UINT8  # flags
        )

    def __len__(self) -> int:
        # return super()._total_length() + len(self.dek_keyblob)
        return self.length

    def export(self) -> bytes:
        """Export Signature Block Blob.

        :return: bytes representing Signature Block Blob.
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
        """Verify container blob data."""
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
        """Parse input binary chunk to the container object.

        :param data: Binary data with Blob block to parse.
        :return: Object recreated from the binary data.
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

    def create_config(self, index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image Blob.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Any] = {}
        assert isinstance(self.dek_keyblob, bytes)
        filename = f"container{index}_dek_keyblob.bin"
        write_file(self.export(), os.path.join(data_path, filename), "wb")
        ret_cfg["dek_key_size"] = self._size
        ret_cfg["dek_key"] = "N/A"
        ret_cfg["dek_keyblob"] = filename
        ret_cfg["key_identifier"] = self.key_identifier

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> "AhabBlob":
        """Converts the configuration option into an AHAB image signature block blob object.

        "config" content of container configurations.

        :param config: Blob configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid configuration - Invalid DEK KeyBlob
        :return: Blob object.
        """
        dek_size = value_to_int(config.get("dek_key_size", 128))
        dek_input = config.get("dek_key")
        dek_keyblob_input = config.get("dek_keyblob")
        key_identifier = config.get("key_identifier", 0)
        if not dek_input:
            raise SPSDKValueError("Invalid configuration - Missing DEK key")

        dek = load_hex_string(dek_input, dek_size // 8, search_paths)

        if dek_keyblob_input is None:
            logger.warning(
                "The keyblob has not been specified. The empty keyblob placeholder has been used in container."
            )
            # Create empty DEK keyblob as a placeholder
            return AhabBlob(
                size=dek_size,
                flags=AhabBlob.FLAGS_DEK,
                dek_keyblob=bytes(48 + dek_size // 8),
                dek=dek,
                key_identifier=key_identifier,
                mode=0,
                algorithm=KeyBlobEncryptionAlgorithm.AES_CBC,
            )

        dek_keyblob_value = load_hex_string(
            dek_keyblob_input, AhabBlob.compute_keyblob_size(dek_size) + 8, search_paths
        )
        if not dek_keyblob_value:
            raise SPSDKValueError("Invalid DEK KeyBlob.")

        keyblob = AhabBlob.parse(dek_keyblob_value)
        keyblob.dek = dek
        keyblob.key_identifier = key_identifier

        return keyblob

    def encrypt_data(self, iv: bytes, data: bytes) -> bytes:
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param data: Data to encrypt
        :raises SPSDKError: Missing DEK, unsupported algorithm
        :return: Encrypted data
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
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param encrypted_data: Data to decrypt
        :raises SPSDKError: Missing DEK, unsupported algorithm
        :return: Plain data
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

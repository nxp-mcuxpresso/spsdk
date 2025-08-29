#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EncryptionProvider is an Interface for all potential encryption providers."""

import abc
import logging
from typing import Any, Optional

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.symmetric import aes_cbc_encrypt
from spsdk.sbfile.utils.key_derivator import SB31KeyDerivator, get_sb31_key_derivator

logger = logging.getLogger(__name__)


class EncryptionProvider:
    """Abstract base class for data encryption providers used in SB3.1 format.

    Defines the interface for encrypting data blocks in a secure boot file.
    """

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption is enabled.

        :return: Boolean indicating whether encryption is active
        """
        return False

    @abc.abstractmethod
    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Encrypt a data block.

        :param block_number: Sequential number of the block to encrypt
        :param data: Raw data to be encrypted
        :return: Encrypted data
        """

    @abc.abstractmethod
    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """Configure the encryption provider with required parameters.

        :param timestamp: Timestamp to use for configuration
        :param kdk_access_rights: Access rights for the Key Derivation Key
        :param key_length: Length of encryption key in bits, defaults to 256
        """

    @staticmethod
    def get_key_length(hash_type: EnumHashAlgorithm) -> int:
        """Get the key length based on the hash algorithm.

        :param hash_type: Hash algorithm to determine key length
        :return: Key length in bits
        """
        key_lengths = {
            EnumHashAlgorithm.SHA256: 128,
            EnumHashAlgorithm.SHA384: 256,
        }
        return key_lengths.get(hash_type, 256)  # Default to 256 if not found


class NoEncryption(EncryptionProvider):
    """Encryption provider that doesn't perform any encryption.

    Used when encryption is not required for the secure boot file.
    """

    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Pass through the data without encryption.

        :param block_number: Sequential number of the block (ignored)
        :param data: Raw data that remains unmodified
        :return: Original unmodified data
        """
        return data

    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """No-op configuration method.

        :param timestamp: Timestamp (ignored)
        :param kdk_access_rights: Access rights (ignored)
        :param key_length: Length of encryption key in bits, defaults to 256 (ignored)
        """


class SB31EncryptionProvider(EncryptionProvider):
    """Encryption provider for SB3.1 format.

    Uses a key derivator to generate keys for encrypting individual blocks.
    """

    def __init__(self, key_derivator: SB31KeyDerivator) -> None:
        """Initialize the SB3.1 encryption provider.

        :param key_derivator: Key derivator to generate encryption keys
        """
        self.key_derivator = key_derivator

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption is enabled.

        :return: Boolean indicating whether encryption is active
        """
        return True

    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Encrypt a data block using AES-CBC algorithm.

        :param block_number: Sequential number of the block to encrypt
        :param data: Raw data to be encrypted
        :return: Encrypted data
        """
        block_key = self.key_derivator.get_block_key(block_number=block_number)
        return aes_cbc_encrypt(key=block_key, plain_data=data)

    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """Configure the key derivator with required parameters.

        :param timestamp: Timestamp to use for configuration
        :param kdk_access_rights: Access rights for the Key Derivation Key
        :param key_length: Length of encryption key in bits, defaults to 256
        """
        return self.key_derivator.configure(
            timestamp=timestamp, kdk_access_rights=kdk_access_rights, key_length=key_length
        )


def get_encryption_provider(
    is_encrypted: bool = True,
    service_config: Optional[str] = None,
    local_file: Optional[str] = None,
    search_paths: Optional[list[str]] = None,
    **kwargs: Any,
) -> EncryptionProvider:
    """Factory function to create an appropriate encryption provider.

    Creates either a no-encryption provider or an SB3.1 encryption provider based on requirements.

    :param is_encrypted: Whether encryption is required
    :param service_config: Path to service configuration file
    :param local_file: Path to local key file
    :param search_paths: Additional paths to search for keys
    :param kwargs: Additional arguments passed to key derivator
    :return: Configured encryption provider instance
    """
    if not is_encrypted:
        return NoEncryption()
    key_derivator = get_sb31_key_derivator(
        kd_cfg=service_config,
        local_file_key=local_file,
        search_paths=search_paths,
        **kwargs,
    )
    return SB31EncryptionProvider(key_derivator=key_derivator)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB file encryption provider interface and implementations.

This module provides an abstract interface for encryption providers used in
Secure Binary (SB) file generation, along with concrete implementations for
different encryption schemes including no encryption and SB3.1 encryption.
"""

import abc
import logging
from typing import Any, Optional

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.symmetric import aes_cbc_encrypt
from spsdk.sbfile.utils.key_derivator import SB31KeyDerivator, get_sb31_key_derivator

logger = logging.getLogger(__name__)


class EncryptionProvider:
    """Abstract base class for data encryption providers used in SB3.1 format.

    Defines the interface for encrypting data blocks in secure boot files, providing
    standardized methods for block-level encryption operations and key management
    configuration.
    """

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption is enabled.

        :return: True if encryption is active, False otherwise.
        """
        return False

    @abc.abstractmethod
    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Encrypt a data block using the configured encryption method.

        :param block_number: Sequential number of the block to encrypt.
        :param data: Raw data to be encrypted.
        :return: Encrypted data.
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

        :param hash_type: Hash algorithm to determine key length for encryption.
        :return: Key length in bits (128 for SHA256, 256 for SHA384, default 256).
        """
        key_lengths = {
            EnumHashAlgorithm.SHA256: 128,
            EnumHashAlgorithm.SHA384: 256,
        }
        return key_lengths.get(hash_type, 256)  # Default to 256 if not found


class NoEncryption(EncryptionProvider):
    """No-operation encryption provider for secure boot files.

    This encryption provider implements the EncryptionProvider interface without
    performing any actual encryption operations. It serves as a pass-through
    implementation for scenarios where encryption is not required in the secure
    boot file generation process.
    """

    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Pass through the data without encryption.

        This method implements a no-op encryption for cases where data should remain unmodified
        while maintaining compatibility with the encryption provider interface.

        :param block_number: Sequential number of the block (ignored in this implementation).
        :param data: Raw data bytes that will remain unmodified.
        :return: Original unmodified data bytes.
        """
        return data

    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """Configure encryption provider with no operation.

        This is a no-operation implementation that accepts configuration parameters
        but does not perform any actual configuration.

        :param timestamp: Timestamp value for configuration.
        :param kdk_access_rights: Secure Binary key access rights.
        :param key_length: Length of encryption key in bits, defaults to 256.
        """


class SB31EncryptionProvider(EncryptionProvider):
    """SB31EncryptionProvider for Secure Binary 3.1 format.

    This class provides encryption capabilities specifically designed for SB3.1 secure boot files.
    It manages block-by-block encryption using dynamically generated keys through a key derivation
    mechanism, ensuring each data block is encrypted with a unique key for enhanced security.
    """

    def __init__(self, key_derivator: SB31KeyDerivator) -> None:
        """Initialize the SB3.1 encryption provider.

        :param key_derivator: Key derivator to generate encryption keys.
        """
        self.key_derivator = key_derivator

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption is enabled.

        :return: True if encryption is active, False otherwise.
        """
        return True

    def encrypt_block(self, block_number: int, data: bytes) -> bytes:
        """Encrypt a data block using AES-CBC algorithm.

        :param block_number: Sequential number of the block to encrypt.
        :param data: Raw data to be encrypted.
        :return: Encrypted data.
        """
        block_key = self.key_derivator.get_block_key(block_number=block_number)
        return aes_cbc_encrypt(key=block_key, plain_data=data)

    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """Configure the key derivator with required parameters.

        :param timestamp: Timestamp to use for configuration.
        :param kdk_access_rights: Access rights for the Key Derivation Key.
        :param key_length: Length of encryption key in bits, defaults to 256.
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

    Creates either a no-encryption provider or an SB3.1 encryption provider based on
    the encryption requirements and provided configuration.

    :param is_encrypted: Whether encryption is required, defaults to True.
    :param service_config: Path to service configuration file for key derivation.
    :param local_file: Path to local key file for encryption.
    :param search_paths: Additional paths to search for encryption keys.
    :param kwargs: Additional arguments passed to the key derivator.
    :return: Configured encryption provider instance.
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

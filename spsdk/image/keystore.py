#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for KeyStore used in MasterBootImage."""

from typing import Optional

from spsdk.crypto.symmetric import aes_ecb_encrypt
from spsdk.exceptions import SPSDKError
from spsdk.utils.spsdk_enum import SpsdkEnum


class KeySourceType(SpsdkEnum):
    """Device key source enumeration for SPSDK operations.

    This enumeration defines the available sources where device keys can be stored,
    including OTP (One-Time Programmable) memory and KeyStore locations.
    """

    OTP = (0, "OTP", "Device keys stored in OTP")
    KEYSTORE = (1, "KEYSTORE", "Device keys stored in KeyStore")


class KeyStore:
    """SPSDK KeyStore manager for Master Boot Image operations.

    This class manages cryptographic key storage and derivation for secure boot
    operations, supporting different key sources and providing key derivation
    functionality for encryption, authentication, and OTFAD operations.

    :cvar KEY_STORE_SIZE: Size of key store in bytes (device-specific).
    :cvar SBKEK_SIZE: Size of Secure Binary KEK in bytes.
    :cvar OTP_MASTER_KEY_SIZE: Size of OTP master key in bytes.
    :cvar OTFAD_KEY_SIZE: Size of OTFAD key in bytes.
    """

    # size of key store in bytes
    KEY_STORE_SIZE = 1424  # Size can be device-specific, the current value is valid for currently supported devices

    SBKEK_SIZE = 32  # Size of Secure Binary KEK in bytes

    OTP_MASTER_KEY_SIZE = 32  # Size of OTP master key in bytes
    OTFAD_KEY_SIZE = 16  # Size of OTFAD key in bytes

    @property
    def key_source(self) -> KeySourceType:
        """Get the device key source type.

        :return: The key source type for the device.
        """
        return self._key_source

    def __init__(self, key_source: KeySourceType, key_store: Optional[bytes] = None) -> None:
        """Initialize Keystore.

        :param key_source: Device key source type.
        :param key_store: Initial content of the key store in the bootable image; None if empty.
        :raises SPSDKError: If invalid key-store size.
        :raises SPSDKError: KeyStore can be initialized only if key_source == KEYSTORE.
        """
        if key_store:
            if len(key_store) != self.KEY_STORE_SIZE:
                raise SPSDKError(
                    f"Invalid key-store size, expected is {str(self.KEY_STORE_SIZE)} bytes"
                )
            if key_source != KeySourceType.KEYSTORE:
                raise SPSDKError("KeyStore can be initialized only if key_source == KEYSTORE")

        self._key_source = key_source
        self._key_store = key_store

    def export(self) -> bytes:
        """Export binary key store content.

        Returns the binary representation of the key store data, or empty bytes
        if the key store is empty.

        :return: Binary key store content as bytes, empty bytes for empty key-store.
        """
        return self._key_store if self._key_store else bytes()

    def __repr__(self) -> str:
        """Return string representation of KeyStore object.

        :return: String containing class name and key source information.
        """
        return f"KeyStore Class, Source: {self.key_source}"

    def __str__(self) -> str:
        """Get string representation of the key store.

        Provides information about the device key source and the length of the exported
        key store data in a human-readable text format.

        :return: Formatted string containing key source label and key store length.
        """
        return (
            f"Device key source:    {self.key_source.label}\n"
            f"Device key store len: {str(len(self.export()))}"
        )

    @staticmethod
    def derive_hmac_key(hmac_key: bytes) -> bytes:
        """Derive HMAC key from master or user key.

        This method performs AES-ECB encryption on a zero-filled 16-byte block using the provided
        HMAC key to derive the final HMAC key for image header authentication.

        :param hmac_key: Master key (for key_source == OTP) or user key (for key_source == KEYSTORE),
            must be exactly 32 bytes long.
        :return: Derived key used for image header authentication in LoadToRam images.
        :raises SPSDKError: If invalid length of hmac key (must be 32 bytes).
        """
        if len(hmac_key) != 32:
            raise SPSDKError("Invalid length of hmac key")
        return aes_ecb_encrypt(hmac_key, bytes([0] * 16))

    @staticmethod
    def derive_enc_image_key(master_key: bytes) -> bytes:
        """Derive encryption image key from master key.

        The method derives the encryption key used to decrypt encrypted images during boot process
        from the master key stored in OTP memory using AES ECB encryption.

        :param master_key: Master key stored in OTP memory (must be 32 bytes).
        :return: Derived key used to decrypt encrypted images during boot.
        :raises SPSDKError: If invalid length of master key.
        """
        if len(master_key) != 32:
            raise SPSDKError("Invalid length of master key")
        return aes_ecb_encrypt(master_key, bytes([1] + [0] * 15 + [2] + [0] * 15))

    @staticmethod
    def derive_sb_kek_key(master_key: bytes) -> bytes:
        """Derive SBKEK key from master key.

        This method derives a Secure Binary Key Encryption Key (SBKEK) from a master key
        using AES-ECB encryption with a specific derivation pattern.

        :param master_key: 32-byte master key stored in OTP memory.
        :return: Derived encryption key for handling SB2 file (update capsule).
        :raises SPSDKError: If master key length is not exactly 32 bytes.
        """
        if len(master_key) != 32:
            raise SPSDKError("Invalid length of master key")
        return aes_ecb_encrypt(master_key, bytes([3] + [0] * 15 + [4] + [0] * 15))

    @staticmethod
    def derive_otfad_kek_key(master_key: bytes, otfad_input: bytes) -> bytes:
        """Derive OTFAD KEK key from master key and OTFAD input.

        This method uses AES ECB encryption to derive the OTFAD Key Encryption Key
        from the provided master key and OTFAD input data.

        :param master_key: 32-byte master key stored in OTP memory
        :param otfad_input: 16-byte OTFAD input data stored in OTP memory
        :return: Derived OTFAD encryption key for FLASH encryption/decryption
        :raises SPSDKError: Invalid length of master key (must be 32 bytes)
        :raises SPSDKError: Invalid length of OTFAD input (must be 16 bytes)
        """
        if len(master_key) != KeyStore.OTP_MASTER_KEY_SIZE:
            raise SPSDKError("Invalid length of master key")
        if len(otfad_input) != KeyStore.OTFAD_KEY_SIZE:
            raise SPSDKError("Invalid length of input")
        return aes_ecb_encrypt(master_key, otfad_input)

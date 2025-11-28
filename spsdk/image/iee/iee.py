#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IEE (In-Line Encryption Engine) support module.

This module provides comprehensive functionality for handling IEE operations
including key blob management, encryption attributes configuration, and IEE
engine setup for NXP MCUs with in-line encryption capabilities.
"""

import logging
import os
from copy import deepcopy
from struct import pack
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.apps.utils.utils import filepath_from_config
from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import Counter, aes_ctr_encrypt, aes_xts_encrypt
from spsdk.exceptions import SPSDKError
from spsdk.fuses.fuses import FuseScript
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import (
    Endianness,
    align_block,
    reverse_bytes_in_longs,
    split_data,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class IeeKeyBlobLockAttributes(SpsdkEnum):
    """IEE keyblob lock attributes enumeration.

    This enumeration defines the available lock states for IEE (Inline Encryption Engine)
    keyblob regions, controlling whether encryption regions are locked or unlocked.
    """

    LOCK = (0x95, "LOCK")  #  IEE region lock.
    UNLOCK = (0x59, "UNLOCK")  #  IEE region unlock.


class IeeKeyBlobKeyAttributes(SpsdkEnum):
    """IEE keyblob key attributes enumeration.

    This enumeration defines the supported key attribute configurations for IEE
    (Inline Encryption Engine) keyblob operations, specifying the encryption
    algorithms and key sizes for CTR and XTS modes.

    :cvar CTR128XTS256: AES 128-bit CTR mode with 256-bit XTS mode configuration.
    :cvar CTR256XTS512: AES 256-bit CTR mode with 512-bit XTS mode configuration.
    """

    CTR128XTS256 = (0x5A, "CTR128XTS256")  # AES 128 bits (CTR), 256 bits (XTS)
    CTR256XTS512 = (0xA5, "CTR256XTS512")  # AES 256 bits (CTR), 512 bits (XTS)


class IeeKeyBlobModeAttributes(SpsdkEnum):
    """IEE Keyblob mode attributes enumeration.

    Defines the available encryption modes for IEE (Inline Encryption Engine) keyblob operations,
    including bypass mode and various AES encryption modes with different addressing and keystream
    configurations.
    """

    Bypass = (0x6A, "Bypass")  # AES encryption/decryption bypass
    AesXTS = (0xA6, "AesXTS")  # AES XTS mode
    AesCTRWAddress = (0x66, "AesCTRWAddress")  # AES CTR w address binding mode
    AesCTRWOAddress = (0xAA, "AesCTRWOAddress")  # AES CTR w/o address binding mode
    AesCTRkeystream = (0x19, "AesCTRkeystream")  # AES CTR keystream only


class IeeKeyBlobWritePmsnAttributes(SpsdkEnum):
    """IEE key blob write permission attributes enumeration.

    This enumeration defines the available write permission settings for IEE (Inline Encryption Engine)
    key blobs in APC (Application Processing Core) context.

    :cvar ENABLE: Enable write permission in APC IEE (0x99).
    :cvar DISABLE: Disable write permission in APC IEE (0x11).
    """

    ENABLE = (0x99, "ENABLE")  # Enable write permission in APC IEE
    DISABLE = (0x11, "DISABLE")  # Disable write permission in APC IEE


class IeeKeyBlobAttribute:
    """IEE Keyblob Attribute configuration.

    This class represents the attribute structure for IEE (Inline Encryption Engine) keyblob
    configuration, managing lock control, key size, and AES mode settings. It provides
    methods to determine encryption mode characteristics and key size requirements.
    The class maps to the C structure:
    | typedef struct _iee_keyblob_attribute
    | {
    |     uint8_t lock;      #  IEE Region Lock control flag.
    |     uint8_t keySize;   #  IEE AES key size.
    |     uint8_t aesMode;   #  IEE AES mode.
    |     uint8_t reserved;  #  Reserved.
    | } iee_keyblob_attribute_t;
    """

    _FORMAT = "<BBBB"
    _SIZE = 4

    def __init__(
        self,
        lock: IeeKeyBlobLockAttributes,
        key_attribute: IeeKeyBlobKeyAttributes,
        aes_mode: IeeKeyBlobModeAttributes,
    ) -> None:
        """Initialize IEE keyblob with security attributes.

        Creates a new IEE (Inline Encryption Engine) keyblob instance with the specified
        lock, key, and AES mode attributes for secure data encryption.

        :param lock: Lock attributes controlling keyblob access permissions.
        :param key_attribute: Key attributes defining encryption key properties.
        :param aes_mode: AES mode attributes specifying encryption algorithm mode.
        """
        self.lock = lock
        self.key_attribute = key_attribute
        self.aes_mode = aes_mode

    @property
    def ctr_mode(self) -> bool:
        """Check if AES mode is CTR (Counter) mode.

        Determines whether the current AES mode configuration is set to any of the
        Counter (CTR) mode variants including CTR with address, CTR without address,
        or CTR keystream mode.

        :return: True if AES mode is CTR variant, False otherwise.
        """
        if self.aes_mode in [
            IeeKeyBlobModeAttributes.AesCTRWAddress,
            IeeKeyBlobModeAttributes.AesCTRWOAddress,
            IeeKeyBlobModeAttributes.AesCTRkeystream,
        ]:
            return True
        return False

    @property
    def key1_size(self) -> int:
        """Get IEE key1 size based on selected encryption mode.

        The key size depends on the key attribute configuration. For CTR128XTS256 mode,
        a 16-byte key is used, while other modes require a 32-byte key.

        :return: Key size in bytes.
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        return 32

    @property
    def key2_size(self) -> int:
        """Get IEE key2 size based on selected encryption mode.

        The method determines the appropriate key size by checking the key attribute
        and CTR mode configuration to return the correct size for the second key.

        :return: Key size in bytes (16 for CTR128XTS256 and CTR modes, 32 otherwise).
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        if self.ctr_mode:
            return 16
        return 32

    def export(self) -> bytes:
        """Export binary representation of KeyBlobAttribute.

        The method packs the lock tag, key attribute tag, AES mode tag, and a reserved zero value
        into a binary format using the predefined structure format.

        :return: Exported binary data as bytes.
        """
        return pack(self._FORMAT, self.lock.tag, self.key_attribute.tag, self.aes_mode.tag, 0)


class IeeKeyBlob:
    """IEE KeyBlob representation for NXP MCU image encryption.

    This class manages IEE (Inline Encryption Engine) key blob data structures
    used for configuring encryption regions in NXP MCU images. It handles both
    XTS-AES and AES-CTR encryption modes, providing functionality to encrypt
    image data and manage encryption parameters.
    The key blob contains encryption keys, region addresses, and configuration
    attributes that define how the IEE hardware should encrypt specific memory
    regions during runtime.

    | typedef struct _iee_keyblob_
    | {
    |     uint32_t header;                   #  IEE Key Blob header tag.
    |     uint32_t version;                  #  IEE Key Blob version, upward compatible.
    |     iee_keyblob_attribute_t attribute; #  IEE configuration attribute.
    |     uint32_t pageOffset;               #  IEE page offset.
    |     uint32_t key1[IEE_MAX_AES_KEY_SIZE_IN_BYTE /
    |                   sizeof(uint32_t)]; #  Encryption key1 for XTS-AES mode, encryption key for AES-CTR mode.
    |     uint32_t key2[IEE_MAX_AES_KEY_SIZE_IN_BYTE /
    |                   sizeof(uint32_t)]; #  Encryption key2 for XTS-AES mode, initial counter for AES-CTR mode.
    |     uint32_t startAddr;              #  Physical address of encryption region.
    |     uint32_t endAddr;                #  Physical address of encryption region.
    |     uint32_t reserved;               #  Reserved word.
    |     uint32_t crc32;                  #  Entire IEE Key Blob CRC32 value. Must be the last struct member.
    | } iee_keyblob_t

    :cvar HEADER_TAG: IEE Key Blob header identifier (0x49454542).
    :cvar KEYBLOB_VERSION: Version identifier for keyblob format (0x56010000).
    :cvar KEYBLOB_OFFSET: Default offset for keyblob placement (0x1000).
    """

    _FORMAT = "LL4BL8L8LLLLL96B"

    HEADER_TAG = 0x49454542
    # Tag used in keyblob header
    # (('I' << 24) | ('E' << 16) | ('E' << 8) | ('B' << 0))
    KEYBLOB_VERSION = 0x56010000
    # Identifier of IEE keyblob version
    # (('V' << 24) | (1 << 16) | (0 << 8) | (0 << 0))
    KEYBLOB_OFFSET = 0x1000

    _IEE_ENCR_BLOCK_SIZE_XTS = 0x1000

    _ENCRYPTION_BLOCK_SIZE = 0x10

    _START_ADDR_MASK = 0x400 - 1
    # Region addresses are modulo 1024

    _END_ADDR_MASK = 0x3F8

    def __init__(
        self,
        attributes: IeeKeyBlobAttribute,
        start_addr: int,
        end_addr: int,
        key1: Optional[bytes] = None,
        key2: Optional[bytes] = None,
        page_offset: int = 0,
        crc: Optional[bytes] = None,
    ):
        """Initialize IEE keyblob with encryption parameters and memory region.

        Creates a new IEE (Inline Encryption Engine) keyblob instance with specified
        attributes, memory region boundaries, and encryption keys. If keys are not
        provided, random keys will be generated automatically.

        :param attributes: IEE keyblob attributes defining encryption mode and key sizes.
        :param start_addr: Start address of the memory region to be encrypted.
        :param end_addr: End address of the memory region to be encrypted.
        :param key1: Encryption key1 for XTS-AES mode, encryption key for AES-CTR mode.
        :param key2: Encryption key2 for XTS-AES mode, initial_counter for AES-CTR mode.
        :param page_offset: Page offset value for the encryption region.
        :param crc: Optional CRC fill value for testing purposes; None to use calculated value.
        :raises SPSDKError: When start or end address are not properly aligned.
        :raises SPSDKError: When there is invalid key configuration.
        :raises SPSDKError: When start/end addresses are invalid or out of range.
        """
        self.attributes = attributes

        if key1 is None:
            key1 = random_bytes(self.attributes.key1_size)
        if key2 is None:
            key2 = random_bytes(self.attributes.key2_size)

        key1 = value_to_bytes(key1, byte_cnt=self.attributes.key1_size)
        key2 = value_to_bytes(key2, byte_cnt=self.attributes.key2_size)

        if start_addr < 0 or start_addr > end_addr or end_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid start/end address")

        if (start_addr & self._START_ADDR_MASK) != 0:
            raise SPSDKError(
                f"Start address must be aligned to {hex(self._START_ADDR_MASK + 1)} boundary"
            )

        self.start_addr = start_addr
        self.end_addr = end_addr

        self.key1 = key1
        self.key2 = key2
        self.page_offset = page_offset

        self.crc_fill = crc

    def __str__(self) -> str:
        """Get string representation of the IEE instance.

        Returns formatted information about the IEE configuration including encryption keys
        and memory address range.

        :return: Formatted string containing key values and address range information.
        """
        msg = ""
        msg += f"KEY 1:        {self.key1.hex()}\n"
        msg += f"KEY 2:       {self.key2.hex()}\n"
        msg += f"Start Addr: {hex(self.start_addr)}\n"
        msg += f"End Addr:   {hex(self.end_addr)}\n"
        return msg

    def plain_data(self) -> bytes:
        """Export key blob data in binary format.

        Serializes the key blob structure including header, attributes, page offset,
        encryption keys, address range, and CRC checksum into binary representation.

        :return: Key blob exported into binary form with proper alignment and CRC.
        """
        result = bytes()
        result += pack("<II", self.HEADER_TAG, self.KEYBLOB_VERSION)
        result += self.attributes.export()
        result += pack("<I", self.page_offset)
        result += align_block(self.key1, 32)
        result += align_block(self.key2, 32)
        result += pack("<III", self.start_addr, self.end_addr, 0)
        crc = (
            from_crc_algorithm(CrcAlg.CRC32_MPEG)
            .calculate(result)
            .to_bytes(4, Endianness.LITTLE.value)
        )
        result += crc

        return result

    def contains_addr(self, addr: int) -> bool:
        """Check if the key blob contains the specified address.

        :param addr: Memory address to be tested for containment within the key blob range.
        :return: True if the address is within the key blob range, False otherwise.
        """
        return self.start_addr <= addr <= self.end_addr

    def matches_range(self, image_start: int, image_end: int) -> bool:
        """Check if key blob matches the address range of the image to be encrypted.

        The method verifies that both the start and end addresses of the image
        fall within the address range covered by this key blob.

        :param image_start: Start address of the image to be encrypted.
        :param image_end: End address of the image to be encrypted.
        :return: True if the key blob covers the entire image address range, False otherwise.
        """
        return self.contains_addr(image_start) and self.contains_addr(image_end)

    def encrypt_image_xts(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using AES-XTS algorithm.

        The method encrypts data block by block using AES-XTS encryption with the configured
        keys. The base address must be within the valid memory range defined by start_addr
        and end_addr.

        :param base_address: Base address of the data in target memory, must be >= self.start_addr.
        :param data: Data to be encrypted (e.g. plain image), base_address + len(data) must be
            <= self.end_addr.
        :return: Encrypted data as bytes.
        """
        encrypted_data = bytes()
        current_start = base_address
        key1 = reverse_bytes_in_longs(self.key1)
        key2 = reverse_bytes_in_longs(self.key2)

        for block in split_data(bytearray(data), self._IEE_ENCR_BLOCK_SIZE_XTS):
            tweak = self.calculate_tweak(current_start)

            encrypted_block = aes_xts_encrypt(
                key1 + key2,
                block,
                tweak,
            )
            encrypted_data += encrypted_block
            current_start += len(block)

        return encrypted_data

    def encrypt_image_ctr(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using AES-CTR algorithm.

        The method encrypts data block by block using AES-CTR mode with keys and nonce
        derived from the IEE configuration. The counter is initialized based on the
        base address and incremented for each encryption block.

        :param base_address: Base address of the data in target memory; must be >= self.start_addr
        :param data: Data to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: Encrypted data as bytes
        """
        encrypted_data = bytes()
        key = reverse_bytes_in_longs(self.key1)
        nonce = reverse_bytes_in_longs(self.key2)

        counter = Counter(nonce, ctr_value=base_address >> 4, ctr_byteorder_encoding=Endianness.BIG)

        for block in split_data(bytearray(data), self._ENCRYPTION_BLOCK_SIZE):
            encrypted_block = aes_ctr_encrypt(
                key,
                block,
                counter.value,
            )
            encrypted_data += encrypted_block
            counter.increment(self._ENCRYPTION_BLOCK_SIZE >> 4)

        return encrypted_data

    def encrypt_image(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using IEE encryption.

        The method encrypts the provided data using either AES-XTS or AES-CTR mode
        based on the configuration. The data is automatically aligned to the required
        block size and the base address must be 16-byte aligned.

        :param base_address: Base address of the data in target memory, must be 16-byte aligned
        :param data: Data to be encrypted (e.g. plain image)
        :return: Encrypted data with proper alignment
        :raises SPSDKError: If start address is not 16-byte aligned
        :raises NotImplementedError: If AES-CTR mode is not implemented yet
        """
        if base_address % 16 != 0:
            raise SPSDKError("Invalid start address")  # Start address has to be 16 byte aligned
        data = align_block(data, self._ENCRYPTION_BLOCK_SIZE)  # align data length
        data_len = len(data)

        # check start and end addresses
        if not self.matches_range(base_address, base_address + data_len - 1):
            logger.warning(
                f"Image address range is not within key blob: {hex(self.start_addr)}-{hex(self.end_addr)}."
            )

        if self.attributes.ctr_mode:
            return self.encrypt_image_ctr(base_address, data)
        return self.encrypt_image_xts(base_address, data)

    @staticmethod
    def calculate_tweak(address: int) -> bytes:
        """Calculate tweak value for AES-XTS encryption based on the address value.

        The method calculates a 16-byte tweak by extracting the sector number from the address
        (address >> 12) and distributing its bytes across the tweak array.

        :param address: Start address of encryption.
        :return: 16-byte tweak value for AES-XTS encryption.
        """
        sector = address >> 12
        tweak = bytearray(16)
        for n in range(16):
            tweak[n] = sector & 0xFF
            sector = sector >> 8
        return bytes(tweak)


class Iee(FeatureBaseClass):
    """IEE (Inline Encryption Engine) manager for NXP MCU devices.

    This class provides functionality to manage inline encryption operations including
    key blob management, image encryption, and export capabilities. It handles the
    configuration and processing of encryption keys, binary images, and generates
    necessary output files for secure provisioning.

    :cvar FEATURE: Database feature identifier for IEE operations.
    :cvar IEE_DATA_UNIT: Standard data unit size for IEE operations (4KB).
    :cvar IEE_KEY_BLOBS_SIZE: Size of IEE key blobs in bytes.
    """

    FEATURE = DatabaseManager.IEE

    IEE_DATA_UNIT = 0x1000
    IEE_KEY_BLOBS_SIZE = 384

    def __init__(
        self,
        family: FamilyRevision,
        keyblob_address: int,
        ibkek1: Optional[Union[bytes, str]] = None,
        ibkek2: Optional[Union[bytes, str]] = None,
        key_blobs: Optional[list[IeeKeyBlob]] = None,
        binaries: Optional[BinaryImage] = None,
        iee_export_filepath: str = "iee_full_image",
        keyblob_export_filepath: str = "iee_keyblob",
        generate_readme: bool = True,
        generate_fuse_script: bool = True,
    ) -> None:
        """Initialize IEE (Inline Encryption Engine) configuration.

        Sets up the IEE configuration with encryption keys, key blobs, and export settings
        for secure image processing on NXP MCU devices.

        :param family: Target device family and revision information.
        :param keyblob_address: Memory address where key blobs will be stored.
        :param ibkek1: First 256-bit key for IEE keyblob encryption (hex string or bytes).
        :param ibkek2: Second 256-bit key for IEE keyblob encryption (hex string or bytes).
        :param key_blobs: List of IEE key blob objects to include in configuration.
        :param binaries: Additional binary images to process with IEE.
        :param iee_export_filepath: Output file path for complete IEE image with keyblobs.
        :param keyblob_export_filepath: Output file path for standalone IEE keyblobs.
        :param generate_readme: Whether to generate documentation readme file.
        :param generate_fuse_script: Whether to generate fuse programming script.
        :raises SPSDKValueError: Unsupported device family or invalid configuration.
        """
        self._key_blobs: list[IeeKeyBlob] = []

        self.db = get_db(family)
        self.family = family
        self.ibkek1 = bytes.fromhex(ibkek1) if isinstance(ibkek1, str) else ibkek1
        self.ibkek2 = bytes.fromhex(ibkek2) if isinstance(ibkek2, str) else ibkek2
        self.keyblob_address = keyblob_address
        self.binaries = binaries

        self.blobs_min_cnt = self.db.get_int(DatabaseManager.IEE, "key_blob_min_cnt")
        self.blobs_max_cnt = self.db.get_int(DatabaseManager.IEE, "key_blob_max_cnt")
        self.generate_keyblob = self.db.get_bool(DatabaseManager.IEE, "generate_keyblob")
        self.iee_all = iee_export_filepath
        self.keyblob_name = keyblob_export_filepath
        self.generate_readme = generate_readme
        self.generate_fuse_script = generate_fuse_script

        if key_blobs:
            for key_blob in key_blobs:
                self.add_key_blob(key_blob)

    def __repr__(self) -> str:
        """Get string representation of IEE object.

        :return: String representation containing the target family name.
        """
        return f"IEE object for {self.family}"

    def __str__(self) -> str:
        """Get string representation of IEE object.

        Returns a formatted string containing IEE configuration details including family,
        keyblob address, binaries information, and IBKEK keys if available.

        :return: Formatted string with IEE object details.
        """
        description = (
            f"IEE object for {self.family}:\n"
            f" Keyblob address: {hex(self.keyblob_address)}\n"
            f" Binaries: {self.binaries.draw() if self.binaries else 'No binaries available'}\n"
        )
        if isinstance(self.ibkek1, bytes) and isinstance(self.ibkek2, bytes):
            description += f" IBKEK1: {hex(int(self.ibkek1))}\n"
            description += f" IBKEK2: {hex(int(self.ibkek2))}\n"
        return description

    def __getitem__(self, index: int) -> IeeKeyBlob:
        """Get key blob at specified index.

        :param index: Index of the key blob to retrieve.
        :return: Key blob at the specified index.
        """
        return self._key_blobs[index]

    def __setitem__(self, index: int, value: IeeKeyBlob) -> None:
        """Set key blob at specified index.

        Replaces the existing key blob at the given index with a new key blob value.

        :param index: Index position where to set the key blob.
        :param value: IeeKeyBlob instance to set at the specified index.
        :raises IndexError: If index is out of range.
        """
        self._key_blobs.remove(self._key_blobs[index])
        self._key_blobs.insert(index, value)

    def add_key_blob(self, key_blob: IeeKeyBlob) -> None:
        """Add key blob for specified address range.

        :param key_blob: IEE key blob object to be added to the collection.
        """
        self._key_blobs.append(key_blob)

    def encrypt_image(self, image: bytes, base_addr: int) -> bytes:
        """Encrypt image with all available keyblobs.

        The method iterates through the image data in blocks and applies encryption
        using matching keyblobs based on memory address ranges. Each block is
        encrypted with all keyblobs that cover its address range.

        :param image: Plain image data to be encrypted.
        :param base_addr: Base address where the image will be located in target processor.
        :return: Encrypted image data.
        """
        encrypted_data = bytearray(image)
        addr = base_addr
        for block in split_data(image, self.IEE_DATA_UNIT):
            for key_blob in self._key_blobs:
                if key_blob.matches_range(addr, addr + len(block)):
                    logger.debug(
                        f"Encrypting {hex(addr)}:{hex(len(block) + addr)}"
                        f" with keyblob: \n {str(key_blob)}"
                    )
                    encrypted_data[addr - base_addr : len(block) + addr - base_addr] = (
                        key_blob.encrypt_image(addr, block)
                    )
            addr += len(block)

        return bytes(encrypted_data)

    def get_key_blobs(self) -> bytes:
        """Get key blobs data.

        Retrieves all key blobs as concatenated binary data, aligned to the required IEE key blobs size.

        :return: Binary key blobs joined together and aligned to IEE_KEY_BLOBS_SIZE.
        """
        result = bytes()
        for key_blob in self._key_blobs:
            result += key_blob.plain_data()

        # return result
        return align_block(result, self.IEE_KEY_BLOBS_SIZE)

    def encrypt_key_blobs(
        self,
        ibkek1: Union[bytes, str],
        ibkek2: Union[bytes, str],
        keyblob_address: int,
    ) -> bytes:
        """Encrypt keyblobs and export them as binary.

        This method takes two key encryption keys and encrypts the keyblobs using AES-XTS encryption
        with a calculated tweak based on the keyblob address.

        :param ibkek1: First key encryption key for AES-XTS 256-bit encryption (32 bytes).
        :param ibkek2: Second key encryption key for AES-XTS 256-bit encryption (32 bytes).
        :param keyblob_address: Base address of the keyblob used for tweak calculation.
        :return: Encrypted keyblobs as binary data.
        """
        plain_key_blobs = self.get_key_blobs()

        ibkek1 = reverse_bytes_in_longs(value_to_bytes(ibkek1, byte_cnt=32))
        logger.debug(f"IBKEK1: {' '.join(f'{b:02x}' for b in ibkek1)}")
        ibkek2 = reverse_bytes_in_longs(value_to_bytes(ibkek2, byte_cnt=32))
        logger.debug(f"IBKEK2 {' '.join(f'{b:02x}' for b in ibkek2)}")

        tweak = IeeKeyBlob.calculate_tweak(keyblob_address)
        return aes_xts_encrypt(
            ibkek1 + ibkek2,
            plain_key_blobs,
            tweak,
        )

    def export_key_blobs(self) -> bytes:
        """Export encrypted keyblobs in binary format.

        This method encrypts and exports the key blobs using the configured IBKEK1 and IBKEK2 keys
        at the specified keyblob address.

        :raises SPSDKError: When IBKEK1 or IBKEK2 is missing.
        :return: Encrypted keyblobs as binary data.
        """
        if self.ibkek1 and self.ibkek2:
            return self.encrypt_key_blobs(self.ibkek1, self.ibkek2, self.keyblob_address)
        raise SPSDKError("Cannot export key blobs: IBKEK1 or IBKEK2 is missing")

    def export(self) -> bytes:
        """Export object into bytes array.

        This is an abstract method that must be implemented by child classes to provide
        serialization functionality for IEE objects.

        :raises NotImplementedError: Method not implemented in child class.
        :return: Exported bytes representation of the object.
        """
        raise NotImplementedError()

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export steps for IEE image generation.

        Exports the complete IEE binary image, individual encrypted data blobs, generates
        documentation files, and creates fuse programming scripts based on configuration.
        The method handles file generation with proper logging and skips disabled components.

        :param output_path: Directory path where generated files will be saved.
        :return: List of file paths for all successfully generated files.
        """
        generated_files = []

        binary_image = self.binary_image(keyblob_name=self.keyblob_name, image_name=self.iee_all)
        logger.info(binary_image.draw())

        if self.iee_all == "":
            logger.info("Skipping export of IEE whole image")
        else:
            write_file(binary_image.export(), self.iee_all, mode="wb")
            generated_files.append(self.iee_all)

        memory_map = (
            "Output folder contains:\n"
            "  -  Binary file that contains whole image data including "
            f"IEE key blobs data {self.iee_all}.\n"
            f"IEE memory map:\n{binary_image.draw(no_color=True)}"
        )

        for image in binary_image.sub_images:
            if image.name != "":
                write_file(image.export(), image.name, mode="wb")
                generated_files.append(image.name)
                logger.info(f"Created Encrypted IEE data blob {image.description}:\n{image.name}")
                memory_map += f"\n{image.name}:\n{str(image)}"
            else:
                logger.info(
                    f"Skipping export of {str(image)}, value is blank in the configuration file"
                )

        readme_file = os.path.join(output_path, "readme.txt")

        if self.generate_readme:
            write_file(memory_map, readme_file)
            generated_files.append(readme_file)
            logger.info(f"Created IEE readme file:\n{readme_file}")
        else:
            logger.info("Skipping generation of IEE readme file")

        if self.db.get_bool(DatabaseManager.IEE, "has_kek_fuses") and self.generate_fuse_script:
            blhost_script = self.get_blhost_script_otp_kek()
            blhost_script_filename = os.path.join(output_path, f"iee_{self.family.name}_blhost.bcf")
            write_file(blhost_script, blhost_script_filename)
            generated_files.append(blhost_script_filename)
        else:
            logger.info("Skipping generation of IEE BLHOST load fuses script")

        return generated_files

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        This is an abstract method that must be implemented by subclasses to deserialize
        an object from its binary representation.

        :param data: Input bytes array containing the serialized object data.
        :raises NotImplementedError: This method must be implemented by subclasses.
        :return: Parsed object instance.
        """
        raise NotImplementedError

    def export_image(self) -> Optional[BinaryImage]:
        """Export encrypted image.

        This method processes all binary images and their segments, encrypting each binary
        using the configured encryption settings. The original binaries are preserved by
        creating a deep copy before encryption.

        :return: Encrypted binary image with all sub-images and segments processed,
            or None if no binaries are available.
        """
        if self.binaries is None:
            return None
        self.binaries.validate()

        binaries: BinaryImage = deepcopy(self.binaries)

        for binary in binaries.sub_images:
            if binary.binary:
                binary.binary = self.encrypt_image(
                    binary.binary, binary.absolute_address + self.keyblob_address
                )
            for segment in binary.sub_images:
                if segment.binary:
                    segment.binary = self.encrypt_image(
                        segment.binary,
                        segment.absolute_address + self.keyblob_address,
                    )

        binaries.validate()
        return binaries

    def get_blhost_script_otp_kek(self) -> str:
        """Generate BLHOST script to load fuses needed to run IEE with OTP fuses.

        The method checks if the target family supports IEE KEK fuses and generates
        a fuse script accordingly. If KEK fuses are not supported, returns empty string.

        :return: BLHOST script that loads the keys into fuses, or empty string if not supported.
        """
        if not self.db.get_bool(DatabaseManager.IEE, "has_kek_fuses", default=False):
            logger.debug(f"The {self.family} has no IEE KEK fuses")
            return ""

        fuses_script = FuseScript(self.family, DatabaseManager.IEE)
        return fuses_script.generate_script(self)

    def binary_image(
        self,
        plain_data: bool = False,
        data_alignment: int = 16,
        keyblob_name: str = "iee_keyblob.bin",
        image_name: str = "encrypted.bin",
    ) -> BinaryImage:
        """Get the IEE Binary Image representation.

        The method creates a binary image containing IEE keyblobs and encrypted data,
        with configurable alignment and naming options for output files.

        :param plain_data: Binary representation in plain format, defaults to False
        :param data_alignment: Alignment of data part key blobs, defaults to 16
        :param keyblob_name: Filename of the IEE keyblob, defaults to "iee_keyblob.bin"
        :param image_name: Filename of the IEE image, defaults to "encrypted.bin"
        :return: IEE in BinaryImage format.
        """
        iee = BinaryImage(image_name, offset=self.keyblob_address)
        if self.generate_keyblob:
            # Add mandatory IEE keyblob
            iee_keyblobs = self.get_key_blobs() if plain_data else self.export_key_blobs()
            iee.add_image(
                BinaryImage(
                    keyblob_name,
                    offset=0,
                    description=f"IEE keyblobs {self.family}",
                    binary=iee_keyblobs,
                )
            )
        binaries = self.export_image()

        if binaries:
            binaries.alignment = data_alignment
            binaries.validate()
            iee.add_image(binaries)

        return iee

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for IEE configuration.

        Retrieves validation schemas including family-specific schema, general IEE schemas,
        and any additional schemas defined in the database for the specified family.

        :param family: Family revision for which the validation schemas should be generated.
        :return: List of validation schema dictionaries for IEE configuration.
        """
        database = get_db(family)
        schemas = get_schema_file(DatabaseManager.IEE)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=sch_family["properties"], devices=cls.get_supported_families(), family=family
        )
        sch_family["main_title"] = f"IEE: Inline Encryption Engine Configuration for {family}."
        sch_family["note"] = database.get_str(
            DatabaseManager.IEE, "additional_template_text", default=""
        )

        ret = [sch_family, schemas["iee_output"], schemas["iee"]]
        additional_schemes = database.get_list(
            DatabaseManager.IEE, "additional_template", default=[]
        )
        ret.extend([schemas[x] for x in additional_schemes])
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Get configuration of the IEE feature.

        Creates a configuration object that can be used to configure the IEE (Inline Encryption Engine)
        feature with the specified data path for storing configuration files.

        :param data_path: Path to directory where configuration data files will be stored.
        :raises NotImplementedError: This method must be implemented by subclasses.
        :return: Configuration object for the IEE feature.
        """
        raise NotImplementedError

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load IEE image object from configuration.

        Creates an IEE (In-line Encryption Engine) image object by parsing the provided
        configuration data, including key blobs, data blobs, and encryption parameters.

        :param config: Configuration object containing IEE settings and key blob definitions.
        :return: Initialized IEE object with configured key blobs and encryption settings.
        """
        family = FamilyRevision.load_from_config(config)
        ibkek1: Optional[bytes] = None
        ibkek2: Optional[bytes] = None
        try:
            ibkek1 = config.load_symmetric_key("ibkek1", expected_size=32)
            ibkek2 = config.load_symmetric_key("ibkek2", expected_size=32)

            logger.debug(f"Loaded IBKEK1: {ibkek1.hex()}")
            logger.debug(f"Loaded IBKEK2: {ibkek2.hex()}")
        except SPSDKError:
            logger.debug("IBKEK not provided")
            ibkek1 = ibkek2 = None

        keyblob_address = config.get_int("keyblob_address")
        if "key_blobs" in config:
            iee_config = config.get_list_of_configs("key_blobs")
        else:
            iee_config = [config.get_config("key_blob")]
        start_address = min(
            [value_to_int(addr.get("start_address", 0xFFFFFFFF)) for addr in iee_config]
        )

        binaries = None
        if "data_blobs" in config:
            # start address to calculate offset from keyblob, min from keyblob or data blob address
            # pylint: disable-next=nested-min-max
            data_blobs = config.get_list_of_configs("data_blobs")
            start_address_data = min(
                [value_to_int(addr.get("address", 0xFFFFFFFF)) for addr in data_blobs]
            )
            if start_address_data < start_address:
                start_address = start_address_data
            binaries = BinaryImage(
                filepath_from_config(
                    config,
                    "encrypted_name",
                    "encrypted_blobs",
                    config["output_folder"],
                ),
                offset=start_address - keyblob_address,
                alignment=IeeKeyBlob._ENCRYPTION_BLOCK_SIZE,
            )
            for data_blob in data_blobs:
                address = value_to_int(
                    data_blob.get("address", 0), keyblob_address + binaries.offset
                )

                binary = BinaryImage.load_binary_image(
                    path=data_blob["data"],
                    search_paths=config.search_paths,
                    offset=address - keyblob_address - binaries.offset,
                    alignment=IeeKeyBlob._ENCRYPTION_BLOCK_SIZE,
                    size=0,
                )

                binaries.add_image(binary)

        output_folder = config.get_output_file_name("output_folder")
        iee_export_filename = filepath_from_config(
            config, "output_name", "iee_full_image", output_folder
        )
        keyblob_export_filename = filepath_from_config(
            config, "keyblob_name", "iee_keyblob", output_folder
        )
        generate_readme = config.get("generate_readme", True)
        generate_fuse_script = config.get("generate_fuses_script", True)

        iee = cls(
            family,
            keyblob_address,
            ibkek1,
            ibkek2,
            binaries=binaries,
            iee_export_filepath=iee_export_filename,
            keyblob_export_filepath=keyblob_export_filename,
            generate_readme=generate_readme,
            generate_fuse_script=generate_fuse_script,
        )

        for key_blob_cfg in iee_config:
            region_lock = "LOCK" if key_blob_cfg.get("region_lock") else "UNLOCK"

            attributes = IeeKeyBlobAttribute(
                IeeKeyBlobLockAttributes.from_label(region_lock),
                IeeKeyBlobKeyAttributes.from_label(key_blob_cfg.get_str("key_size")),
                IeeKeyBlobModeAttributes.from_label(key_blob_cfg.get_str("aes_mode")),
            )

            key1 = key_blob_cfg.load_symmetric_key("key1", attributes.key1_size)
            key2 = key_blob_cfg.load_symmetric_key("key2", attributes.key2_size)

            start_addr = key_blob_cfg.get_int("start_address", start_address)
            end_addr = key_blob_cfg.get_int("end_address", 0xFFFFFFFF)
            page_offset = key_blob_cfg.get_int("page_offset", 0)

            iee.add_key_blob(
                IeeKeyBlob(
                    attributes=attributes,
                    start_addr=start_addr,
                    end_addr=end_addr,
                    key1=key1,
                    key2=key2,
                    page_offset=page_offset,
                )
            )

        return iee

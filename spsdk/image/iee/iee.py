#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for IEE (In-Line Encryption Engine)."""

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
    """IEE keyblob lock attributes."""

    LOCK = (0x95, "LOCK")  #  IEE region lock.
    UNLOCK = (0x59, "UNLOCK")  #  IEE region unlock.


class IeeKeyBlobKeyAttributes(SpsdkEnum):
    """IEE keyblob key attributes."""

    CTR128XTS256 = (0x5A, "CTR128XTS256")  # AES 128 bits (CTR), 256 bits (XTS)
    CTR256XTS512 = (0xA5, "CTR256XTS512")  # AES 256 bits (CTR), 512 bits (XTS)


class IeeKeyBlobModeAttributes(SpsdkEnum):
    """IEE Keyblob mode attributes."""

    Bypass = (0x6A, "Bypass")  # AES encryption/decryption bypass
    AesXTS = (0xA6, "AesXTS")  # AES XTS mode
    AesCTRWAddress = (0x66, "AesCTRWAddress")  # AES CTR w address binding mode
    AesCTRWOAddress = (0xAA, "AesCTRWOAddress")  # AES CTR w/o address binding mode
    AesCTRkeystream = (0x19, "AesCTRkeystream")  # AES CTR keystream only


class IeeKeyBlobWritePmsnAttributes(SpsdkEnum):
    """IEE keblob write permission attributes."""

    ENABLE = (0x99, "ENABLE")  # Enable write permission in APC IEE
    DISABLE = (0x11, "DISABLE")  # Disable write permission in APC IEE


class IeeKeyBlobAttribute:
    """IEE Keyblob Attribute.

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
        """IEE keyblob constructor.

        :param lock: IeeKeyBlobLockAttributes
        :param key_attribute: IeeKeyBlobKeyAttributes
        :param aes_mode: IeeKeyBlobModeAttributes
        """
        self.lock = lock
        self.key_attribute = key_attribute
        self.aes_mode = aes_mode

    @property
    def ctr_mode(self) -> bool:
        """Return true if AES mode is CTR.

        :return: True if AES-CTR, false otherwise
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
        """Return IEE key size based on selected mode.

        :return: Key size in bytes
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        return 32

    @property
    def key2_size(self) -> int:
        """Return IEE key size based on selected mode.

        :return: Key size in bytes
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        if self.ctr_mode:
            return 16
        return 32

    def export(self) -> bytes:
        """Export binary representation of KeyBlobAttribute.

        :return: Exported binary data
        """
        return pack(self._FORMAT, self.lock.tag, self.key_attribute.tag, self.aes_mode.tag, 0)


class IeeKeyBlob:
    """IEE KeyBlob.

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
        """Constructor.

        :param attributes: IEE keyblob attributes
        :param start_addr: start address of the region
        :param end_addr: end address of the region
        :param key1: Encryption key1 for XTS-AES mode, encryption key for AES-CTR mode.
        :param key2: Encryption key2 for XTS-AES mode, initial_counter for AES-CTR mode.
        :param crc: optional value for unused CRC fill (for testing only); None to use calculated value
        :raises SPSDKError: Start or end address are not aligned
        :raises SPSDKError: When there is invalid key
        :raises SPSDKError: When there is invalid start/end address
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
        """Text info about the instance."""
        msg = ""
        msg += f"KEY 1:        {self.key1.hex()}\n"
        msg += f"KEY 2:       {self.key2.hex()}\n"
        msg += f"Start Addr: {hex(self.start_addr)}\n"
        msg += f"End Addr:   {hex(self.end_addr)}\n"
        return msg

    def plain_data(self) -> bytes:
        """Plain data for selected key range.

        :return: key blob exported into binary form (serialization)
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
        """Whether key blob contains specified address.

        :param addr: to be tested
        :return: True if yes, False otherwise
        """
        return self.start_addr <= addr <= self.end_addr

    def matches_range(self, image_start: int, image_end: int) -> bool:
        """Whether key blob matches address range of the image to be encrypted.

        :param image_start: start address of the image
        :param image_end: last address of the image
        :return: True if yes, False otherwise
        """
        return self.contains_addr(image_start) and self.contains_addr(image_end)

    def encrypt_image_xts(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using AES-XTS.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
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
        """Encrypt specified data using AES-CTR.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
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
        """Encrypt specified data.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
        :raises SPSDKError: If start address is not valid
        :raises NotImplementedError: AES-CTR is not implemented yet
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

        :param address: start address of encryption
        :return: 16 byte tweak values
        """
        sector = address >> 12
        tweak = bytearray(16)
        for n in range(16):
            tweak[n] = sector & 0xFF
            sector = sector >> 8
        return bytes(tweak)


class Iee(FeatureBaseClass):
    """IEE: Inline Encryption Engine."""

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
        """Constructor.

        :param family: Device family
        :param ibkek1: 256 bit key to encrypt IEE keyblob
        :param ibkek2: 256 bit key to encrypt IEE keyblob
        :param key_blobs: Optional Key blobs to add to IEE, defaults to None
        :param binaries: Optional extra binaries
        :param iee_export_filepath: Filepath for export to IEE full image with keyblobs
        :param keyblob_export_filepath: Filepath to export for IEE keyblobs
        :param generate_readme: True to generate readme file
        :param generate_fuse_script: True to generate fuse script
        :raises SPSDKValueError: Unsupported family
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
        """Simple object text representation."""
        return f"IEE object for {self.family}"

    def __str__(self) -> str:
        """Object text representation."""
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
        return self._key_blobs[index]

    def __setitem__(self, index: int, value: IeeKeyBlob) -> None:
        self._key_blobs.remove(self._key_blobs[index])
        self._key_blobs.insert(index, value)

    def add_key_blob(self, key_blob: IeeKeyBlob) -> None:
        """Add key for specified address range.

        :param key_blob: to be added
        """
        self._key_blobs.append(key_blob)

    def encrypt_image(self, image: bytes, base_addr: int) -> bytes:
        """Encrypt image with all available keyblobs.

        :param image: plain image to be encrypted
        :param base_addr: where the image will be located in target processor
        :return: encrypted image
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
        """Get key blobs.

        :return: Binary key blobs joined together
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

        :param ibkek1: key encryption key AES-XTS 256 bit
        :param ibkek2: key encryption key AES-XTS 256 bit
        :param keyblob_address: keyblob base address
        :return: encrypted keyblobs
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
        """Export encrypted keyblobs in binary.

        :return: Encrypted keyblobs
        """
        if self.ibkek1 and self.ibkek2:
            return self.encrypt_key_blobs(self.ibkek1, self.ibkek2, self.keyblob_address)
        raise SPSDKError("Cannot export key blobs: IBKEK1 or IBKEK2 is missing")

    def export(self) -> bytes:
        """Export object into bytes array.

        :raises: NotImplementedError if not implemented in child class
        :return: Exported bytes
        """
        raise NotImplementedError()

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export steps like saving the script files."""
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

        :param data: Input bytes array
        :return: Parsed object
        """
        raise NotImplementedError

    def export_image(self) -> Optional[BinaryImage]:
        """Export encrypted image.

        :return: Encrypted image
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
        """Create BLHOST script to load fuses needed to run IEE with OTP fuses.

        :return: BLHOST script that loads the keys into fuses.
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

        :param plain_data: Binary representation in plain format, defaults to False
        :param data_alignment: Alignment of data part key blobs.
        :param keyblob_name: Filename of the IEE keyblob
        :param image_name: Filename of the IEE image
        :return: IEE in BinaryImage.
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
        """Get list of validation schemas.

        :param family: Family for which the template should be generated.
        :return: Validation list of schemas.
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
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        raise NotImplementedError

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration option into an IEE image object.

        "config" content array of containers configurations.

        :param config: array of IEE configuration dictionaries.
        :return: initialized IEE object.
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

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Bus Encryption Engine (BEE) support module.

This module provides comprehensive functionality for handling BEE encryption
used in NXP MCUs. It includes classes for managing BEE regions, protection
blocks, key information blocks (KIB), and AES encryption modes for secure
boot and runtime protection of code and data.
"""


import logging
from struct import calcsize, pack, unpack_from
from typing import Any, Optional, Sequence

from typing_extensions import Self

from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import (
    Counter,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ctr_encrypt,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
)
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKOverlapError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import (
    Endianness,
    align_block_fill_random,
    extend_block,
    load_binary,
    split_data,
    value_to_int,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)

# maximal size of encrypted block in bytes
BEE_ENCR_BLOCK_SIZE = 0x400
# mask of the bits in the address, that must be zero
_ENCR_BLOCK_ADDR_MASK = BEE_ENCR_BLOCK_SIZE - 1  # 0x3FF


class BeeBaseClass:
    """BEE base class for binary data serialization and validation.

    This abstract base class provides common functionality for BEE (Bus Encryption Engine)
    related classes that need to serialize to/from binary format. It defines the interface
    for size calculation, data validation, export operations, and comparison methods.

    :cvar _FORMAT: Binary format string for struct.pack/unpack operations (must be defined in subclasses).
    """

    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    # the format is class specific, and must be defined in child class
    _FORMAT = "@_must_be_defined_in_child_class_@"

    @classmethod
    def _struct_format(cls) -> str:
        """Get struct format string for binary operations.

        Returns the format string used by struct.pack/unpack functions for converting
        between binary format and object representation.

        :return: Format string for struct pack/unpack operations.
        """
        return cls._FORMAT  # _FORMAT class constant must be defined in child class

    @classmethod
    def get_size(cls) -> int:
        """Get size of the exported binary data.

        :return: Size of the exported binary data in bytes.
        """
        return calcsize(cls._struct_format())

    def __eq__(self, other: Any) -> bool:
        """Check equality with another object.

        Compares this instance with another object by checking if they are of the same class
        and have identical instance variables.

        :param other: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and (vars(other) == vars(self))

    @property
    def size(self) -> int:
        """Get size of the exported binary data.

        :return: Size of the exported binary data in bytes.
        """
        return self.get_size()

    def __repr__(self) -> str:
        """Return string representation of BEE object.

        Provides a concise string representation showing the BEE object type and its size in bytes.

        :return: String representation in format "BEE, Length = {size}B".
        """
        return f"BEE, Length = {self.size}B"

    def __str__(self) -> str:
        """Get string representation of the instance.

        :raises NotImplementedError: Derived class has to implement this method.
        :return: Text description of the instance.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def update(self) -> None:
        """Updates internal fields of the instance.

        This method refreshes and synchronizes the internal state of the BEE
        (Bus Encryption Engine) instance to ensure all fields are current and
        consistent.
        """

    def validate(self) -> None:
        """Validate the configuration of the BEE instance.

        Ensures all required configuration parameters are properly set and valid.
        It is recommended to call this method before export and after parsing.

        :raises SPSDKError: Invalid configuration detected.
        """

    def export(self) -> bytes:
        """Export binary representation of the region.

        The method updates and validates the region before serialization to ensure
        data consistency and integrity.

        :return: Binary representation of the region (serialization).
        """
        self.update()
        self.validate()
        return b""

    @classmethod
    def check_data_to_parse(cls, data: bytes) -> None:
        """Check if binary data has sufficient size for parsing.

        Validates that the provided binary data contains enough bytes to be
        successfully parsed by the class.

        :param data: Binary data to be validated for parsing.
        :raises SPSDKError: If size of the data is not sufficient.
        """
        if len(data) < cls.get_size():
            raise SPSDKError("Insufficient size of the data")


class BeeFacRegion(BeeBaseClass):
    """BEE Factory Access Control (FAC) region.

    This class represents a memory region configuration for BEE (Bus Encryption Engine)
    Factory Access Control, defining protected memory areas with specific access levels
    and encryption boundaries aligned to 1KB boundaries.

    :cvar _FORMAT: Binary format string for struct pack/unpack operations.
    """

    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    _FORMAT = "<3I20s"

    def __init__(self, start: int = 0, length: int = 0, protected_level: int = 0):
        """Initialize BEE FAC region configuration.

        Creates a new FAC (Flexible Access Control) region with specified memory boundaries
        and protection settings for BEE encryption engine.

        :param start: Start address of FAC region, must be aligned at 1KB boundary.
        :param length: Length of FAC region in bytes, must be aligned at 1KB boundary.
        :param protected_level: Protection level (0=unprotected, 1-3=increasing protection).
        """
        self.start_addr = start
        self.length = length
        self.protected_level = protected_level
        # immediately validate all parameters
        self.validate()

    @property
    def end_addr(self) -> int:
        """Get end address of the region.

        The end address represents the first address after the region (last address + 1).

        :return: End address of the region.
        """
        return self.start_addr + self.length

    def __repr__(self) -> str:
        """Return string representation of FAC region.

        Provides a formatted string showing the start address and length of the
        Flash Access Control region in hexadecimal format.

        :return: Formatted string with FAC start address and length in hex format.
        """
        return f"FAC: 0x{self.start_addr:08x}[0x{self.length:x}]"

    def __str__(self) -> str:
        """Get string representation of the FAC instance.

        :return: String containing start address, length, and protection level in hexadecimal format.
        """
        return f"FAC(start={hex(self.start_addr)}, length={hex(self.length)}, protected_level={self.protected_level})"

    def validate(self) -> None:
        """Validate the BEE encryption region configuration.

        Performs comprehensive validation of the encryption region including address alignment,
        protection level bounds, and address range validity.

        :raises SPSDKError: Invalid encryption block address alignment.
        :raises SPSDKError: Invalid protected level (must be 0-3).
        :raises SPSDKError: Invalid start/end address range or bounds.
        """
        if (self.start_addr & _ENCR_BLOCK_ADDR_MASK != 0) and (
            self.length & _ENCR_BLOCK_ADDR_MASK != 0
        ):
            raise SPSDKError("Invalid configuration of the instance")
        if self.protected_level < 0 or self.protected_level > 3:
            raise SPSDKError("Invalid protected level")
        if self.start_addr < 0 or self.end_addr > 0xFFFFFFFF or self.start_addr >= self.end_addr:
            raise SPSDKError("Invalid start/end address")

    def export(self) -> bytes:
        """Export the binary representation of the BEE region configuration.

        The method exports the current BEE region configuration including the parent
        class data followed by the region-specific parameters (start address, end
        address, protection level, and padding).

        :return: Binary representation of the BEE region configuration.
        """
        result = super().export()
        return result + pack(
            self._struct_format(),
            self.start_addr,
            self.end_addr,
            self.protected_level,
            b"\x00" * 20,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data to create BeeFacRegion instance.

        Deserializes binary data into a BeeFacRegion object by extracting start address,
        end address, and protection level from the structured data format.

        :param data: Binary data to be parsed into BeeFacRegion instance.
        :return: BeeFacRegion instance created from the parsed binary data.
        :raises SPSDKError: If reserved area contains non-zero values.
        """
        cls.check_data_to_parse(data)  # check size of the data
        (start, end, protected_level, _reserved) = unpack_from(BeeFacRegion._struct_format(), data)
        if _reserved != b"\x00" * 20:
            raise SPSDKError("Reserved area is non-zero")
        return cls(start, end - start, protected_level)


class BeeProtectRegionBlockAesMode(SpsdkEnum):
    """AES mode selection enumeration for BEE PRDB encryption.

    This enumeration defines the available AES encryption modes that can be used
    for Bus Encryption Engine (BEE) Protect Region Data Block operations.
    """

    ECB = (0, "ECB")
    CTR = (1, "CTR")


class BeeProtectRegionBlock(BeeBaseClass):
    """BEE protect region block (PRDB).

    This class represents a Bus Encryption Engine (BEE) protection region data block that manages
    encrypted memory regions and their associated Flash Access Control (FAC) regions. It handles
    AES encryption configuration, lock options, and counter values for secure boot operations.

    :cvar TAGL: Low TAG identifier for the header (0x5F474154).
    :cvar TAGH: High TAG identifier for the header (0x52444845).
    :cvar VERSION: Format version identifier (0x56010000).
    :cvar FAC_REGIONS: Maximum number of FAC regions supported (4).
    :cvar SIZE: Total size of the protection region block (0x100 bytes).
    """

    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    _FORMAT = "<8I16s32s"
    # low TAG used in the header
    TAGL = 0x5F474154  # "TAG_"
    # high TAG used in the header
    TAGH = 0x52444845  # "EHDR"
    # version of the format
    VERSION = 0x56010000
    # number of FAC regions included in the header; the real limit of FAC regions depends on the processor
    FAC_REGIONS = 4
    # total size
    SIZE = 0x100

    @classmethod
    def get_size(cls) -> int:
        """Get size of the exported binary data.

        :return: Size of the exported binary data in bytes.
        """
        return cls.SIZE

    def __init__(
        self,
        encr_mode: BeeProtectRegionBlockAesMode = BeeProtectRegionBlockAesMode.CTR,
        lock_options: int = 0,
        counter: Optional[bytes] = None,
    ):
        """Initialize BEE protect region block.

        Creates a new BEE (Bus Encryption Engine) protect region block with specified
        encryption mode, lock options, and counter value.

        :param encr_mode: AES encryption mode for the protect region.
        :param lock_options: Lock options as 32-bit number.
        :param counter: Counter for AES-CTR mode (16 bytes). If None, random value is used.
        """
        # - Encrypt region info:
        self._start_addr = 0  # this is calculated automatically based on FAC regions
        self._end_addr = 0xFFFFFFFF  # this is calculated automatically based on FAC regions
        self.mode = encr_mode
        self.lock_options = lock_options
        self.counter = counter if counter else random_bytes(12) + b"\x00\x00\x00\x00"

        # - FAC regions, 1 - 4
        self.fac_regions: list[BeeFacRegion] = []

    def update(self) -> None:
        """Update encryption region boundaries based on FAC regions.

        The method updates all FAC (Flash Access Control) regions first, then calculates
        and sets the minimum start address and maximum end address across all FAC regions
        to define the overall encryption region boundaries.

        :raises SPSDKError: If FAC region update fails.
        """
        super().update()
        # update FAC regions
        for fac in self.fac_regions:
            fac.update()
        # update start and end address
        min_addr = 0 if self.fac_count == 0 else 0xFFFFFFFF
        max_addr = 0
        for fac in self.fac_regions:
            min_addr = min(min_addr, fac.start_addr)
            max_addr = max(max_addr, fac.end_addr)
        self._start_addr = min_addr
        self._end_addr = max_addr

    def add_fac(self, fac: BeeFacRegion) -> None:
        """Add FAC region to the BEE configuration.

        Appends a Factory Access Control region to the list of FAC regions and updates
        the internal state of the BEE configuration.

        :param fac: Factory Access Control region to be added to the configuration
        """
        self.fac_regions.append(fac)
        self.update()

    @property
    def fac_count(self) -> int:
        """Get the number of Factory Access Control regions.

        :return: Number of Factory Access Control regions.
        """
        return len(self.fac_regions)

    def __repr__(self) -> str:
        """Return string representation of BEE protect region block.

        Provides a human-readable string representation showing the start address
        of the BEE protect region block in hexadecimal format.

        :return: String representation with start address in hex format.
        """
        return f"BEE protect region block, start={hex(self._start_addr)}"

    def __str__(self) -> str:
        """Get string representation of BEE region header.

        Provides a formatted string containing the BEE region header information including start and end
        addresses, AES encryption mode, and details of all FAC regions.

        :return: Formatted string description of the BEE region header instance.
        """
        result = f"BEE Region Header (start={hex(self._start_addr)}, end={hex(self._end_addr)})\n"
        result += f"AES Encryption mode: {self.mode.label}\n"
        for fac in self.fac_regions:
            result += str(fac) + "\n"
        return result

    def validate(self) -> None:
        """Validate the BEE protect region block settings.

        Performs comprehensive validation of all configuration parameters including
        address ranges, encryption mode, counter format, and FAC regions.

        :raises SPSDKError: Invalid start address (negative or exceeds 32-bit range).
        :raises SPSDKError: Invalid end address or start address greater than end address.
        :raises SPSDKError: Unsupported encryption mode (only AES/CTR is supported).
        :raises SPSDKError: Invalid counter length (must be 16 bytes).
        :raises SPSDKError: Invalid counter format (last 4 bytes must be zero).
        :raises SPSDKError: Invalid FAC regions count (must be 1-8).
        :raises SPSDKError: Invalid FAC region configuration from nested validation.
        """
        if self._start_addr < 0 or self._start_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid start address")
        if self._start_addr > self._end_addr or self._end_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid start/end address")
        if self.mode != BeeProtectRegionBlockAesMode.CTR:
            raise SPSDKError("Only AES/CTR encryption mode supported now")
        if len(self.counter) != 16:
            raise SPSDKError("Invalid counter")
        if self.counter[-4:] != b"\x00\x00\x00\x00":
            raise SPSDKError("last four bytes must be zero")
        if self.fac_count <= 0 or self.fac_count > self.FAC_REGIONS:
            raise SPSDKError("Invalid FAC regions")
        for fac in self.fac_regions:
            fac.validate()

    def export(self) -> bytes:
        """Export the BEE region to binary format.

        Serializes the BEE region including header information, FAC regions, and padding
        to create a binary representation suitable for deployment.

        :return: Binary representation of the complete BEE region with proper formatting.
        """
        result = super().export()
        result += pack(
            self._struct_format(),
            self.TAGL,
            self.TAGH,
            self.VERSION,
            self.fac_count,
            self._start_addr,
            self._end_addr,
            self.mode.tag,
            self.lock_options,
            self.counter[::-1],  # bytes swapped: reversed order
            b"\x00" * 32,
        )
        for fac in self.fac_regions:
            result += fac.export()
        result = extend_block(result, self.SIZE)
        return result

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse BEE protect region block from binary data.

        Deserializes binary data into a BeeProtectRegionBlock instance by extracting
        header information, validating format and version, and parsing associated
        FAC regions.

        :param data: Binary data containing the BEE protect region block structure.
        :return: BeeProtectRegionBlock instance created from the parsed binary data.
        :raises SPSDKError: If tag is invalid, version is unsupported, reserved area
            is non-zero, or format does not match expected structure.
        """
        cls.check_data_to_parse(data)  # check size of the input data
        (
            tagl,
            tagh,
            version,
            fac_count,
            start_addr,
            end_addr,
            mode,
            lock_options,
            counter,
            _reserved_32,
        ) = unpack_from(BeeProtectRegionBlock._struct_format(), data)
        #
        if (tagl != BeeProtectRegionBlock.TAGL) or (tagh != BeeProtectRegionBlock.TAGH):
            raise SPSDKError("Invalid tag or unsupported version")
        if version != BeeProtectRegionBlock.VERSION:
            raise SPSDKError("Unsupported version")
        if _reserved_32 != b"\x00" * 32:
            raise SPSDKError("Reserved area is non-zero")
        #
        result = cls(BeeProtectRegionBlockAesMode.from_tag(mode), lock_options, counter[::-1])
        result._start_addr = start_addr
        result._end_addr = end_addr
        offset = calcsize(BeeProtectRegionBlock._struct_format())
        for _ in range(fac_count):
            fac = BeeFacRegion.parse(data[offset:])
            result.add_fac(fac)
            offset += fac.size
        result.validate()
        return result

    def is_inside_region(self, start_addr: int) -> bool:
        """Check if the start address lies within the FAC region.

        :param start_addr: Start address of the data to check.
        :return: True if the address is within the region, False otherwise.
        """
        return self._start_addr <= start_addr < self._end_addr

    def encrypt_block(self, key: bytes, start_addr: int, data: bytes) -> bytes:
        """Encrypt block located in any FAC region.

        The method encrypts data using AES/CTR mode if the block is within any configured FAC
        (Flash Access Control) region. Data outside FAC regions remains unchanged.

        :param key: AES encryption key (must be 16 bytes)
        :param start_addr: Start address of the data block
        :param data: Binary block to be encrypted; size must not exceed BEE_ENCR_BLOCK_SIZE
        :return: Encrypted block if inside any FAC region; untouched block otherwise
        :raises SPSDKError: When incorrect length of binary block
        :raises SPSDKError: When encryption mode different from AES/CTR provided
        :raises SPSDKError: When invalid length of key
        :raises SPSDKError: When invalid range of region
        """
        if len(data) > BEE_ENCR_BLOCK_SIZE:
            raise SPSDKError("Incorrect length of binary block to be encrypted")
        if self.is_inside_region(start_addr):
            if self.mode != BeeProtectRegionBlockAesMode.CTR:
                raise SPSDKError("only AES/CTR encryption mode supported now")
            if len(key) != 16:
                raise SPSDKError("Invalid length of key")
            for fac in self.fac_regions:
                if fac.start_addr <= start_addr < fac.end_addr:
                    if start_addr + len(data) > fac.end_addr:
                        raise SPSDKError("Invalid range of region")
                    cntr_key = Counter(
                        self.counter,
                        ctr_value=start_addr >> 4,
                        ctr_byteorder_encoding=Endianness.BIG,
                    )
                    logger.debug(
                        f"Encrypting data, start={hex(start_addr)},"
                        f"end={hex(start_addr + len(data))} with {str(self)} using fac {str(fac)}"
                    )
                    data = align_block_fill_random(data, 16)  # align data to 16 bytes
                    return aes_ctr_encrypt(key, data, cntr_key.value)
        return data


class BeeKIB(BeeBaseClass):
    """BEE Key Information Block (KIB) for encryption operations.

    This class manages the AES key and initialization vector used to encrypt
    PRDB (Protected Region Data Block) content in BEE (Bus Encryption Engine)
    operations. It provides functionality for key generation, validation,
    serialization, and deserialization.

    :cvar _KEY_LEN: AES key length in bytes (16 bytes for AES-128).
    :cvar _FORMAT: Binary format string for struct pack/unpack operations.
    """

    # key length in bytes
    _KEY_LEN = 16
    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    _FORMAT = "16s16s"

    def __init__(self, kib_key: Optional[bytes] = None, kib_iv: Optional[bytes] = None):
        """Initialize BEE (Bus Encryption Engine) configuration.

        Creates a new BEE instance with AES encryption parameters. If key or IV are not
        provided, random values will be generated automatically.

        :param kib_key: AES encryption key for Key Info Block, defaults to random 16 bytes
        :param kib_iv: AES initialization vector for Key Info Block, defaults to random 16 bytes
        """
        # Key Info Block (KIB)
        self.kib_key = kib_key if kib_key else random_bytes(16)
        self.kib_iv = kib_iv if kib_iv else random_bytes(16)

    def __repr__(self) -> str:
        """Return string representation of BEE KIB object.

        Provides a human-readable string representation showing the BEE KIB
        with its hexadecimal key value for debugging and logging purposes.

        :return: String representation containing BEE KIB and hexadecimal key.
        """
        return f"BEE KIB, Key: {self.kib_key.hex()}"

    def __str__(self) -> str:
        """Return string representation of the BEE instance.

        :return: String containing BEE-KIB key and IV in hexadecimal format.
        """
        return f"BEE-KIB: {self.kib_key.hex()}, {self.kib_iv.hex()}"

    def validate(self) -> None:
        """Validates the BEE instance settings.

        Checks that both the KIB key and KIB IV have the correct length according to the
        specification requirements.

        :raises SPSDKError: If invalid length of kib key.
        :raises SPSDKError: If invalid length of kib iv.
        """
        if len(self.kib_key) != self._KEY_LEN:
            raise SPSDKError("Invalid length of kib key")
        if len(self.kib_iv) != self._KEY_LEN:
            raise SPSDKError("Invalid length of kib iv")

    def export(self) -> bytes:
        """Export binary representation of the BEE region.

        Serializes the BEE region data including the parent region data and appends
        the KIB key and initialization vector using the struct format.

        :return: Binary representation of the complete BEE region data.
        """
        result = super().export()
        return result + pack(self._struct_format(), self.kib_key, self.kib_iv)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data to create BeeKIB instance.

        Deserializes binary data containing key and initialization vector information
        to reconstruct a BeeKIB object with proper validation.

        :param data: Binary data to be parsed containing key and IV information.
        :raises SPSDKError: Invalid input data size or format.
        :return: BeeKIB instance created from the parsed binary data.
        """
        cls.check_data_to_parse(data)  # check size of the input data
        (key, iv) = unpack_from(BeeKIB._struct_format(), data)
        result = cls(key, iv)
        result.validate()
        return result


class BeeRegionHeader(BeeBaseClass):
    """BEE keys and regions header.

    This class manages the Bus Encryption Engine (BEE) region header structure,
    which contains protected region blocks, software keys, and key information
    blocks for secure boot operations.

    :cvar PRDB_OFFSET: Offset of the Protected Region Block in the header (0x80).
    :cvar SIZE: Total size of the header including padding (0x200 bytes).
    """

    # offset of the Protected Region Block in the header
    PRDB_OFFSET = 0x80
    # total size including padding
    SIZE = 0x200

    @classmethod
    def _struct_format(cls) -> str:
        """Get the struct format string for binary representation.

        This method is not implemented for this class as the format depends on its fields
        and should be handled differently than other classes in the hierarchy.

        :raises SPSDKError: This method is not expected to be called for this class.
        :return: Struct format string.
        """
        raise SPSDKError(
            "This method is not expected to be used for this class, format depends on its fields"
        )

    @classmethod
    def get_size(cls) -> int:
        """Get size of the exported binary data.

        :return: Size of the exported binary data in bytes.
        """
        return cls.SIZE

    def __init__(
        self,
        prdb: Optional[BeeProtectRegionBlock] = None,
        sw_key: Optional[bytes] = None,
        kib: Optional[BeeKIB] = None,
    ):
        """Initialize BEE (Bus Encryption Engine) configuration.

        Creates a new BEE instance with protection region block, software key for KIB encryption,
        and key information block. Default values are generated if parameters are not provided.

        :param prdb: Protection region block configuration, defaults to new BeeProtectRegionBlock.
        :param sw_key: 16-byte software key used to encrypt KIB content, defaults to random key.
        :param kib: Key information block containing encryption keys, defaults to new BeeKIB.
        """
        self._prdb = prdb if (prdb is not None) else BeeProtectRegionBlock()
        self._sw_key = sw_key if (sw_key is not None) else random_bytes(16)
        self._kib = kib if (kib is not None) else BeeKIB()

    def add_fac(self, fac: BeeFacRegion) -> None:
        """Add FAC region to the BEE configuration.

        Appends a new FAC (Flash Access Control) region to the internal PRDB
        (Protected Region Database) for BEE encryption configuration.

        :param fac: FAC region configuration to be added to the BEE setup.
        """
        self._prdb.add_fac(fac)

    @property
    def fac_regions(self) -> Sequence[BeeFacRegion]:
        """Get list of Factory Access Control regions.

        :return: Sequence of Factory Access Control regions.
        """
        return self._prdb.fac_regions

    def __repr__(self) -> str:
        """Return string representation of BEE Region Header.

        :return: String representation of the BEE Region Header object.
        """
        return "BEE Region Header"

    def __str__(self) -> str:
        """Get string representation of the BEE region header.

        :return: Formatted string containing BEE region header information including KIB and PRDB details.
        """
        result = "BEE Region Header\n"
        result += f"- KIB: {str(self._kib)}"
        result += f"- PRDB: {str(self._prdb)}"
        return result

    def sw_key_fuses(self) -> Sequence[int]:
        """Get SW key fuse values for processor burning.

        The method extracts the software key and converts it into a sequence of fuse values
        that should be burned into the processor. The result is ordered so that the first
        value should be burned to the lowest address.

        :return: Sequence of fuse values for SW key to be burned into processor.
        """
        result = []
        for pos in range(16, 0, -4):
            result.append(unpack_from(">I", self._sw_key[pos - 4 : pos])[0])
        return result

    def update(self) -> None:
        """Updates internal fields of the instance.

        This method calls the parent class update method and then updates the internal
        Key Information Block (KIB) and Protected Region Database (PRDB) components.
        """
        super().update()
        self._kib.update()
        self._prdb.update()

    def validate(self) -> None:
        """Validates settings of the BEE instance.

        The method validates the Key Info Block (KIB) and Protection Region Database (PRDB)
        components, and ensures the software key has the correct length of 16 bytes.

        :raises SPSDKError: If KIB settings are invalid, PRDB settings are invalid, or software
            key length is not 16 bytes.
        """
        self._kib.validate()
        self._prdb.validate()
        if len(self._sw_key) != 16:
            raise SPSDKError("Invalid settings")

    def export(self) -> bytes:
        """Export BEE region to binary representation.

        Serializes the BEE region including KIB (Key Info Block) and PRDB (Protected Region Data Block)
        with proper encryption and padding to create the final binary output.

        :return: Binary representation of the complete BEE region with encrypted data blocks.
        """
        result = super().export()
        # KIB
        kib_data = self._kib.export()
        result += aes_ecb_encrypt(self._sw_key, kib_data)
        # padding
        result = extend_block(result, self.PRDB_OFFSET)
        # PRDB
        prdb_data = self._prdb.export()
        result += aes_cbc_encrypt(self._kib.kib_key, prdb_data, self._kib.kib_iv)
        # padding
        return extend_block(result, self.SIZE)

    @classmethod
    def parse(cls, data: bytes, sw_key: bytes = b"") -> Self:
        """Parse binary data to create BEE instance.

        Deserializes encrypted binary data using the provided software key to decrypt
        the EKIB (Encrypted Key Info Block) and PRDB (Protect Region Data Block) data.

        :param data: Binary data to be parsed containing encrypted BEE information.
        :param sw_key: 16-byte software key used to decrypt the EKIB data.
        :return: BEE instance created from the parsed binary data.
        :raises SPSDKError: If invalid software key length (must be 16 bytes).
        """
        cls.check_data_to_parse(data)  # check size of the input data
        if len(sw_key) != 16:
            raise SPSDKError("Invalid sw key")
        decr_data = aes_ecb_decrypt(sw_key, data[: BeeKIB.get_size()])
        kib = BeeKIB.parse(decr_data)
        decr_data = aes_cbc_decrypt(
            kib.kib_key,
            data[cls.PRDB_OFFSET : cls.PRDB_OFFSET + BeeProtectRegionBlock.SIZE],
            kib.kib_iv,
        )
        prdb = BeeProtectRegionBlock.parse(decr_data)
        result = cls(prdb, sw_key, kib)
        result.validate()
        return result

    def is_inside_region(self, start_addr: int) -> bool:
        """Check if start address lies within any FAC region.

        :param start_addr: Start address of the data to check.
        :return: True if the address is within any FAC region, False otherwise.
        """
        return self._prdb.is_inside_region(start_addr)

    def encrypt_block(self, start_addr: int, data: bytes) -> bytes:
        """Encrypt block located in any FAC region.

        The method encrypts a binary block if it falls within any configured FAC (Flash Access Control)
        region using the internal software key and PRDB configuration.

        :param start_addr: Start address of the data block.
        :param data: Binary block to be encrypted; the block size must be BEE_ENCR_BLOCK_SIZE.
        :return: Encrypted block if it is inside any FAC region; untouched block if it is not in any
            FAC region.
        """
        return self._prdb.encrypt_block(self._sw_key, start_addr, data)


class Bee(FeatureBaseClass):
    """SPSDK Bus Encryption Engine (BEE) manager.

    This class handles encryption and decryption operations for NXP MCU images using the
    Bus Encryption Engine feature. It manages BEE region headers and processes input images
    to generate encrypted binary outputs with proper region configuration.

    :cvar FEATURE: Database feature identifier for BEE operations.
    """

    FEATURE = DatabaseManager.BEE

    def __init__(
        self,
        family: FamilyRevision,
        headers: list[Optional[BeeRegionHeader]],
        input_images: list[tuple[bytes, int]],
    ):
        """Initialize BEE (Bus Encryption Engine) configuration.

        Creates a new BEE instance with the specified family, region headers, and input images
        for encryption processing.

        :param family: The target MCU/MPU family and revision information.
        :param headers: List of BEE region headers, may contain None values for unused regions.
        :param input_images: List of tuples containing image data and corresponding base addresses.
        """
        self.family = family
        self.headers = headers
        self.input_images = input_images

    def __repr__(self) -> str:
        """Get string representation of BEE object.

        :return: String representation containing the BEE class and target family.
        """
        return f"BEE class for {self.family}"

    def __str__(self) -> str:
        """Get string representation of the BEE object.

        Provides a detailed string representation including the object's repr
        and formatted headers information.

        :return: String representation of the BEE object with headers details.
        """
        ret = repr(self)
        ret += f"\nHeaders: {str(self.headers)}\n"

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Input binary data to parse
        :raises SPSDKNotImplementedError: Method not implemented in base class
        """
        raise SPSDKNotImplementedError()

    def export(self) -> bytes:
        """Export encrypted binary image.

        Handles both single and multiple input images. For single images, returns the encrypted
        image directly. For multiple images, combines them into a single binary with proper
        address alignment, fills gaps with 0xFF (flash erase value), and encrypts the result.

        :return: Encrypted binary image data, or empty bytes if no input images are available.
        """
        if not self.input_images:
            return bytes()

        # For backward compatibility, if there's only one image, just return it encrypted
        if len(self.input_images) == 1 and self.input_images[0][0]:
            image_data, base_address = self.input_images[0]
            return self._encrypt_single_image(image_data, base_address)

        # For multiple images, we need to compute the overall size and create a combined image
        min_address = min(addr for _, addr in self.input_images)
        max_address = max(addr + len(img) for img, addr in self.input_images)
        total_size = max_address - min_address

        # Create a bytearray filled with 0xFF (typical flash erase value)
        combined_image = bytearray([0xFF] * total_size)

        # Place each image at its correct offset
        for image_data, addr in self.input_images:
            offset = addr - min_address
            combined_image[offset : offset + len(image_data)] = image_data

        # Encrypt the combined image
        return self._encrypt_single_image(bytes(combined_image), min_address)

    def _encrypt_single_image(self, image_data: bytes, base_address: int) -> bytes:
        """Encrypt a single image using BEE encryption.

        The method processes the image data in blocks of BEE_ENCR_BLOCK_SIZE and applies
        encryption using configured BEE headers for each block sequentially.

        :param image_data: Raw binary data of the image to be encrypted.
        :param base_address: Starting memory address where the image will be located.
        :return: Encrypted image data as bytes.
        """
        encrypted_data = bytearray()
        image_bytes = bytearray(image_data)
        addr = base_address

        for block in split_data(image_bytes, BEE_ENCR_BLOCK_SIZE):
            logger.debug(f"Reading {hex(addr)}, size={hex(len(block))}")
            for header in self.headers:
                if header:
                    block = header.encrypt_block(addr, block)
            encrypted_data.extend(block)
            addr += len(block)

        return bytes(encrypted_data)

    def export_headers(self) -> list[Optional[bytes]]:
        """Export BEE headers for all configured regions.

        The method iterates through all BEE headers and exports them as bytes. If a header
        is not configured (None), it remains None in the output list.

        :return: List of exported BEE region headers as bytes, or None for unconfigured regions.
        """
        headers: list[Optional[bytes]] = [None, None]
        for idx, header in enumerate(self.headers):
            headers[idx] = header.export() if header else None

        return headers

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for BEE configuration.

        The method retrieves and combines validation schemas including family-specific schemas,
        BEE output schemas, and general BEE schemas. It updates the family schema with supported
        families for the given family revision.

        :param family: The MCU/MPU family revision to get validation schemas for.
        :return: List of validation schema dictionaries for BEE configuration.
        """
        schemas = get_schema_file(DatabaseManager.BEE)
        family_schemas = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_schemas["properties"], cls.get_supported_families(), family
        )
        return [family_schemas, schemas["bee_output"], schemas["bee"]]

    @staticmethod
    def check_image_overlaps(images: list[tuple[bytes, int]]) -> None:
        """Check for overlaps in input images.

        This method validates that no two images in the provided list have overlapping
        memory regions by comparing their base addresses and sizes.

        :param images: List of tuples containing (image_data, base_address) where
                       image_data is bytes and base_address is int
        :raises SPSDKOverlapError: If any two images overlap in memory space
        """
        # Sort images by start address for easier overlap checking
        sorted_images = sorted(images, key=lambda x: x[1])

        for i in range(len(sorted_images) - 1):
            img1, addr1 = sorted_images[i]
            _, addr2 = sorted_images[i + 1]

            end_addr1 = addr1 + len(img1)

            # Check if image1 overlaps with image2
            if end_addr1 > addr2:
                raise SPSDKOverlapError(
                    f"Image at address {hex(addr1)} (size: {hex(len(img1))}) "
                    f"overlaps with image at address {hex(addr2)}"
                )

    @staticmethod
    def check_overlaps(bee_headers: list[Optional[BeeRegionHeader]], start_addr: int) -> None:
        """Check for overlaps in regions.

        Validates that a given start address does not overlap with any existing
        BEE (Bus Encryption Engine) regions defined in the provided headers.

        :param bee_headers: List of BeeRegionHeader objects to check against.
        :param start_addr: Start address of a region to be checked for overlaps.
        :raises SPSDKOverlapError: If the address is inside any existing region.
        """
        for header in bee_headers:
            if header:
                for region in header.fac_regions:
                    if region.start_addr <= start_addr < region.end_addr:
                        raise SPSDKOverlapError(
                            f"Region start address {hex(start_addr)} is overlapping with {str(region)}"
                        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load BEE configuration and create BEE image object.

        Converts the provided configuration into a BEE (Bus Encryption Engine) image object,
        handling both single and multi-image modes with engine selection and protected regions.

        :param config: Configuration dictionary containing BEE settings, engines, and data blobs.
        :return: Initialized Bee object with configured headers and input images.
        :raises SPSDKError: Invalid BEE engine count or configuration errors.
        """
        family = FamilyRevision.load_from_config(config)

        # Handle new multi-image mode
        input_images = []
        if "data_blobs" in config:
            data_blobs = config.get_list_of_configs("data_blobs")
            for data_blob in data_blobs:
                data = load_binary(data_blob.get_input_file_name("data"))
                address = data_blob.get_int("address")
                input_images.append((data, address))

                # Check for overlapping images
                cls.check_image_overlaps(input_images)

        engine_selection = config.get_str("engine_selection")
        bee_engines = config.get_list_of_configs("bee_engine")

        bee_headers: list[Optional[BeeRegionHeader]] = [None, None]

        engine_selections = {"engine0": [0], "engine1": [1], "both": [0, 1]}

        for engine_idx in engine_selections[engine_selection]:
            prdb = BeeProtectRegionBlock()
            kib = BeeKIB()
            header_idx = engine_idx
            if engine_idx == len(bee_engines) and engine_selections[engine_selection] == [1]:
                engine_idx = 0
            elif engine_idx >= len(bee_engines):
                raise SPSDKError("The count of BEE engines is invalid")
            # BEE Configuration

            if "bee_cfg" in bee_engines[engine_idx]:
                bee_cfg = bee_engines[engine_idx].get_config("bee_cfg")
                key = bee_cfg.load_symmetric_key("user_key", expected_size=16)
                bee_headers[header_idx] = BeeRegionHeader(prdb, key, kib)
                protected_regions = bee_cfg.get("protected_region", [])
                for protected_region in protected_regions:
                    fac = BeeFacRegion(
                        value_to_int(protected_region["start_address"]),
                        value_to_int(protected_region["length"]),
                        value_to_int(protected_region["protected_level"]),
                    )
                    Bee.check_overlaps(bee_headers, fac.start_addr)
                    hdr = bee_headers[header_idx]
                    if hdr:
                        hdr.add_fac(fac)
                continue

            # BEE Binary configuration
            if "bee_binary_cfg" in bee_engines[engine_idx]:
                bee_bin_cfg = bee_engines[engine_idx].get_config("bee_binary_cfg")
                key = bee_bin_cfg.load_symmetric_key("user_key", expected_size=16)
                bin_ehdr = load_binary(bee_bin_cfg.get_input_file_name("header_path"))
                bee_headers[header_idx] = BeeRegionHeader.parse(bin_ehdr, sw_key=key)
                continue

        return cls(family, bee_headers, input_images=input_images)

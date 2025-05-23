#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Contains support for BEE encryption."""


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
    """BEE base class."""

    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    # the format is class specific, and must be defined in child class
    _FORMAT = "@_must_be_defined_in_child_class_@"

    @classmethod
    def _struct_format(cls) -> str:
        """:return: format string for struct.pack/unpack function used for export/import from binary format."""
        return cls._FORMAT  # _FORMAT class constant must be defined in child class

    @classmethod
    def get_size(cls) -> int:
        """:return: size of the exported binary data in bytes."""
        return calcsize(cls._struct_format())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and (vars(other) == vars(self))

    @property
    def size(self) -> int:
        """:return: size of the exported binary data in bytes."""
        return self.get_size()

    def __repr__(self) -> str:
        return f"BEE, Length = {self.size}B"

    def __str__(self) -> str:
        """Info method.

        :return: text description of the instance.
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def update(self) -> None:
        """Updates internal fields of the instance."""

    def validate(self) -> None:
        """Validates the configuration of the instance.

        It is recommended to call the method before export and after parsing.
        """

    def export(self) -> bytes:
        """:return: binary representation of the region (serialization)."""
        self.update()
        self.validate()
        return b""

    @classmethod
    def check_data_to_parse(cls, data: bytes) -> None:
        """Deserialization.

        :param data: binary data to be parsed
        :raises SPSDKError: If size of the data is not sufficient
        """
        if len(data) < cls.get_size():
            raise SPSDKError("Insufficient size of the data")


class BeeFacRegion(BeeBaseClass):
    """BEE Factory Access Control (FAC) region."""

    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    _FORMAT = "<3I20s"

    def __init__(self, start: int = 0, length: int = 0, protected_level: int = 0):
        """Constructor.

        :param start: Start address of one FAC region, align at 1KB boundary; 32-bit number
        :param length: Length of one FAC region, align at 1KB boundary; 32-bit number
        :param protected_level: Protected level: 0/1/2/3; 32-bit number
        """
        self.start_addr = start
        self.length = length
        self.protected_level = protected_level
        # immediately validate all parameters
        self.validate()

    @property
    def end_addr(self) -> int:
        """:return: end address of the region (which is last address of the region + 1)."""
        return self.start_addr + self.length

    def __repr__(self) -> str:
        return f"FAC: 0x{self.start_addr:08x}[0x{self.length:x}]"

    def __str__(self) -> str:
        """:return: test description of the instance."""
        return f"FAC(start={hex(self.start_addr)}, length={hex(self.length)}, protected_level={self.protected_level})"

    def validate(self) -> None:
        """Validates the configuration of the instance."""
        if (self.start_addr & _ENCR_BLOCK_ADDR_MASK != 0) and (
            self.length & _ENCR_BLOCK_ADDR_MASK != 0
        ):
            raise SPSDKError("Invalid configuration of the instance")
        if self.protected_level < 0 or self.protected_level > 3:
            raise SPSDKError("Invalid protected level")
        if self.start_addr < 0 or self.end_addr > 0xFFFFFFFF or self.start_addr >= self.end_addr:
            raise SPSDKError("Invalid start/end address")

    def export(self) -> bytes:
        """Exports the binary representation."""
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
        """Deserialization.

        :param data: binary data to be parsed
        :return: instance created from binary data
        :raises SPSDKError: If reserved area is non-zero
        """
        cls.check_data_to_parse(data)  # check size of the data
        (start, end, protected_level, _reserved) = unpack_from(BeeFacRegion._struct_format(), data)
        if _reserved != b"\x00" * 20:
            raise SPSDKError("Reserved area is non-zero")
        return cls(start, end - start, protected_level)


class BeeProtectRegionBlockAesMode(SpsdkEnum):
    """AES mode selection for BEE PRDB encryption."""

    ECB = (0, "ECB")
    CTR = (1, "CTR")


class BeeProtectRegionBlock(BeeBaseClass):
    """BEE protect region block (PRDB)."""

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
        """:return: size of the exported binary data in bytes."""
        return cls.SIZE

    def __init__(
        self,
        encr_mode: BeeProtectRegionBlockAesMode = BeeProtectRegionBlockAesMode.CTR,
        lock_options: int = 0,
        counter: Optional[bytes] = None,
    ):
        """Constructor.

        :param encr_mode: AES encryption mode
        :param lock_options: Lock options; 32-bit number
        :param counter: Counter for AES-CTR mode; 16 bytes; by default, random value is used
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
        """Updates start and end address of the encryption region."""
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
        """Append FAC region.

        :param fac: Factory Access Control to be added
        """
        self.fac_regions.append(fac)
        self.update()

    @property
    def fac_count(self) -> int:
        """:return: number of Factory Access Control regions."""
        return len(self.fac_regions)

    def __repr__(self) -> str:
        return f"BEE protect region block, start={hex(self._start_addr)}"

    def __str__(self) -> str:
        """:return: test description of the instance."""
        result = f"BEE Region Header (start={hex(self._start_addr)}, end={hex(self._end_addr)})\n"
        result += f"AES Encryption mode: {self.mode.label}\n"
        for fac in self.fac_regions:
            result += str(fac) + "\n"
        return result

    def validate(self) -> None:
        """Validates settings of the instance."""
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
        """:return: binary representation of the region (serialization)."""
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
        """Deserialization.

        :param data: binary data to be parsed
        :return: instance created from binary data
        :raises SPSDKError: If format does not match
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
        """Returns true if the start address lies within any FAC region.

        :param start_addr: start address of the data
        """
        return self._start_addr <= start_addr < self._end_addr

    def encrypt_block(self, key: bytes, start_addr: int, data: bytes) -> bytes:
        """Encrypt block located in any FAC region.

        :param key: user for encryption
        :param start_addr: start address of the data
        :param data: binary block to be encrypted; the block size must be BEE_ENCR_BLOCK_SIZE
        :return: encrypted block if it is inside any FAC region; untouched block if it is not in any FAC region
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
    """BEE Key block.

    Contains keys used to encrypt PRDB content.
    """

    # key length in bytes
    _KEY_LEN = 16
    # format of the binary representation of the class, used as parameter for struct.pack/unpack methods
    _FORMAT = "16s16s"

    def __init__(self, kib_key: Optional[bytes] = None, kib_iv: Optional[bytes] = None):
        """Constructor.

        :param kib_key: AES key
        :param kib_iv: AES initialization vector
        """
        # Key Info Block (KIB)
        self.kib_key = kib_key if kib_key else random_bytes(16)
        self.kib_iv = kib_iv if kib_iv else random_bytes(16)

    def __repr__(self) -> str:
        return f"BEE KIB, Key: {self.kib_key.hex()}"

    def __str__(self) -> str:
        """:return: test description of the instance."""
        return f"BEE-KIB: {self.kib_key.hex()}, {self.kib_iv.hex()}"

    def validate(self) -> None:
        """Validates settings of the instance.

        :raises SPSDKError: If invalid length of kib key
        :raises SPSDKError: If invalid length of kib iv
        """
        if len(self.kib_key) != self._KEY_LEN:
            raise SPSDKError("Invalid length of kib key")
        if len(self.kib_iv) != self._KEY_LEN:
            raise SPSDKError("Invalid length of kib iv")

    def export(self) -> bytes:
        """Exports binary representation of the region (serialization)."""
        result = super().export()
        return result + pack(self._struct_format(), self.kib_key, self.kib_iv)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialization.

        :param data: binary data to be parsed
        :return: instance created from binary data
        """
        cls.check_data_to_parse(data)  # check size of the input data
        (key, iv) = unpack_from(BeeKIB._struct_format(), data)
        result = cls(key, iv)
        result.validate()
        return result


class BeeRegionHeader(BeeBaseClass):
    """BEE keys and regions header."""

    # offset of the Protected Region Block in the header
    PRDB_OFFSET = 0x80
    # total size including padding
    SIZE = 0x200

    @classmethod
    def _struct_format(cls) -> str:
        """:raises SPSDKError: It is not expected to called for the class."""
        raise SPSDKError(
            "This method is not expected to be used for this class, format depends on its fields"
        )

    @classmethod
    def get_size(cls) -> int:
        """:return: size of the exported binary data in bytes."""
        return cls.SIZE

    def __init__(
        self,
        prdb: Optional[BeeProtectRegionBlock] = None,
        sw_key: Optional[bytes] = None,
        kib: Optional[BeeKIB] = None,
    ):
        """Constructor.

        :param prdb: protect region block; None to use default
        :param sw_key: key used to encrypt KIB content
        :param kib: keys block; None to use default
        """
        self._prdb = prdb if (prdb is not None) else BeeProtectRegionBlock()
        self._sw_key = sw_key if (sw_key is not None) else random_bytes(16)
        self._kib = kib if (kib is not None) else BeeKIB()

    def add_fac(self, fac: BeeFacRegion) -> None:
        """Append FAC region.

        :param fac: to be added
        """
        self._prdb.add_fac(fac)

    @property
    def fac_regions(self) -> Sequence[BeeFacRegion]:
        """:return: lift of Factory Access Control regions."""
        return self._prdb.fac_regions

    def __repr__(self) -> str:
        return "BEE Region Header"

    def __str__(self) -> str:
        """:return: test description of the instance."""
        result = "BEE Region Header\n"
        result += f"- KIB: {str(self._kib)}"
        result += f"- PRDB: {str(self._prdb)}"
        return result

    def sw_key_fuses(self) -> Sequence[int]:
        """:return: sequence of fuse values for SW key to be burned into processor.

        The result is ordered, first value should be burned to the lowest address.
        """
        result = []
        for pos in range(16, 0, -4):
            result.append(unpack_from(">I", self._sw_key[pos - 4 : pos])[0])
        return result

    def update(self) -> None:
        """Updates internal fields of the instance."""
        super().update()
        self._kib.update()
        self._prdb.update()

    def validate(self) -> None:
        """Validates settings of the instance.

        :raises SPSDKError: If settings invalid
        """
        self._kib.validate()
        self._prdb.validate()
        if len(self._sw_key) != 16:
            raise SPSDKError("Invalid settings")

    def export(self) -> bytes:
        """Serialization to binary representation.

        :return: binary representation of the region (serialization).
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
        """Deserialization.

        :param data: binary data to be parsed
        :param sw_key: SW key used to decrypt the EKIB data
        :return: instance created from binary data
        :raises SPSDKError: If invalid sw key
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
        """Returns true if the start address lies within any FAC region.

        :param start_addr: start address of the data
        """
        return self._prdb.is_inside_region(start_addr)

    def encrypt_block(self, start_addr: int, data: bytes) -> bytes:
        """Encrypt block located in any FAC region.

        :param start_addr: start address of the data
        :param data: binary block to be encrypted; the block size must be BEE_ENCR_BLOCK_SIZE
        :return: encrypted block if it is inside any FAC region; untouched block if it is not in any FAC region
        """
        return self._prdb.encrypt_block(self._sw_key, start_addr, data)


class Bee(FeatureBaseClass):
    """Bee class."""

    FEATURE = DatabaseManager.BEE

    def __init__(
        self,
        family: FamilyRevision,
        headers: list[Optional[BeeRegionHeader]],
        input_images: list[tuple[bytes, int]],
    ):
        """Constructor.

        :param family: The CPU family
        :param headers: list of BEE Region Headers
        :param input_images: List of (image_data, base_address) tuples
        """
        self.family = family
        self.headers = headers
        self.input_images = input_images

    def __repr__(self) -> str:
        """Object representation in string format."""
        return f"BEE class for {self.family}"

    def __str__(self) -> str:
        """Object description in string format."""
        ret = repr(self)
        ret += f"\nHeaders: {str(self.headers)}\n"

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Input binary data
        """
        raise SPSDKNotImplementedError()

    def export(self) -> bytes:
        """Export encrypted binary image.

        :return: encrypted image
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
        """Encrypt a single image.

        :param image_data: Image data to encrypt
        :param base_address: Base address of the image
        :return: Encrypted image
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
        """Export BEE headers.

        :return: BEE region headers
        """
        headers: list[Optional[bytes]] = [None, None]
        for idx, header in enumerate(self.headers):
            headers[idx] = header.export() if header else None

        return headers

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: The CPU family
        :return: Validation list of schemas.
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

        :param images: List of tuples (image_data, base_address)
        :raises SPSDKOverlapError: if any two images overlap
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

        :param bee_headers: List of BeeRegionHeader
        :param start_addr: start address of a region to be checked
        :raises SPSDKOverlapError: if the address is inside any region
        """
        for header in bee_headers:
            if header:
                for region in header.fac_regions:
                    if region.start_addr <= start_addr < region.end_addr:
                        raise SPSDKOverlapError(
                            f"Region start address {hex(start_addr)} is overlapping with {str(region)}"
                        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError()

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Converts the configuration into an BEE image object.

        :param config: Configuration dictionary.
        :return: Initialized Bee object.
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

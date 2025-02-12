#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container Image Array Entry support."""

import logging
import os
from struct import pack, unpack
from typing import Any, Optional, Type, TypeVar, Union

from typing_extensions import Self

from spsdk.__version__ import version
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import Container, HeaderContainerData
from spsdk.image.ahab.ahab_data import (
    BINARY_IMAGE_ALIGNMENTS,
    RESERVED,
    UINT32,
    UINT64,
    AhabChipContainerConfig,
    AHABSignHashAlgorithm,
    AHABSignHashAlgorithmV1,
    AHABSignHashAlgorithmV2,
    AHABTags,
    AhabTargetMemory,
    load_images_types,
)
from spsdk.utils.database import DatabaseManager, Features, get_db
from spsdk.utils.misc import (
    align,
    align_block,
    clean_up_file_name,
    extend_block,
    load_binary,
    value_to_bool,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkSoftEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class ImageArrayEntry(Container):
    """Class representing image array entry as part of image array in the AHAB container.

    Image Array Entry content::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |                        Image Offset                           |
        +-----+---------------------------------------------------------------+
        |0x04 |                        Image Size                             |
        +-----+---------------------------------------------------------------+
        |0x08 |                                                               |
        |-----+                        Load Address (64 bits)                 |
        |0x0C |                                                               |
        +-----+---------------------------------------------------------------+
        |0x10 |                                                               |
        |-----+                        Entry Point (64 bits)                  |
        |0x14 |                                                               |
        +-----+---------------------------------------------------------------+
        |0x18 |                        Flags                                  |
        +-----+---------------------------------------------------------------+
        |0x1C |                        Image meta data                        |
        +-----+---------------------------------------------------------------+
        |0x20 |                                                               |
        |-----+                        Hash (512 bits)                        |
        |.... |                                                               |
        +-----+---------------------------------------------------------------+
        |0x60 |                        IV (256 bits)                          |
        +-----+---------------------------------------------------------------+

    """

    IMAGE_OFFSET_LEN = 4
    IMAGE_SIZE_LEN = 4
    LOAD_ADDRESS_LEN = 8
    ENTRY_POINT_ADDRESS_LEN = 8
    FLAGS_LEN = 4
    IMAGE_META_DATA_LEN = 4
    HASH_LEN = 64
    IV_LEN = 32
    FLAGS_TYPE_OFFSET = 0
    FLAGS_TYPE_SIZE = 4
    FLAGS_CORE_ID_OFFSET = 4
    FLAGS_CORE_ID_SIZE = 4
    FLAGS_HASH_OFFSET = 8
    FLAGS_HASH_SIZE = 3
    FLAGS_IS_ENCRYPTED_OFFSET = 11
    FLAGS_IS_ENCRYPTED_SIZE = 1
    FLAGS_BOOT_FLAGS_OFFSET = 16
    FLAGS_BOOT_FLAGS_SIZE = 15
    METADATA_START_CPU_ID_OFFSET = 0
    METADATA_START_CPU_ID_SIZE = 10
    METADATA_MU_CPU_ID_OFFSET = 10
    METADATA_MU_CPU_ID_SIZE = 10
    METADATA_START_PARTITION_ID_OFFSET = 20
    METADATA_START_PARTITION_ID_SIZE = 8

    FLAGS_HASH_ALGORITHM_TYPE: Type[Union[AHABSignHashAlgorithmV1, AHABSignHashAlgorithmV2]] = (
        AHABSignHashAlgorithmV1
    )

    def __init__(
        self,
        chip_config: AhabChipContainerConfig,
        image: Optional[bytes] = None,
        image_offset: int = 0,
        load_address: int = 0,
        entry_point: int = 0,
        flags: int = 0,
        image_meta_data: int = 0,
        image_hash: Optional[bytes] = None,
        image_iv: Optional[bytes] = None,
        already_encrypted_image: bool = False,
        image_name: Optional[str] = None,
        gap_after_image: int = 0,
        image_size_alignment: Optional[int] = None,
    ) -> None:
        """Class object initializer.

        :param chip_config: Ahab container chip configuration.
        :param image: Image in bytes.
        :param image_offset: Offset in bytes from start of container to beginning of image.
        :param load_address: Address the image is written to in memory (absolute address in system memory map).
        :param entry_point: Entry point of image (absolute address). Only valid for executable image types.
            For other image types the value is irrelevant.
        :param flags: flags.
        :param image_meta_data: image meta-data.
        :param image_hash: SHA of image (512 bits) in big endian. Left
            aligned and padded with zeroes for hash sizes below 512 bits.
        :param image_iv: SHA256 of plain text image (256 bits) in big endian.
        :param already_encrypted_image: The input image is already encrypted.
            Used only for encrypted images.
        :param image_name: Optional name of the image
        :param gap_after_image: Size of Gap after the image in container.
        :param image_size_alignment: Optional force non standard alignment for image size.
        """
        self._image_offset = 0
        self.chip_config = chip_config
        self.flags = flags
        self.already_encrypted_image = already_encrypted_image
        self.image = image if image else b""
        self.image_offset = image_offset
        self.image_size_alignment = image_size_alignment
        self.image_size = self._get_valid_size(self.image)
        self.load_address = load_address
        self.entry_point = entry_point
        self.image_meta_data = image_meta_data
        self.image_hash = image_hash
        self.image_iv = (
            image_iv or get_hash(self.plain_image, algorithm=EnumHashAlgorithm.SHA256)
            if self.flags_is_encrypted
            else bytes(self.IV_LEN)
        )
        self.gap_after_image = gap_after_image
        self.image_name = image_name

    @property
    def image_offset(self) -> int:
        """Image offset."""
        return self._image_offset + self.chip_config.container_offset

    @image_offset.setter
    def image_offset(self, offset: int) -> None:
        """Image offset.

        :param offset: Image offset.
        """
        self._image_offset = offset - self.chip_config.container_offset

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            if (
                self._image_offset  # pylint: disable=too-many-boolean-expressions
                == other._image_offset
                and self.image_size == other.image_size
                and self.load_address == other.load_address
                and self.entry_point == other.entry_point
                and self.flags == other.flags
                and self.image_meta_data == other.image_meta_data
                and self.image_hash == other.image_hash
                and self.image_iv == other.image_iv
            ):
                return True

        return False

    def __repr__(self) -> str:
        return f"AHAB Image Array Entry, load address({hex(self.load_address)})"

    def __str__(self) -> str:
        ret = (
            "AHAB Image Array Entry:\n"
            f"  Image size:             {self.image_size}B\n"
            f"  Image offset in table:  {hex(self._image_offset)}\n"
            f"  Entry point:            {hex(self.entry_point)}\n"
            f"  Load address:           {hex(self.load_address)}\n"
            f"  Flags:                  {hex(self.flags)})\n"
            f"  Meta data:              {hex(self.image_meta_data)})\n"
            f"  Image hash:             {self.image_hash.hex() if self.image_hash else 'Not available'})\n"
            f"  Image IV:               {self.image_iv.hex()})\n"
            f"  Image type:             {self.flags_image_type_name}\n"
            f"  Core ID:                {self.flags_core_id_name}\n"
            f"  Is encrypted:           {self.flags_is_encrypted}\n"
            f"  Boot flags:             {self.flags_boot_flags}\n"
            f"  Start CPU ID:           {self.metadata_start_cpu_id}\n"
        )
        if self.image_size_alignment:
            ret += f"  Image size alignment:   {self.image_size_alignment}\n"
        return ret

    @property
    def image(self) -> bytes:
        """Image data for this Image array entry.

        The class decide by flags if encrypted of plain data has been returned.

        :raises SPSDKError: Invalid Image - Image is not encrypted yet.
        :return: Image bytes.
        """
        # if self.flags_is_encrypted and not self.already_encrypted_image:
        #     raise SPSDKError("Image is NOT encrypted, yet.")

        if self.flags_is_encrypted and self.already_encrypted_image:
            return self.encrypted_image
        return self.plain_image

    @image.setter
    def image(self, data: bytes) -> None:
        """Image data for this Image array entry.

        The class decide by flags if encrypted of plain data has been stored.
        """
        input_image = align_block(
            data,
            1 if self.chip_config.locked else self.chip_config.base.container_image_size_alignment,
            padding=RESERVED,
        )  # align to minimal SD card block if not locked container
        self.plain_image = input_image if not self.already_encrypted_image else b""
        self.encrypted_image = input_image if self.already_encrypted_image else b""

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness from base class
            + UINT32  # Image Offset
            + UINT32  # Image Size
            + UINT64  # Load Address
            + UINT64  # Entry Point
            + UINT32  # Flags
            + UINT32  # Image Meta Data
            + "64s"  # HASH
            + "32s"  # Input Vector
        )

    def update_fields(self) -> None:
        """Updates the image fields in container based on provided image."""
        self.image_size = self._get_valid_size(self.image)
        if not self.image_hash:
            algorithm = self.get_hash_from_flags(self.flags)
            self.image_hash = extend_block(
                get_hash(extend_block(self.image, self.image_size), algorithm=algorithm),
                self.HASH_LEN,
                padding=0,
            )
        # Check if the image IV is not set (all zeros) and the image is encrypted
        if self.image_iv.count(0) == len(self.image_iv) and self.flags_is_encrypted:
            self.image_iv = get_hash(self.plain_image, algorithm=EnumHashAlgorithm.SHA256)

    @staticmethod
    def create_meta(start_cpu_id: int = 0, mu_cpu_id: int = 0, start_partition_id: int = 0) -> int:
        """Create meta data field.

        :param start_cpu_id: ID of CPU to start, defaults to 0
        :param mu_cpu_id: ID of MU for selected CPU to start, defaults to 0
        :param start_partition_id: ID of partition to start, defaults to 0
        :return: Image meta data field.
        """
        meta_data = start_cpu_id
        meta_data |= mu_cpu_id << 10
        meta_data |= start_partition_id << 20
        return meta_data

    @classmethod
    def create_flags(
        cls,
        image_type: int,
        core_id: int,
        hash_type: AHABSignHashAlgorithm,
        is_encrypted: bool = False,
        boot_flags: int = 0,
    ) -> int:
        """Create flags field.

        :param image_type: Type of image
        :param core_id: Core ID
        :param hash_type: Hash type, defaults to sha256
        :param is_encrypted: Is image encrypted, defaults to False
        :param boot_flags: Boot flags controlling the SCFW boot, defaults to 0
        :return: Image flags data field.
        """
        flags_data = image_type
        flags_data |= core_id << cls.FLAGS_CORE_ID_OFFSET
        flags_data |= hash_type.tag << cls.FLAGS_HASH_OFFSET
        flags_data |= 1 << cls.FLAGS_IS_ENCRYPTED_OFFSET if is_encrypted else 0
        flags_data |= boot_flags << cls.FLAGS_BOOT_FLAGS_OFFSET

        return flags_data

    def get_hash_from_flags(self, flags: int) -> EnumHashAlgorithm:
        """Get Hash algorithm name from flags.

        :param flags: Value of flags.
        :return: Hash name.
        """
        hash_val = (flags >> self.FLAGS_HASH_OFFSET) & ((1 << self.FLAGS_HASH_SIZE) - 1)
        return EnumHashAlgorithm.from_label(
            self.FLAGS_HASH_ALGORITHM_TYPE.from_tag(hash_val).label.lower()
        )

    @staticmethod
    def get_image_types(chip_config: AhabChipContainerConfig, core_id: int) -> Type[SpsdkSoftEnum]:
        """Get correct image type enum.

        :param chip_config: Container chip config
        :param core_id: Core ID
        :return: Enumeration of Image types
        """
        image_type_group = "application"
        for k, v in chip_config.base.image_types_mapping.items():
            if core_id in v:
                image_type_group = k
        return chip_config.base.image_types[image_type_group]

    @property
    def flags_image_type(self) -> SpsdkSoftEnum:
        """Get Image type from flags.

        :return: Image type
        """
        return self.get_image_types(self.chip_config, self.flags_core_id.tag).from_tag(
            (self.flags >> self.FLAGS_TYPE_OFFSET) & ((1 << self.FLAGS_TYPE_SIZE) - 1)
        )

    @property
    def flags_image_type_name(self) -> str:
        """Get Image type name from flags.

        :return: Image type name
        """
        return self.flags_image_type.label

    @property
    def flags_core_id(self) -> SpsdkSoftEnum:
        """Get Core ID from flags.

        :return: Core ID
        """
        return self.chip_config.base.core_ids.from_tag(
            (self.flags >> self.FLAGS_CORE_ID_OFFSET) & ((1 << self.FLAGS_CORE_ID_SIZE) - 1)
        )

    @property
    def flags_core_id_name(self) -> str:
        """Get Core ID from flags in readable string.

        :return: Core ID name
        """
        return self.flags_core_id.label

    @property
    def flags_is_encrypted(self) -> bool:
        """Get Is encrypted property from flags.

        :return: True if is encrypted, false otherwise
        """
        return bool(
            (self.flags >> self.FLAGS_IS_ENCRYPTED_OFFSET)
            & ((1 << self.FLAGS_IS_ENCRYPTED_SIZE) - 1)
        )

    @property
    def flags_boot_flags(self) -> int:
        """Get boot flags property from flags.

        :return: Boot flags
        """
        return (self.flags >> self.FLAGS_BOOT_FLAGS_OFFSET) & (
            (1 << self.FLAGS_BOOT_FLAGS_SIZE) - 1
        )

    @property
    def metadata_start_cpu_id(self) -> int:
        """Get CPU ID property from Meta data.

        :return: Start CPU ID
        """
        return (self.image_meta_data >> self.METADATA_START_CPU_ID_OFFSET) & (
            (1 << self.METADATA_START_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_mu_cpu_id(self) -> int:
        """Get Start CPU Memory Unit ID property from Meta data.

        :return: Start CPU MU ID
        """
        return (self.image_meta_data >> self.METADATA_MU_CPU_ID_OFFSET) & (
            (1 << self.METADATA_MU_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_start_partition_id(self) -> int:
        """Get Start Partition ID property from Meta data.

        :return: Start Partition ID
        """
        return (self.image_meta_data >> self.METADATA_START_PARTITION_ID_OFFSET) & (
            (1 << self.METADATA_START_PARTITION_ID_SIZE) - 1
        )

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        The hash and IV are kept in big endian form.

        :return: bytes representing container content.
        """
        # hash: fixed at 512 bits, left aligned and padded with zeros for hash below 512 bits.
        # In case the hash is shorter, the pack() (in little endian mode) should grant, that the
        # hash is left aligned and padded with zeros due to the '64s' formatter.
        # iv: fixed at 256 bits.
        data = pack(
            self.format(),
            self._image_offset,
            self.image_size,
            self.load_address,
            self.entry_point,
            self.flags,
            self.image_meta_data,
            self.image_hash,
            self.image_iv,
        )

        return data

    def verify(self) -> Verifier:
        """Verify object data.

        :return: Verifier object with the verification results.
        """

        def verify_image() -> None:
            if self.image is None:
                ret.add_record("Image", VerifierResult.ERROR, "Doesn't exists")
            elif self._get_valid_size(self.image) != self.image_size:
                ret.add_record(
                    "Image",
                    VerifierResult.ERROR,
                    f"Invalid length: {self._get_valid_size(self.image)}B != {self.image_size}B",
                )
            elif self.image_size == 0 and self.flags_image_type_name != "v2x_dummy":
                ret.add_record(
                    "Image",
                    VerifierResult.WARNING,
                    "The zero length is used just for V2X dummy image.",
                )
            else:
                ret.add_record("Image", VerifierResult.SUCCEEDED)

        def verify_flags() -> None:
            ver_flags = Verifier("Flags")
            ver_flags.add_record_bit_range("Range", self.flags)
            ver_flags.add_record_enum(
                "Image type",
                self.flags_image_type,
                self.get_image_types(self.chip_config, self.flags_core_id.tag),
            )
            ver_flags.add_record_enum("Core Id", self.flags_core_id, self.chip_config.base.core_ids)
            hash_val = (self.flags >> self.FLAGS_HASH_OFFSET) & ((1 << self.FLAGS_HASH_SIZE) - 1)
            ver_flags.add_record_enum("Hash algorithm", hash_val, self.FLAGS_HASH_ALGORITHM_TYPE)
            ver_flags.add_record("Boot flags", VerifierResult.SUCCEEDED, self.flags_boot_flags)
            ver_flags.add_record("Is encrypted", VerifierResult.SUCCEEDED, self.flags_is_encrypted)
            ret.add_child(ver_flags)

        def verify_metadata() -> None:
            ver_metadata = Verifier("Metadata")
            ver_metadata.add_record_bit_range("Range", self.image_meta_data)
            ver_metadata.add_record(
                "Start partition Id", VerifierResult.SUCCEEDED, self.metadata_start_partition_id
            )
            ver_metadata.add_record("MU CPU Id", VerifierResult.SUCCEEDED, self.metadata_mu_cpu_id)
            ver_metadata.add_record(
                "Start CPU Id", VerifierResult.SUCCEEDED, self.metadata_start_cpu_id
            )
            ret.add_child(ver_metadata)

        def verify_hash_format() -> None:
            if self.image_hash is None:
                ret.add_record("Image hash", VerifierResult.ERROR, "Doesn't exists")
            elif not any(self.image_hash):
                result = VerifierResult.ERROR
                if self.chip_config.base.allow_empty_hash:
                    result = VerifierResult.WARNING
                ret.add_record("Image hash", result, "All zeros")
            elif len(self.image_hash) != self.HASH_LEN:
                ret.add_record(
                    "Image hash",
                    VerifierResult.ERROR,
                    f"Invalid length ({self.image_hash.hex()}B), it MUST be {self.HASH_LEN}",
                )
            else:
                image_hash_cmp = extend_block(
                    get_hash(
                        extend_block(self.image, self.image_size),
                        algorithm=self.get_hash_from_flags(self.flags),
                    ),
                    self.HASH_LEN,
                    padding=0,
                )
                ret.add_record(
                    "Image hash", self.image_hash == image_hash_cmp, self.image_hash.hex()
                )

        ret = Verifier(name=repr(self), description="")
        verify_image()
        ret.add_record_bit_range("Offset in container", self._image_offset)
        ret.add_record_bit_range("Image Size [B]", self.image_size)
        ret.add_record_bit_range("Load address", self.load_address, 64)
        ret.add_record_bit_range("Entry point", self.entry_point, 64)
        verify_flags()
        verify_metadata()
        verify_hash_format()

        return ret

    @classmethod
    def parse(cls, data: bytes, chip_config: AhabChipContainerConfig) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse input binary chunk to the container object.

        :param data: Binary data with Image Array Entry block to parse.
        :param chip_config: AHAB container chip configuration.
        :raises SPSDKLengthError: If invalid length of image is detected.
        :raises SPSDKValueError: Invalid hash for image.
        :return: Object recreated from the binary data.
        """
        # Just updates offsets from AHAB Image start As is feature of none xip containers
        cls._check_fixed_input_length(data).validate()
        (
            image_offset,
            image_size,
            load_address,
            entry_point,
            flags,
            image_meta_data,
            image_hash,
            image_iv,
        ) = unpack(cls.format(), data[: cls.fixed_length()])

        iae = cls(
            chip_config=chip_config,
            image_offset=0,
            image=None,
            load_address=load_address,
            entry_point=entry_point,
            flags=flags,
            image_meta_data=image_meta_data,
            image_hash=image_hash,
            image_iv=image_iv,
            already_encrypted_image=bool(
                (flags >> cls.FLAGS_IS_ENCRYPTED_OFFSET) & ((1 << cls.FLAGS_IS_ENCRYPTED_SIZE) - 1)
            ),
        )
        iae.image_size = image_size
        iae._image_offset = image_offset

        logger.debug(
            (
                "Parsing Image array Entry:\n"
                f"Image offset: {hex(iae.image_offset)}\n"
                f"Image offset raw: {hex(iae._image_offset)}"
            )
        )

        return iae

    @classmethod
    def load_from_config(cls, chip_config: AhabChipContainerConfig, config: dict[str, Any]) -> Self:
        """Converts the configuration option into an AHAB image array entry object.

        "config" content of container configurations.

        :param chip_config: Chip container configuration.
        :param config: Configuration of ImageArray.
        :return: Container Header Image Array Entry object.
        """
        image_path = config.get("image_path")
        image_size_alignment = config.get("image_size_alignment")
        search_paths = chip_config.base.search_paths
        is_encrypted = config.get("is_encrypted", False)
        meta_data = cls.create_meta(
            value_to_int(config.get("meta_data_start_cpu_id", 0)),
            value_to_int(config.get("meta_data_mu_cpu_id", 0)),
            value_to_int(config.get("meta_data_start_partition_id", 0)),
        )
        image_data = load_binary(image_path, search_paths=search_paths) if image_path else b""
        core_id = chip_config.base.core_ids.from_label(config.get("core_id", "Unknown")).tag
        flags = cls.create_flags(
            image_type=cls.get_image_types(chip_config, core_id)
            .from_label(config.get("image_type", "executable"))
            .tag,
            core_id=core_id,
            hash_type=cls.FLAGS_HASH_ALGORITHM_TYPE.from_label(config.get("hash_type", "sha256")),
            is_encrypted=is_encrypted,
            boot_flags=value_to_int(config.get("boot_flags", 0)),
        )

        if chip_config.base.target_memory == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER:
            image_offset = 0
        else:
            image_offset = value_to_int(config.get("image_offset", 0))

        gap_after_image = value_to_int(config.get("gap_after_image", 0))

        return cls(
            chip_config=chip_config,
            image=image_data,
            image_offset=image_offset,
            load_address=value_to_int(config.get("load_address", 0)),
            entry_point=value_to_int(config.get("entry_point", 0)),
            flags=flags,
            image_meta_data=meta_data,
            image_iv=None,  # IV data are updated by UpdateFields function
            gap_after_image=gap_after_image,
            image_size_alignment=image_size_alignment,
        )

    def create_config(self, index: int, image_index: int, data_path: str) -> dict[str, Any]:
        """Create configuration of the AHAB Image data blob.

        :param index: Container index.
        :param image_index: Data Image index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Union[str, int, bool]] = {}
        image_name = None
        if self.plain_image:
            image_name = clean_up_file_name(
                f"container{index}_image{image_index}_"
                f"{self.flags_image_type_name}_{self.flags_core_id_name}.bin"
            )
            write_file(self.plain_image, os.path.join(data_path, image_name), mode="wb")
        if self.encrypted_image:
            image_name_encrypted = clean_up_file_name(
                f"container{index}_image{image_index}_{self.flags_image_type_name}_encrypted.bin"
            )
            write_file(
                self.encrypted_image, os.path.join(data_path, image_name_encrypted), mode="wb"
            )
            if not image_name:
                image_name = image_name_encrypted

        if image_name:
            ret_cfg["image_path"] = image_name
        ret_cfg["image_offset"] = hex(self.image_offset)
        ret_cfg["load_address"] = hex(self.load_address)
        ret_cfg["entry_point"] = hex(self.entry_point)
        ret_cfg["image_type"] = self.flags_image_type_name
        ret_cfg["core_id"] = self.flags_core_id_name
        ret_cfg["is_encrypted"] = bool(self.flags_is_encrypted)
        ret_cfg["boot_flags"] = self.flags_boot_flags
        ret_cfg["meta_data_start_cpu_id"] = self.metadata_start_cpu_id
        ret_cfg["meta_data_mu_cpu_id"] = self.metadata_mu_cpu_id
        ret_cfg["meta_data_start_partition_id"] = self.metadata_start_partition_id
        ret_cfg["hash_type"] = self.get_hash_from_flags(self.flags).label

        return ret_cfg

    def get_valid_alignment(self) -> int:
        """Get valid alignment for AHAB container and memory target.

        :return: AHAB valid alignment
        """
        if self.flags_image_type_name == "ele":
            return 4

        return max([BINARY_IMAGE_ALIGNMENTS[self.chip_config.base.target_memory], 1024])

    def _get_valid_size(self, image: Optional[bytes]) -> int:
        """Get valid image size that will be stored.

        :return: AHAB valid image size
        """
        if not image:
            return 0
        if self.image_size_alignment:
            return align(len(image), self.image_size_alignment)
        return align(len(image), 4 if self.flags_image_type_name == "ele" else 1)

    def get_valid_offset(self, original_offset: int) -> int:
        """Get valid offset for AHAB container.

        :param original_offset: Offset that should be updated to valid one
        :return: AHAB valid offset
        """
        alignment = self.get_valid_alignment()
        alignment = max(alignment, self.chip_config.base.valid_offset_minimal_alignment)
        return align(original_offset, alignment)


class ImageArrayEntryV2(ImageArrayEntry):
    """Class representing image array entry as part of image array in the AHAB container version 2."""

    # The bits for HASH description has been expanded to 4 bits
    FLAGS_HASH_SIZE = 4
    # The encrypted flag has been moved due to hash field expansion
    FLAGS_IS_ENCRYPTED_OFFSET = 12
    # The Container version 2 using more hash algorithms
    FLAGS_HASH_ALGORITHM_TYPE = AHABSignHashAlgorithmV2


IAE_TYPE = TypeVar("IAE_TYPE", Type[ImageArrayEntry], Type[ImageArrayEntryV2])


class ImageArrayEntryTemplates:
    """Class to handle standard templates for AHAB Image array entries."""

    IMAGE_NAME: str = "None"
    KEY: str = "none"
    DEFAULT_OFFSET: int = 0

    @classmethod
    def _load_value(
        cls,
        database: Features,
        key_name: str,
        config: Optional[dict[str, Any]] = None,
        default: Optional[Any] = None,
    ) -> Any:
        """Load value from all sources."""
        if config:
            ret = config.get(key_name)
            if ret is not None:
                return ret
        return database.get_value(DatabaseManager.AHAB, f"{cls.KEY}_{key_name}", default=default)

    @classmethod
    def _load_int(
        cls,
        database: Features,
        key_name: str,
        config: Optional[dict[str, Any]] = None,
        default: Optional[int] = None,
    ) -> int:
        """Load integer value from all sources."""
        return value_to_int(
            cls._load_value(database=database, key_name=key_name, config=config, default=default)
        )

    @classmethod
    def _load_bool(
        cls,
        database: Features,
        key_name: str,
        config: Optional[dict[str, Any]] = None,
        default: Optional[bool] = None,
    ) -> bool:
        """Load boolean value from all sources."""
        return value_to_bool(
            cls._load_value(database=database, key_name=key_name, config=config, default=default)
        )

    @classmethod
    def _load_str(
        cls,
        database: Features,
        key_name: str,
        config: Optional[dict[str, Any]] = None,
        default: Optional[str] = None,
    ) -> str:
        """Load string value from all sources."""
        ret = cls._load_value(database=database, key_name=key_name, config=config, default=default)
        assert isinstance(ret, str)
        return ret

    @classmethod
    def _load_str_int(
        cls,
        database: Features,
        key_name: str,
        config: Optional[dict[str, Any]] = None,
        default: Optional[Union[str, int]] = None,
    ) -> Union[str, int]:
        """Load string value from all sources."""
        ret = cls._load_value(database=database, key_name=key_name, config=config, default=default)
        assert isinstance(ret, (str, int))
        return ret

    @classmethod
    def _create_image_array_entry(
        cls,
        iae_cls: IAE_TYPE,
        binary: bytes,
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> Union[ImageArrayEntry, ImageArrayEntryV2]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class to create.
        :param binary: Binary image data
        :param chip_configuration: Ahab chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        family = chip_config.base.family
        # get DB for family
        database = get_db(family)
        image_offset = cls._load_int(
            database, "image_offset", config=config, default=cls.DEFAULT_OFFSET
        )
        load_address = cls._load_int(database, "load_address", config=config)
        entry_point = cls._load_int(database, "entry_point", config=config, default=load_address)
        core_id = chip_config.base.core_ids.from_attr(
            cls._load_str(database, "core_id", config=config)
        )
        image_type = iae_cls.get_image_types(chip_config, core_id.tag).from_attr(
            cls._load_str(database, "image_type", config=config, default="executable")
        )
        is_encrypted = cls._load_bool(database, "is_encrypted", config=config, default=False)
        boot_flags = cls._load_int(database, "boot_flags", config=config, default=0)
        meta_data_start_cpu_id = cls._load_int(
            database, "meta_data_start_cpu_id", config=config, default=0
        )
        meta_data_mu_cpu_id = cls._load_int(
            database, "meta_data_mu_cpu_id", config=config, default=0
        )
        meta_data_start_partition_id = cls._load_int(
            database, "meta_data_start_partition_id", config=config, default=0
        )
        hash_type = AHABSignHashAlgorithmV1.from_attr(
            cls._load_str(database, "hash_type", config=config, default="SHA384")
        )
        meta_data = iae_cls.create_meta(
            start_cpu_id=meta_data_start_cpu_id,
            mu_cpu_id=meta_data_mu_cpu_id,
            start_partition_id=meta_data_start_partition_id,
        )
        flags = iae_cls.create_flags(
            image_type=image_type.tag,
            core_id=core_id.tag,
            hash_type=hash_type,
            is_encrypted=is_encrypted,
            boot_flags=boot_flags,
        )
        gap_after_image = cls._load_int(database, "gap_after_image", config=config, default=0)
        try:
            image_size_alignment = cls._load_int(database, "image_size_alignment", config=config)
        except SPSDKError:
            image_size_alignment = None

        return iae_cls(
            chip_config=chip_config,
            image=binary,
            image_offset=image_offset,
            load_address=load_address,
            entry_point=entry_point,
            flags=flags,
            image_meta_data=meta_data,
            image_name=cls.IMAGE_NAME,
            gap_after_image=gap_after_image,
            image_size_alignment=image_size_alignment,
        )

    @classmethod
    def get_default_setting_description(cls, family: str) -> str:
        """Get default settings text description.

        :param family: Family name of device
        :return: Default text description
        """

        def get_image_types() -> Type[SpsdkSoftEnum]:
            image_type_group = "application"
            db_image_types_mapping = database.get_dict(DatabaseManager.AHAB, "image_types_mapping")
            db_image_types = load_images_types(database)
            for k, v in db_image_types_mapping.items():
                if core_id.tag in v:
                    image_type_group = k
            return db_image_types[image_type_group]

        database = get_db(family)
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", database.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        image_offset = cls._load_int(database, "image_offset", default=cls.DEFAULT_OFFSET)
        load_address = cls._load_int(database, "load_address")
        entry_point = cls._load_int(database, "entry_point", default=load_address)
        core_id = core_ids.from_attr(cls._load_str_int(database, "core_id"))
        image_type = get_image_types().from_attr(
            cls._load_str_int(database, "image_type", default="executable")
        )
        is_encrypted = cls._load_bool(database, "is_encrypted", default=False)
        boot_flags = cls._load_int(database, "boot_flags", default=0)
        meta_data_start_cpu_id = cls._load_int(database, "meta_data_start_cpu_id", default=0)
        meta_data_mu_cpu_id = cls._load_int(database, "meta_data_mu_cpu_id", default=0)
        meta_data_start_partition_id = cls._load_int(
            database, "meta_data_start_partition_id", default=0
        )
        hash_type = AHABSignHashAlgorithmV2.from_attr(
            cls._load_str(database, "hash_type", default="SHA384")
        )
        ret = "Image array default settings. Can be overridden by definitions that are hidden in the template:\n"
        if image_offset != cls.DEFAULT_OFFSET:
            ret += f"image_offset:                  0x{image_offset:08X}\n"
        ret += f"load_address:                  0x{load_address:016X}\n"
        if entry_point != load_address:
            ret += f"entry_point:                   0x{entry_point:016X}\n"
        if image_type.tag != 0:
            ret += f"image_type:                    {image_type.label}\n"
        if core_id.tag != 0:
            ret += f"core_id:                       {core_id.label}\n"
        if is_encrypted:
            ret += f"is_encrypted:                  {is_encrypted}\n"
        if boot_flags != 0:
            ret += f"boot_flags:                    0x{boot_flags:08X}\n"
        if meta_data_start_cpu_id:
            ret += f"meta_data_start_cpu_id:        {meta_data_start_cpu_id}\n"
        if meta_data_mu_cpu_id:
            ret += f"meta_data_mu_cpu_id:           {meta_data_mu_cpu_id}\n"
        if meta_data_start_partition_id:
            ret += f"meta_data_start_partition_id:  {meta_data_start_partition_id}\n"
        ret += f"hash_type:                     {hash_type.label}"

        return ret

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: IAE_TYPE,
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        return [
            cls._create_image_array_entry(
                iae_cls,
                binary=load_binary(config[cls.KEY], search_paths=chip_config.base.search_paths),
                chip_config=chip_config,
                config=config,
            )
        ]

    @classmethod
    def create_image_array_entries(
        cls,
        iae_cls: IAE_TYPE,
        chip_config: AhabChipContainerConfig,
        config: list[dict[str, Any]],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry list of records.

        :param iae_cls: Image array class type
        :param chip_config: AHAB container configuration
        :param config: Configuration from user
        :return: List of image array entries
        """
        config_loaders = ImageArrayEntryTemplates.__subclasses__()
        image_array: list = []
        for image in config:
            hit = False
            if "image_path" in image:
                image_array.append(iae_cls.load_from_config(chip_config, image))
                continue
            for iae_template_class in config_loaders:
                if image.get(iae_template_class.KEY):
                    image_array.extend(
                        iae_template_class.create_image_array_entry(
                            iae_cls,
                            chip_config,
                            image,
                        )
                    )
                    hit = True
                    break
            if not hit:
                logger.error(f"Can't handle {image} configuration record")

        return image_array


class IaeDoubleAuthentication(ImageArrayEntryTemplates):
    """Class to handle NXP images to be double authenticated (also by OEM) for AHAB Image array entries."""

    IMAGE_NAME: str = "Double Authentication for NXP images"
    KEY: str = "double_authentication"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        ret = []
        search_paths = chip_config.base.search_paths
        # load lpddr binary files
        logger.info("Adding Double Authentication NXP firmware image")
        nxp_image = load_binary(config[cls.KEY], search_paths)

        # Try to get ELE FW
        header = HeaderContainerData.parse(nxp_image)
        if header.tag != AHABTags.CONTAINER_HEADER.tag:
            raise SPSDKError("Invalid NXP Container")
        if header.version == 0 and iae_cls != ImageArrayEntry:
            raise SPSDKError("Invalid NXP container version")
        container_size = 0x4000 if header.version == 1 else 0x400
        ele_iae = iae_cls.parse(nxp_image[0x10:], chip_config)
        ele_container = (
            nxp_image[:container_size]
            + bytes(ele_iae.image_offset - container_size)
            + ele_iae.image
        )
        config["core_id"] = "ele"
        config["image_type"] = "ele_as_image"
        ret.append(
            cls._create_image_array_entry(
                iae_cls=iae_cls, binary=ele_container, chip_config=chip_config, config=config
            )
        )

        # Try to get V2X FW
        header = HeaderContainerData.parse(nxp_image[container_size:])
        if header.tag == AHABTags.CONTAINER_HEADER.tag:
            v2xfhp_iae = iae_cls.parse(nxp_image[container_size + 0x10 :], chip_config)
            v2xfhs_iae = iae_cls.parse(nxp_image[container_size + 0x80 + 0x10 :], chip_config)
            v2xfh_container = nxp_image[container_size : 2 * container_size]
            v2xfh_container += bytes(v2xfhp_iae._image_offset)  # Add Padding
            v2xfh_container += nxp_image[
                container_size
                + v2xfhp_iae._image_offset : container_size
                + v2xfhs_iae._image_offset
                + v2xfhs_iae.image_size
            ]
            config["core_id"] = "v2x-1"
            config["image_type"] = "v2x_as_image"
            ret.append(
                cls._create_image_array_entry(
                    iae_cls=iae_cls, binary=v2xfh_container, chip_config=chip_config, config=config
                )
            )
        return ret


class IaeSPLDDR(ImageArrayEntryTemplates):
    """Class to handle SPL for AHAB Image array entries."""

    IMAGE_NAME: str = "U-Boot SPL with DDR tunning images"
    KEY: str = "spl_ddr"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        family = chip_config.base.family
        search_paths = chip_config.base.search_paths
        # get DB for family
        database = get_db(family)
        ddr_binary = b""
        # load lpddr binary files
        logger.info("Adding DDR memory areas into SPL image")
        lpddr_imem_1d = load_binary(config["lpddr_imem_1d"], search_paths)
        lpddr_dmem_1d = load_binary(config["lpddr_dmem_1d"], search_paths)
        lpddr_imem_2d = load_binary(config["lpddr_imem_2d"], search_paths)
        lpddr_dmem_2d = load_binary(config["lpddr_dmem_2d"], search_paths)

        ddr_binaries = [lpddr_imem_1d, lpddr_dmem_1d, lpddr_imem_2d, lpddr_dmem_2d]
        alignments = database.get_list(DatabaseManager.AHAB, "ddr_alignments")

        # align the binaries
        for idx, alignment in enumerate(alignments):
            if alignment:
                ddr_binaries[idx] = align_block(ddr_binaries[idx], alignment)

        # merge the ddr binaries
        ddr_binary = b"".join(ddr_binaries)

        # load ddr fw binary
        ddr_fw = load_binary(config["spl_ddr"], search_paths)
        ddr_fw_alignment = database.get_value(DatabaseManager.AHAB, "ddr_fw_alignment")

        # merge to final binary
        binary_image = align_block(ddr_fw, ddr_fw_alignment) + ddr_binary

        # Check if binary fits into device OCRAM
        ocram_size = database.device.info.memory_map.get_memory("ocram_ns").size
        if len(binary_image) > ocram_size:
            logger.warning(
                f"The SPL DDR binary is too large for the OCRAM {hex(len(binary_image))} > {hex(ocram_size)}"
            )

        return [
            cls._create_image_array_entry(
                iae_cls=iae_cls, binary=binary_image, chip_config=chip_config, config=config
            )
        ]


class IaeUPower(ImageArrayEntryTemplates):
    """Class to handle uPower for AHAB Image array entries."""

    IMAGE_NAME: str = "uPower"
    KEY: str = "upower"


class IaeSPL(ImageArrayEntryTemplates):
    """Class to handle SPL for AHAB Image array entries."""

    IMAGE_NAME: str = "U-Boot SPL"
    KEY: str = "spl"


class IaeOEIDDR(ImageArrayEntryTemplates):
    """Class to handle OEI DDR for AHAB Image array entries."""

    IMAGE_NAME: str = "OEI DDR"
    KEY: str = "oei_ddr"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """

        def create_fw_header(imem: bytes, dmem: bytes) -> bytes:
            return len(imem).to_bytes(4, "little") + len(dmem).to_bytes(4, "little")

        search_paths = chip_config.base.search_paths
        # load lpddr binary files
        lpddr_imem = load_binary(config["lpddr_imem"], search_paths)
        lpddr_dmem = load_binary(config["lpddr_dmem"], search_paths)
        quick_boot = config.get("lpddr_imem_qb") and config.get("lpddr_dmem_qb")

        if quick_boot:
            lpddr_imem_qb = load_binary(config["lpddr_imem_qb"], search_paths)
            lpddr_dmem_qb = load_binary(config["lpddr_dmem_qb"], search_paths)

        binary_image = align_block(load_binary(config["oei_ddr"], search_paths), 4)
        # add ddr fw header
        binary_image += create_fw_header(lpddr_imem, lpddr_dmem)
        binary_image += lpddr_imem
        binary_image += lpddr_dmem
        if quick_boot:
            # add ddr fw header for quick boot
            binary_image += create_fw_header(lpddr_imem_qb, lpddr_dmem_qb)
            binary_image += lpddr_imem_qb
            binary_image += lpddr_dmem_qb

        ret = [
            cls._create_image_array_entry(
                iae_cls=iae_cls, binary=binary_image, chip_config=chip_config, config=config
            )
        ]

        if quick_boot:
            db = get_db(chip_config.base.family, chip_config.base.revision)
            qb_data_mandatory = db.get_bool(
                DatabaseManager.AHAB, f"{cls.KEY}_qb_data_mandatory", False
            )
            qb_data = config.get("qb_data")
            if qb_data_mandatory and qb_data is None:
                raise SPSDKValueError("The 'qb_data' is mandatory in this configuration.")

            if qb_data:
                qb_data_binary = load_binary(qb_data, search_paths)

                meta_data = iae_cls.create_meta()
                image_type = chip_config.base.image_types["application"].from_attr("oei_ddr").tag

                flags = iae_cls.create_flags(
                    image_type=image_type, core_id=0, hash_type=AHABSignHashAlgorithmV1.SHA384
                )
                qb_iae = iae_cls(
                    chip_config=chip_config,
                    image=qb_data_binary,
                    image_offset=0,
                    load_address=0,
                    entry_point=0,
                    flags=flags,
                    image_meta_data=meta_data,
                    image_name=cls.IMAGE_NAME,
                    gap_after_image=0,
                    image_size_alignment=64 * 1024,
                )
                qb_iae.image_size = 0
                ret.append(qb_iae)

        return ret


class IaeOEITCM(ImageArrayEntryTemplates):
    """Class to handle OEI TCM for AHAB Image array entries."""

    IMAGE_NAME: str = "OEI TCM"
    KEY: str = "oei_tcm"


class IaeSystemManager(ImageArrayEntryTemplates):
    """Class to handle System manager for AHAB Image array entries."""

    IMAGE_NAME: str = "System manager"
    KEY: str = "system_manager"


class IaeCortexM33_2App(ImageArrayEntryTemplates):
    """Class to handle Additional Cortex M33 core 2 application for AHAB Image array entries."""

    IMAGE_NAME: str = "Additional Cortex M33 application running on core 2"
    KEY: str = "cortex_m33_2_app"


class IaeCortexM7App(ImageArrayEntryTemplates):
    """Class to handle Additional Cortex M7 application for AHAB Image array entries."""

    IMAGE_NAME: str = "Additional Cortex M7 application"
    KEY: str = "cortex_m7_app"


class IaeCortexM7_2App(ImageArrayEntryTemplates):
    """Class to handle Additional Cortex M7 core 2 application for AHAB Image array entries."""

    IMAGE_NAME: str = "Additional Cortex M7 application running on core 2"
    KEY: str = "cortex_m7_2_app"


class IaeATF(ImageArrayEntryTemplates):
    """Class to handle ATF for AHAB Image array entries."""

    IMAGE_NAME: str = "ATF - ARM Trusted Firmware"
    KEY: str = "atf"


class IaeUBoot(ImageArrayEntryTemplates):
    """Class to handle U-Boot for AHAB Image array entries."""

    IMAGE_NAME: str = "U-Boot Firmware"
    KEY: str = "uboot"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        search_paths = chip_config.base.search_paths
        binary_image = load_binary(config[cls.KEY], search_paths)
        spsdk_signature = "SPSDK " + version
        return [
            cls._create_image_array_entry(
                iae_cls=iae_cls,
                binary=binary_image + bytes(spsdk_signature, encoding="ascii") + b"\xa0",
                chip_config=chip_config,
                config=config,
            )
        ]


class IaeTEE(ImageArrayEntryTemplates):
    """Class to handle U-Boot TEE - Trusted Execution Environment for AHAB Image array entries."""

    IMAGE_NAME: str = "U-Boot TEE - Trusted Execution Environment"
    KEY: str = "tee"


class IaeV2XDummy(ImageArrayEntryTemplates):
    """Class to handle V2X core Dummy record for AHAB Image array entries."""

    IMAGE_NAME: str = "V2X core Dummy record"
    KEY: str = "v2x_dummy"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: dict[str, Any],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create Image array entry from config and database information.

        :param iae_cls: Image Array Entry class
        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        if not config["v2x_dummy"]:
            logger.warning(
                "The setting of V2X dummy in configuration doesn't affect the presence "
                "in Image Array Entry table, just presence in configuration it enables."
            )
        return [
            cls._create_image_array_entry(
                iae_cls=iae_cls,
                binary=b"",
                chip_config=chip_config,
                config=config,
            )
        ]

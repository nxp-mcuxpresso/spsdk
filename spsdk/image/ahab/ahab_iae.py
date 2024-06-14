#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container Image Array Entry support."""

import logging
import os
from struct import pack, unpack
from typing import Any, Dict, Optional, Union

from typing_extensions import Self

from spsdk.__version__ import version
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.image.ahab.ahab_abstract_interfaces import Container
from spsdk.image.ahab.ahab_data import (
    BINARY_IMAGE_ALIGNMENTS,
    RESERVED,
    TARGET_MEMORY_BOOT_OFFSETS,
    UINT32,
    UINT64,
    AhabChipContainerConfig,
    AHABSignHashAlgorithm,
    AhabTargetMemory,
)
from spsdk.utils.database import DatabaseManager, Features, get_db
from spsdk.utils.misc import (
    align,
    align_block,
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
        """
        self._image_offset = 0
        self.chip_config = chip_config
        self.flags = flags
        self.already_encrypted_image = already_encrypted_image
        self.image = image if image else b""
        self.image_offset = image_offset
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

    @property
    def image_offset_real(self) -> int:
        """Real offset in Bootable image."""
        target_memory = self.chip_config.base.target_memory
        return self.image_offset + TARGET_MEMORY_BOOT_OFFSETS[target_memory]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ImageArrayEntry):
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
        return (
            "AHAB Image Array Entry:\n"
            f"  Image size:             {self.image_size}B\n"
            f"  Image offset in table:  {hex(self._image_offset)}\n"
            f"  Image offset real:      {hex(self.image_offset_real)}\n"
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
                get_hash(self.image, algorithm=algorithm),
                self.HASH_LEN,
                padding=0,
            )
        if not self.image_iv and self.flags_is_encrypted:
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

    @staticmethod
    def create_flags(
        image_type: int,
        core_id: int,
        hash_type: AHABSignHashAlgorithm = AHABSignHashAlgorithm.SHA256,
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
        flags_data |= core_id << ImageArrayEntry.FLAGS_CORE_ID_OFFSET
        flags_data |= hash_type.tag << ImageArrayEntry.FLAGS_HASH_OFFSET
        flags_data |= 1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET if is_encrypted else 0
        flags_data |= boot_flags << ImageArrayEntry.FLAGS_BOOT_FLAGS_OFFSET

        return flags_data

    @staticmethod
    def get_hash_from_flags(flags: int) -> EnumHashAlgorithm:
        """Get Hash algorithm name from flags.

        :param flags: Value of flags.
        :return: Hash name.
        """
        hash_val = (flags >> ImageArrayEntry.FLAGS_HASH_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_HASH_SIZE) - 1
        )
        return EnumHashAlgorithm.from_label(AHABSignHashAlgorithm.from_tag(hash_val).label.lower())

    @property
    def flags_image_type(self) -> SpsdkSoftEnum:
        """Get Image type from flags.

        :return: Image type
        """
        return self.chip_config.base.image_types.from_tag(
            (self.flags >> ImageArrayEntry.FLAGS_TYPE_OFFSET)
            & ((1 << ImageArrayEntry.FLAGS_TYPE_SIZE) - 1)
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
            (self.flags >> ImageArrayEntry.FLAGS_CORE_ID_OFFSET)
            & ((1 << ImageArrayEntry.FLAGS_CORE_ID_SIZE) - 1)
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
            (self.flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
            & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
        )

    @property
    def flags_boot_flags(self) -> int:
        """Get boot flags property from flags.

        :return: Boot flags
        """
        return (self.flags >> ImageArrayEntry.FLAGS_BOOT_FLAGS_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_BOOT_FLAGS_SIZE) - 1
        )

    @property
    def metadata_start_cpu_id(self) -> int:
        """Get CPU ID property from Meta data.

        :return: Start CPU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_mu_cpu_id(self) -> int:
        """Get Start CPU Memory Unit ID property from Meta data.

        :return: Start CPU MU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_MU_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_MU_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_start_partition_id(self) -> int:
        """Get Start Partition ID property from Meta data.

        :return: Start Partition ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_PARTITION_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_PARTITION_ID_SIZE) - 1
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
                "Image type", self.flags_image_type, self.chip_config.base.image_types
            )
            ver_flags.add_record_enum("Core Id", self.flags_core_id, self.chip_config.base.core_ids)
            hash_val = (self.flags >> ImageArrayEntry.FLAGS_HASH_OFFSET) & (
                (1 << ImageArrayEntry.FLAGS_HASH_SIZE) - 1
            )
            ver_flags.add_record_enum("Hash algorithm", hash_val, AHABSignHashAlgorithm)
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
                ret.add_record("Image hash", VerifierResult.ERROR, "All zeros")
            elif len(self.image_hash) != self.HASH_LEN:
                ret.add_record(
                    "Image hash",
                    VerifierResult.ERROR,
                    f"Invalid length ({self.image_hash.hex()}B), it MUST be {self.HASH_LEN}",
                )
            else:
                image_hash_cmp = extend_block(
                    get_hash(self.image, algorithm=ImageArrayEntry.get_hash_from_flags(self.flags)),
                    ImageArrayEntry.HASH_LEN,
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

        :param chip_config: AHAB container chip configuration.
        :param data: Binary data with Image Array Entry block to parse.
        :raises SPSDKLengthError: If invalid length of image is detected.
        :raises SPSDKValueError: Invalid hash for image.
        :return: Object recreated from the binary data.
        """
        # Just updates offsets from AHAB Image start As is feature of none xip containers
        ImageArrayEntry._check_fixed_input_length(data).validate()
        (
            image_offset,
            _,  # image_size
            load_address,
            entry_point,
            flags,
            image_meta_data,
            image_hash,
            image_iv,
        ) = unpack(ImageArrayEntry.format(), data[: ImageArrayEntry.fixed_length()])

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
                (flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
                & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
            ),
        )
        iae._image_offset = image_offset

        logger.debug(
            (
                "Parsing Image array Entry:\n"
                f"Image offset: {hex(iae.image_offset)}\n"
                f"Image offset raw: {hex(iae._image_offset)}\n"
                f"Image offset real: {hex(iae.image_offset_real)}"
            )
        )

        return iae

    @staticmethod
    def load_from_config(
        chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> "ImageArrayEntry":
        """Converts the configuration option into an AHAB image array entry object.

        "config" content of container configurations.

        :param chip_config: Chip container configuration.
        :param config: Configuration of ImageArray.
        :return: Container Header Image Array Entry object.
        """
        image_path = config.get("image_path")
        search_paths = chip_config.base.search_paths
        is_encrypted = config.get("is_encrypted", False)
        meta_data = ImageArrayEntry.create_meta(
            value_to_int(config.get("meta_data_start_cpu_id", 0)),
            value_to_int(config.get("meta_data_mu_cpu_id", 0)),
            value_to_int(config.get("meta_data_start_partition_id", 0)),
        )
        image_data = load_binary(image_path, search_paths=search_paths) if image_path else b""
        flags = ImageArrayEntry.create_flags(
            image_type=chip_config.base.image_types.from_label(
                config.get("image_type", "executable")
            ).tag,
            core_id=chip_config.base.core_ids.from_label(config.get("core_id", "Unknown")).tag,
            hash_type=AHABSignHashAlgorithm.from_label(config.get("hash_type", "sha256")),
            is_encrypted=is_encrypted,
            boot_flags=value_to_int(config.get("boot_flags", 0)),
        )

        if chip_config.base.target_memory == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER:
            image_offset = 0
        else:
            image_offset = value_to_int(config.get("image_offset", 0))

        return ImageArrayEntry(
            chip_config=chip_config,
            image=image_data,
            image_offset=image_offset,
            load_address=value_to_int(config.get("load_address", 0)),
            entry_point=value_to_int(config.get("entry_point", 0)),
            flags=flags,
            image_meta_data=meta_data,
            image_iv=None,  # IV data are updated by UpdateFields function
        )

    def create_config(self, index: int, image_index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image data blob.

        :param index: Container index.
        :param image_index: Data Image index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Union[str, int, bool]] = {}
        image_name = None
        if self.plain_image:
            image_name = (
                f"container{index}_image{image_index}_"
                f"{self.flags_image_type_name}_{self.flags_core_id_name}.bin"
            )
            write_file(self.plain_image, os.path.join(data_path, image_name), "wb")
        if self.encrypted_image:
            image_name_encrypted = (
                f"container{index}_image{image_index}_{self.flags_image_type_name}_encrypted.bin"
            )
            write_file(self.encrypted_image, os.path.join(data_path, image_name_encrypted), "wb")
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
        return align(len(image), 4 if self.flags_image_type_name == "ele" else 1)

    def get_valid_offset(self, original_offset: int) -> int:
        """Get valid offset for AHAB container.

        :param original_offset: Offset that should be updated to valid one
        :return: AHAB valid offset
        """
        alignment = self.get_valid_alignment()
        alignment = max(alignment, self.chip_config.base.valid_offset_minimal_alignment)
        return align(original_offset, alignment)


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
        config: Optional[Dict[str, Any]] = None,
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
        config: Optional[Dict[str, Any]] = None,
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
        config: Optional[Dict[str, Any]] = None,
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
        config: Optional[Dict[str, Any]] = None,
        default: Optional[str] = None,
    ) -> str:
        """Load string value from all sources."""
        ret = cls._load_value(database=database, key_name=key_name, config=config, default=default)
        assert isinstance(ret, str)
        return ret

    @classmethod
    def _create_image_array_entry(
        cls,
        binary: bytes,
        chip_config: AhabChipContainerConfig,
        config: Dict[str, Any],
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

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
        image_type = chip_config.base.image_types.from_attr(
            cls._load_str(database, "image_type", config=config, default="executable")
        )
        core_id = chip_config.base.core_ids.from_attr(
            cls._load_str(database, "core_id", config=config)
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
        hash_type = AHABSignHashAlgorithm.from_attr(
            cls._load_str(database, "hash_type", config=config, default="SHA384")
        )
        meta_data = ImageArrayEntry.create_meta(
            start_cpu_id=meta_data_start_cpu_id,
            mu_cpu_id=meta_data_mu_cpu_id,
            start_partition_id=meta_data_start_partition_id,
        )
        flags = ImageArrayEntry.create_flags(
            image_type=image_type.tag,
            core_id=core_id.tag,
            hash_type=hash_type,
            is_encrypted=is_encrypted,
            boot_flags=boot_flags,
        )

        return ImageArrayEntry(
            chip_config=chip_config,
            image=binary,
            image_offset=image_offset,
            load_address=load_address,
            entry_point=entry_point,
            flags=flags,
            image_meta_data=meta_data,
            image_name=cls.IMAGE_NAME,
        )

    @classmethod
    def get_default_setting_description(cls, family: str) -> str:
        """Get default settings text description.

        :param family: Family name of device
        :return: Default text description
        """
        database = get_db(family)
        core_ids = SpsdkSoftEnum.create_from_dict(
            "AHABCoreId", database.get_dict(DatabaseManager.AHAB, "core_ids")
        )
        image_types = SpsdkSoftEnum.create_from_dict(
            "AHABImageTypes", database.get_dict(DatabaseManager.AHAB, "image_types")
        )
        image_offset = cls._load_int(database, "image_offset", default=cls.DEFAULT_OFFSET)
        load_address = cls._load_int(database, "load_address")
        entry_point = cls._load_int(database, "entry_point", default=load_address)
        image_type = image_types.from_attr(
            cls._load_str(database, "image_type", default="executable")
        )
        core_id = core_ids.from_attr(cls._load_str(database, "core_id"))
        is_encrypted = cls._load_bool(database, "is_encrypted", default=False)
        boot_flags = cls._load_int(database, "boot_flags", default=0)
        meta_data_start_cpu_id = cls._load_int(database, "meta_data_start_cpu_id", default=0)
        meta_data_mu_cpu_id = cls._load_int(database, "meta_data_mu_cpu_id", default=0)
        meta_data_start_partition_id = cls._load_int(
            database, "meta_data_start_partition_id", default=0
        )
        hash_type = AHABSignHashAlgorithm.from_attr(
            cls._load_str(database, "hash_type", default="SHA384")
        )
        ret = "Image array default settings. Can be overridden by definitions that are hidden in the template:\n"
        if image_offset != ImageArrayEntryTemplates.DEFAULT_OFFSET:
            ret += f"image_offset:                  0x{image_offset:08X}\n"
        ret += f"load_address:                  0x{load_address:016X}\n"
        if entry_point != load_address:
            ret += f"entry_point:                   0x{entry_point:016X}\n"
        ret += f"image_type:                    {image_type.label}\n"
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
        cls, chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        return cls._create_image_array_entry(
            binary=load_binary(config[cls.KEY], search_paths=chip_config.base.search_paths),
            chip_config=chip_config,
            config=config,
        )


class IaeSPLDDR(ImageArrayEntryTemplates):
    """Class to handle SPL for AHAB Image array entries."""

    IMAGE_NAME: str = "U-Boot SPL with DDR tunning images"
    KEY: str = "spl_ddr"

    @classmethod
    def create_image_array_entry(
        cls, chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

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

        return cls._create_image_array_entry(
            binary=binary_image, chip_config=chip_config, config=config
        )


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
        cls, chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """

        def create_fw_header(imem: bytes, dmem: bytes) -> bytes:
            return len(imem).to_bytes(4, "little") + len(dmem).to_bytes(4, "little")

        search_paths = chip_config.base.search_paths
        # load lpddr binary files
        lpddr_imem_1d = load_binary(config["lpddr_imem_1d"], search_paths)
        lpddr_dmem_1d = load_binary(config["lpddr_dmem_1d"], search_paths)
        lpddr_imem_2d = load_binary(config["lpddr_imem_2d"], search_paths)
        lpddr_dmem_2d = load_binary(config["lpddr_dmem_2d"], search_paths)

        binary_image = align_block(load_binary(config["oei_ddr"], search_paths), 4)
        # add ddr fw header
        binary_image += create_fw_header(lpddr_imem_1d, lpddr_dmem_1d)
        binary_image += lpddr_imem_1d
        binary_image += lpddr_dmem_1d
        # add ddr fw header
        binary_image += create_fw_header(lpddr_imem_2d, lpddr_dmem_2d)
        binary_image += lpddr_imem_2d
        binary_image += lpddr_dmem_2d

        return cls._create_image_array_entry(
            binary=binary_image, chip_config=chip_config, config=config
        )


class IaeOEITCM(ImageArrayEntryTemplates):
    """Class to handle OEI TCM for AHAB Image array entries."""

    IMAGE_NAME: str = "OEI TCM"
    KEY: str = "oei_tcm"


class IaeSystemManager(ImageArrayEntryTemplates):
    """Class to handle System manager for AHAB Image array entries."""

    IMAGE_NAME: str = "System manager"
    KEY: str = "system_manager"


class IaeCortexM7App(ImageArrayEntryTemplates):
    """Class to handle Additional Cortex M7 application for AHAB Image array entries."""

    IMAGE_NAME: str = "Additional Cortex M7 application"
    KEY: str = "cortex_m7_app"


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
        cls, chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        search_paths = chip_config.base.search_paths
        binary_image = load_binary(config[cls.KEY], search_paths)
        spsdk_signature = "SPSDK " + version
        return cls._create_image_array_entry(
            binary=binary_image + bytes(spsdk_signature, encoding="ascii") + b"\xa0",
            chip_config=chip_config,
            config=config,
        )


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
        cls, chip_config: AhabChipContainerConfig, config: Dict[str, Any]
    ) -> ImageArrayEntry:
        """Create Image array entry from config and database information.

        :param chip_config: AHAB Container chip configuration
        :param config: Configuration dictionary
        :return: Image array entry
        """
        if not config["v2x_dummy"]:
            logger.warning(
                "The setting of V2X dummy in configuration doesn't affect the presence "
                "in Image Array Entry table, just presence in configuration it enables."
            )
        return cls._create_image_array_entry(
            binary=b"",
            chip_config=chip_config,
            config=config,
        )

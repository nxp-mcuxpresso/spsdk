#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB (Advanced High Assurance Boot) container Image Array Entry support.

This module provides classes for handling image array entries within AHAB containers,
supporting various image types, encryption, and hash verification for NXP secure boot.
"""

import logging
import os
from struct import pack, unpack
from typing import Any, Optional, Type, TypeVar, Union

from typing_extensions import Self

from spsdk.__version__ import version
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_abstract_interfaces import Container, HeaderContainerData
from spsdk.image.ahab.ahab_data import (
    BINARY_IMAGE_ALIGNMENTS,
    INT32,
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
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, Features
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import (
    align,
    align_block,
    clean_up_file_name,
    extend_block,
    load_binary,
    split_data,
    value_to_bool,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkSoftEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class ImageArrayEntry(Container):
    """Class representing an image array entry as part of the image array in the AHAB container.

    An image array entry contains information about a firmware/software component within
    the AHAB container, including its location, size, load address, entry point, and security
    attributes like hash and encryption status.

    Image Array Entry content structure::

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
        """Initialize an Image Array Entry object.

        :param chip_config: Ahab container chip configuration providing target-specific parameters
        :param image: Binary image data, defaults to None
        :param image_offset: Offset in bytes from start of container to beginning of image, defaults to 0
        :param load_address: Address where the image will be loaded in memory
            (absolute address in system memory map), defaults to 0
        :param entry_point: Entry point of image (absolute address), only valid for
            executable image types, defaults to 0
        :param flags: Configuration flags controlling image type, core ID, hash type,
             and encryption status, defaults to 0
        :param image_meta_data: Image metadata containing CPU and partition information, defaults to 0
        :param image_hash: SHA hash of image (512 bits) in big endian,
            left-aligned and padded for smaller hashes, defaults to None
        :param image_iv: SHA256 of plain text image (256 bits) in big endian used for encryption, defaults to None
        :param already_encrypted_image: Whether the input image is already encrypted, defaults to False
        :param image_name: Optional name/identifier for the image, defaults to None
        :param gap_after_image: Size of gap (in bytes) to add after the image in container, defaults to 0
        :param image_size_alignment: Optional override for standard image size alignment, defaults to None
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
        """Get the absolute image offset within the container.

        :return: Image offset in bytes relative to the start of the container
        """
        return self._image_offset + self.chip_config.container_offset

    @image_offset.setter
    def image_offset(self, offset: int) -> None:
        """Set the image offset.

        :param offset: Absolute image offset to set (will be adjusted for container_offset)
        """
        self._image_offset = offset - self.chip_config.container_offset

    def __eq__(self, other: object) -> bool:
        """Compare two ImageArrayEntry objects for equality.

        Two entries are considered equal if all their attributes match.

        :param other: Object to compare with
        :return: True if objects are equal, False otherwise
        """
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
        """Get string representation of the object.

        :return: String representation with load address
        """
        return f"AHAB Image Array Entry, load address({hex(self.load_address)})"

    def __str__(self) -> str:
        """Get detailed string representation of the object.

        :return: Formatted string with all relevant attributes
        """
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
        """Get the image data for this Image array entry.

        The class determines by flags whether encrypted or plain data should be returned.

        :raises SPSDKError: When image is flagged as encrypted but not actually encrypted yet
        :return: Image bytes (encrypted or plain based on flags)
        """
        # if self.flags_is_encrypted and not self.already_encrypted_image:
        #     raise SPSDKError("Image is NOT encrypted, yet.")

        if self.flags_is_encrypted and self.already_encrypted_image:
            return self.encrypted_image
        return self.plain_image

    @image.setter
    def image(self, data: bytes) -> None:
        """Set the image data for this Image array entry.

        The class decides based on flags whether to store encrypted or plain data.

        :param data: Binary image data to set
        """
        input_image = align_block(
            data,
            1 if self.chip_config.locked else self.chip_config.base.container_image_size_alignment,
            padding=RESERVED,
        )  # align to minimal SD card block if not locked container
        self.plain_image = input_image if not self.already_encrypted_image else b""
        self.encrypted_image = input_image if self.already_encrypted_image else b""

    @classmethod
    def format(cls, signed_offset: bool = False) -> str:
        """Get the format string for binary representation.

        :param signed_offset: Whether the image offset should be treated as signed
        :return: Format string for struct pack/unpack
        """
        offset_format = INT32 if signed_offset else UINT32
        return (
            super().format()  # endianness from base class
            + offset_format  # Image Offset
            + UINT32  # Image Size
            + UINT64  # Load Address
            + UINT64  # Entry Point
            + UINT32  # Flags
            + UINT32  # Image Meta Data
            + "64s"  # HASH
            + "32s"  # Input Vector
        )

    def update_fields(self) -> None:
        """Update the image fields in container based on the provided image.

        Recalculates image size, updates hash if not provided, and sets the IV for encrypted images.
        The hash is calculated based on the algorithm defined in the flags, and the IV is generated
        using SHA256 for encrypted images that don't already have an IV set.
        """
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
        """Create a meta data field by combining CPU and partition IDs.

        The meta data is constructed by placing each ID in its proper bit position:
        - start_cpu_id: bits 0-9
        - mu_cpu_id: bits 10-19
        - start_partition_id: bits 20-27

        :param start_cpu_id: ID of CPU to start, defaults to 0
        :param mu_cpu_id: ID of Message Unit (MU) for the selected CPU to start, defaults to 0
        :param start_partition_id: ID of partition to start, defaults to 0
        :return: Combined image meta data field as a 32-bit integer
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
        """Create a flags field by combining multiple configuration settings.

        The flags field is constructed by placing each value in its proper bit position:
        - image_type: bits 0-3
        - core_id: bits 4-7
        - hash_type: bits 8-10 (or 8-11 in v2)
        - is_encrypted: bit 11 (or 12 in v2)
        - boot_flags: bits 16-30

        :param image_type: Type of image (executable, data, etc.)
        :param core_id: Target processor core ID
        :param hash_type: Hash algorithm used (SHA256, SHA384, etc.)
        :param is_encrypted: Whether the image is encrypted, defaults to False
        :param boot_flags: Boot flags controlling the SCFW boot, defaults to 0
        :return: Combined flags field as a 32-bit integer
        """
        flags_data = image_type
        flags_data |= core_id << cls.FLAGS_CORE_ID_OFFSET
        flags_data |= hash_type.tag << cls.FLAGS_HASH_OFFSET
        flags_data |= 1 << cls.FLAGS_IS_ENCRYPTED_OFFSET if is_encrypted else 0
        flags_data |= boot_flags << cls.FLAGS_BOOT_FLAGS_OFFSET

        return flags_data

    def get_hash_from_flags(self, flags: int) -> EnumHashAlgorithm:
        """Extract the hash algorithm from the flags field.

        Extracts the hash type bits from the flags and converts them to the
        corresponding EnumHashAlgorithm value.

        :param flags: Value of flags field
        :return: Corresponding hash algorithm enum
        """
        hash_val = (flags >> self.FLAGS_HASH_OFFSET) & ((1 << self.FLAGS_HASH_SIZE) - 1)
        return EnumHashAlgorithm.from_label(
            self.FLAGS_HASH_ALGORITHM_TYPE.from_tag(hash_val).label.lower()
        )

    @staticmethod
    def get_image_types(chip_config: AhabChipContainerConfig, core_id: int) -> Type[SpsdkSoftEnum]:
        """Get the appropriate image type enumeration based on core ID.

        Different core IDs may support different image types. This method
        determines the correct image type group from the mapping in the chip
        configuration.

        :param chip_config: Container chip configuration
        :param core_id: Core ID to get image types for
        :return: Enumeration of image types supported by the specified core
        """
        image_type_group = "application"
        for k, v in chip_config.base.image_types_mapping.items():
            if core_id in v:
                image_type_group = k
        return chip_config.base.image_types[image_type_group]

    @property
    def flags_image_type(self) -> SpsdkSoftEnum:
        """Get the image type from the flags field.

        Extracts the image type bits from the flags and converts them to the
        corresponding image type enum value.

        :return: Image type as an enum value
        """
        return self.get_image_types(self.chip_config, self.flags_core_id.tag).from_tag(
            (self.flags >> self.FLAGS_TYPE_OFFSET) & ((1 << self.FLAGS_TYPE_SIZE) - 1)
        )

    @property
    def flags_image_type_name(self) -> str:
        """Get the image type name from the flags field.

        Convenience property that returns the string label of the image type.

        :return: Image type name as a string
        """
        return self.flags_image_type.label

    @property
    def flags_core_id(self) -> SpsdkSoftEnum:
        """Get the core ID from the flags field.

        Extracts the core ID bits from the flags and converts them to the
        corresponding core ID enum value.

        :return: Core ID as an enum value
        """
        return self.chip_config.base.core_ids.from_tag(
            (self.flags >> self.FLAGS_CORE_ID_OFFSET) & ((1 << self.FLAGS_CORE_ID_SIZE) - 1)
        )

    @property
    def flags_core_id_name(self) -> str:
        """Get the core ID name from the flags field.

        Convenience property that returns the string label of the core ID.

        :return: Core ID name as a string
        """
        return self.flags_core_id.label

    @property
    def flags_is_encrypted(self) -> bool:
        """Get the encryption status from the flags field.

        Extracts the encryption bit from the flags.

        :return: True if the image is flagged as encrypted, False otherwise
        """
        return bool(
            (self.flags >> self.FLAGS_IS_ENCRYPTED_OFFSET)
            & ((1 << self.FLAGS_IS_ENCRYPTED_SIZE) - 1)
        )

    @property
    def flags_boot_flags(self) -> int:
        """Get the boot flags from the flags field.

        Extracts the boot flags bits from the flags. These control System Controller
        Firmware (SCFW) boot behavior.

        :return: Boot flags as an integer
        """
        return (self.flags >> self.FLAGS_BOOT_FLAGS_OFFSET) & (
            (1 << self.FLAGS_BOOT_FLAGS_SIZE) - 1
        )

    @property
    def metadata_start_cpu_id(self) -> int:
        """Get the start CPU ID from the metadata field.

        Extracts the CPU ID bits from the metadata. This identifies which CPU
        should start executing the image.

        :return: Start CPU ID as an integer
        """
        return (self.image_meta_data >> self.METADATA_START_CPU_ID_OFFSET) & (
            (1 << self.METADATA_START_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_mu_cpu_id(self) -> int:
        """Get the Message Unit (MU) CPU ID from the metadata field.

        Extracts the MU CPU ID bits from the metadata. This identifies the Message Unit
        for the selected CPU to start.

        :return: MU CPU ID as an integer
        """
        return (self.image_meta_data >> self.METADATA_MU_CPU_ID_OFFSET) & (
            (1 << self.METADATA_MU_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_start_partition_id(self) -> int:
        """Get the start partition ID from the metadata field.

        Extracts the partition ID bits from the metadata. This identifies which
        partition should be started.

        :return: Start partition ID as an integer
        """
        return (self.image_meta_data >> self.METADATA_START_PARTITION_ID_OFFSET) & (
            (1 << self.METADATA_START_PARTITION_ID_SIZE) - 1
        )

    def export(self) -> bytes:
        """Export the container object into bytes in little-endian format.

        Packs all fields of the image array entry into a binary representation.
        The hash and IV values maintain their big-endian form as required by the
        AHAB container format.

        Note: For hash values shorter than 512 bits, they are left-aligned and
        padded with zeros due to the '64s' format specifier.

        :return: Bytes representing the container content
        """
        # hash: fixed at 512 bits, left aligned and padded with zeros for hash below 512 bits.
        # In case the hash is shorter, the pack() (in little endian mode) should grant, that the
        # hash is left aligned and padded with zeros due to the '64s' formatter.
        # iv: fixed at 256 bits.
        data = pack(
            self.format(self.chip_config.base.iae_has_signed_offsets),
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
        """Verify the integrity and validity of the image array entry.

        Performs comprehensive verification of all aspects of the image array entry:
        1. Validates the image size and content
        2. Checks offsets, load address, and entry point
        3. Verifies all flag fields (image type, core ID, hash algorithm)
        4. Validates metadata fields
        5. Verifies image hash matches the calculated hash of the image

        The verification is hierarchical, with sub-verifiers for flags and metadata.

        :return: Verifier object containing detailed verification results
        """

        def verify_image() -> None:
            """Verify the image content and size.

            Checks if the image exists, has correct size, and validates special
            cases like zero-length images for v2x_dummy.
            """
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
            """Verify the flags field and its component parts.

            Creates a sub-verifier to validate image type, core ID,
            hash algorithm, boot flags, and encryption status.
            """
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
            """Verify the metadata field and its component parts.

            Creates a sub-verifier to validate start partition ID,
            MU CPU ID, and start CPU ID.
            """
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
            """Verify the image hash value.

            Checks if the hash exists, has correct length, and matches
            the calculated hash of the image. Also handles special cases
            like empty hashes which are allowed for certain configurations.
            """
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
        """Parse a binary data chunk into an ImageArrayEntry object.

        Extracts and interprets all fields from the binary representation of an
        image array entry according to the AHAB container format. The offset
        handling is adjusted based on the AHAB image start as required for
        non-XIP containers.

        :param data: Binary data containing the Image Array Entry block to parse
        :param chip_config: AHAB container chip configuration
        :raises SPSDKLengthError: If the input data has invalid length
        :raises SPSDKValueError: If the hash is invalid for the image
        :return: New ImageArrayEntry object initialized from the binary data
        """
        # Validate the input length and format
        cls._check_fixed_input_length(data).validate()

        # Unpack the binary data into individual fields
        (
            image_offset,
            image_size,
            load_address,
            entry_point,
            flags,
            image_meta_data,
            image_hash,
            image_iv,
        ) = unpack(cls.format(chip_config.base.iae_has_signed_offsets), data[: cls.fixed_length()])

        # Create the image array entry with the parsed values
        iae = cls(
            chip_config=chip_config,
            image_offset=0,  # Will be set explicitly below
            image=None,  # Only parsing header, not the actual image
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
        # Set fields that need special handling
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
    def load_from_config(cls, chip_config: AhabChipContainerConfig, config: Config) -> Self:
        """Convert configuration options into an AHAB image array entry object.

        Creates a new ImageArrayEntry object based on the provided configuration dictionary.
        The configuration can include various parameters such as image path, offset, load address,
        entry point, image type, core ID, encryption status, etc.

        :param chip_config: Chip-specific container configuration
        :param config: Configuration dictionary containing ImageArray parameters
        :return: Fully initialized Container Header Image Array Entry object
        """
        image_size_alignment = config.get("image_size_alignment")
        is_encrypted = config.get("is_encrypted", False)
        meta_data = cls.create_meta(
            config.get_int("meta_data_start_cpu_id", 0),
            config.get_int("meta_data_mu_cpu_id", 0),
            config.get_int("meta_data_start_partition_id", 0),
        )
        image_data = (
            load_binary(config.get_input_file_name("image_path")) if "image_path" in config else b""
        )
        core_id = chip_config.base.core_ids.from_label(config.get_str("core_id", "Unknown")).tag
        flags = cls.create_flags(
            image_type=cls.get_image_types(chip_config, core_id)
            .from_label(config.get_str("image_type", "executable"))
            .tag,
            core_id=core_id,
            hash_type=cls.FLAGS_HASH_ALGORITHM_TYPE.from_label(config.get("hash_type", "sha256")),
            is_encrypted=is_encrypted,
            boot_flags=config.get_int("boot_flags", 0),
        )

        # For serial downloader, image offset is always 0
        if chip_config.base.target_memory == AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER:
            image_offset = 0
        else:
            image_offset = config.get_int("image_offset", 0)

        gap_after_image = config.get_int("gap_after_image", 0)

        return cls(
            chip_config=chip_config,
            image=image_data,
            image_offset=image_offset,
            load_address=config.get_int("load_address", 0),
            entry_point=config.get_int("entry_point", 0),
            flags=flags,
            image_meta_data=meta_data,
            image_iv=None,  # IV data are updated by UpdateFields function
            gap_after_image=gap_after_image,
            image_size_alignment=image_size_alignment,
        )

    def get_config(self, index: int, image_index: int, data_path: str) -> Config:
        """Create a configuration dictionary representing this image array entry.

        Exports the current state of the ImageArrayEntry into a configuration dictionary
        that can be used to recreate the entry. Also writes associated image files to disk.

        :param index: Container index for filename generation
        :param image_index: Image index within the container for filename generation
        :param data_path: Directory path where image files should be stored
        :return: Configuration dictionary with all parameters of this image array entry
        """
        ret_cfg = Config()
        image_name = None

        # Export plain image if available
        if self.plain_image:
            image_name = clean_up_file_name(
                f"container{index}_image{image_index}_"
                f"{self.flags_image_type_name}_{self.flags_core_id_name}.bin"
            )
            write_file(self.plain_image, os.path.join(data_path, image_name), mode="wb")

        # Export encrypted image if available
        if self.encrypted_image:
            image_name_encrypted = clean_up_file_name(
                f"container{index}_image{image_index}_{self.flags_image_type_name}_encrypted.bin"
            )
            write_file(
                self.encrypted_image, os.path.join(data_path, image_name_encrypted), mode="wb"
            )
            if not image_name:
                image_name = image_name_encrypted

        # Build configuration dictionary with all parameters
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
        """Get the valid alignment for AHAB container based on memory target.

        Different image types and memory targets require different alignments.
        For example, ELE images use 4-byte alignment, while other types use
        the greater of 1024 bytes or the target memory's required alignment.

        :return: Required alignment in bytes for this image
        """
        if self.flags_image_type_name == "ele":
            return 4

        return max([BINARY_IMAGE_ALIGNMENTS[self.chip_config.base.target_memory], 1024])

    def _get_valid_size(self, image: Optional[bytes]) -> int:
        """Calculate the valid image size that should be stored in the container.

        Applies appropriate alignment rules based on image type and
        configured alignment. If a custom image_size_alignment is specified,
        it takes precedence over the default rules.

        :param image: Image data to calculate size for
        :return: Valid aligned size in bytes (0 if image is None)
        """
        if not image:
            return 0
        if self.image_size_alignment:
            return align(len(image), self.image_size_alignment)
        return align(len(image), 4 if self.flags_image_type_name == "ele" else 1)

    def get_valid_offset(self, original_offset: int) -> int:
        """Adjust an offset to comply with AHAB container alignment requirements.

        Ensures that image offsets within the container meet the alignment
        requirements of both the image type and the chip configuration.

        :param original_offset: Original requested offset
        :return: Adjusted offset that meets alignment requirements
        """
        alignment = self.get_valid_alignment()
        alignment = max(alignment, self.chip_config.base.valid_offset_minimal_alignment)
        return align(original_offset, alignment)


class ImageArrayEntryV2(ImageArrayEntry):
    """Class representing image array entry for AHAB container version 2.

    This extends the base ImageArrayEntry with V2-specific modifications:
    - Expanded hash field size (4 bits instead of 3)
    - Relocated encryption flag due to hash field expansion
    - Support for more hash algorithms through AHABSignHashAlgorithmV2
    """

    # The bits for HASH description has been expanded to 4 bits
    FLAGS_HASH_SIZE = 4
    # The encrypted flag has been moved due to hash field expansion
    FLAGS_IS_ENCRYPTED_OFFSET = 12
    # The Container version 2 using more hash algorithms
    FLAGS_HASH_ALGORITHM_TYPE = AHABSignHashAlgorithmV2


IAE_TYPE = TypeVar("IAE_TYPE", Type[ImageArrayEntry], Type[ImageArrayEntryV2])


class ImageArrayEntryTemplates:
    """Base class to handle standard templates for AHAB Image array entries.

    This class and its subclasses provide factory methods to create standardized
    image array entries for various types of images (SPL, U-Boot, ATF, etc.).
    Each template handles the specific configuration needs of different image types.

    Subclasses define their own KEY and IMAGE_NAME to identify the template type.
    """

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
        """Load a value from configuration or database.

        Attempts to retrieve a value from the provided configuration dictionary first.
        If not found or if config is None, falls back to retrieving from the database
        using a key formed by combining the template's KEY with the provided key_name.

        :param database: Database containing default values
        :param key_name: Name of the key to retrieve
        :param config: Optional configuration dictionary to check first
        :param default: Default value to return if not found in config or database
        :return: Retrieved value or the default value
        """
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
        """Load an integer value from configuration or database.

        Uses _load_value to retrieve the raw value and converts it to an integer.

        :param database: Database containing default values
        :param key_name: Name of the key to retrieve
        :param config: Optional configuration dictionary to check first
        :param default: Default value to return if not found
        :return: Retrieved value as an integer
        """
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
        """Load a boolean value from configuration or database.

        Uses _load_value to retrieve the raw value and converts it to a boolean.

        :param database: Database containing default values
        :param key_name: Name of the key to retrieve
        :param config: Optional configuration dictionary to check first
        :param default: Default value to return if not found
        :return: Retrieved value as a boolean
        """
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
        """Load a string value from configuration or database.

        Uses _load_value to retrieve the raw value and ensures it's a string.

        :param database: Database containing default values
        :param key_name: Name of the key to retrieve
        :param config: Optional configuration dictionary to check first
        :param default: Default value to return if not found
        :return: Retrieved value as a string
        :raises AssertionError: If the retrieved value is not a string
        """
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
        """Load a value that can be either string or integer.

        Uses _load_value to retrieve the raw value and ensures it's either a string or integer.

        :param database: Database containing default values
        :param key_name: Name of the key to retrieve
        :param config: Optional configuration dictionary to check first
        :param default: Default value to return if not found
        :return: Retrieved value as either a string or integer
        :raises AssertionError: If the retrieved value is neither a string nor an integer
        """
        ret = cls._load_value(database=database, key_name=key_name, config=config, default=default)
        assert isinstance(ret, (str, int))
        return ret

    @classmethod
    def _create_image_array_entry(
        cls,
        iae_cls: IAE_TYPE,
        binary: bytes,
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> Union[ImageArrayEntry, ImageArrayEntryV2]:
        """Create an image array entry from binary data and configuration.

        Builds an ImageArrayEntry (or V2) instance using values from the configuration
        and database, combined with the provided binary image data.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param binary: Binary image data
        :param chip_config: AHAB chip container configuration
        :param config: Configuration dictionary with override values
        :return: Fully initialized image array entry
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
    def get_default_setting_description(cls, family: FamilyRevision) -> str:
        """Generate a human-readable description of default settings for this template.

        Retrieves default values from the database for the specified family and
        formats them into a text description. This is useful for documentation
        and user guidance about what settings are applied by default.

        :param family: Chip family revision to get settings for
        :return: Formatted string containing default settings description
        """

        def get_image_types() -> Type[SpsdkSoftEnum]:
            """Determine the appropriate image type enumeration for the core ID.

            Looks up the image type group based on the core ID in the database
            mapping, then retrieves the corresponding enumeration.

            :return: Appropriate image type enumeration class
            """
            image_type_group = "application"
            db_image_types_mapping = database.get_dict(DatabaseManager.AHAB, "image_types_mapping")
            db_image_types = load_images_types(database)
            for k, v in db_image_types_mapping.items():
                if core_id.tag in v:
                    image_type_group = k
            return db_image_types[image_type_group]

        # Load default settings from database
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

        # Format description, including only non-default values
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
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create an image array entry using this template.

        This is the base implementation that loads binary data from the
        specified file path (using the template's KEY) and creates a
        single image array entry with appropriate configuration.

        Subclasses may override this method to provide specialized behavior
        for different image types.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary with settings
        :return: List containing a single image array entry
        """
        return [
            cls._create_image_array_entry(
                iae_cls,
                binary=load_binary(config.get_input_file_name(cls.KEY)),
                chip_config=chip_config,
                config=config,
            )
        ]

    @classmethod
    def create_image_array_entries(
        cls,
        iae_cls: IAE_TYPE,
        chip_config: AhabChipContainerConfig,
        config: list[Config],
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create multiple image array entries from a list of configurations.

        This method processes a list of configuration dictionaries and creates
        image array entries for each one. It handles both direct image_path
        entries and template-based entries (identified by template KEY).

        For each configuration item, it either:
        1. Loads directly using load_from_config if "image_path" is specified
        2. Finds a matching template class and uses create_image_array_entry

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: List of configuration dictionaries
        :return: List of image array entries created from all configurations
        """
        config_loaders = ImageArrayEntryTemplates.__subclasses__()
        image_array: list = []

        for image in config:
            hit = False
            # Direct image_path entry
            if "image_path" in image:
                image_array.append(iae_cls.load_from_config(chip_config, image))
                continue

            # Template-based entry
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
    """Template for NXP images requiring double authentication (by NXP and OEM).

    This template handles special processing for NXP firmware images that
    need to be authenticated both by NXP and the OEM. It extracts ELE firmware
    and optionally V2X firmware from a combined NXP container.
    """

    IMAGE_NAME: str = "Double Authentication for NXP images"
    KEY: str = "double_authentication"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create image array entries for double-authenticated NXP firmware.

        This specialized implementation:
        1. Loads a combined NXP firmware image
        2. Extracts the ELE firmware container
        3. Optionally extracts the V2X firmware container if present
        4. Creates image array entries for each extracted container

        This enables OEMs to sign NXP-provided firmware components with
        their own keys while preserving the original NXP signatures.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary
        :return: List of image array entries for extracted firmware components
        :raises SPSDKError: If the NXP container is invalid or version mismatch
        """
        ret = []
        # Load the NXP firmware image
        logger.info("Adding Double Authentication NXP firmware image")
        nxp_image = load_binary(config.get_input_file_name(cls.KEY))

        # Process ELE firmware container
        header = HeaderContainerData.parse(nxp_image)
        if header.tag != AHABTags.CONTAINER_HEADER.tag:
            raise SPSDKError("Invalid NXP Container")
        if header.version == 0 and iae_cls != ImageArrayEntry:
            raise SPSDKError("Invalid NXP container version")

        # Extract ELE firmware
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

        # Process V2X firmware container if present
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
    """Template for U-Boot SPL combined with DDR tuning images.

    This template handles the creation of a special boot image that combines
    the U-Boot SPL (Secondary Program Loader) with DDR (DRAM) tuning parameters
    required for initializing memory on the target device.
    """

    IMAGE_NAME: str = "U-Boot SPL with DDR tunning images"
    KEY: str = "spl_ddr"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create image array entry for SPL with DDR tuning parameters.

        This specialized implementation:
        1. Loads four LPDDR tuning binary files (imem_1d, dmem_1d, imem_2d, dmem_2d)
        2. Aligns each binary according to device requirements
        3. Combines them with the SPL binary
        4. Checks if the resulting image fits in the device OCRAM

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary with file paths
        :return: List containing a single image array entry for the combined SPL+DDR image
        :raises SPSDKError: If required files can't be loaded
        """
        family = chip_config.base.family
        # get DB for family
        database = get_db(family)
        ddr_binary = b""

        # load lpddr binary files
        logger.info("Adding DDR memory areas into SPL image")
        lpddr_imem_1d = load_binary(config.get_input_file_name("lpddr_imem_1d"))
        lpddr_dmem_1d = load_binary(config.get_input_file_name("lpddr_dmem_1d"))
        lpddr_imem_2d = load_binary(config.get_input_file_name("lpddr_imem_2d"))
        lpddr_dmem_2d = load_binary(config.get_input_file_name("lpddr_dmem_2d"))

        ddr_binaries = [lpddr_imem_1d, lpddr_dmem_1d, lpddr_imem_2d, lpddr_dmem_2d]
        alignments = database.get_list(DatabaseManager.AHAB, "ddr_alignments")

        # align the binaries according to device requirements
        for idx, alignment in enumerate(alignments):
            if alignment:
                ddr_binaries[idx] = align_block(ddr_binaries[idx], alignment)

        # merge the ddr binaries
        ddr_binary = b"".join(ddr_binaries)

        # load and align the main SPL binary
        ddr_fw = load_binary(config.get_input_file_name("spl_ddr"))
        ddr_fw_alignment = database.get_value(DatabaseManager.AHAB, "ddr_fw_alignment")

        # merge to final binary
        binary_image = align_block(ddr_fw, ddr_fw_alignment) + ddr_binary

        # Check if binary fits into device OCRAM (non-secure)
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
    """Template for μPower firmware.

    The μPower (micropower) subsystem is a low-power microcontroller used for
    system power management on certain NXP SoCs. This template handles the
    inclusion of μPower firmware in AHAB containers.
    """

    IMAGE_NAME: str = "uPower"
    KEY: str = "upower"


class IaeSPL(ImageArrayEntryTemplates):
    """Template for standalone U-Boot SPL.

    This template handles the inclusion of the U-Boot Secondary Program Loader
    without additional DDR initialization data (unlike IaeSPLDDR). This is used
    when DDR parameters are either not needed or provided through other means.
    """

    IMAGE_NAME: str = "U-Boot SPL"
    KEY: str = "spl"


class IaeOEIDDR(ImageArrayEntryTemplates):
    """Template for OEI DDR initialization firmware.

    OEI (On-chip External Interface) DDR handles memory initialization
    at an early boot stage. This template processes the OEI firmware
    and associated DDR parameters, with optional support for QuickBoot.
    """

    IMAGE_NAME: str = "OEI DDR"
    KEY: str = "oei_ddr"
    QB_DATA_SIZE = 64 * 1024

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create image array entries for OEI DDR initialization.

        This specialized implementation:
        1. Loads LPDDR IMEM and DMEM binary files
        2. Optionally loads QuickBoot versions if specified
        3. Creates firmware headers with size information
        4. Combines all components into a single binary
        5. Adds a separate QuickBoot data entry if needed

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary with file paths
        :return: List of image array entries (main OEI DDR and optional QB data)
        :raises SPSDKError: If required files can't be loaded
        """

        def create_fw_header(imem: bytes, dmem: bytes) -> bytes:
            """Create firmware header with size information.

            :param imem: IMEM binary data
            :param dmem: DMEM binary data
            :return: 8-byte header containing IMEM and DMEM sizes
            """
            return len(imem).to_bytes(4, "little") + len(dmem).to_bytes(4, "little")

        # load lpddr binary files
        lpddr_imem = load_binary(config.get_input_file_name("lpddr_imem"))
        lpddr_dmem = load_binary(config.get_input_file_name("lpddr_dmem"))

        # Check for QuickBoot configuration
        quick_boot = config.get("lpddr_imem_qb") and config.get("lpddr_dmem_qb")
        if quick_boot:
            lpddr_imem_qb = load_binary(config.get_input_file_name("lpddr_imem_qb"))
            lpddr_dmem_qb = load_binary(config.get_input_file_name("lpddr_dmem_qb"))

        # Prepare the main binary with headers and DDR configuration
        binary_image = align_block(load_binary(config.get_input_file_name("oei_ddr")), 4)
        # add ddr fw header and data
        binary_image += create_fw_header(lpddr_imem, lpddr_dmem)
        binary_image += lpddr_imem
        binary_image += lpddr_dmem

        # Add QuickBoot data if configured
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

        # Add separate QuickBoot data entry if needed
        if quick_boot:
            db = get_db(chip_config.base.family)
            qb_data_binary = None
            qb_data_mandatory = db.get_bool(
                DatabaseManager.AHAB, f"{cls.KEY}_qb_data_mandatory", False
            )
            qb_data_dummy = db.get_bool(DatabaseManager.AHAB, f"{cls.KEY}_qb_data_dummy", False)
            qb_data = config.get("qb_data")

            # Handle mandatory QB data (use blank if not provided)
            if qb_data_mandatory and qb_data is None:
                logger.debug(
                    "Quick boot data are mandatory, but not provided, using 64k blank data"
                )
                # In case QB data are not provided add 64k blank data
                qb_data_binary = bytes(cls.QB_DATA_SIZE)
            elif qb_data_dummy and qb_data is None:
                qb_data_binary = bytes()

            elif qb_data:
                qb_data_binary = load_binary(qb_data, config.search_paths)

            # Create separate QB data entry
            if qb_data_binary is not None:
                meta_data = iae_cls.create_meta()
                image_type = chip_config.base.image_types["application"].from_attr("oei_ddr").tag

                flags = iae_cls.create_flags(
                    image_type=image_type, core_id=0, hash_type=AHABSignHashAlgorithmV1.SHA384
                )
                gap_after_image = 0
                if qb_data_dummy:
                    gap_after_image = 0x10000

                qb_iae = iae_cls(
                    chip_config=chip_config,
                    image=qb_data_binary,
                    image_offset=0,
                    load_address=0,
                    entry_point=0,
                    flags=flags,
                    image_meta_data=meta_data,
                    image_name=cls.IMAGE_NAME,
                    gap_after_image=gap_after_image,
                    image_size_alignment=64 * 1024,
                )
                qb_iae.image_size = 0
                ret.append(qb_iae)

        return ret


class IaeOEITCM(ImageArrayEntryTemplates):
    """Template for OEI TCM firmware.

    OEI (On-chip External Interface) TCM handles the Tightly Coupled Memory
    configuration at boot time. This template handles the inclusion of
    OEI TCM firmware in AHAB containers.
    """

    IMAGE_NAME: str = "OEI TCM"
    KEY: str = "oei_tcm"


class IaeSystemManager(ImageArrayEntryTemplates):
    """Template for System Manager firmware.

    The System Manager is a firmware component responsible for managing
    system-level operations on certain NXP SoCs. This template handles
    the inclusion of System Manager firmware in AHAB containers.
    """

    IMAGE_NAME: str = "System manager"
    KEY: str = "system_manager"


class IaeCortexM33_2App(ImageArrayEntryTemplates):
    """Template for Cortex-M33 core 2 application.

    This template handles applications designed to run on the second Cortex-M33
    core when the SoC has multiple M33 cores. It configures the appropriate
    load address, core ID, and other parameters specific to this core.
    """

    IMAGE_NAME: str = "Additional Cortex M33 application running on core 2"
    KEY: str = "cortex_m33_2_app"


class IaeCortexM7App(ImageArrayEntryTemplates):
    """Template for Cortex-M7 application.

    This template handles applications designed to run on the Cortex-M7 core.
    It configures the appropriate load address, core ID, and other parameters
    specific to this core.
    """

    IMAGE_NAME: str = "Additional Cortex M7 application"
    KEY: str = "cortex_m7_app"


class IaeCortexM7_2App(ImageArrayEntryTemplates):
    """Template for Cortex-M7 core 2 application.

    This template handles applications designed to run on the second Cortex-M7
    core when the SoC has multiple M7 cores. It configures the appropriate
    load address, core ID, and other parameters specific to this core.
    """

    IMAGE_NAME: str = "Additional Cortex M7 application running on core 2"
    KEY: str = "cortex_m7_2_app"


class IaeATF(ImageArrayEntryTemplates):
    """Template for ARM Trusted Firmware.

    ARM Trusted Firmware (ATF) provides a reference implementation of secure
    software for ARMv8-A processors. This template handles the inclusion
    of ATF in AHAB containers for secure boot on NXP platforms.
    """

    IMAGE_NAME: str = "ATF - ARM Trusted Firmware"
    KEY: str = "atf"


class IaeKernel(ImageArrayEntryTemplates):
    """Template for Linux Kernel Image.

    This template handles the inclusion of Linux kernel executable images
    (typically Image.bin) in AHAB containers. The kernel image is loaded
    and executed as part of the boot sequence after earlier boot stages
    like U-Boot have completed system initialization.
    """

    IMAGE_NAME: str = "Linux Kernel Image"
    KEY: str = "kernel"

    @classmethod
    def create_image_array_entry(
        cls, iae_cls: IAE_TYPE, chip_config: AhabChipContainerConfig, config: Config
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create image array entries for Linux Kernel Image.

        This specialized implementation:
        1. Checks if the chip revision requires kernel splitting
        2. If splitting is not required, delegates to parent implementation
        3. If splitting is required, loads the kernel binary and splits it into chunks
        4. Creates multiple image array entries with sequential load addresses
        5. Each chunk is configured with appropriate load and entry point addresses

        Kernel splitting is necessary on certain chip revisions due to memory
        layout constraints or boot ROM limitations that prevent loading large
        contiguous kernel images.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary with file paths
        :return: List of image array entries (single entry if no splitting, multiple if split)
        :raises SPSDKError: If required files can't be loaded
        """
        revision = chip_config.base.family.get_real_revision()
        db = get_db(chip_config.base.family)
        revisions_to_split = db.get_list(
            DatabaseManager.AHAB, f"{cls.KEY}_revisions_to_split", default=[]
        )

        if revision not in revisions_to_split:
            return super().create_image_array_entry(iae_cls, chip_config, config)

        chunk_size = db.get_int(DatabaseManager.AHAB, f"{cls.KEY}_chunk_size")
        load_address = db.get_int(DatabaseManager.AHAB, f"{cls.KEY}_load_address")
        logger.debug(f"Kernel needs to be split into chunks of {chunk_size} bytes")
        binary_image = load_binary(config.get_input_file_name(cls.KEY))

        entries = []
        for binary in split_data(binary_image, chunk_size):
            iae = cls._create_image_array_entry(
                iae_cls=iae_cls,
                binary=binary,
                chip_config=chip_config,
                config=config,
            )
            iae.load_address = load_address
            iae.entry_point = load_address
            load_address += chunk_size
            entries.append(iae)
        return entries


class IaeDTB(ImageArrayEntryTemplates):
    """Template for Device Tree Blob.

    This template handles the inclusion of Device Tree Blob (DTB) files
    in AHAB containers. The DTB contains hardware description information
    that the Linux kernel uses to understand the hardware configuration
    of the target device.
    """

    IMAGE_NAME: str = "Device Tree Blob"
    KEY: str = "dtb"


class IaeUBoot(ImageArrayEntryTemplates):
    """Template for U-Boot firmware.

    U-Boot is a widely used bootloader for embedded systems. This template
    handles the inclusion of the main U-Boot firmware (not SPL) in AHAB
    containers, with the addition of an SPSDK signature.
    """

    IMAGE_NAME: str = "U-Boot Firmware"
    KEY: str = "uboot"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create image array entry for U-Boot firmware.

        This specialized implementation:
        1. Loads the U-Boot binary
        2. Appends an SPSDK signature and padding to the binary
        3. Creates an image array entry with the modified binary

        The SPSDK signature is added for identification purposes and
        includes the SPSDK version used to create the image.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary with file paths
        :return: List containing a single image array entry for U-Boot
        :raises SPSDKError: If required files can't be loaded
        """
        binary_image = load_binary(config.get_input_file_name(cls.KEY))
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
    """Template for U-Boot TEE (Trusted Execution Environment).

    The TEE provides a secure environment for executing sensitive code,
    isolated from the normal operating system. This template handles
    the inclusion of TEE firmware in AHAB containers.

    TEE firmware typically works alongside the main U-Boot firmware to
    provide secure services and protect sensitive operations.
    """

    IMAGE_NAME: str = "U-Boot TEE - Trusted Execution Environment"
    KEY: str = "tee"


class IaeV2XDummy(ImageArrayEntryTemplates):
    """Template for V2X core Dummy record.

    V2X (Vehicle-to-Everything) is a communication technology for vehicles.
    This template creates a dummy record for V2X core which is required in
    certain boot configurations even when no actual V2X firmware is needed.
    """

    IMAGE_NAME: str = "V2X core Dummy record"
    KEY: str = "v2x_dummy"

    @classmethod
    def create_image_array_entry(
        cls,
        iae_cls: Type[ImageArrayEntry],
        chip_config: AhabChipContainerConfig,
        config: Config,
    ) -> list[Union[ImageArrayEntry, ImageArrayEntryV2]]:
        """Create a dummy image array entry for V2X core.

        This specialized implementation:
        1. Checks the configuration setting
        2. Issues a warning that the setting doesn't affect presence in IAE table
        3. Creates an empty (zero-length) image array entry

        The V2X dummy entry is included in the image array table regardless
        of the configuration setting - the presence in configuration merely
        enables it, it doesn't control whether it appears in the table.

        :param iae_cls: ImageArrayEntry class type to instantiate
        :param chip_config: AHAB container chip configuration
        :param config: Configuration dictionary
        :return: List containing a single empty image array entry
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


class IaeMCU(ImageArrayEntryTemplates):
    """Template for MCU Image."""

    IMAGE_NAME: str = "MCU Firmware"
    KEY: str = "mcu"

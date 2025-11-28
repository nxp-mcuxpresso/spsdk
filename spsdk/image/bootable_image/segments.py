#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK bootable image segments management.

This module provides classes and utilities for handling various segments
that compose bootable images across NXP MCU portfolio. It includes segment
types for key blobs, FCB, image versions, key stores, BEE headers, XMCD,
MBI, HAB, AHAB, and Secure Binary containers.
"""


import logging
import os
from inspect import isclass
from struct import unpack
from typing import Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.fcb.fcb import FCB
from spsdk.image.hab.hab_image import HabImage
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mem_type import MemoryType
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.abstract import BaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import BinaryPattern, Endianness, align, load_binary, value_to_int, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class BootableImageSegment(SpsdkEnum):
    """Bootable image segment type enumeration.

    This enumeration defines the different types of segments that can be found
    in bootable images across NXP MCU portfolio, including security headers,
    containers, and image data segments.
    """

    UNKNOWN = (0, "unknown", "Unknown segment")
    KEYBLOB = (1, "keyblob", "Keyblob segment")
    FCB = (2, "fcb", "Fcb segment")
    IMAGE_VERSION = (3, "image_version", "Image version segment")
    IMAGE_VERSION_AP = (4, "image_version_ap", "Image version antipole segment")
    KEYSTORE = (5, "keystore", "Keystore segment")
    BEE_HEADER_0 = (6, "bee_header_0", "BEE header 0 segment")
    BEE_HEADER_1 = (7, "bee_header_1", "BEE header 1 segment")
    XMCD = (8, "xmcd", "XMCD segment")
    MBI = (9, "mbi", "Masterboot image segment")
    HAB_CONTAINER = (10, "hab_container", "HAB container segment")
    AHAB_CONTAINER = (11, "ahab_container", "AHAB container segment")
    PRIMARY_IMAGE_CONTAINER_SET = (
        12,
        "primary_image_container_set",
        "Primary Image Container Set segment",
    )
    SECONDARY_IMAGE_CONTAINER_SET = (
        13,
        "secondary_image_container_set",
        "Secondary Image Container Set segment",
    )
    SB21 = (14, "sb21", "Secure binary 2.1 segment")
    SB31 = (15, "sb31", "Secure binary 3.1 segment")


class Segment(BaseClass):
    """Base class for bootable image segments.

    This class provides the foundation for all bootable image segments, managing
    segment data, positioning, and export functionality. Each segment represents
    a specific part of a bootable image with defined offset and memory type.

    :cvar NAME: Segment type identifier from BootableImageSegment enumeration.
    :cvar BOOT_HEADER: Flag indicating if segment requires boot header.
    :cvar INIT_SEGMENT: Flag indicating if this is an initialization segment.
    :cvar CFG_NAME: Configuration name for the segment type.
    :cvar IMAGE_PATTERNS: Supported image patterns for segment generation.
    :cvar OFFSET_ALIGNMENT: Required alignment for segment offset positioning.
    """

    NAME = BootableImageSegment.UNKNOWN
    BOOT_HEADER = True
    INIT_SEGMENT = False
    CFG_NAME: Optional[str] = None
    IMAGE_PATTERNS = ["zeros", "ones"]
    OFFSET_ALIGNMENT = 1

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
    ) -> None:
        """Initialize a bootable image segment with basic properties.

        Stores the segment's position, target hardware configuration, and optional raw data
        for further processing in the bootable image creation workflow.

        :param offset: Offset of segment in the full bootable image.
        :param family: Target chip family and revision information.
        :param mem_type: Memory type where the segment will be stored.
        :param raw_block: Raw binary data of the segment, defaults to None.
        """
        self._offset = offset
        self.family = family
        self.mem_type = mem_type
        self.raw_block = raw_block
        self.excluded = False
        self.not_parsed = True

    @property
    def size(self) -> int:
        """Get the size of the segment.

        :return: Size of the segment in bytes, returns -1 if size cannot be determined.
        """
        return -1

    @property
    def is_present(self) -> bool:
        """Check if the segment is present in the bootable image.

        The segment is considered present when it's not excluded and has exportable content.

        :return: True if segment is present and has content, False otherwise.
        """
        return not (self.excluded) and bool(self.export())

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment by setting the raw_block attribute to None,
        effectively returning the segment to its initial uninitialized state.
        """
        self.raw_block = None

    def __repr__(self) -> str:
        """Get string representation of the bootable image segment.

        :return: String describing the segment with its name and description.
        """
        return f"Bootable image segment: {self.NAME.description}"

    def __str__(self) -> str:
        """Get string representation of the object.

        :return: String representation of the object.
        """
        return self.__repr__()

    def __len__(self) -> int:
        """Get the length of the segment.

        Returns the number of bytes in the exported segment data.

        :return: Length of the segment in bytes.
        """
        return len(self.export())

    @property
    def full_image_offset(self) -> int:
        """Get the offset of the segment within the full bootable image.

        The method returns the aligned offset for positive values or the raw offset for negative
        values. The offset must be defined before calling this method.

        :raises SPSDKValueError: When segment offset is not defined.
        :return: Aligned offset for positive values, raw offset for negative values.
        """
        if self._offset is None:
            raise SPSDKValueError("Segment offset is not defined.")
        if self._offset < 0:
            return self._offset
        return align(self._offset, self.OFFSET_ALIGNMENT)

    @full_image_offset.setter
    def full_image_offset(self, offset: int) -> None:
        """Set the full image offset for this segment.

        This method updates the internal offset value that represents the position
        of this segment within the complete bootable image.

        :param offset: The byte offset position within the full image.
        """
        self._offset = offset

    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Raw binary block of segment if available, empty bytes otherwise.
        """
        if self.raw_block:
            return self.raw_block
        return b""

    def post_export(self, output_path: str) -> list[str]:
        """Post export artifacts like fuse scripts.

        This method handles the generation and export of additional artifacts that are created
        after the main export process, typically including fuse scripts or other configuration files.

        :param output_path: Path to export artifacts.
        :return: List of post export artifacts (usually fuse scripts).
        """
        return []

    def image_info(self) -> BinaryImage:
        """Get image information in binary format.

        Exports the segment content and wraps it in a BinaryImage object containing
        metadata such as name, size, and offset information.

        :return: The segment content wrapped in Binary Image format with metadata.
        """
        export_binary = self.export()
        return BinaryImage(
            name=self.NAME.label,
            size=len(export_binary),
            offset=self.full_image_offset,
            binary=export_binary,
        )

    @staticmethod
    def find_segment_offset(binary: bytes) -> int:
        """Find the start offset of a Segment in binary data.

        This method searches through the provided binary data to locate where
        a Segment begins and returns the byte offset position.

        :param binary: Binary data to search for Segment start position.
        :return: Byte offset where the Segment begins in the data.
        """
        return 0

    @classmethod
    def cfg_key(cls) -> str:
        """Get configuration key name for the segment.

        Returns the configuration key name used in configuration files. Falls back to
        the segment's label name if no specific configuration name is defined.

        :return: Configuration key name as string.
        """
        return cls.CFG_NAME or cls.NAME.label

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Input data to parse.
        :raises NotImplementedError: Method must be implemented by subclass.
        :return: Parsed object instance.
        """
        raise NotImplementedError

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        This method processes a binary block and populates the segment object with the parsed data.
        It validates the binary size against the expected segment size and checks for padding-only
        content.

        :param binary: Binary image data to be parsed into the segment.
        :raises SPSDKParsingError: If given binary block size is smaller than expected segment size.
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes.
        """
        self.not_parsed = True
        if self.size > 0 and len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than parsed segment.")
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent(f"The segment {self.NAME.label} is not present")
        self.not_parsed = False
        self.raw_block = binary[: self.size] if self.size > 0 else binary

    def _is_padding(self, binary: bytes) -> bool:
        """Check if given binary data contains only padding patterns.

        This method verifies whether the provided binary data consists entirely of
        recognized padding patterns used in bootable images.

        :param binary: Binary data to check for padding patterns.
        :return: True if the binary contains only padding patterns, False otherwise.
        """
        if self.size > 0 and binary[: self.size] in [
            BinaryPattern(pattern).get_block(self.size) for pattern in self.IMAGE_PATTERNS
        ]:
            return True
        return False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store segment data to specified directory.

        Exports the segment data to a binary file in the output directory if the segment
        is present, otherwise returns an empty string.

        :param output_dir: Directory path where the segment data file should be stored.
        :return: Filename of the created binary file or empty string if segment not present.
        """
        if not self.is_present:
            return ""
        ret = f"segment_{self.NAME.label}.bin"
        write_file(self.export(), os.path.join(output_dir, ret), mode="wb")
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        The method loads a binary file specified in the configuration and assigns it to the
        raw_block attribute of the segment.

        :param config: Configuration object containing segment settings and file paths.
        :raises SPSDKSegmentNotPresent: When the segment is not present in config file.
        :raises SPSDKValueError: When the binary file path is invalid or cannot be loaded.
        """
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent(
                f"The segment '{self.NAME.label}' is not present in the config file"
            )

        try:
            self.raw_block = load_binary(path=config.get_input_file_name(self.cfg_key()))
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"The binary file path to load {self.NAME.label} segment expected."
            ) from exc

    def pre_parse_verify(self, data: bytes) -> Verifier:
        """Pre-parse binary to validate data before full parsing.

        The method performs initial validation of the bootable image binary data
        to identify potential issues before attempting full parsing operations.

        :param data: Bootable image binary data to be validated.
        :return: Verifier object containing pre-parse validation results.
        """
        ret = Verifier(f"Segment({self.NAME}) pre-parse")
        if self.size > 0 and len(data) < self.size:
            ret.add_record(
                "Data",
                VerifierResult.ERROR,
                f"Invalid length: Current-{len(data)} < Expected-{self.size}.",
            )
        else:
            ret.add_record("Data", VerifierResult.SUCCEEDED, "Fits")

        return ret

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        Creates and returns a Verifier instance that validates the segment's properties including
        offset, size, and raw data integrity. The verifier checks for proper offset values,
        validates data size constraints, and ensures raw block data consistency.

        :return: Verifier object containing validation results for the current segment.
        """
        ret = Verifier(f"Segment({self.NAME}) details")
        if self._offset < 0:
            ret.add_record("Offset", VerifierResult.SUCCEEDED, "Automatic")
        else:
            ret.add_record_range("Offset", hex(self._offset), min_val=0)
        bin_size = len(self.raw_block) if (self.raw_block is not None) else 0
        ret.add_record_range("Size", bin_size)
        if self.not_parsed:
            ret.add_record("Raw data", VerifierResult.WARNING, "Not used")
        elif self.raw_block is None:
            ret.add_record("Raw data", VerifierResult.ERROR, "Is missing")
        elif self.size > 0 and bin_size > self.size:
            ret.add_record(
                "Raw data",
                VerifierResult.ERROR,
                f"Invalid length: Current-{len(self.raw_block)} != Expected-{self.size}.",
            )
        else:
            ret.add_record_bytes("Raw data", self.raw_block)

        return ret


class SegmentKeyBlob(Segment):
    """Bootable Image KeyBlob Segment.

    This segment represents a key blob section in bootable images, containing
    cryptographic keys and security data with a fixed size of 256 bytes.

    :cvar NAME: Segment type identifier for keyblob segments.
    """

    NAME = BootableImageSegment.KEYBLOB

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes (always 256).
        """
        return 256


class SegmentFcb(Segment):
    """Bootable Image FCB Segment.

    This class represents a Flash Configuration Block (FCB) segment within a bootable image.
    It manages FCB data including validation, parsing, and configuration for NXP MCU families
    that support FCB functionality.

    :cvar NAME: Segment type identifier for FCB segments.
    :cvar INIT_SEGMENT: Flag indicating this is an initialization segment.
    """

    NAME = BootableImageSegment.FCB
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        fcb: Optional[FCB] = None,
    ) -> None:
        """Initialize FCB segment with offset and memory configuration.

        The segment stores raw data and validates FCB block consistency if both
        raw data and FCB object are provided.

        :param offset: Offset of segment in whole bootable image.
        :param family: Chip family revision identifier.
        :param mem_type: Target memory type for the segment.
        :param raw_block: Raw binary data of the segment, defaults to None.
        :param fcb: Flash Configuration Block object, defaults to None.
        :raises SPSDKParsingError: When FCB block doesn't match the raw data.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.fcb = fcb
        if fcb and raw_block and raw_block != fcb.export():
            raise SPSDKParsingError("The FCB block doesn't match the raw data.")
        self._size: Optional[int] = None

    @property
    def is_fcb_supported(self) -> bool:
        """Check if FCB is supported for the current family.

        This property determines whether Flash Configuration Block (FCB) functionality
        is available for the chip family assigned to this segment.

        :return: True if FCB is supported for the current family, False otherwise.
        """
        return self.family in FCB.get_supported_families(True)

    def clear(self) -> None:
        """Clear the segment to initial state.

        This method resets the segment by calling the parent class clear method
        and setting the FCB (Flash Configuration Block) to None.
        """
        super().clear()
        self.fcb = None

    @property
    def size(self) -> int:
        """Size of the segment in bytes.

        Calculates the segment size based on FCB (Flash Configuration Block) support.
        If FCB is supported, returns the size of existing FCB or creates a new FCB
        to determine the size. Returns -1 for unsupported segments.

        :return: The segment size in bytes, or -1 if FCB is not supported.
        """
        if self._size is None:
            if self.is_fcb_supported:
                # Use existing FCB if available, otherwise create a new one to get size
                self._size = (
                    self.fcb.size
                    if self.fcb
                    else FCB(family=self.family, mem_type=self.mem_type).size
                )
            else:
                self._size = -1
        return self._size

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into FCB Segment object.

        The method attempts to parse the binary data as an FCB (Flash Configuration Block).
        It first checks if the binary contains valid FCB tags and if FCB is supported for
        the current family. If FCB is not present or parsing fails, appropriate exceptions
        are raised.

        :param binary: Binary image data to parse into FCB segment.
        :raises SPSDKParsingError: If binary block is smaller than FCB size or parsing fails.
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes.
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than FCB.")
        if binary[:4] in [FCB.TAG, FCB.TAG_SWAPPED]:
            if self.is_fcb_supported:
                self.raw_block = binary[: self.size]
                self.fcb = FCB.parse(
                    binary[: self.size], family=self.family, mem_type=self.mem_type
                )
                self.not_parsed = False
                return

            logger.warning("Get the FCB binary from device where FCB is not yet supported.")
            super().parse_binary(binary=binary)
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent("The FCB segment is not present.")
        raise SPSDKParsingError("Parsing of FCB segment failed.")

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store data to specified path.

        The method generates configuration data for the segment and optionally writes
        FCB configuration to a YAML file in the output directory.

        :param output_dir: Path where the configuration information should be stored
        :return: Value of segment for configuration file
        """
        ret = super().create_config(output_dir)
        if self.fcb:
            write_file(
                self.fcb.get_config_yaml(),
                os.path.join(output_dir, f"segment_{self.NAME.label}.yaml"),
            )
        return ret

    def load_config(self, config: Config) -> None:
        """Load FCB segment from configuration.

        Attempts to load FCB (Flash Configuration Block) segment from configuration,
        first trying to load from config structure, then falling back to binary file.
        Validates the FCB data and logs warnings for corrupted blocks.

        :param config: Configuration object containing FCB segment settings.
        :raises SPSDKSegmentNotPresent: When FCB segment is not present in config file.
        """
        # Try to load FCB from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent("The FCB segment is not present in the config file")
        try:
            fcb = FCB.load_from_config(config.load_sub_config(self.cfg_key()))
            self.raw_block = fcb.export()
            self.fcb = fcb
            return
        except SPSDKError:
            pass

        try:
            FCB.parse(
                load_binary(config.get_input_file_name(self.cfg_key())),
                family=self.family,
                mem_type=self.mem_type,
            )
        except SPSDKError as exc:
            logger.warning(f"The given binary form of FCB block looks corrupted: {str(exc)}")
        super().load_config(config=config)


class SegmentImageVersion(Segment):
    """Bootable Image version segment.

    This class represents a segment that stores version information for bootable images.
    It handles parsing, configuration, and verification of 4-byte version data with
    little-endian byte ordering.

    :cvar NAME: Segment type identifier for image version segments.
    """

    NAME = BootableImageSegment.IMAGE_VERSION

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes.
        """
        return 4

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        The method extracts segment data from the provided binary based on the segment size
        and marks the segment as parsed.

        :param binary: Binary image data to parse.
        :raises SPSDKParsingError: If given binary block size is not equal to block size in header.
        """
        self.not_parsed = False
        self.raw_block = binary[: self.size] if self.size > 0 else binary

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and extract segment value.

        Extracts the first 4 bytes from the raw block data and converts them to an integer
        using little-endian byte order. Returns 0 if the segment is not present.

        :param output_dir: Path where the information should be stored.
        :return: Integer value extracted from segment data, or 0 if segment not present.
        """
        if not self.is_present:
            return 0
        assert isinstance(self.raw_block, bytes)
        return int.from_bytes(self.raw_block[:4], Endianness.LITTLE.value)

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        The method extracts configuration value using the segment's configuration key,
        validates it as an integer, and converts it to raw bytes in little-endian format.

        :param config: Configuration object containing segment settings.
        :raises SPSDKValueError: Invalid configuration value (not an integer).
        """
        cfg_value = config.get(self.cfg_key(), 0)
        if not isinstance(cfg_value, int):
            raise SPSDKValueError(
                f"Invalid value of image version. It should be integer, and is: {cfg_value}"
            )
        self.raw_block = cfg_value.to_bytes(length=self.size, byteorder=Endianness.LITTLE.value)

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        Creates and returns a verifier object for the current segment, including validation
        of the image version from the raw block data if available.

        :return: Verifier object containing validation records for the current segment.
        """
        ret = super().verify()
        if self.raw_block:
            ret.add_record_range(
                "Image Version", int.from_bytes(self.raw_block[:4], Endianness.LITTLE.value)
            )
        return ret


class SegmentImageVersionAntiPole(Segment):
    """Bootable Image segment for image version with antipole value.

    This segment manages image version data using an antipole encoding scheme where
    the version value and its bitwise complement are stored together for data
    integrity verification.

    :cvar NAME: Segment identifier for bootable image processing.
    :cvar CFG_NAME: Configuration key name for this segment type.
    :cvar UNPROGRAMMED_VALUE: Default value for unprogrammed flash memory.
    """

    NAME = BootableImageSegment.IMAGE_VERSION_AP
    CFG_NAME = "image_version"
    UNPROGRAMMED_VALUE = 0xFFFF

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes.
        """
        return 4

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and extract segment value.

        The method extracts a 2-byte value from the raw block data in little-endian format.
        Returns 0 if the segment is not present.

        :param output_dir: Path where the information should be stored.
        :return: Value of segment for configuration file (0 if not present, otherwise extracted value).
        """
        if not self.is_present:
            return 0
        assert isinstance(self.raw_block, bytes)
        return int.from_bytes(self.raw_block[:2], Endianness.LITTLE.value)

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        The method loads image version from configuration and processes it into raw block data.
        If no configuration value is provided, uses unprogrammed values. The image version
        is stored with its complement in the upper 16 bits.

        :param config: Configuration object containing segment settings.
        :raises SPSDKValueError: Invalid configuration value (not an integer).
        """
        cfg_value = config.get(self.cfg_key())
        if cfg_value is None:
            image_version = self.UNPROGRAMMED_VALUE << 16 | self.UNPROGRAMMED_VALUE
        else:
            if not isinstance(cfg_value, int):
                raise SPSDKValueError(
                    f"Invalid value for image version. It should be integer, and is: {cfg_value}"
                )
            image_version = cfg_value & 0xFFFF
            image_version |= (image_version ^ 0xFFFF) << 16
        self.raw_block = image_version.to_bytes(length=self.size, byteorder=Endianness.LITTLE.value)

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        The method validates the binary size against the segment requirements and stores
        the raw block data for further processing.

        :param binary: Binary image data to be parsed into segment.
        :raises SPSDKParsingError: If given binary block size is smaller than required segment size.
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than Image version needs.")
        self.not_parsed = False
        self.raw_block = binary[:4]

    def verify(self) -> Verifier:
        """Verify the segment and return verifier object with validation results.

        The method validates the image version by checking if the version and its antipole
        (bitwise inverse) match the expected pattern. It handles three cases: valid version
        pairs, unprogrammed default values, and mismatched version/antipole pairs.

        :return: Verifier object containing validation results for the segment.
        """
        ret = super().verify()
        if not ret.has_errors and self.raw_block:
            image_version, image_version_anti = unpack("<HH", self.raw_block)
            if image_version == (image_version_anti ^ 0xFFFF):
                ret.add_record(
                    "Image version",
                    VerifierResult.SUCCEEDED,
                    f"{str(image_version)}, 0x{hex(image_version)}",
                )
            # unprogrammed value 0xFFFFFFFF is also considered as a valid value.
            elif image_version == image_version_anti == self.UNPROGRAMMED_VALUE:
                ret.add_record("Image version", VerifierResult.WARNING, "Has default value: 0xffff")
            else:
                ret.add_record(
                    "Image version",
                    VerifierResult.ERROR,
                    f" Image version doesn't match antipole part"
                    f"{hex(image_version)} != ^{hex(image_version_anti)}",
                )
        return ret


class SegmentKeyStore(Segment):
    """Bootable Image KeyStore Segment.

    This class represents a keystore segment within a bootable image, managing
    cryptographic key storage with a fixed size allocation for security operations.

    :cvar NAME: Segment type identifier for keystore segments.
    """

    NAME = BootableImageSegment.KEYSTORE

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes (always 2048).
        """
        return 2048


class SegmentBeeHeader0(Segment):
    """Bootable Image BEE encryption header 0 segment.

    This segment represents the first BEE (Bus Encryption Engine) header used for
    encryption configuration in bootable images. It provides a fixed-size header
    structure for BEE encryption parameters.

    :cvar NAME: Segment identifier for BEE header 0.
    """

    NAME = BootableImageSegment.BEE_HEADER_0

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes (always 512).
        """
        return 512


class SegmentBeeHeader1(Segment):
    """Bootable Image BEE encryption header 1 segment.

    This segment represents the first header used in Bus Encryption Engine (BEE)
    encryption for bootable images, providing encryption metadata and configuration
    with a fixed size of 512 bytes.

    :cvar NAME: Segment type identifier for BEE header 1.
    """

    NAME = BootableImageSegment.BEE_HEADER_1

    @property
    def size(self) -> int:
        """Get the size of the keyblob segment.

        :return: Size of the keyblob segment in bytes (always 512).
        """
        return 512


class SegmentXmcd(Segment):
    """Bootable Image XMCD Segment class.

    This class represents an External Memory Configuration Data (XMCD) segment
    within a bootable image, providing functionality to parse, validate, and
    manage XMCD configuration data for external memory initialization.

    :cvar NAME: Segment type identifier for XMCD segments.
    """

    NAME = BootableImageSegment.XMCD

    @property
    def size(self) -> int:
        """Get keyblob segment size.

        :return: Size of the keyblob segment in bytes (always 512).
        """
        return 512

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        xmcd: Optional[XMCD] = None,
    ) -> None:
        """Initialize XMCD segment with configuration data.

        The segment stores XMCD (eXternal Memory Configuration Data) block that contains
        memory configuration parameters for external memory initialization.

        :param offset: Offset of segment in whole bootable image.
        :param family: Target chip family and revision information.
        :param mem_type: Type of memory where segment will be stored.
        :param raw_block: Raw binary data of the segment, optional.
        :param xmcd: XMCD configuration object, optional.
        :raises SPSDKParsingError: When XMCD block doesn't match provided raw data.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.xmcd = xmcd
        if xmcd and raw_block and raw_block != xmcd.export():
            raise SPSDKParsingError("The XMCD block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment to its initial state by calling the parent class
        clear method and setting the xmcd attribute to None.
        """
        super().clear()
        self.xmcd = None

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into XMCD Segment object.

        The method parses the input binary data to create an XMCD (External Memory Configuration Data)
        segment. It validates the binary size and checks for padding bytes to ensure valid XMCD data
        is present.

        :param binary: Binary image data to parse into XMCD segment.
        :raises SPSDKParsingError: If given binary block size is smaller than required XMCD size.
        :raises SPSDKSegmentNotPresent: If the input binary contains only padding bytes.
        """
        self.not_parsed = True
        if len(binary) < self.size:
            raise SPSDKParsingError("The input binary block is smaller than XMCD.")
        # Check if the header of XMCD exists
        if self._is_padding(binary):
            raise SPSDKSegmentNotPresent("The XMCD segment is not present.")

        xmcd = XMCD.parse(binary, family=self.family)
        self.raw_block = xmcd.export()
        self.xmcd = xmcd
        self.not_parsed = False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store data to specified path.

        The method creates configuration data by calling the parent class method and
        additionally writes XMCD configuration to a YAML file if XMCD data exists.

        :param output_dir: Directory path where the configuration files should be stored.
        :return: Configuration value for the segment.
        """
        ret = super().create_config(output_dir)
        if self.xmcd:
            write_file(self.xmcd.get_config_yaml(), os.path.join(output_dir, "segment_xmcd.yaml"))
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        The method attempts to load XMCD from configuration first. If XMCD loading fails,
        it falls back to the parent class loading method.

        :param config: Configuration object containing segment data.
        :raises SPSDKSegmentNotPresent: When XMCD segment is not present in config file.
        :raises SPSDKError: When configuration loading fails.
        """
        # Try to load XMCD from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent("The XMCD segment is not present in the config file")
        try:
            xmcd = XMCD.load_from_config(config.load_sub_config(self.cfg_key()))
            self.raw_block = xmcd.export()
            self.xmcd = xmcd
        except SPSDKError:
            super().load_config(config=config)

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        Performs verification of the segment and includes XMCD verification if present.

        :return: Verifier object containing validation results for current segment.
        """
        ret = super().verify()
        if not ret.has_errors and self.xmcd:
            ret.add_child(self.xmcd.verify())
        return ret


class SegmentMbi(Segment):
    """Bootable Image Master Boot Image (MBI) Segment.

    This class represents a segment containing Master Boot Image data within a bootable image.
    It manages MBI-specific operations including parsing, configuration, and export of MBI
    segments for NXP MCU bootable images.

    :cvar NAME: Segment type identifier for MBI segments.
    :cvar BOOT_HEADER: Indicates this segment is not a boot header.
    :cvar INIT_SEGMENT: Marks this as an initialization segment.
    """

    NAME = BootableImageSegment.MBI
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        mbi: Optional[MasterBootImage] = None,
    ) -> None:
        """Initialize MBI segment with offset and configuration data.

        The segment stores raw data and optionally validates it against the provided
        Master Boot Image instance. If both raw_block and mbi are provided, they are
        compared for consistency.

        :param offset: Offset of segment in whole bootable image.
        :param family: Chip family revision identifier.
        :param mem_type: Target memory type for the segment.
        :param raw_block: Raw binary data of the segment, defaults to None.
        :param mbi: Master Boot Image instance for validation, defaults to None.
        """
        super().__init__(offset, family, mem_type, raw_block)
        if mbi and raw_block and raw_block != mbi.export():
            logger.info("The MBI block doesn't match the raw data.")
        self.mbi = mbi

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment to its initial state by calling the parent class
        clear method and setting the MBI (Master Boot Image) attribute to None.
        """
        super().clear()
        self.mbi = None

    def image_info(self) -> BinaryImage:
        """Get image information in binary format.

        Retrieves the segment content as a BinaryImage object. If MBI (Master Boot Image)
        is available, exports the MBI image with proper offset and name. Otherwise,
        falls back to the parent class implementation.

        :return: The segment content in Binary Image format.
        """
        if not self.mbi:
            return super().image_info()

        image = self.mbi.export_image()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def __len__(self) -> int:
        """Get the length of the MBI segment.

        Returns the total length of the MBI (Master Boot Image) if available,
        otherwise falls back to the parent class length calculation.

        :return: Length of the MBI segment in bytes.
        """
        if self.mbi:
            return self.mbi.total_len
        return super().__len__()

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        The method parses a binary image into a Master Boot Image (MBI) object, validates it,
        and stores the parsed data in the segment. Sets the parsing state accordingly.

        :param binary: Binary image data to be parsed.
        :raises SPSDKParsingError: When the input binary block has zero length.
        :raises SPSDKError: When MBI parsing or validation fails.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")
        mbi = MasterBootImage.parse(data=binary, family=self.family)
        mbi.validate()
        self.raw_block = binary
        self.mbi = mbi
        self.not_parsed = False

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store data to specified path.

        The method generates configuration data for the segment and optionally creates
        an MBI configuration YAML file if an MBI object is present.

        :param output_dir: Directory path where configuration files should be stored.
        :return: Configuration value for the segment.
        """
        ret = super().create_config(output_dir)
        if self.mbi:
            write_file(
                self.mbi.get_config_yaml(output_dir), os.path.join(output_dir, "mbi_config.yaml")
            )
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        Attempts to load MBI (Master Boot Image) from configuration first, falling back
        to binary loading if configuration parsing fails.

        :param config: Configuration object containing segment data.
        :raises SPSDKValueError: When MBI container cannot be exported from configuration.
        """
        # Try to load MBI from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "application"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config=config)
            return
        try:
            mbi = MasterBootImage.load_from_config(config_data)
            self.raw_block = mbi.export()
            self.mbi = mbi
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export MBI container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentHab(Segment):
    """Bootable Image High Assurance Boot (HAB) Segment.

    This class represents a HAB segment within a bootable image, managing High Assurance Boot
    container data and providing functionality for HAB image processing, validation, and export
    operations.

    :cvar NAME: Segment type identifier for HAB container.
    :cvar BOOT_HEADER: Indicates this segment does not contain boot header.
    :cvar INIT_SEGMENT: Marks this as an initialization segment.
    """

    NAME = BootableImageSegment.HAB_CONTAINER
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        hab: Optional[HabImage] = None,
    ) -> None:
        """Initialize HAB segment with raw data and configuration.

        The segment stores raw data and optionally validates it against HAB image patterns
        to ensure data integrity and proper formatting.

        :param offset: Offset of segment in whole bootable image.
        :param family: Chip family revision information.
        :param mem_type: Memory type used for the segment.
        :param raw_block: Raw binary data of the segment, defaults to None.
        :param hab: High Assurance Boot image instance for validation, defaults to None.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.hab = hab
        if self.hab and raw_block:
            for pattern in self.IMAGE_PATTERNS:
                self.hab.image_pattern = pattern
                if raw_block == self.hab.export():
                    return
            logger.info("The HAB block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment to its initial state by calling the parent class
        clear method and setting the HAB (High Assurance Boot) attribute to None.
        """
        super().clear()
        self.hab = None

    def __len__(self) -> int:
        """Get the length of the HAB segment.

        Returns the length of the HAB data if present, otherwise falls back to the parent class
        implementation.

        :return: Length of the HAB segment in bytes.
        """
        if self.hab:
            return len(self.hab)
        return super().__len__()

    def image_info(self) -> BinaryImage:
        """Get image information in binary format.

        Retrieves the segment content as a BinaryImage object. If HAB (High Assurance Boot)
        is available, uses HAB's image info with updated offset and name. Otherwise, falls
        back to the parent class implementation.

        :return: The segment content in Binary Image format.
        """
        if not self.hab:
            return super().image_info()

        image = self.hab.image_info()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        The method parses the provided binary data into a HAB (High Assurance Boot) image format
        and updates the segment's internal state accordingly.

        :param binary: Binary image data to be parsed.
        :raises SPSDKParsingError: When the input binary block has zero length.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")
        hab = HabImage.parse(data=binary, family=self.family)
        self.raw_block = binary
        self.hab = hab
        self.not_parsed = False

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        Attempts to load HAB (High Assurance Boot) configuration first, then falls back to
        parent class configuration loading if HAB loading fails.

        :param config: Configuration object containing segment data.
        :raises SPSDKValueError: When HAB container cannot be exported from configuration.
        """
        # Try to load HAB from configuration as a first attempt
        try:
            parsed_conf = config.load_sub_config(self.cfg_key())
        except (SPSDKError, UnicodeDecodeError):
            super().load_config(config=config)
            return
        try:

            schemas = HabImage.get_validation_schemas(self.family)
            parsed_conf.check(schemas, check_unknown_props=True)
            hab = HabImage.load_from_config(parsed_conf)
            self.raw_block = hab.export()
            self.hab = hab
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export HAB container from the configuration:\n{str(exc)}"
            ) from exc


class SegmentAhab(Segment):
    """Bootable Image Advanced High Assurance Boot (AHAB) Segment.

    This class represents a segment containing AHAB container data within a bootable image.
    It manages AHAB-specific operations including parsing, validation, and export of AHAB
    containers used for secure boot processes in NXP MCUs.

    :cvar NAME: Segment type identifier for AHAB containers.
    :cvar BOOT_HEADER: Indicates this segment does not contain boot header.
    :cvar INIT_SEGMENT: Marks this as an initialization segment.
    """

    NAME = BootableImageSegment.AHAB_CONTAINER
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        ahab: Optional[AHABImage] = None,
    ) -> None:
        """Initialize AHAB segment with bootable image parameters.

        The segment stores raw data and optional AHAB image, validating consistency
        between raw block and AHAB export data if both are provided.

        :param offset: Offset of segment in whole bootable image.
        :param family: Chip family revision identifier.
        :param mem_type: Target memory type for the segment.
        :param raw_block: Raw binary data of the segment, defaults to None.
        :param ahab: Advanced High Assurance Boot image instance, defaults to None.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.ahab = ahab
        if ahab and raw_block and len(raw_block) != len(ahab.export()):
            logger.info("The AHAB block doesn't match the raw data.")

    def __len__(self) -> int:
        """Get the length of the AHAB segment.

        Returns the length of the AHAB segment if it exists, otherwise falls back to the parent
        class implementation.

        :return: Length of the AHAB segment or parent segment length.
        """
        if self.ahab:
            return len(self.ahab)
        return super().__len__()

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment to its initial state by calling the parent class
        clear method and setting the ahab attribute to None.
        """
        super().clear()
        self.ahab = None

    def image_info(self) -> BinaryImage:
        """Get image information in binary format.

        Retrieves the segment content as a BinaryImage object. If AHAB (Advanced High Assurance Boot)
        is available, it uses AHAB's image info with updated offset and name. Otherwise, falls back
        to the parent class implementation.

        :return: The segment content in Binary Image format with proper offset and name.
        """
        if not self.ahab:
            return super().image_info()

        image = self.ahab.image_info()
        image.offset = self.full_image_offset
        image.name = self.NAME.label
        return image

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into AHAB Segment object.

        The method validates the binary data contains a valid AHAB container header,
        parses it into an AHABImage object, and updates the segment's internal state.

        :param binary: Binary image data containing AHAB container.
        :raises SPSDKParsingError: When input binary block has zero length.
        :raises SPSDKSegmentNotPresent: When AHAB container header is not available or invalid.
        """
        self.not_parsed = True
        if len(binary) == 0:
            raise SPSDKParsingError("The input binary block has zero length.")

        try:
            AHABImage._parse_container_type(binary).check_container_head(binary).validate()
        except SPSDKError as exc:
            raise SPSDKSegmentNotPresent("AHAB container header not available") from exc

        ahab = AHABImage.parse(binary, family=self.family)
        self.raw_block = binary[: len(ahab)]
        self.ahab = ahab
        self.not_parsed = False

    def post_export(self, output_path: str) -> list[str]:
        """Execute post-export operations for the bootable image.

        This method performs any necessary post-processing steps after the main export
        operation has completed. If AHAB (Advanced High Assurance Boot) is configured,
        it delegates the post-export handling to the AHAB component.

        :param output_path: Path where the exported image files are located.
        :return: List of additional files created during post-export processing.
        """
        if self.ahab:
            return self.ahab.post_export(output_path)
        return []

    @staticmethod
    def find_segment_offset(binary: bytes) -> int:
        """Find the start offset of AHAB Image in binary data.

        The method locates the beginning position of an AHAB (Advanced High Assurance Boot)
        container within the provided binary data blob.

        :param binary: Binary data to search for AHAB container.
        :return: Byte offset position of the AHAB container in the binary data.
        """
        return AHABImage.find_offset_of_ahab(binary)

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store data to specified path.

        Generates configuration for the segment and writes AHAB configuration
        to YAML file if AHAB container is present.

        :param output_dir: Directory path where configuration files should be stored
        :return: Relative path to generated configuration file or inherited value
        """
        ret = super().create_config(output_dir)
        if self.ahab:
            ahab_parse_path = os.path.join(output_dir, self.NAME.label)
            cfg_path = os.path.join(ahab_parse_path, f"segment_{self.NAME.label}.yaml")
            write_file(self.ahab.get_config_yaml(ahab_parse_path), cfg_path)
            ret = os.path.join(f"{self.NAME.label}", f"segment_{self.NAME.label}.yaml")
        return ret

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        The method attempts to load AHAB container from configuration first. If the configuration
        contains a sub-configuration for the segment, it loads and validates an AHAB image.
        If validation fails or no sub-configuration exists, it falls back to loading as binary data.

        :param config: Configuration object containing segment data and settings.
        :raises SPSDKSegmentNotPresent: When the segment is not present in config file.
        :raises SPSDKValueError: When AHAB container cannot be exported from configuration.
        """
        # Try to load AHAB from configuration as a first attempt
        cfg_value = config.get(self.cfg_key())
        if not cfg_value:
            raise SPSDKSegmentNotPresent(
                f"The segment '{self.NAME.label}' is not present in the config file"
            )
        try:
            config_data = config.load_sub_config(self.cfg_key())
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            AHABImage.pre_check_config(config_data)
            ahab = AHABImage.load_from_config(config_data)
            ahab.update_fields()
            self.raw_block = ahab.export()
            self.ahab = ahab
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export AHAB container from the configuration:\n{str(exc)}"
            ) from exc

    def pre_parse_verify(self, data: bytes) -> Verifier:
        """Pre-parse binary to see main issues before parsing.

        Performs initial validation of the bootable image data by calling the parent
        class pre-parse verification and adding AHAB image specific verification.

        :param data: Bootable image binary data to be pre-parsed.
        :return: Verifier object containing pre-parsed validation results.
        """
        ret = super().pre_parse_verify(data)
        ret.add_child(AHABImage.pre_parse_verify(data))
        return ret

    def verify(self) -> Verifier:
        """Get verifier object of segment.

        Verifies the current segment and includes AHAB container verification
        if present. The method performs hierarchical verification by adding
        child verifier results.

        :return: Verifier object containing validation results for the segment.
        """
        ret = super().verify()
        if not ret.has_errors and self.ahab:
            ret.add_child(self.ahab.verify())
        return ret


class SegmentPrimaryAhab(SegmentAhab):
    """Primary Bootable Image Advanced High Assurance Boot (AHAB) Segment.

    This class represents the primary image container set segment for AHAB-based
    bootable images, managing the primary boot container configuration and data.

    :cvar NAME: Segment identifier for primary image container set.
    """

    NAME = BootableImageSegment.PRIMARY_IMAGE_CONTAINER_SET


class SegmentSecondaryAhab(SegmentAhab):
    """Secondary Bootable Image Advanced High Assurance Boot (AHAB) Segment class.

    This class manages secondary AHAB container segments in bootable images,
    handling configuration loading and creation with custom offset management
    for secondary image containers.

    :cvar NAME: Segment type identifier for secondary image container set.
    :cvar OFFSET_ALIGNMENT: Required alignment boundary of 1024 bytes.
    :cvar INIT_SEGMENT: Flag indicating this is not an initialization segment.
    """

    NAME = BootableImageSegment.SECONDARY_IMAGE_CONTAINER_SET
    OFFSET_ALIGNMENT = 1024
    INIT_SEGMENT = False

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        This method extracts segment configuration data, processes offset if present,
        and delegates path processing to the parent class.

        :param config: Configuration object containing segment settings including optional offset and path.
        :raises SPSDKValueError: If configuration values cannot be processed or converted.
        """
        cfg_value = config.get(self.cfg_key())
        if cfg_value and isinstance(cfg_value, dict):
            if "offset" in cfg_value:
                self._offset = value_to_int(cfg_value["offset"])
            # Update config with just the path for parent class processing
            config[self.cfg_key()] = cfg_value["path"]
        super().load_config(config)

    def create_config(self, output_dir: str) -> Union[str, int, dict]:
        """Create configuration and store data to specified path.

        The method generates configuration data for the segment and optionally includes
        offset information if the segment is not positioned right behind the previous segment.

        :param output_dir: Path where the segment information should be stored.
        :return: Configuration value - either basic segment data or dictionary with path and offset.
        """
        ret = super().create_config(output_dir)
        # if offset is not < 0, the segment isn't right behind the previous segment
        if self.full_image_offset < 0:
            return ret
        return {"path": ret, "offset": self.full_image_offset}


class SegmentSB21(Segment):
    """Bootable Image Secure Binary 2.1 Segment class.

    This class represents a segment containing Secure Binary v2.1 data within a bootable image.
    It handles loading, parsing, and management of SB2.1 format data, supporting both
    configuration-based initialization and raw binary data processing.

    :cvar NAME: Segment type identifier for SB2.1 segments.
    :cvar BOOT_HEADER: Indicates this segment does not contain boot header.
    :cvar INIT_SEGMENT: Indicates this is an initialization segment.
    """

    NAME = BootableImageSegment.SB21
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        sb21: Optional[BootImageV21] = None,
    ) -> None:
        """Initialize Segment with bootable image data.

        Segment initialization requires at least raw data to be stored. The method
        also supports initialization with Secure Binary v2.1 data and validates
        consistency between raw block and SB21 export data.

        :param offset: Offset of Segment in whole bootable image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param raw_block: Raw data of segment.
        :param sb21: Secure Binary v2.1 class.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.sb21 = sb21
        if sb21 and raw_block and raw_block != sb21.export():
            logger.info("The SB21 block doesn't match the raw data.")

    def clear(self) -> None:
        """Clear the segment to initial state.

        This method resets the segment by calling the parent class clear method
        and setting the sb21 attribute to None.
        """
        super().clear()
        self.sb21 = None

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        Loads SB2.1 (Secure Binary 2.1) segment from configuration data. First attempts to load
        as SB2.1 configuration, then falls back to binary loading if configuration parsing fails.

        :param config: Configuration object containing segment data.
        :raises SPSDKValueError: When SB2.1 cannot be exported from the configuration.
        """
        # Try to load SB2.1 from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "sb21"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            config_data.check(
                BootImageV21.get_validation_schemas(self.family), check_unknown_props=True
            )
            sb21 = BootImageV21.load_from_config(config_data)
            self.raw_block = sb21.export()
            self.sb21 = sb21
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export SB2.1 from the configuration:\n{str(exc)}"
            ) from exc

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        This method validates the binary header using BootImageV21 validation and then
        delegates the actual parsing to the parent class implementation.

        :param binary: Binary image data to be parsed into segment structure.
        :raises SPSDKError: Invalid binary header format or parsing failure.
        """
        self.not_parsed = True
        BootImageV21.validate_header(binary)
        super().parse_binary(binary=binary)


class SegmentSB31(Segment):
    """Bootable Image Secure Binary 3.1 Segment class.

    This class represents a segment containing Secure Binary v3.1 data within a bootable image.
    It handles loading, parsing, and management of SB3.1 segments including configuration-based
    initialization and binary data processing.

    :cvar NAME: Segment type identifier for SB3.1 segments.
    :cvar BOOT_HEADER: Indicates this segment type does not contain boot header.
    :cvar INIT_SEGMENT: Indicates this segment requires initialization.
    """

    NAME = BootableImageSegment.SB31
    BOOT_HEADER = False
    INIT_SEGMENT = True

    def __init__(
        self,
        offset: int,
        family: FamilyRevision,
        mem_type: MemoryType,
        raw_block: Optional[bytes] = None,
        sb31: Optional[SecureBinary31] = None,
    ) -> None:
        """Initialize segment with bootable image data and secure binary configuration.

        :param offset: Offset of segment in whole bootable image.
        :param family: Chip family revision identifier.
        :param mem_type: Target memory type for the segment.
        :param raw_block: Raw binary data of the segment, defaults to None.
        :param sb31: Secure Binary v3.1 configuration object, defaults to None.
        """
        super().__init__(offset, family, mem_type, raw_block)
        self.sb31 = sb31

    def clear(self) -> None:
        """Clear the segment to init state.

        This method resets the segment to its initial state by calling the parent class
        clear method and setting the sb31 attribute to None.
        """
        super().clear()
        self.sb31 = None

    def load_config(self, config: Config) -> None:
        """Load segment from configuration.

        Attempts to load SB3.1 (Secure Binary 3.1) from configuration first, falling back
        to binary loading if configuration parsing fails.

        :param config: Configuration object containing segment data.
        :raises SPSDKValueError: When SB3.1 cannot be exported from the configuration.
        """
        # Try to load SB3.1 from configuration as a first attempt
        cfg_key = self.cfg_key() if self.cfg_key() in config else "sb31"
        try:
            config_data = config.load_sub_config(cfg_key)
        except SPSDKError:
            # In case that the file is not configuration, load is as binary
            super().load_config(config)
            return
        try:
            SecureBinary31.pre_check_config(config_data)
            sb31 = SecureBinary31.load_from_config(config_data)
            self.raw_block = sb31.export()
            self.sb31 = sb31
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Cannot export SB3.1 from the configuration:\n{str(exc)}"
            ) from exc

    def parse_binary(self, binary: bytes) -> None:
        """Parse binary block into Segment object.

        This method validates the binary header and delegates parsing to the parent class
        implementation while marking the segment as not parsed initially.

        :param binary: Binary image data to be parsed into segment structure.
        :raises SPSDKError: Invalid binary header format.
        """
        self.not_parsed = True
        SecureBinary31.validate_header(binary)
        super().parse_binary(binary=binary)


def get_segments() -> dict[BootableImageSegment, Type[Segment]]:
    """Get dictionary of all supported bootable image segments.

    This method dynamically discovers all segment classes that inherit from the base Segment class
    by inspecting the global namespace and filtering for valid segment implementations.

    :return: Dictionary mapping segment names to their corresponding segment class types.
    """
    ret = {}
    for var in globals():
        obj = globals()[var]
        if isclass(obj) and issubclass(obj, Segment) and obj is not Segment:
            assert issubclass(obj, Segment)  # pylint: disable=assert-instance
            ret[obj.NAME] = obj
    return ret


def get_segment_class(name: BootableImageSegment) -> Type["Segment"]:
    """Get the segment class type for a bootable image segment.

    :param name: The bootable image segment identifier.
    :raises SPSDKValueError: Unsupported bootable image segment name.
    :return: Segment class type.
    """
    segments = get_segments()
    if name not in segments:
        raise SPSDKValueError(f"Unsupported Bootable image segment with name: {name.label}")
    return segments[name]

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Bootable Image management utilities.

This module provides functionality for creating, parsing, and manipulating
bootable images across NXP MCU portfolio. It handles bootable image segments
and provides the main BootableImage class for comprehensive image operations.
"""


import logging
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError, SPSDKVerificationError
from spsdk.image.bootable_image.segments import (
    BootableImageSegment,
    Segment,
    SPSDKSegmentNotPresent,
    get_segment_class,
)
from spsdk.image.mem_type import MemoryType
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage, BinaryPattern
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import align, value_to_int
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class BootableImage(FeatureBaseClass):
    """Bootable Image representation for NXP MCU devices.

    This class manages the creation and manipulation of bootable images that can be
    programmed to various memory types on NXP MCU devices. It handles image segments,
    memory layout, and provides functionality for exporting complete bootable images.

    :cvar FEATURE: Database feature identifier for bootable image support.
    """

    FEATURE = DatabaseManager.BOOTABLE_IMAGE

    def __init__(
        self,
        family: FamilyRevision,
        mem_type: MemoryType,
        init_offset: Union[BootableImageSegment, int] = 0,
    ) -> None:
        """Bootable Image constructor.

        Initialize a new bootable image instance for the specified chip family and memory type.

        :param family: Chip family and revision information.
        :param mem_type: Target memory type for the bootable image.
        :param init_offset: Initial offset for the image, either as segment or integer value.
        :raises SPSDKValueError: When the specified memory type is not supported for the given family.
        """
        if mem_type not in self.get_supported_memory_types(family):
            raise SPSDKValueError(f"Unsupported memory type: {mem_type.label}")
        self.family = family
        self.mem_type = mem_type
        bimg_descr: dict[str, Any] = self.get_memory_type_config(family, mem_type)
        self.image_pattern = bimg_descr.get("image_pattern", "zeros")
        self._segments: list[Segment] = self._get_segments(family, mem_type)
        self._init_offset: int = 0
        self.set_init_offset(init_offset)

    @property
    def segments(self) -> list[Segment]:
        """Get list of segments that are currently present in the bootable image.

        This method filters the internal segments list to return only those segments
        that have the is_present flag set to True, indicating they contain actual data
        and are part of the bootable image.

        :return: List of segments that are present in the bootable image.
        """
        return [seg for seg in self._segments if seg.is_present]

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export operations on all segments.

        Iterates through all segments in the bootable image and calls their post_export
        method if available, collecting any generated files.

        :param output_path: Directory path where post-export files should be created.
        :return: List of file paths created during post-export operations.
        """
        files = []
        for segment in self.segments:
            if hasattr(segment, "post_export"):
                files.extend(segment.post_export(output_path))

        return files

    def set_init_offset(self, init_offset: Union[BootableImageSegment, int]) -> None:
        """Set init offset by name of segment or length.

        The method allows setting the initialization offset either by providing a direct
        integer value or by specifying a bootable image segment. When a segment is provided,
        the method uses its full image offset as the init offset value.

        :param init_offset: Either an integer offset value or a BootableImageSegment object
                           whose offset will be used.
        :raises SPSDKError: When the specified segment does not exist in the image.
        """
        if isinstance(init_offset, int):
            self.init_offset = init_offset
        else:
            segment = next((seg for seg in self._segments if seg.NAME == init_offset), None)
            if segment is None:
                raise SPSDKError(f"Segment with name {init_offset.label} does not exist.")
            self.init_offset = segment.full_image_offset

    def get_segment(self, segment: Union[str, BootableImageSegment]) -> Segment:
        """Get bootable segment by its name or Enum class.

        :param segment: Name of segment as string or BootableImageSegment enum value.
        :raises SPSDKError: When the specified segment is not present in the bootable image.
        :return: The requested segment object.
        """
        name = segment if isinstance(segment, str) else segment.label
        for seg in self.segments:
            if seg.NAME == name:
                return seg
        raise SPSDKError(
            f"The segment {segment} is not present in this Bootable image: {str(self)}"
        )

    @property
    def init_offset(self) -> int:
        """Get initial offset compared to "full" bootable image.

        Only segments after this offset are considered.

        :return: Initial offset value.
        """
        return self._init_offset

    @init_offset.setter
    def init_offset(self, offset: int) -> None:
        """Set the initial offset for the bootable image.

        This method validates and sets the initial offset, finding the closest upper segment
        offset if needed. When offset is 0, the entire image is used. For non-zero offsets,
        it finds the nearest segment boundary at or above the specified offset.

        :param offset: The initial offset value in bytes, must be non-negative.
        :raises SPSDKValueError: If offset is negative or exceeds the last segment start.
        """
        if offset < 0:
            raise SPSDKValueError("Offset cannot be a negative number.")
        # In case the init offset is 0, return the whole image
        if offset == 0:
            self._init_offset = 0
        else:
            # Find the closest upper offset
            upper_offsets = [
                seg.full_image_offset
                for seg in self._segments
                if seg.full_image_offset >= offset or seg.full_image_offset < 0
            ]
            if not upper_offsets:
                raise SPSDKValueError(
                    f"The given offset {offset} must be lower or equal to the start of last segment of the image."
                )
            self._init_offset = min(upper_offsets)
        self._update_segments()

    def _update_segments(self) -> None:
        """Update segment indexes based on initialization offset.

        This method iterates through all segments and recalculates their offsets relative to the
        initialization offset. Segments are marked as excluded if their new offset becomes negative
        while their full image offset was non-negative, indicating they fall outside the valid
        range after offset adjustment.
        """
        for segment in self._segments:
            full_offset = segment.full_image_offset
            new_offset = full_offset - self.init_offset
            segment.excluded = new_offset < 0 <= full_offset

    def get_segment_offset(self, segment: Segment) -> int:
        """Get segment offset within the bootable image.

        Calculates the absolute offset of a segment within the bootable image. For segments
        with static offsets, returns the predefined value. For segments with dynamic offsets,
        computes the position based on previous segments and alignment requirements.

        :param segment: Segment object to get its offset from.
        :raises SPSDKError: If segment is excluded from image or offset cannot be computed.
        :return: Absolute offset of the segment within the bootable image.
        """

        def _get_segment_offset(segments: list[Segment], segment: Segment) -> int:
            """Get the offset of a segment within the bootable image.

            Calculates either the static offset if already defined, or dynamically computes
            the offset based on the previous segment's position and alignment requirements.

            :param segments: List of all segments in the bootable image.
            :param segment: Target segment to get the offset for.
            :raises SPSDKError: When dynamic offset calculation fails due to missing previous
                segment or segment not found in the list.
            :return: Absolute offset of the segment in bytes.
            """
            if segment.full_image_offset >= 0:
                return segment.full_image_offset

            # It should be dynamically computed
            prev_seg: Optional[Segment] = None
            for seg in segments:
                if seg == segment:
                    if prev_seg is None:
                        raise SPSDKError(
                            "Cannot get dynamically offset of segment because"
                            " there is no any previous segment with static offset."
                        )
                    assert isinstance(prev_seg, Segment)  # oh dear mypy...
                    return align(
                        _get_segment_offset(segments, prev_seg) + len(prev_seg),
                        segment.OFFSET_ALIGNMENT,
                    )
                prev_seg = seg
            raise SPSDKError("Cannot get dynamically offset of segment.")

        if segment.excluded:
            raise SPSDKError(
                f"The segment '{segment.NAME}' is not present in this Bootable image: {str(self)}."
            )
        return _get_segment_offset(self._segments, segment) - self._init_offset

    def __len__(self) -> int:
        """Calculate the total length of the output binary.

        The length is determined by finding the offset of the last segment plus
        the length of that segment, representing the total size of the binary
        when all segments are included.

        :return: Total length of the output binary in bytes.
        """
        last_segment = self.segments[-1]
        return self.get_segment_offset(last_segment) + len(last_segment)

    @property
    def header_len(self) -> int:
        """Get the length of the bootable image header.

        Calculates the length of the space before application data by finding the first
        non-boot header segment and returning its offset position.

        :raises SPSDKError: When unable to determine the size of bootable image header.
        :return: Length of the bootable image header in bytes.
        """
        for segment in self.segments:
            if not segment.BOOT_HEADER:
                return self.get_segment_offset(segment)
        raise SPSDKError("Cannot determine the size of bootable image header")

    @property
    def bootable_header_only(self) -> bool:
        """Check if the image contains only bootable image header.

        The method verifies whether the bootable image consists solely of the header
        without any application data by examining if all segments are either non-boot
        header segments with zero length or boot header segments.

        :return: True if image contains only bootable header, False otherwise.
        """
        return any(((not x.BOOT_HEADER and len(x) == 0) for x in self.segments))

    def _parse(self, binary: bytes) -> None:
        """Parse binary data into bootable image segments.

        Iterates through all non-excluded segments and attempts to parse the binary data
        at their respective offsets. Handles both fixed and variable offset segments,
        with proper alignment and error handling for missing or invalid segments.

        :param binary: Binary data to parse into segments.
        :raises SPSDKError: When input binary is insufficient for required boot header segments
                           or when segment parsing fails.
        """
        try:
            prev_offset = prev_size = 0
            for segment in [seg for seg in self._segments if not seg.excluded]:
                offset = self.get_segment_offset(segment)
                # cover the case with variable offset
                if segment.full_image_offset < 0:
                    start_offset = align(prev_offset + prev_size, segment.OFFSET_ALIGNMENT)
                    if start_offset >= len(binary):
                        continue
                    offset = start_offset + segment.find_segment_offset(binary[start_offset:])
                if len(binary) <= offset and segment.BOOT_HEADER:
                    raise SPSDKError("Insufficient length of input binary.")
                logger.debug(f"Trying to parse segment {segment.NAME} at offset 0x{offset:08X}.")
                try:
                    segment.parse_binary(binary[offset:])
                    # set the actual offset, when segments are not contiguous
                    if segment.full_image_offset < 0 and start_offset != offset:
                        segment.full_image_offset = offset
                except SPSDKSegmentNotPresent:
                    segment.clear()
                    continue
                prev_offset = offset
                prev_size = len(segment)
            return
        except SPSDKError as e:
            logger.debug(f"Parsing of the segment '{segment.NAME}' failed: {e}")
            raise

    @classmethod
    def _parse_all(
        cls,
        binary: bytes,
        family: Optional[FamilyRevision] = None,
        mem_type: Optional[MemoryType] = None,
        no_errors: bool = True,
    ) -> list[Self]:
        """Parse binary data into bootable image objects.

        Attempts to parse the provided binary data into bootable image instances by trying
        different memory types and initial offsets. First tries exact matches, then attempts
        parsing with various initial segment offsets if no exact match is found.

        :param binary: Binary data of the bootable image to parse.
        :param family: Target chip family and revision for parsing.
        :param mem_type: Specific memory type to use, if None tries all supported types.
        :param no_errors: When True, validates parsed images and rejects any with errors.
        :raises SPSDKValueError: When family parameter is not specified.
        :return: List of successfully parsed bootable image instances.
        """
        if not family:
            raise SPSDKValueError("Family attribute must be specified.")
        mem_types = [mem_type] if mem_type else cls.get_supported_memory_types(family)
        mem_types_str = ",".join(
            [(mem_type.description or mem_type.label) for mem_type in mem_types]
        )
        logger.debug(f"Parsing of bootable image for memory type(s): {mem_types_str}")
        bimg_instances: list[Self] = []
        # first try to find the exact match as it is a full bootable image
        for memory_type in mem_types:
            logger.debug(
                f"Parsing the image for memory type '{memory_type.description}' finding the exact match"
            )
            try:
                bimg = cls(family, memory_type)
                bimg._parse(binary)
                if no_errors:
                    bimg.verify().validate()
                bimg_instances.append(bimg)
            except SPSDKError as e:
                logger.debug(e)
                continue
        # try to parse bootable image with moving initial offset
        if not bimg_instances:
            logger.debug("The exact match has not been found")
            for memory_type in mem_types:
                segments = cls._get_segments(family, memory_type)
                init_offsets = [seg.full_image_offset for seg in segments if seg.INIT_SEGMENT]
                for init_offset in init_offsets:
                    logger.debug(
                        f"Parsing the image for memory type '{memory_type.description}' "
                        f"with init offset 0x{init_offset:08X}"
                    )
                    try:
                        bimg = cls(family, memory_type, init_offset)
                        bimg._parse(binary)
                        if no_errors:
                            bimg.verify().validate()
                        bimg_instances.append(bimg)
                    except SPSDKError as e:
                        logger.debug(e)
                        continue

        return bimg_instances

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: Optional[FamilyRevision] = None,
        mem_type: Optional[MemoryType] = None,
    ) -> Self:
        """Parse binary data into a bootable image object.

        The method attempts to parse the provided binary data using all possible memory types
        and returns the first successful match. If multiple memory types are detected, a warning
        is logged and the first one is used.

        :param binary: Binary data of the bootable image to parse.
        :param family: Target chip family revision, auto-detected if not specified.
        :param mem_type: Specific memory type to use, auto-detected if not specified.
        :raises SPSDKError: When binary parsing fails for all memory types.
        :return: Parsed bootable image object.
        """
        bimg_instances = cls._parse_all(binary=binary, family=family, mem_type=mem_type)

        if not bimg_instances:
            raise SPSDKError(
                "The image parsing failed. The image is not matching any of memory types."
                " To get more accurate info try to run verify command or enable debug log."
            )
        if len(bimg_instances) > 1:
            mem_types_str = ", ".join(f'"{img.mem_type.description}"' for img in bimg_instances)
            logger.warning(
                f"Multiple possible memory types detected: {mem_types_str}."
                f'The "{bimg_instances[0].mem_type.description}" memory type will be used.'
            )
        return bimg_instances[0]

    def __repr__(self) -> str:
        """Get text short representation of the BootableImage.

        :return: String representation containing family and memory type information.
        """
        return f"BootableImage, family:{self.family}, mem_type:{self.mem_type.description}"

    def __str__(self) -> str:
        """Get string representation of the BootableImage.

        Provides detailed information about the bootable image including family,
        memory type, and all configured segments in a human-readable format.

        :return: Formatted string containing bootable image information.
        """
        nfo = "BootableImage\n"
        nfo += f"  Family:      {self.family}\n"
        nfo += f"  Memory Type: {self.mem_type.description}\n"
        if self.segments:
            nfo += "  Segments:\n"
        for segment in self.segments:
            nfo += f"      {segment}\n"
        return nfo

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get validation schema for the object.

        The method retrieves validation schemas based on the object's family and memory type
        by delegating to the static get_validation_schemas method.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type)

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mem_type: Optional[MemoryType] = None
    ) -> list[dict[str, Any]]:
        """Get validation schemas for bootable image configuration.

        Retrieves and configures validation schemas specific to the given chip family
        and memory type, including family-specific settings and supported segments.

        :param family: Target chip family and revision.
        :param mem_type: Memory type to be used for bootable image.
        :raises SPSDKValueError: When memory type parameter is not defined.
        :return: List of validation schema dictionaries for configuration.
        """
        if mem_type is None:
            raise SPSDKValueError("The memory type parameter must be defined.")
        bimg = BootableImage(family=family, mem_type=mem_type)
        sch_cfg = get_schema_file(DatabaseManager.BOOTABLE_IMAGE)
        sch_family = get_schema_file("general")["family"]
        try:
            sch_family["note"] = get_db(family).get_str(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type.label, "note"]
            )
        except SPSDKError:
            pass
        sch_family["main_title"] = (
            f"Bootable Image Configuration for {family} / {mem_type.description}."
        )
        update_validation_schema_family(
            sch_family["properties"], bimg.get_supported_families(), family
        )
        sch_cfg["memory_type"]["properties"]["memory_type"]["template_value"] = mem_type.label
        schemas = [sch_family, sch_cfg["memory_type"], sch_cfg["init_offset"]]
        schemas.append(sch_cfg["post_export"])
        for segment in bimg._segments:
            try:
                sch_name = sch_cfg[segment.NAME.label]
            except KeyError:
                logger.error(f"Cannot find schema for segment {segment.NAME}")
                continue
            schemas.append(sch_name)
        return schemas

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the AHAB Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["memory_type"] = self.mem_type.label
        config["init_offset"] = self.init_offset
        for segment in self._segments:
            config[segment.cfg_key()] = segment.create_config(data_path)

        return config

    @staticmethod
    def _init_offset_from_cfg(config: Config) -> Union[int, BootableImageSegment]:
        """Convert configuration value to correct format of init offset.

        Processes the init_offset configuration value and converts it to either an integer
        offset or a BootableImageSegment object based on the input type.

        :param config: Input bootable image configuration containing init_offset value.
        :return: Integer offset value or BootableImageSegment object based on configuration.
        """
        init_offset = config.get("init_offset", 0)
        try:
            init_offset = value_to_int(init_offset)
            # In case that this will be a number in string, just convert it
        except SPSDKError:
            # The string is name of segment probably
            pass
        return (
            BootableImageSegment.from_label(init_offset)
            if isinstance(init_offset, str)
            else init_offset
        )

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method validates the basic configuration, extracts family, memory type,
        and initialization offset parameters, then creates a bootable image instance
        to retrieve the appropriate validation schemas.

        :param config: Configuration object containing bootable image settings
        :return: List of validation schema dictionaries for the specified configuration
        :raises SPSDKError: Invalid configuration or unsupported family/memory type combination
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config["memory_type"])
        init_offset = cls._init_offset_from_cfg(config)

        bimg = cls(family=family, mem_type=mem_type, init_offset=init_offset)
        return bimg.get_validation_schemas(family, mem_type)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load bootable image from configuration.

        Creates a new bootable image instance by parsing the provided configuration data,
        including family revision, memory type, and initialization offset. Loads all
        available segments from the configuration.

        :param config: Configuration data containing bootable image settings.
        :raises SPSDKSegmentNotPresent: When a segment is not present in configuration.
        :return: New bootable image instance configured according to the provided settings.
        """
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config.get_str("memory_type"))
        init_offset = cls._init_offset_from_cfg(config)

        bimg = cls(family=family, mem_type=mem_type, init_offset=init_offset)

        for segment in bimg._segments:
            try:
                segment.load_config(config)
            except SPSDKSegmentNotPresent:
                segment.clear()
                continue

        return bimg

    def image_info(self) -> BinaryImage:
        """Create Binary image representation of the bootable image.

        This method generates a BinaryImage object that contains information about all segments
        in the bootable image, including their offsets, sizes, and descriptions. It handles
        segment alignment and provides detailed information about the memory type and whether
        the image contains only headers or includes application data.

        :return: BinaryImage object containing structured information about the bootable image.
        """
        description = f"Memory type: {self.mem_type}"
        if self.bootable_header_only:
            description += ". This is bootable image header only, no application is included"
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}",
            size=len(self),
            pattern=BinaryPattern(self.image_pattern),
            description=description,
        )
        prev_offset = prev_size = 0
        if self.init_offset:
            logger.info(f"The image is not complete. Starting from offset {self.init_offset}")
        for segment in self.segments:
            seg_offset = segment.full_image_offset
            if segment.full_image_offset < 0:
                seg_offset = align(prev_offset + prev_size, segment.OFFSET_ALIGNMENT)
            img_info = segment.image_info()
            img_info.offset = self.get_segment_offset(segment)
            bin_image.add_image(img_info)
            prev_size = len(segment)
            prev_offset = seg_offset
        return bin_image

    def export(self) -> bytes:
        """Export bootable image to binary format.

        This method generates the complete binary representation of the bootable image
        by calling the export method on the image info object.

        :return: Complete binary data of the bootable image.
        """
        return self.image_info().export()

    @staticmethod
    def pre_parse_verify(data: bytes, family: FamilyRevision, mem_type: MemoryType) -> Verifier:
        """Pre-parse binary to see main issues before parsing.

        Performs verification of bootable image segments to identify potential parsing issues.
        The method attempts to parse the entire image first, and if that fails, tries parsing
        from different initial segment offsets to find a valid starting point.

        :param data: Bootable image binary data to be verified.
        :param family: Target chip family and revision information.
        :param mem_type: Memory type where the image will be stored.
        :raises SPSDKVerificationError: When verification of segments fails.
        :return: Verifier object containing pre-parse verification results.
        """

        def check_segments(bimg_obj: BootableImage, name: str) -> Verifier:
            """Check and verify all segments in a bootable image.

            Validates each non-excluded segment in the bootable image by checking offsets,
            alignment, and performing pre-parse verification on segment data.

            :param bimg_obj: The bootable image object containing segments to verify.
            :param name: Name identifier for the verification process.
            :return: Verifier object containing validation results for all segments.
            """
            ret = Verifier(f"Pre-parsed Bootable Image at offset {hex(bimg_obj.init_offset)}")
            all_ret.add_child(ret, name)

            prev_offset = prev_size = 0
            for segment in [seg for seg in bimg_obj._segments if not seg.excluded]:
                offset = bimg_obj.get_segment_offset(segment)
                # cover the case with variable offset
                if segment.full_image_offset < 0:
                    start_offset = align(prev_offset + prev_size, segment.OFFSET_ALIGNMENT)
                    if start_offset >= len(data):
                        continue
                    offset = start_offset + segment.find_segment_offset(data[start_offset:])
                if len(data) <= offset and segment.BOOT_HEADER:
                    ret.add_record(
                        "Length", VerifierResult.ERROR, "Insufficient length of input binary."
                    )
                    return ret
                try:
                    ret.add_child(segment.pre_parse_verify(data[offset:]))
                    ret.validate()
                except SPSDKVerificationError:
                    return ret
                prev_offset = offset
                prev_size = len(segment)
            return ret

        all_ret = Verifier("Pre-parsed Bootable Images")
        bimg = BootableImage(family, mem_type, 0)
        # check full image
        full_ver = check_segments(bimg, "Whole Image pre-parse verification")
        if not full_ver.has_errors:
            return full_ver

        init_segments = [
            seg for seg in bimg._segments if seg.INIT_SEGMENT and seg.full_image_offset != 0
        ]
        for init_segment in init_segments:
            bimg = BootableImage(family, mem_type, init_segment.full_image_offset)
            seg_ver = check_segments(bimg, f"Starting from {init_segment.NAME.label} segment")
            if not seg_ver.has_errors:
                return seg_ver
        # in this case, everything fails, return information about all fails
        return all_ret

    def verify(self) -> Verifier:
        """Get verifier object for bootable image validation.

        Creates a comprehensive verifier that validates the bootable image structure,
        including header information, segments, and binary layout. The verifier checks
        each segment's availability and offset, validates the overall image structure,
        and provides detailed verification results.

        :raises SPSDKError: When binary structure validation fails.
        :return: Verifier object containing validation results for the bootable image.
        """
        ret = Verifier(f"Bootable Image of {self.family} for {self.mem_type} memory type")
        ret.add_record_range("Header length", self.header_len)
        ret.add_record_range("Initial offset", self.init_offset)

        for seg in self._segments:
            seg_ver = Verifier(f"Segment {seg.NAME}")
            if seg.excluded:
                seg_ver.add_record(
                    "Availability", VerifierResult.WARNING, "The segment is excluded"
                )
            else:
                seg_ver.add_record_range("Offset in image", hex(self.get_segment_offset(seg)))
                seg_ver.add_child(seg.verify())

            ret.add_child(seg_ver)

        image_info = self.image_info()
        try:
            image_info.validate()
            val = "Valid"
            if logger.getEffectiveLevel() <= logging.INFO:
                val = image_info.draw()
            ret.add_record("Binary structure", VerifierResult.SUCCEEDED, val, raw=True)
        except SPSDKError:
            ret.add_record("Binary structure", VerifierResult.ERROR, image_info.draw(), raw=True)
        return ret

    @classmethod
    def get_config_template(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> str:
        """Get configuration template for the family.

        The method generates a configuration template based on the validation schemas
        for the specified chip family and memory type.

        :param family: Chip family and revision information.
        :param mem_type: Memory type to use for template generation.
        :return: Configuration template as a string.
        """
        schemas = cls.get_validation_schemas(family, mem_type)
        return cls._get_config_template(family, schemas)

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[FamilyRevision] = None
    ) -> list[MemoryType]:
        """Get supported memory types for bootable images.

        The method retrieves memory types either for a specific family from the database
        or all supported memory types across families if no family is specified.

        :param family: Optional family revision to get memory types for specific family.
        :return: List of supported memory types.
        """
        if family:
            database = get_db(family)
            return [
                MemoryType.from_label(memory)
                for memory in database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types").keys()
            ]

        return [
            MemoryType.from_label(memory)
            for memory in DatabaseManager().quick_info.features_data.get_mem_types(
                DatabaseManager.BOOTABLE_IMAGE
            )
        ]

    @staticmethod
    def get_memory_type_config(family: FamilyRevision, mem_type: MemoryType) -> dict[str, Any]:
        """Get memory type configuration for specific chip family and memory type.

        The method retrieves configuration dictionary from the database for the specified
        memory type, ensuring it's supported by the given chip family.

        :param family: Chip family revision to get configuration for.
        :param mem_type: Chip memory type to handle bootable area.
        :raises SPSDKKeyError: If memory type does not exist in database.
        :return: Dictionary with memory type configuration.
        """
        if mem_type not in BootableImage.get_supported_memory_types(family):
            raise SPSDKKeyError(f"Memory type not supported: {mem_type.description}")
        database = get_db(family)
        mem_types = database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types")
        return mem_types[mem_type.label]

    @staticmethod
    def _get_segments(family: FamilyRevision, mem_type: MemoryType) -> list[Segment]:
        """Return list of used segments for specific memory type.

        The method retrieves bootable image configuration for the given family and memory type,
        then creates and returns a list of segment objects based on the configuration.

        :param family: Chip family revision identifier.
        :param mem_type: Chip memory type to handle bootable area.
        :return: List of segments for chosen chip and memory type.
        """
        bimg_descr = BootableImage.get_memory_type_config(family=family, mem_type=mem_type)
        segments: list[Segment] = []
        for segment_name, segment_offset in bimg_descr["segments"].items():
            segments.append(
                get_segment_class(BootableImageSegment.from_label(segment_name))(
                    offset=segment_offset, family=family, mem_type=mem_type
                )
            )
        return segments

    @staticmethod
    def get_supported_revisions(family: FamilyRevision) -> list[str]:
        """Get supported revisions for a given family.

        The method retrieves all available revisions for the specified family from the
        database manager, including only enabled revisions.

        :param family: Family revision object containing the family name.
        :return: List of supported revision names for the given family.
        """
        return DatabaseManager().db.devices.get(family.name).revisions.revision_names(True)

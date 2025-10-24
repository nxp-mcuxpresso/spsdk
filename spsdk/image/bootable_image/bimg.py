#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""


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
    """Bootable Image class."""

    FEATURE = DatabaseManager.BOOTABLE_IMAGE

    def __init__(
        self,
        family: FamilyRevision,
        mem_type: MemoryType,
        init_offset: Union[BootableImageSegment, int] = 0,
    ) -> None:
        """Bootable Image constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
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
        """List of used segments."""
        return [seg for seg in self._segments if seg.is_present]

    def post_export(self, output_path: str) -> list[str]:
        """Perform post export on all segments."""
        files = []
        for segment in self.segments:
            if hasattr(segment, "post_export"):
                files.extend(segment.post_export(output_path))

        return files

    def set_init_offset(self, init_offset: Union[BootableImageSegment, int]) -> None:
        """Set init offset by name of segment or length."""
        if isinstance(init_offset, int):
            self.init_offset = init_offset
        else:
            segment = next((seg for seg in self._segments if seg.NAME == init_offset), None)
            if segment is None:
                raise SPSDKError(f"Segment with name {init_offset.label} does not exist.")
            self.init_offset = segment.full_image_offset

    def get_segment(self, segment: Union[str, BootableImageSegment]) -> Segment:
        """Get bootable segment by its name or Enum class.

        :param segment: Name of enum class of segment.
        :return: Segment.
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
        """Initial offset compared to "full" bootable image.Only segments after this offset are considered."""
        return self._init_offset

    @init_offset.setter
    def init_offset(self, offset: int) -> None:
        """Initial offset setter."""
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
        """Update segment indexes."""
        for segment in self._segments:
            full_offset = segment.full_image_offset
            new_offset = full_offset - self.init_offset
            segment.excluded = new_offset < 0 <= full_offset

    def get_segment_offset(self, segment: Segment) -> int:
        """Get segment offset.

        :param segment: Segment object to get its offset
        :return: Segment offset
        """

        def _get_segment_offset(segments: list[Segment], segment: Segment) -> int:
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
        """Length of output binary."""
        last_segment = self.segments[-1]
        return self.get_segment_offset(last_segment) + len(last_segment)

    @property
    def header_len(self) -> int:
        """Length of the header.

        The length of the space before application data.
        :return: Length of the bootable image area.
        """
        for segment in self.segments:
            if not segment.BOOT_HEADER:
                return self.get_segment_offset(segment)
        raise SPSDKError("Cannot determine the size of bootable image header")

    @property
    def bootable_header_only(self) -> bool:
        """The image contains only bootable image header.

        No application is available.
        """
        return any(((not x.BOOT_HEADER and len(x) == 0) for x in self.segments))

    def _parse(self, binary: bytes) -> None:
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
        """Parse binary into bootable image object.

        :param binary: Bootable image binary.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param no_errors: Do not accept any parsing errors.
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
        """Parse binary into bootable image object.

        :param binary: Bootable image binary.
        :param family: Chip family.
        :param mem_type: Used memory type.
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
        """Text short representation about the BootableImage."""
        return f"BootableImage, family:{self.family}, mem_type:{self.mem_type.description}"

    def __str__(self) -> str:
        """Text information about the BootableImage."""
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

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type)

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mem_type: Optional[MemoryType] = None
    ) -> list[dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :return: List of validation schema dictionaries.
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
        :return: Configuration dictionary.c
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

        :param config: Input bootable configuration
        :return: Union - real offset or name v bootable segment
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
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
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

        :param config: Configuration of Bootable image.
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
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
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
            logger.info(f"The image is not complete. Staring from offset {self.init_offset}")
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
        """Export bootable image.

        :return: Complete binary of bootable image.
        """
        return self.image_info().export()

    @staticmethod
    def pre_parse_verify(data: bytes, family: FamilyRevision, mem_type: MemoryType) -> Verifier:
        """Pre-Parse binary T osee main issue before parsing.

        :param data: Bootable image binary.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :return: Verifier object of preparsed data.
        """

        def check_segments(bimg_obj: BootableImage, name: str) -> Verifier:
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
        """Get verifier object of segment.

        :return: Verifier of current object.
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
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :return: Configuration template in string.
        """
        schemas = cls.get_validation_schemas(family, mem_type)
        return cls._get_config_template(family, schemas)

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[FamilyRevision] = None
    ) -> list[MemoryType]:
        """Return list of supported memory types.

        :return: List of supported families.
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
        """Return dictionary with configuration for specific memory type.

        :param family: Chip family name.
        :param mem_type: CHip memory type to handle bootable area.
        :raises SPSDKKeyError: If memory type does not exist in database
        :return: Dictionary with configuration.
        """
        if mem_type not in BootableImage.get_supported_memory_types(family):
            raise SPSDKKeyError(f"Memory type not supported: {mem_type.description}")
        database = get_db(family)
        mem_types = database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types")
        return mem_types[mem_type.label]

    @staticmethod
    def _get_segments(family: FamilyRevision, mem_type: MemoryType) -> list[Segment]:
        """Return list of used segments for specific memory type.

        :param family: Chip family name.
        :param mem_type: CHip memory type to handle bootable area.
        :return: List of segments for choose chip and memory type.
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
        """Return list of supported revisions.

        :return: List of supported revisions.
        """
        return DatabaseManager().db.devices.get(family.name).revisions.revision_names(True)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""


import logging
import os
from typing import Any, Dict, List, Optional, Union

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.image.bootable_image.segments import (
    BootableImageSegment,
    Segment,
    SPSDKSegmentNotPresent,
    get_segment_class,
)
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import align, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


class BootableImage(BaseClass):
    """Bootable Image class."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        init_offset: Union[BootableImageSegment, int] = 0,
    ) -> None:
        """Bootable Image constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        :raises SPSDKValueError: Invalid family.
        """
        if family not in self.get_supported_families():
            raise SPSDKValueError(f"Unsupported family: {family}")
        self.family = family
        self.mem_type = mem_type
        self.revision = revision
        _bimg_descr: Dict[str, Any] = self.get_memory_type_config(family, mem_type, revision)
        self.image_pattern = _bimg_descr.get("image_pattern", "zeros")
        self._segments: List[Segment] = []
        for segment_name, segment_offset in _bimg_descr["segments"].items():
            self._segments.append(
                get_segment_class(BootableImageSegment.from_label(segment_name))(
                    offset=segment_offset, family=family, mem_type=mem_type, revision=revision
                )
            )

        self._init_offset: int = 0
        self.set_init_offset(init_offset)

    @property
    def segments(self) -> List[Segment]:
        """List of used segments."""
        return [seg for seg in self._segments if seg.is_present]

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

        def _get_segment_offset(segments: List[Segment], segment: Segment) -> int:
            if segment.full_image_offset >= 0:
                return segment.full_image_offset

            # It should be dynamically computed
            prev_seg: Optional[Segment] = None
            for seg in segments:
                if seg == segment:
                    if prev_seg == None:
                        raise SPSDKError(
                            "Cannot get dynamically offset of segment because"
                            " there is no any previous segment with static offset."
                        )
                    assert prev_seg
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

        assert False, "Cannot determine the size of bootable image header"

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
    def parse(
        cls,
        binary: bytes,
        family: Optional[str] = None,
        mem_type: Optional[str] = None,
        revision: str = "latest",
    ) -> "BootableImage":
        """Parse binary into bootable image object.

        :param binary: Bootable image binary.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        """
        if not family:
            raise SPSDKValueError("Family attribute must be specified.")
        mem_types = [mem_type] if mem_type else cls.get_supported_memory_types(family, revision)
        logger.debug(f"Parsing of bootable image for memory type(s): {','.join(mem_types)}")
        bimg_instances: List[BootableImage] = []
        # first try to find the exact match as it is a full bootable image
        for memory_type in mem_types:
            logger.debug(
                f"Parsing the image for memory type '{memory_type}' finding the exact match"
            )
            try:
                bimg = cls(family, memory_type, revision)
                bimg._parse(binary)
                bimg_instances.append(bimg)
            except SPSDKError as e:
                logger.debug(e)
                continue
        # try to parse bootable image with moving initial offset
        if not bimg_instances:
            logger.debug("The exact match has not been found")
            for memory_type in mem_types:
                bimg = cls(family, memory_type, revision)
                init_offsets = [seg.full_image_offset for seg in bimg._segments if seg.INIT_SEGMENT]
                for init_offset in init_offsets:
                    logger.debug(
                        f"Parsing the image for memory type '{memory_type}' with init offset 0x{init_offset:08X}"
                    )
                    try:
                        bimg = cls(family, memory_type, revision, init_offset)
                        bimg._parse(binary)
                        bimg_instances.append(bimg)
                    except SPSDKError as e:
                        logger.debug(e)
                        continue
        if not bimg_instances:
            raise SPSDKError(
                f"The image parsing failed. The image is not matching any of memory types: {', '.join(mem_types)}"
            )
        if len(bimg_instances) > 1:
            mem_types_str = ", ".join(f'"{img.mem_type}"' for img in bimg_instances)
            logger.warning(
                f"Multiple possible memory types detected: {mem_types_str}."
                f'The "{bimg_instances[0].mem_type}" memory type will be used.'
            )
        return bimg_instances[0]

    def __repr__(self) -> str:
        """Text short representation about the BootableImage."""
        return f"BootableImage, family:{self.family}, mem_type:{self.mem_type}"

    def __str__(self) -> str:
        """Text information about the BootableImage."""
        nfo = "BootableImage\n"
        nfo += f"  Family:      {self.family}\n"
        nfo += f"  Revision:    {self.revision}\n"
        nfo += f"  Memory Type: {self.mem_type}\n"
        if self.segments:
            nfo += "  Segments:\n"
        for segment in self.segments:
            nfo += f"      {segment}\n"
        return nfo

    @staticmethod
    def get_validation_schemas(
        family: str, mem_type: str, revision: str = "latest"
    ) -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: List of validation schema dictionaries.
        """
        bimg = BootableImage(family=family, mem_type=mem_type, revision=revision)
        sch_cfg = get_schema_file(DatabaseManager.BOOTABLE_IMAGE)
        sch_cfg["family_rev"]["properties"]["family"]["template_value"] = family
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = bimg.get_supported_revisions(
            family
        )
        sch_cfg["family_rev"]["properties"]["revision"]["template_value"] = revision
        sch_cfg["family_rev"]["properties"]["memory_type"]["template_value"] = mem_type
        schemas = [sch_cfg["family_rev"], sch_cfg["init_offset"]]
        for segment in bimg._segments:
            schemas.append(sch_cfg[segment.NAME.label])
        return schemas

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self.get_validation_schemas(self.family, self.mem_type, self.revision)
        config: Dict[str, Union[str, int]] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["memory_type"] = self.mem_type
        config["init_offset"] = self.init_offset
        for segment in self._segments:
            config[segment.cfg_key()] = segment.create_config(output)

        yaml = CommentedConfig(
            f"Bootable Image Configuration for {self.family}.", schemas
        ).get_config(config)

        write_file(
            yaml,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )

    @staticmethod
    def load_from_config(config: Dict, search_paths: Optional[List[str]] = None) -> "BootableImage":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, BootableImage.get_validation_schemas_family())
        family = config["family"]
        mem_type = config["memory_type"]
        revision = config.get("revision", "latest")
        init_offset = config.get("init_offset", 0)
        init_offset = (
            BootableImageSegment.from_label(init_offset)
            if isinstance(init_offset, str)
            else init_offset
        )
        bimg = BootableImage(
            family=family, mem_type=mem_type, revision=revision, init_offset=init_offset
        )
        schemas = bimg.get_validation_schemas(family, mem_type, revision)
        check_config(config, schemas, search_paths=search_paths)

        for segment in bimg._segments:
            try:
                segment.load_config(config, search_paths)
            except SPSDKSegmentNotPresent:
                segment.clear()
                continue

        return bimg

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        description = f"Memory type: {self.mem_type}\nRevision: {self.revision}"
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
    def get_validation_schemas_family() -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for Bootable Image supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.BOOTABLE_IMAGE)
        return [sch_cfg["family_rev"]]

    @classmethod
    def generate_config_template(cls, family: str, mem_type: str, revision: str = "latest") -> str:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Validation schema.
        """
        schemas = cls.get_validation_schemas(family, mem_type, revision)
        try:
            note = get_db(family, revision=revision).get_str(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", mem_type, "note"]
            )
        except SPSDKError:
            note = None
        return CommentedConfig(
            f"Bootable Image Configuration template for {family} / {mem_type}.", schemas, note=note
        ).get_template()

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        return get_families(DatabaseManager.BOOTABLE_IMAGE)

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[str] = None, revision: str = "latest"
    ) -> List[str]:
        """Return list of supported memory types.

        :return: List of supported families.
        """
        if family:
            database = get_db(family, revision)
            return list(database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types").keys())
        mem_types = []
        families = cls.get_supported_families()
        for supported_family in families:
            database = get_db(supported_family, revision)
            mem_types.extend(
                list(database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types").keys())
            )
        return list(set(mem_types))

    @classmethod
    def get_memory_type_config(
        cls, family: str, mem_type: str, revision: str = "latest"
    ) -> Dict[str, Any]:
        """Return dictionary with configuration for specific memory type.

        :raises SPSDKKeyError: If memory type does not exist in database
        :return: Dictionary with configuration.
        """
        if mem_type not in cls.get_supported_memory_types(family):
            raise SPSDKKeyError(f"Memory type not supported: {mem_type}")
        database = get_db(family, revision)
        mem_types = database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types")
        return mem_types[mem_type]

    @staticmethod
    def get_supported_revisions(family: str) -> List[str]:
        """Return list of supported revisions.

        :return: List of supported revisions.
        """
        return DatabaseManager().db.devices.get(family).revisions.revision_names(True)

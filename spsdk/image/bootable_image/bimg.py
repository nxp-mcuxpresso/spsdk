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

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.image.bootable_image.segments import Segment, get_segment_class
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


class BootableImage(BaseClass):
    """Bootable Image class."""

    def __init__(self, family: str, mem_type: str, revision: str = "latest") -> None:
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
        self.database = get_db(family, revision)
        self.revision = self.database.name
        self.mem_types = self.database.get_dict(DatabaseManager.BOOTABLE_IMAGE, "mem_types")
        if mem_type not in self.mem_types.keys():
            raise SPSDKValueError(f"Unsupported memory type: {mem_type}")
        self.bimg_descr: Dict[str, Any] = self.mem_types[self.mem_type]

        self.image_pattern = self.bimg_descr.get("image_pattern", "zeros")
        self.bimg_segments_descr: Dict[str, int] = self.bimg_descr["segments"]
        self.segments: List[Segment] = []

    def _parse(self, binary: bytes) -> None:
        """Parse binary and set internal members.

        :param binary: Bootable image binary.
        """
        self.segments.clear()
        bimg_segs: Dict[str, int] = self.bimg_segments_descr
        for name, offset in bimg_segs.items():
            seg_cls = get_segment_class(name)
            seg = seg_cls.parse(
                binary[offset:],
                family=self.family,
                mem_type=self.mem_type,
                revision=self.revision,
            )
            self.segments.append(seg)

    @classmethod
    def parse(
        cls,
        binary: bytes,
        family: Optional[str] = None,
        mem_type: Optional[str] = None,
        revision: str = "latest",
    ) -> Self:
        """Parse binary into bootable image object.

        :param binary: Bootable image binary.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        """
        if not family:
            raise SPSDKValueError("Family attribute must be specified.")
        bimg_instances: List[Self] = []
        mem_types = [mem_type] if mem_type else cls.get_supported_memory_types(family, revision)
        for mem_type in mem_types:
            image = cls(family, mem_type, revision)
            try:
                image._parse(binary)
                bimg_instances.append(image)
            except SPSDKError:
                continue
        if not bimg_instances:
            raise SPSDKError(
                f"The image is not matching any of memory types: {', '.join(mem_types)}"
            )
        bimg_instance = bimg_instances[0]
        if len(bimg_instances) > 1:
            mem_types_str = ", ".join(f'"{img.mem_type}"' for img in bimg_instances)
            logger.warning(
                f"Multiple possible memory types detected: {mem_types_str}."
                f'The "{bimg_instance.mem_type}" memory type will be used.'
            )
        return bimg_instance

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
        sch_cfg["family_rev"]["properties"]["family"]["enum"] = bimg.get_supported_families()
        sch_cfg["family_rev"]["properties"]["family"]["template_value"] = family
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = bimg.get_supported_revisions(
            family
        )
        sch_cfg["family_rev"]["properties"]["revision"]["template_value"] = revision
        sch_cfg["family_rev"]["properties"]["memory_type"][
            "enum"
        ] = bimg.get_supported_memory_types(family, revision)
        sch_cfg["family_rev"]["properties"]["memory_type"]["template_value"] = mem_type
        schemas = [sch_cfg["family_rev"]]
        for segment in bimg.bimg_segments_descr:
            schemas.append(sch_cfg[segment])
        return schemas

    def store_config(self, output: str) -> None:  # TODO refactor to get_config()->Dict[str,Any]:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self.get_validation_schemas(self.family, self.mem_type, self.revision)
        config: Dict[str, Union[str, int]] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["memory_type"] = self.mem_type
        for segment in self.segments:
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
        bimg = BootableImage(family=family, mem_type=mem_type, revision=revision)
        schemas = bimg.get_validation_schemas(family, mem_type, revision)
        check_config(config, schemas, search_paths=search_paths)
        for segment in bimg.bimg_segments_descr:
            bimg.segments.append(get_segment_class(segment).load_from_config(config, search_paths))
        return bimg

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}",
            size=0,
            pattern=BinaryPattern(self.image_pattern),
            description=f"Memory type: {self.mem_type}\nRevision: {self.revision}",
        )
        for segment in self.segments:
            if segment.raw_block:
                bin_image.add_image(
                    BinaryImage(
                        name=segment.NAME,
                        size=len(segment.raw_block),
                        offset=self.bimg_segments_descr[segment.NAME],
                        binary=segment.raw_block,
                    )
                )
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

        return CommentedConfig(
            f"Bootable Image Configuration template for {family}.", schemas
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
        else:
            mem_types = []
            families = cls.get_supported_families()
            for family in families:
                database = get_db(family, revision)
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

    @classmethod
    def get_supported_revisions(cls, family: str) -> List[str]:
        """Return list of supported revisions.

        :return: List of supported revisions.
        """
        return DatabaseManager().db.devices.get(family).revisions.revision_names(True)

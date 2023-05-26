#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""

import abc
import logging
import os
import re
import sys
from copy import deepcopy
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from spsdk.exceptions import SPSDKKeyError, SPSDKParsingError, SPSDKTypeError, SPSDKValueError
from spsdk.image.bootable_image import BIMG_DATABASE_FILE, BIMG_SCH_FILE
from spsdk.image.fcb.fcb import FCB
from spsdk.image.segments import FlexSPIConfBlockFCB, XMCDHeader
from spsdk.image.xmcd.xmcd import XMCD, ConfigurationBlockType, MemoryType
from spsdk.utils.database import Database
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config

logger = logging.getLogger(__name__)

BIMG_CLASSES = [
    "BootableImageRtxxx",
    "BootableImageLpc55s3x",
    "BootableImageRt101x",
    "BootableImageRt10xx",
    "BootableImageRt11xx",
    "BootableImageRt118x",
]


class EnumBimgSegments(str, Enum):
    """Bootable image segments."""

    KEYBLOB = "keyblob"
    FCB = "fcb"
    IMAGE_VERSION = "image_version"
    KEYSTORE = "keystore"
    APPLICATION = "application"
    BEE_HEADER_0 = "bee_header_0"
    BEE_HEADER_1 = "bee_header_1"
    XMCD = "xmcd"
    HAB_CONTAINER = "hab_container"
    AHAB_CONTAINER = "ahab_container"

    @staticmethod
    def get_segment_type(segment: "EnumBimgSegments") -> Type:
        """Get the output value type.

        :param segment: Bootable image segment
        :return: True is the segment output type is binary. False otherwise.
        """
        if segment == EnumBimgSegments.IMAGE_VERSION:
            return int
        return bytes


def convert_segment_value(value: bytes, output_type: Type) -> Any:
    """Convert value of segment into desired type.

    :param value: Segment value as bytes.
    :param output_type: Output type.
    :raises SPSDKTypeError: If given type is not supported
    :return: Converted value.
    """
    if output_type == int:
        return int.from_bytes(value, "little")
    if output_type == bytes:
        return value
    raise SPSDKTypeError(f"Unsupported output type {output_type}")


def get_bimg_class(family: str) -> Type["BootableImage"]:
    """Get the class that supports the family.

    :param family: Chip family
    :return: Bootable Image class.
    :raises SPSDKValueError: Invalid family.
    """
    for cls_name in BIMG_CLASSES:
        cls: Type["BootableImage"] = getattr(sys.modules[__name__], cls_name)
        if family in cls.get_supported_families():
            return cls
    raise SPSDKValueError(f"Unsupported family({family}) by Bootable Image.")


class BootableImage:
    """Bootable Image class."""

    IMAGE_PATTERN = BinaryPattern("zeros")

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
        self.revision = revision
        self.mem_type = mem_type
        self.database = Database(BIMG_DATABASE_FILE)
        self.mem_types: Dict = self.database.get_device_value("mem_types", family, revision)
        if mem_type not in self.mem_types.keys():
            raise SPSDKValueError(f"Unsupported memory type: {mem_type}")
        self.bimg_descr: Dict = self.mem_types[self.mem_type]

    @staticmethod
    @abc.abstractmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """

    def get_segment_size(self, segment: EnumBimgSegments) -> int:
        """Get size of segment. Return -1 if it is the last segment."""
        segments = {
            EnumBimgSegments.FCB: 512,
            EnumBimgSegments.BEE_HEADER_0: 512,
            EnumBimgSegments.BEE_HEADER_1: 512,
            EnumBimgSegments.KEYBLOB: 256,
            EnumBimgSegments.KEYSTORE: 2048,
            EnumBimgSegments.IMAGE_VERSION: 4,
            EnumBimgSegments.APPLICATION: -1,
            EnumBimgSegments.HAB_CONTAINER: -1,
            EnumBimgSegments.AHAB_CONTAINER: -1,
        }
        return segments[segment]

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        for segment in self.get_segments(self.mem_type):
            offset_from = self.bimg_descr[f"{segment.value}_offset"]
            offset_to = (
                offset_from + self.get_segment_size(segment)
                if self.get_segment_size(segment) != -1
                else None
            )
            value = binary[offset_from:offset_to]
            setattr(self, segment.value, value)

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
        bimg_cls = get_bimg_class(family)
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"]["enum"] = bimg_cls.get_supported_families()
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = bimg_cls.get_supported_revisions(
            family
        )

        sch_cfg["family_rev"]["properties"]["memory_type"][
            "enum"
        ] = bimg_cls.get_supported_memory_types(family, revision)
        schemas = [sch_cfg["family_rev"]]
        for segment in bimg_cls.get_segments(mem_type):
            schemas.append(sch_cfg[segment.value])
        return schemas

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self._get_validation_schemas()
        override: Dict[str, str] = {}
        override["family"] = self.family
        override["revision"] = self.revision
        override["memory_type"] = self.mem_type
        for segment in self.get_segments(self.mem_type):
            segment_value = getattr(self, segment.value)
            if segment_value is not None:
                segment_value = convert_segment_value(
                    segment_value, EnumBimgSegments.get_segment_type(segment)
                )
                if isinstance(segment_value, bytes):
                    override[segment.value] = f"{segment.value}.bin"
                else:
                    override[segment.value] = segment_value
            else:
                override[segment.value] = ""

        config = ConfigTemplate(
            f"Bootable Image Configuration for {self.family}.",
            schemas,
            override,
        ).export_to_yaml()
        write_file(
            config,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )
        for segment in self.get_segments(self.mem_type):
            segment_value = getattr(self, segment.value)
            if segment_value is not None:
                if EnumBimgSegments.get_segment_type(segment) == bytes:
                    write_file(
                        segment_value, os.path.join(output, f"{segment.value}.bin"), mode="wb"
                    )

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImage":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        bimg_cls = get_bimg_class(config["family"])
        check_config(config, cls.get_validation_schemas_family())
        chip_family = config["family"]
        mem_type = config["memory_type"]
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(chip_family, mem_type, revision)
        check_config(config, schemas, search_paths=search_paths)
        params = {"family": chip_family, "mem_type": mem_type, "revision": revision}
        for segment in bimg_cls.get_segments(mem_type):
            segment_value = config.get(segment.value)
            if EnumBimgSegments.get_segment_type(segment) == bytes:
                value = (
                    load_binary(segment_value, search_paths=search_paths) if segment_value else None
                )
            else:
                value = segment_value
            params[segment.value] = value
        return bimg_cls(**params)

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}", size=0, pattern=self.IMAGE_PATTERN
        )
        for segment in self.get_segments(self.mem_type):
            segment_value = getattr(self, segment.value)
            if segment_value:
                bin_image.add_image(
                    BinaryImage(
                        name=segment.value,
                        size=len(segment_value),
                        offset=self.bimg_descr[f"{segment.value}_offset"],
                        binary=segment_value,
                        parent=bin_image,
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
        sch_cfg = ValidationSchemas.get_schema_file(BIMG_SCH_FILE)
        return [sch_cfg["family_rev"]]

    def _get_validation_schemas(self) -> List[Dict[str, Any]]:
        """Get validation schema.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type, self.revision)

    @staticmethod
    def generate_config_template(family: str, mem_type: str, revision: str = "latest") -> str:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Validation schema.
        """
        schemas = BootableImage.get_validation_schemas(family, mem_type, revision)
        override = {}
        override["family"] = family
        override["revision"] = revision
        override["memory_type"] = mem_type

        return ConfigTemplate(
            f"Bootable Image Configuration template for {family}.",
            schemas,
            override,
        ).export_to_yaml()

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        return Database(BIMG_DATABASE_FILE).devices.device_names

    @staticmethod
    def get_supported_memory_types(family: str, revision: str = "latest") -> List[str]:
        """Return list of supported memory types.

        :return: List of supported families.
        """
        database = Database(BIMG_DATABASE_FILE)
        return list(database.get_device_value("mem_types", family, revision).keys())

    @staticmethod
    def get_memory_type_config(
        family: str, mem_type: str, revision: str = "latest"
    ) -> Dict[str, Any]:
        """Return dictionary with configuration for specific memory type.

        :raises SPSDKKeyError: If memory type does not exist in database
        :return: Dictionary with configuration.
        """
        if mem_type not in BootableImage.get_supported_memory_types(family):
            raise SPSDKKeyError(f"Memory type not supported: {mem_type}")
        database = Database(BIMG_DATABASE_FILE)
        mem_types: Dict = database.get_device_value("mem_types", family, revision)
        return mem_types[mem_type]

    @staticmethod
    def get_supported_revisions(family: str) -> List[str]:
        """Return list of supported revisions.

        :return: List of supported revisions.
        """
        database = Database(BIMG_DATABASE_FILE)
        revisions = ["latest"]
        revisions.extend(database.devices.get_by_name(family).revisions.revision_names)
        return revisions

    @classmethod
    def _load_bin_from_config(
        cls, config: Dict, config_key: str, search_paths: Optional[List[str]] = None
    ) -> Optional[bytes]:
        """Load the binary defined in condig file."""
        bin_path = config.get(config_key)
        if not bin_path or bin_path == "":
            return None
        return load_binary(bin_path, search_paths=search_paths)


class BootableImageRtxxx(BootableImage):
    """Bootable Image class for RTxxx devices."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        keyblob: Optional[bytes] = None,
        fcb: Optional[bytes] = None,
        image_version: Optional[int] = None,
        keystore: Optional[bytes] = None,
        application: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for RTxxx devices.

        :param keyblob: Key Blob block, defaults to None
        :param fcb: FCB block, defaults to None
        :param image_version: Image version number, defaults to 0
        :param keystore: Key store block, defaults to None
        :param app: Application block, defaults to None
        """
        super().__init__(family, mem_type, revision)
        self.keyblob = keyblob
        self.fcb = fcb
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)

        self.image_version = (image_version or 0).to_bytes(4, "little")
        self.keystore = keystore
        self.application = application

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        return [
            EnumBimgSegments.KEYBLOB,
            EnumBimgSegments.FCB,
            EnumBimgSegments.IMAGE_VERSION,
            EnumBimgSegments.KEYSTORE,
            EnumBimgSegments.APPLICATION,
        ]

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Complete binary of bootable image.
        """
        # first of all we need to identify where the image starts.
        # That could be determined by FCB block that start at zero offset
        # as some compilers do that, otherwise we assume standard start at zero offset
        start_block_offset = 0
        if binary[:4] == FlexSPIConfBlockFCB.TAG:
            start_block_offset = self.bimg_descr["fcb_offset"]

        # KeyBlob
        if start_block_offset == 0:
            offset = self.bimg_descr["keyblob_offset"]
            self.keyblob = binary[offset : offset + self.get_segment_size(EnumBimgSegments.KEYBLOB)]
        else:
            self.keyblob = None
        # FCB
        offset = self.bimg_descr["fcb_offset"] - start_block_offset
        self.fcb = binary[offset : offset + self.get_segment_size(EnumBimgSegments.FCB)]
        self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
        self.fcb_obj.parse(self.fcb)
        # Image version
        offset = self.bimg_descr["image_version_offset"] - start_block_offset
        self.image_version = binary[
            offset : offset + self.get_segment_size(EnumBimgSegments.IMAGE_VERSION)
        ]
        # KeyStore
        offset = self.bimg_descr["keystore_offset"] - start_block_offset
        self.keystore = binary[offset : offset + self.get_segment_size(EnumBimgSegments.KEYSTORE)]
        # application
        offset = self.bimg_descr["application_offset"] - start_block_offset
        self.application = binary[offset:]

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        full_list = BootableImage.get_supported_families()
        # filter out just RTxxx
        return [x for x in full_list if re.match(r"[rR][tT][\dxX]{3}$", x)]


class BootableImageLpc55s3x(BootableImage):
    """Bootable Image class for LPC55S3x devices."""

    IMAGE_PATTERN = BinaryPattern("ones")

    def __init__(
        self,
        family: str,
        mem_type: str = "flexspi_nor",
        revision: str = "latest",
        fcb: Optional[bytes] = None,
        image_version: Optional[int] = None,
        application: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for Lpc55s3x devices.

        :param mem_type: Used memory type.
        :param fcb: FCB block, defaults to None
        :param image_version: Image version number, defaults to 0
        :param app: Application block, defaults to None
        """
        assert mem_type == "flexspi_nor"
        super().__init__(family, mem_type, revision)
        self.fcb = fcb
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)

        image_version = (image_version or 0) & 0xFFFF
        image_version |= (image_version ^ 0xFFFF) << 16
        self.image_version = image_version.to_bytes(4, "little")
        self.application = application

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        return [
            EnumBimgSegments.FCB,
            EnumBimgSegments.IMAGE_VERSION,
            EnumBimgSegments.APPLICATION,
        ]

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Complete binary of bootable image.
        :raises SPSDKValueError: In case of invalid SW image version.
        """
        # first of all we need to identify where the image starts.
        # That could be determined by FCB block that start at zero offset
        # as some compilers do that, otherwise we assume standard start at zero offset
        start_block_offset = 0
        if binary[:4] == FlexSPIConfBlockFCB.TAG:
            start_block_offset = self.bimg_descr["fcb_offset"]

        # FCB
        offset = self.bimg_descr["fcb_offset"] - start_block_offset
        self.fcb = binary[offset : offset + self.get_segment_size(EnumBimgSegments.FCB)]
        self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
        self.fcb_obj.parse(self.fcb)
        # Image version
        offset = self.bimg_descr["image_version_offset"] - start_block_offset
        image_version = int.from_bytes(
            binary[offset : offset + self.get_segment_size(EnumBimgSegments.IMAGE_VERSION)],
            "little",
        )
        if image_version != 0xFFFFFFFF and (
            image_version & 0xFFFF != ((image_version >> 16) ^ 0xFFFF) & 0xFFFF
        ):
            raise SPSDKValueError("Invalid Image version loaded during parse of bootable image.")
        self.image_version = (image_version & 0xFFFF).to_bytes(4, "little")
        # application
        offset = self.bimg_descr["application_offset"] - start_block_offset
        self.application = binary[offset:]

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        full_list = BootableImage.get_supported_families()
        # filter out just LPC55S3x
        return [x for x in full_list if re.match(r"[lL][pP][cC]55[sS]3[\dxX]$", x)]


class BootableImageRt101x(BootableImage):
    """Bootable Image class for RT11x devices."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        keyblob: Optional[bytes] = None,
        fcb: Optional[bytes] = None,
        hab_container: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for RT1xxx devices.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        :param keyblob: BEE encryption header 0
        :param fcb: FCB block, defaults to None
        :param hab_container: Boot image container
        """
        super().__init__(family, mem_type, revision)
        self.keyblob = keyblob
        self.fcb = fcb
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)
        self.hab_container = hab_container

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        return [
            EnumBimgSegments.KEYBLOB,
            EnumBimgSegments.FCB,
            EnumBimgSegments.HAB_CONTAINER,
        ]

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        super().parse(binary)
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        return ["rt101x"]


class BootableImageRt10xx(BootableImage):
    """Bootable Image class for RT1xxx devices."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        bee_header_0: Optional[bytes] = None,
        bee_header_1: Optional[bytes] = None,
        fcb: Optional[bytes] = None,
        hab_container: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for RT1xxx devices.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        :param bee_header_0: BEE encryption header 0
        :param bee_header_1: BEE encryption header 1
        :param fcb: FCB block, defaults to None
        :param hab_container: Boot image container
        """
        super().__init__(family, mem_type, revision)
        self.bee_header_0 = bee_header_0
        self.bee_header_1 = bee_header_1
        self.fcb = fcb
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)
        self.hab_container = hab_container

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        return [
            EnumBimgSegments.FCB,
            EnumBimgSegments.BEE_HEADER_0,
            EnumBimgSegments.BEE_HEADER_1,
            EnumBimgSegments.HAB_CONTAINER,
        ]

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        super().parse(binary)
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        ignored = BootableImageRt101x.get_supported_families()
        full_list = BootableImage.get_supported_families()
        return [x for x in full_list if re.match(r"[rR][tT]10[\dxX]{2}$", x) and x not in ignored]


class BootableImageRt11xx(BootableImage):
    """Bootable Image class for RT1xxx devices."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        keyblob: Optional[bytes] = None,
        fcb: Optional[bytes] = None,
        keystore: Optional[bytes] = None,
        hab_container: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for RT1xxx devices.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        :param keyblob: Key Blob block, defaults to None
        :param fcb: FCB block, defaults to None
        :param keystore: Key store block, defaults to None
        :param hab_container: Boot image container
        """
        super().__init__(family, mem_type, revision)
        self.keyblob = keyblob
        self.fcb = fcb
        self.keystore = keystore
        self.fcb_obj = None
        if self.fcb is not None:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)
        self.hab_container = hab_container

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        segments = [EnumBimgSegments.HAB_CONTAINER]
        if mem_type == "flexspi_nor":
            segments.extend(
                [
                    EnumBimgSegments.KEYBLOB,
                    EnumBimgSegments.FCB,
                    EnumBimgSegments.KEYSTORE,
                ]
            )
        return segments

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        super().parse(binary)
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        full_list = BootableImage.get_supported_families()
        ignored = BootableImageRt118x.get_supported_families()
        # filter out just RT1xxx
        return [x for x in full_list if re.match(r"[rR][tT]11[\dxX]{2}$", x) and x not in ignored]


class BootableImageRt118x(BootableImage):
    """Bootable Image class for RT118x devices."""

    def __init__(
        self,
        family: str = "rt118x",
        mem_type: str = "flexspi_nor",
        revision: str = "latest",
        keyblob: Optional[bytes] = None,
        fcb: Optional[bytes] = None,
        xmcd: Optional[bytes] = None,
        ahab_container: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for Lpc55s3x devices.

        :param mem_type: Used memory type.
        :param fcb: FCB block, defaults to None
        :param image_version: Image version number, defaults to 0
        :param app: Application block, defaults to None
        """
        assert mem_type == "flexspi_nor"
        super().__init__(family, mem_type, revision)
        self.keyblob = keyblob
        self.fcb = fcb
        self.fcb_obj = None
        if self.fcb:
            self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
            self.fcb_obj.parse(self.fcb)
        self.xmcd = xmcd
        self.xmcd_obj = None
        if self.xmcd:
            self.xmcd_obj = XMCD(self.family, self.revision)
            self.xmcd_obj.parse(self.xmcd)
        self.ahab_container = ahab_container

    @staticmethod
    def get_segments(mem_type: str) -> List[EnumBimgSegments]:
        """Get list of image segments.

        :param mem_type: Used memory type.
        """
        return [
            EnumBimgSegments.KEYBLOB,
            EnumBimgSegments.FCB,
            EnumBimgSegments.XMCD,
            EnumBimgSegments.AHAB_CONTAINER,
        ]

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        super().store_config(output)
        if self.fcb_obj:
            write_file(self.fcb_obj.create_config(), os.path.join(output, "fcb.yaml"))
        if self.xmcd_obj:
            write_file(self.xmcd_obj.create_config(), os.path.join(output, "xmcd.yaml"))

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        # KeyBlob
        offset = self.bimg_descr["keyblob_offset"]
        self.keyblob = binary[offset : offset + self.get_segment_size(EnumBimgSegments.KEYBLOB)]
        # FCB
        offset = self.bimg_descr["fcb_offset"]
        self.fcb = binary[offset : offset + self.get_segment_size(EnumBimgSegments.FCB)]
        self.fcb_obj = FCB(self.family, self.mem_type, self.revision)
        self.fcb_obj.parse(self.fcb)
        # XMCD
        offset = self.bimg_descr["xmcd_offset"]
        size = self._get_xmcd_size(binary[offset : offset + XMCDHeader.SIZE])
        self.xmcd_obj
        if size > 0:
            self.xmcd = binary[offset:size]
            self.xmcd_obj = XMCD(self.family, self.revision)
            self.xmcd_obj.parse(self.xmcd)
        # AHAB container
        offset = self.bimg_descr["ahab_container_offset"]
        self.ahab_container = binary[offset:]

    def _get_xmcd_size(self, header_binary: bytes) -> int:
        try:
            header = XMCDHeader.parse(header_binary)
        except SPSDKParsingError:
            return 0
        mem_type = MemoryType.name(header.interface)
        config_type = ConfigurationBlockType.name(header.block_type)
        registers = XMCD.load_registers(self.family, mem_type, config_type, self.revision)
        return len(registers.image_info())

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of supported families.
        """
        return ["rt118x"]

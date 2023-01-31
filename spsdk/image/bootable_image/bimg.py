#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""

import abc
import inspect
import logging
import os
import re
import sys
from copy import deepcopy
from typing import Any, Dict, List, Optional, Type, Union

from spsdk.exceptions import SPSDKKeyError, SPSDKValueError
from spsdk.image.bootable_image import BIMG_DATABASE_FILE, BIMG_SCH_FILE
from spsdk.image.fcb.fcb import FCB
from spsdk.image.header import UnparsedException
from spsdk.image.images import BootImgRT
from spsdk.image.segments import (
    AbstractFCB,
    FlexSPIConfBlockFCB,
    PaddingFCB,
    SegAPP,
    SegBDT,
    SegBEE,
    SegCSF,
    SegDCD,
    SegIVT2,
    SegXMCD,
    XMCDHeader,
)
from spsdk.image.xmcd.xmcd import XMCD, ConfigurationBlockType, MemoryType
from spsdk.utils.database import Database
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import DebugInfo, find_first, load_binary, write_file
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config

logger = logging.getLogger(__name__)

BIMG_CLASSES = [
    "BootableImageRtxxx",
    "BootableImageLpc55s3x",
    "BootableImageRt1xxx",
    "BootableImageRt118x",
]


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

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImage":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        bimg_cls = get_bimg_class(config["family"])
        return bimg_cls.load_from_config(config, search_paths=search_paths)

    @abc.abstractmethod
    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """

    def export(self) -> bytes:
        """Export bootable image.

        :return: Complete binary of bootable image.
        """
        return self.image_info().export()

    @abc.abstractmethod
    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Complete binary of bootable image.
        """

    @abc.abstractmethod
    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """

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
        return self.get_validation_schemas(self.family)

    @staticmethod
    def get_validation_schemas(family: str) -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :return: List of validation schema dictionaries.
        """
        return get_bimg_class(family).get_validation_schemas(family)

    @staticmethod
    def generate_config_template(family: str, mem_type: str, revision: str = "latest") -> str:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Validation schema.
        """
        schemas = BootableImage.get_validation_schemas(family)
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
        image_version: int = 0,
        keystore: Optional[bytes] = None,
        app: Optional[bytes] = None,
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
        self.fcb = None
        if fcb:
            self.fcb = FCB(self.family, self.mem_type, self.revision)
            self.fcb.parse(fcb)

        self.image_version = image_version
        self.keystore = keystore
        self.app = app

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param revision: Chip revision specification, as default, latest is used.
        :return: List of validation schema dictionaries.
        """
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"][
            "enum"
        ] = BootableImageRtxxx.get_supported_families()
        sch_cfg["family_rev"]["properties"]["revision"][
            "enum"
        ] = BootableImageRtxxx.get_supported_revisions(family)
        sch_cfg["family_rev"]["properties"]["memory_type"][
            "enum"
        ] = BootableImageRtxxx.get_supported_memory_types(family, revision)
        sch_cfg["keyblob"]["properties"]["keyblob"][
            "template_title"
        ] = "Bootable Image blocks definition"
        ret = []
        for item in ["family_rev", "keyblob", "fcb", "image_version", "keystore", "application"]:
            ret.append(sch_cfg[item])
        return ret

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}", size=0, pattern=BinaryPattern("zeros")
        )
        if self.keyblob:
            bin_image.add_image(
                BinaryImage(
                    name="Key Blob",
                    size=self.bimg_descr["keyblob_len"],
                    offset=self.bimg_descr["keyblob_offset"],
                    binary=self.keyblob,
                    parent=bin_image,
                )
            )
        if self.fcb:
            bin_image.add_image(
                BinaryImage(
                    name="FCB",
                    size=self.bimg_descr["fcb_len"],
                    offset=self.bimg_descr["fcb_offset"],
                    binary=self.fcb.export(),
                    parent=bin_image,
                )
            )
        if self.image_version:
            bin_image.add_image(
                BinaryImage(
                    name="Image version",
                    size=self.bimg_descr["image_version_len"],
                    offset=self.bimg_descr["image_version_offset"],
                    description=f"Image version is {self.image_version}",
                    binary=self.image_version.to_bytes(4, "little"),
                    parent=bin_image,
                )
            )
        if self.keystore:
            bin_image.add_image(
                BinaryImage(
                    name="Key Store",
                    size=self.bimg_descr["keystore_len"],
                    offset=self.bimg_descr["keystore_offset"],
                    binary=self.keystore,
                    parent=bin_image,
                )
            )
        if self.app:
            bin_image.add_image(
                BinaryImage(
                    name="Application",
                    offset=self.bimg_descr["application_offset"],
                    binary=self.app,
                    parent=bin_image,
                )
            )

        return bin_image

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImageRtxxx":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        chip_family = config["family"]
        mem_type = config["memory_type"]
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(chip_family, revision)
        check_config(config, schemas, search_paths=search_paths)
        keyblob_path = config.get("keyblob")
        fcb_path = config.get("fcb")
        image_version = config.get("image_version", 0)
        keystore_path = config.get("keystore")
        app_path = config.get("application")
        keyblob = load_binary(keyblob_path, search_paths=search_paths) if keyblob_path else None
        fcb = load_binary(fcb_path, search_paths=search_paths) if fcb_path else None
        keystore = load_binary(keystore_path, search_paths=search_paths) if keystore_path else None
        app = load_binary(app_path, search_paths=search_paths) if app_path else None

        return BootableImageRtxxx(
            family=chip_family,
            mem_type=mem_type,
            revision=revision,
            keyblob=keyblob,
            fcb=fcb,
            image_version=image_version,
            keystore=keystore,
            app=app,
        )

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
            size = self.bimg_descr["keyblob_len"]
            self.keyblob = binary[offset : offset + size]
        else:
            self.keyblob = None
        # FCB
        offset = self.bimg_descr["fcb_offset"] - start_block_offset
        size = self.bimg_descr["fcb_len"]
        self.fcb = FCB(self.family, self.mem_type, self.revision)
        self.fcb.parse(binary[offset : offset + size])
        # Image version
        offset = self.bimg_descr["image_version_offset"] - start_block_offset
        size = self.bimg_descr["image_version_len"]
        self.image_version = int.from_bytes(binary[offset : offset + size], "little")
        # KeyStore
        offset = self.bimg_descr["keystore_offset"] - start_block_offset
        size = self.bimg_descr["keystore_len"]
        self.keystore = binary[offset : offset + size]
        # application
        offset = self.bimg_descr["application_offset"] - start_block_offset
        self.app = binary[offset:]

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self._get_validation_schemas()
        override: Dict[str, Union[str, int]] = {}
        override["family"] = self.family
        override["revision"] = self.revision
        override["memory_type"] = self.mem_type
        override["image_version"] = self.image_version
        override["keyblob"] = "keyblob.bin" if self.keyblob else ""
        override["fcb"] = "fcb.bin" if self.fcb else ""
        override["keystore"] = "keystore.bin" if self.keystore else ""
        override["application"] = "application.bin" if self.app else ""
        config = ConfigTemplate(
            f"Bootable Image Configuration for {self.family}.",
            schemas,
            override,
        ).export_to_yaml()
        write_file(
            config,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )
        if self.keyblob:
            write_file(self.keyblob, os.path.join(output, "keyblob.bin"), mode="wb")
        if self.fcb:
            write_file(self.fcb.export(), os.path.join(output, "fcb.bin"), mode="wb")
            write_file(self.fcb.create_config(), os.path.join(output, "fcb.yaml"))
        if self.keystore:
            write_file(self.keystore, os.path.join(output, "keystore.bin"), mode="wb")
        if self.app:
            write_file(self.app, os.path.join(output, "application.bin"), mode="wb")

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

    def __init__(
        self,
        family: str,
        mem_type: str = "flexspi_nor",
        revision: str = "latest",
        fcb: Optional[bytes] = None,
        image_version: int = 0,
        app: Optional[bytes] = None,
    ) -> None:
        """Bootable Image constructor for Lpc55s3x devices.

        :param mem_type: Used memory type.
        :param fcb: FCB block, defaults to None
        :param image_version: Image version number, defaults to 0
        :param app: Application block, defaults to None
        """
        assert mem_type == "flexspi_nor"
        super().__init__(family, mem_type, revision)
        self.fcb = None
        if fcb:
            self.fcb = FCB(self.family, self.mem_type, self.revision)
            self.fcb.parse(fcb)

        self.image_version = image_version
        self.app = app

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param revision: Chip revision specification, as default, latest is used.
        :return: List of validation schema dictionaries.
        """
        ret = []
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"][
            "enum"
        ] = BootableImageLpc55s3x.get_supported_families()
        revisions = ["latest"]
        revisions_device = BootableImageLpc55s3x.get_supported_revisions(family)
        revisions.extend(revisions_device)
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = revisions
        mem_types = BootableImageLpc55s3x.get_supported_memory_types(family, revision)
        sch_cfg["family_rev"]["properties"]["memory_type"]["enum"] = mem_types

        ret.append(sch_cfg["family_rev"])
        ret.append(sch_cfg["fcb"])
        ret.append(sch_cfg["image_version"])
        ret.append(sch_cfg["application"])
        return ret

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}", size=0, pattern=BinaryPattern("ones")
        )
        if self.fcb:
            bin_image.add_image(
                BinaryImage(
                    name="FCB",
                    size=self.bimg_descr["fcb_len"],
                    offset=self.bimg_descr["fcb_offset"],
                    binary=self.fcb.export(),
                    parent=bin_image,
                )
            )
        if self.image_version:
            data = self.image_version & 0xFFFF
            data |= (data ^ 0xFFFF) << 16
            bin_image.add_image(
                BinaryImage(
                    name="Image version",
                    size=self.bimg_descr["image_version_len"],
                    offset=self.bimg_descr["image_version_offset"],
                    description=f"Image version is {self.image_version}",
                    binary=data.to_bytes(4, "little"),
                    parent=bin_image,
                )
            )
        if self.app:
            bin_image.add_image(
                BinaryImage(
                    name="Application",
                    offset=self.bimg_descr["application_offset"],
                    binary=self.app,
                    parent=bin_image,
                )
            )

        return bin_image

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImageLpc55s3x":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        chip_family = config["family"]
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(chip_family, revision)
        check_config(config, schemas, search_paths=search_paths)
        fcb_path = config.get("fcb")
        image_version = config.get("image_version", 0)
        app_path = config.get("application")
        fcb = load_binary(fcb_path, search_paths=search_paths) if fcb_path else None
        app = load_binary(app_path, search_paths=search_paths) if app_path else None

        return BootableImageLpc55s3x(
            family=chip_family,
            revision=revision,
            fcb=fcb,
            image_version=image_version,
            app=app,
        )

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
        size = self.bimg_descr["fcb_len"]
        self.fcb = FCB(self.family, self.mem_type, self.revision)
        self.fcb.parse(binary[offset : offset + size])
        # Image version
        offset = self.bimg_descr["image_version_offset"] - start_block_offset
        size = self.bimg_descr["image_version_len"]
        image_version = int.from_bytes(binary[offset : offset + size], "little")
        if image_version != 0xFFFFFFFF and (
            image_version & 0xFFFF != ((image_version >> 16) ^ 0xFFFF) & 0xFFFF
        ):
            raise SPSDKValueError("Invalid Image version loaded during parse of bootable image.")
        self.image_version = image_version & 0xFFFF
        # application
        offset = self.bimg_descr["application_offset"] - start_block_offset
        self.app = binary[offset:]

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self._get_validation_schemas()
        override: Dict[str, Union[str, int]] = {}
        override["family"] = self.family
        override["revision"] = self.revision
        override["memory_type"] = self.mem_type
        override["image_version"] = self.image_version
        override["fcb"] = "fcb.bin" if self.fcb else ""
        override["application"] = "application.bin" if self.app else ""
        config = ConfigTemplate(
            f"Bootable Image Configuration for {self.family}.",
            schemas,
            override,
        ).export_to_yaml()
        write_file(
            config,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )
        if self.fcb:
            write_file(self.fcb.export(), os.path.join(output, "fcb.bin"), mode="wb")
            write_file(self.fcb.create_config(), os.path.join(output, "fcb.yaml"))
        if self.app:
            write_file(self.app, os.path.join(output, "application.bin"), mode="wb")

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        full_list = BootableImage.get_supported_families()
        # filter out just LPC55S3x
        return [x for x in full_list if re.match(r"[lL][pP][cC]55[sS]3[\dxX]$", x)]


class BootImgRtSegment(abc.ABC):
    """Base class for BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """Base class constructor."""
        self.boot_image = boot_image
        self.segment: Any = None

    @abc.abstractmethod
    def set_value(self, data: bytes) -> None:
        """Set value abstract method.

        :param data: Bytes data to set.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def is_defined(self) -> bool:
        """Is defined abstract property."""
        raise NotImplementedError()

    @property
    def offset(self) -> int:
        """Offset abstract property."""
        raise SPSDKValueError("Offset not defined")

    @property
    def size(self) -> int:
        """Get the size of the block."""
        return getattr(self.segment, "size")

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        export = getattr(self.segment, "export")
        return export()[: self.size]


class BootImgRtFcbSegment(BootImgRtSegment):
    """Wrapper of FCB BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT, segments_config: Dict) -> None:
        """FCB BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        :param segments_config: Additional configuration of segments
        """
        super().__init__(boot_image)
        self.segments_config = segments_config
        self.segment: AbstractFCB = self.boot_image.fcb

    def set_value(self, data: bytes) -> None:
        """Set value of FCB segment.

        :param data: Bytes data to set.
        """
        if data[:4] == FlexSPIConfBlockFCB.TAG:
            self.boot_image.fcb = FlexSPIConfBlockFCB.parse(data)
        else:
            fcb_len = len(data) if len(data) > 0 else BootImgRT.IVT_OFFSET_OTHER
            self.boot_image.fcb = PaddingFCB(fcb_len, enabled=True)

    @property
    def offset(self) -> int:
        """Get the offset of FCB block."""
        fcb_offset = self.segments_config.get("fcb_offset")
        if fcb_offset:
            return fcb_offset
        return self.boot_image.FCB_OFFSETS[0]

    @property
    def is_defined(self) -> bool:
        """Returns true if FCB block is defined. False otherwise."""
        return self.boot_image.fcb.size > 0

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        data = self.boot_image.export_fcb(DebugInfo.disabled())[: self.size]
        return data


class BootImgRtBeeSegment(BootImgRtSegment):
    """Wrapper of BEE BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """BEE BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: SegBEE = self.boot_image.bee

    def set_value(self, data: bytes) -> None:
        """Set value of BEE segment.

        :param data: Bytes data to set.
        """
        self.boot_image.bee = SegBEE.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of BEE block."""
        return BootImgRT.BEE_OFFSET

    @property
    def is_defined(self) -> bool:
        """Returns true if BEE block is defined. False otherwise."""
        return self.boot_image.bee.size > 0

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        data = self.boot_image.export_bee(DebugInfo.disabled())[: self.size]
        return data


class BootImgRtIvtSegment(BootImgRtSegment):
    """Wrapper of IVT BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """IVT BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: SegIVT2 = self.boot_image.ivt

    def set_value(self, data: bytes) -> None:
        """Set value of IVT segment.

        :param data: Bytes data to set.
        """
        self.boot_image.ivt = SegIVT2.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of IVT block."""
        return BootImgRT.IVT_OFFSET_NOR_FLASH

    @property
    def is_defined(self) -> bool:
        """Returns true if IVT block is defined. False otherwise."""
        return self.boot_image.ivt.size > 0


class BootImgRtBdiSegment(BootImgRtSegment):
    """Wrapper of BDI BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """BDI BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: SegBDT = self.boot_image.bdt

    def set_value(self, data: bytes) -> None:
        """Set value of Bdi segment.

        :param data: Bytes data to set.
        """
        self.boot_image.bdt = SegBDT.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of IVT block."""
        return (
            self.boot_image.ivt.bdt_address
            - self.boot_image.ivt.ivt_address
            + self.boot_image.ivt_offset
        )

    @property
    def is_defined(self) -> bool:
        """Returns true if BDI block is defined. False otherwise."""
        return self.boot_image.bdt.size > 0


class BootImgRtDcdSegment(BootImgRtSegment):
    """Wrapper of DCD BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """DCD BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: Optional[SegDCD] = self.boot_image.dcd

    def set_value(self, data: bytes) -> None:
        """Set value of Dcd segment.

        :param data: Bytes data to set.
        """
        self.boot_image.dcd = SegDCD.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of DCD block."""
        return (
            self.boot_image.ivt.dcd_address
            - self.boot_image.ivt.ivt_address
            + self.boot_image.ivt_offset
        )

    @property
    def is_defined(self) -> bool:
        """Returns true if block is defined. False otherwise."""
        return self.boot_image.dcd is not None and self.boot_image.dcd.size > 0

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        data = self.boot_image.export_dcd(DebugInfo.disabled())[: self.size]
        return data


class BootImgRtAppSegment(BootImgRtSegment):
    """Wrapper of App BootImgRT segment ."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """App BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: SegAPP = self.boot_image.app

    def set_value(self, data: bytes) -> None:
        """Set value of App segment.

        :param data: Bytes data to set.
        """
        self.boot_image.app.data = data

    @property
    def offset(self) -> int:
        """Get the offset of App block."""
        return self.boot_image.app_offset

    @property
    def is_defined(self) -> bool:
        """Returns True if block is defined. False otherwise."""
        return self.boot_image.app.size > 0


class BootImgRtXmcdSegment(BootImgRtSegment):
    """Wrapper of XMCD BootImgRT segment."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """XMCD BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: Optional[SegXMCD] = self.boot_image.xmcd

    def set_value(self, data: bytes) -> None:
        """Set value of XMCD segment.

        :param data: Bytes data to set.
        """
        self.boot_image.xmcd = SegXMCD.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of XMCD block."""
        return self.boot_image.ivt_offset + self.boot_image.XMCD_IVT_OFFSET

    @property
    def is_defined(self) -> bool:
        """Returns True if block is defined. False otherwise."""
        return self.boot_image.xmcd is not None

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        data = b""
        if self.boot_image.xmcd:
            data = self.boot_image.xmcd.export()
        return data


class BootImgRtCsfSegment(BootImgRtSegment):
    """Wrapper of CSF BootImgRT segment."""

    def __init__(self, boot_image: BootImgRT) -> None:
        """CSF BootImgRT segment constructor.

        :param boot_image: Instance of BootImgRT.
        """
        super().__init__(boot_image)
        self.segment: Optional[SegCSF] = self.boot_image.csf

    def set_value(self, data: bytes) -> None:
        """Set value of CSF segment.

        :param data: Bytes data to set.
        """
        self.boot_image.csf = SegCSF.parse(data)

    @property
    def offset(self) -> int:
        """Get the offset of CSF block."""
        return (
            self.boot_image.ivt.csf_address
            - self.boot_image.ivt.ivt_address
            + self.boot_image.ivt_offset
        )

    @property
    def is_defined(self) -> bool:
        """Returns True if block is defined. False otherwise."""
        return self.boot_image.csf is not None and self.boot_image.csf.size > 0

    def export(self) -> bytes:
        """Export data of given block as bytes object."""
        data = b""
        if self.boot_image.csf:
            data = self.boot_image.csf.export()
        return data


class BootImgRTSegmentsFactory:
    """Factory class for BootImgRT segments."""

    BOOT_IMAGE_SEGMENTS: Dict[str, Type[BootImgRtSegment]] = {
        "fcb": BootImgRtFcbSegment,
        "bee": BootImgRtBeeSegment,
        "ivt": BootImgRtIvtSegment,
        "bdi": BootImgRtBdiSegment,
        "xmcd": BootImgRtXmcdSegment,
        "dcd": BootImgRtDcdSegment,
        "application": BootImgRtAppSegment,
        "csf": BootImgRtCsfSegment,
    }

    def __init__(self, boot_image: BootImgRT) -> None:
        """Factory class constructor.

        :param boot_image: Instance of BootImgRT.
        :param segments_config: Additional configuration of segments.
        """
        self.boot_image = boot_image

    def get_segment(self, name: str, segments_config: Optional[Dict] = None) -> BootImgRtSegment:
        """Get instance of segment by given name.

        :param name: Name of segment.
        :param segments_config: Additional configuration of segments.
        :raises SPSDKValueError: If segments_config value is missing for segment with required segments_config parameter
        """
        try:
            segment = self.BOOT_IMAGE_SEGMENTS[name]
        except KeyError:
            logger.debug(f"Segment {name} is not recognized as valid segment.")
        init_signature = inspect.signature(segment.__init__)
        kwargs = {}
        if "segments_config" in init_signature.parameters:
            if not segments_config:
                raise SPSDKValueError(f"Segments config must be speecified for segment {name}")
            kwargs["segments_config"] = segments_config
        return segment(self.boot_image, **kwargs)

    def get_all_segments(
        self, segments_config: Optional[Dict] = None
    ) -> Dict[str, BootImgRtSegment]:
        """Get instances of all segments.

        :param segments_config: Additional configuration of segments.
        """
        segments = {}
        for name in self.BOOT_IMAGE_SEGMENTS:
            segments[name] = self.get_segment(name, segments_config)
        return segments

    @staticmethod
    def get_all_segment_names() -> List[str]:
        """Get list of all segment names."""
        return list(BootImgRTSegmentsFactory.BOOT_IMAGE_SEGMENTS.keys())


class BootableImageRt1xxx(BootableImage):
    """Bootable Image class for RT1xxx devices."""

    DEFAULT_IMAGE_VERSION = BootImgRT.VERSIONS[0]

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        image_version: int = DEFAULT_IMAGE_VERSION,
        **segments: bytes,
    ) -> None:
        """Bootable Image constructor for RT1xxx devices.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Chip silicon revision.
        :param image_version: Image version number, defaults to 0
        """
        super().__init__(family, mem_type, revision)
        self.image_version = image_version
        self.boot_image = BootImgRT(
            0,
            version=image_version,
        )
        self.segments = segments
        self.bimg_descr: Dict = self.mem_types[self.mem_type]
        self.segment_factory = BootImgRTSegmentsFactory(self.boot_image)
        for name, value in segments.items():
            if value is not None:
                segment = self.segment_factory.get_segment(name, self.bimg_descr)
                segment.set_value(value)
        # Construct the FCB object so the yaml can be exported
        self.fcb = None
        if segments.get("fcb") is not None:
            self.fcb = FCB(self.family, self.mem_type, self.revision)
            self.fcb.parse(segments["fcb"])

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :raises SPSDKKeyError: If given item is not defined in validation schema.
        :return: List of validation schema dictionaries.
        """
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"][
            "enum"
        ] = BootableImageRt1xxx.get_supported_families()
        sch_cfg["family_rev"]["properties"]["revision"][
            "enum"
        ] = BootableImageRt1xxx.get_supported_revisions(family)
        sch_cfg["family_rev"]["properties"]["memory_type"][
            "enum"
        ] = BootableImageRt1xxx.get_supported_memory_types(family, revision)
        sch_cfg["fcb"]["properties"]["fcb"]["template_title"] = "Bootable Image blocks definition"
        ret = []
        schema_items = [
            "family_rev",
            "image_version",
        ] + BootImgRTSegmentsFactory.get_all_segment_names()
        for item in schema_items:
            try:
                ret.append(sch_cfg[item])
            except KeyError as e:
                raise SPSDKKeyError(
                    f"Item {item} not defined in validation schema {BIMG_SCH_FILE}"
                ) from e
        return ret

    def export(self) -> bytes:
        """Export bootable image.

        :return: Complete binary of bootable image.
        """
        return self.image_info().export()

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}", size=0, pattern=BinaryPattern("zeros")
        )
        segments = self.segment_factory.get_all_segments(self.bimg_descr)
        for name, seg_instance in segments.items():
            if seg_instance.is_defined:
                bin_image.add_image(
                    BinaryImage(
                        name=name.upper(),
                        size=seg_instance.size,
                        offset=seg_instance.offset,
                        binary=seg_instance.export(),
                        parent=bin_image,
                    )
                )
        return bin_image

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImageRt1xxx":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(config["family"], revision)
        check_config(config, schemas, search_paths=search_paths)
        segments: Dict[str, Any] = {}
        for name in BootImgRTSegmentsFactory.get_all_segment_names():
            segments[name] = cls._load_bin_from_config(config, name, search_paths)
        return BootableImageRt1xxx(
            family=config["family"],
            mem_type=config["memory_type"],
            revision=revision,
            image_version=config.get("image_version", cls.DEFAULT_IMAGE_VERSION),
            **segments,
        )

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Complete binary of bootable image.
        """
        self.boot_image = self.boot_image.parse(binary)
        self.image_version = self.boot_image.ivt.version
        self.boot_image._update()
        self.segment_factory = BootImgRTSegmentsFactory(self.boot_image)
        debug_disabled = DebugInfo.disabled()
        if self.boot_image.fcb.enabled:
            data = self.boot_image.export_fcb(debug_disabled)
            self.fcb = FCB(self.family, self.mem_type, self.revision)
            self.fcb.parse(data[: self.boot_image.fcb.size])

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self._get_validation_schemas()
        override: Dict[str, Union[str, int]] = {}
        override["family"] = self.family
        override["revision"] = self.revision
        override["memory_type"] = self.mem_type
        override["image_version"] = self.image_version
        segments = self.segment_factory.get_all_segments(self.bimg_descr)
        # Write binaries
        for name, seg_instance in segments.items():
            override[name] = ""
            if seg_instance.is_defined:
                override[name] = self.get_validation_schema_template(schemas, name)
                write_file(
                    seg_instance.export(),
                    os.path.join(output, self.get_validation_schema_template(schemas, name)),
                    mode="wb",
                )
        # Write YAMLs
        config = ConfigTemplate(
            f"Bootable Image Configuration for {self.family}.",
            schemas,
            override,
        ).export_to_yaml()
        write_file(
            config,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )
        if self.fcb:
            write_file(self.fcb.create_config(), os.path.join(output, "fcb.yaml"))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of families.
        """
        full_list = BootableImage.get_supported_families()
        ignored = ["rt118x"]
        # filter out just RT1xxx
        return [x for x in full_list if re.match(r"[rR][tT]1[\dxX]{3}$", x) and x not in ignored]

    @staticmethod
    def get_validation_schema_template(schemas: List[Dict[str, Any]], property_name: str) -> str:
        """Get the template value from validation schema for specific.

        :param schemas: Validation schemas.
        :param property_name: name of propetry to be searched.
        :raises SPSDKKeyError: If property with given name does nto exist.
        """
        prop = find_first(schemas, lambda x: property_name in x["properties"])
        if not prop:
            raise SPSDKKeyError(f"A property {property_name} is not defined in validation schemas")
        return prop["properties"][property_name]["template_value"]


class BootableImageRt118x(BootableImage):
    """Bootable Image class for RT1180 devices."""

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
        self.fcb = None
        if fcb:
            self.fcb = FCB(self.family, self.mem_type, self.revision)
            self.fcb.parse(fcb)
        self.xmcd = None
        if xmcd:
            self.xmcd = XMCD(self.family, self.revision)
            self.xmcd.parse(xmcd)
        self.ahab_container = ahab_container

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param revision: Chip revision specification, as default, latest is used.
        :return: List of validation schema dictionaries.
        """
        ret = []
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"][
            "enum"
        ] = BootableImageRt118x.get_supported_families()
        revisions = ["latest"]
        revisions_device = BootableImageRt118x.get_supported_revisions(family)
        revisions.extend(revisions_device)
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = revisions
        mem_types = BootableImageRt118x.get_supported_memory_types(family, revision)
        sch_cfg["family_rev"]["properties"]["memory_type"]["enum"] = mem_types

        ret.append(sch_cfg["family_rev"])
        ret.append(sch_cfg["keyblob"])
        ret.append(sch_cfg["fcb"])
        ret.append(sch_cfg["xmcd"])
        ret.append(sch_cfg["ahab_container"])
        return ret

    def image_info(self) -> BinaryImage:
        """Create Binary image of bootable image.

        :return: BinaryImage object of bootable image.
        """
        bin_image = BinaryImage(
            name=f"Bootable Image for {self.family}", size=0, pattern=BinaryPattern("zeros")
        )
        if self.keyblob:
            bin_image.add_image(
                BinaryImage(
                    name="Key Blob",
                    size=len(self.keyblob),
                    offset=self.bimg_descr["keyblob_offset"],
                    binary=self.keyblob,
                    parent=bin_image,
                )
            )
        if self.fcb:
            bin_image.add_image(
                BinaryImage(
                    name="FCB",
                    size=len(self.fcb.registers.image_info()),
                    offset=self.bimg_descr["fcb_offset"],
                    binary=self.fcb.export(),
                    parent=bin_image,
                )
            )
        if self.xmcd:
            bin_image.add_image(
                BinaryImage(
                    name="XMCD",
                    size=len(self.xmcd.registers.image_info()),
                    offset=self.bimg_descr["xmcd_offset"],
                    binary=self.xmcd.export(),
                    parent=bin_image,
                )
            )
        if self.ahab_container:
            bin_image.add_image(
                BinaryImage(
                    name="AHAB Container",
                    offset=self.bimg_descr["ahab_container_offset"],
                    binary=self.ahab_container,
                    parent=bin_image,
                )
            )
        return bin_image

    @classmethod
    def load_from_config(
        cls, config: Dict, search_paths: Optional[List[str]] = None
    ) -> "BootableImageRt118x":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        chip_family = config["family"]
        mem_type = config["memory_type"]
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(chip_family, revision)
        check_config(config, schemas, search_paths=search_paths)
        keyblob_path = config.get("keyblob")
        fcb_path = config.get("fcb")
        xmcd_path = config.get("xmcd")
        ahab_container_path = config.get("ahab_container")
        keyblob = load_binary(keyblob_path, search_paths=search_paths) if keyblob_path else None
        fcb = load_binary(fcb_path, search_paths=search_paths) if fcb_path else None
        xmcd = load_binary(xmcd_path, search_paths=search_paths) if xmcd_path else None
        ahab_container = (
            load_binary(ahab_container_path, search_paths=search_paths)
            if ahab_container_path
            else None
        )
        return BootableImageRt118x(
            family=chip_family,
            mem_type=mem_type,
            revision=revision,
            keyblob=keyblob,
            fcb=fcb,
            xmcd=xmcd,
            ahab_container=ahab_container,
        )

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Full binary of bootable image.
        """
        # KeyBlob
        offset = self.bimg_descr["keyblob_offset"]
        size = self.bimg_descr["keyblob_len"]
        self.keyblob = binary[offset : offset + size]
        # FCB
        offset = self.bimg_descr["fcb_offset"]
        size = self.bimg_descr["fcb_len"]
        self.fcb = FCB(self.family, self.mem_type, self.revision)
        self.fcb.parse(binary[offset : offset + size])
        # XMCD
        offset = self.bimg_descr["xmcd_offset"]
        size = self._get_xmcd_size(binary[offset : offset + XMCDHeader.SIZE])
        if size > 0:
            self.xmcd = XMCD(self.family, self.revision)
            self.xmcd.parse(binary[offset:size])
        # AHAB container
        offset = self.bimg_descr["ahab_container_offset"]
        self.ahab_container = binary[offset:]

    def _get_xmcd_size(self, header_binary: bytes) -> int:
        try:
            header = XMCDHeader.parse(header_binary)
        except UnparsedException:
            return 0
        mem_type = MemoryType(header.interface).name.lower()
        config_type = ConfigurationBlockType(header.block_type).name.lower()
        registers = XMCD.load_registers(self.family, mem_type, config_type, self.revision)
        return len(registers.image_info())

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """
        schemas = self._get_validation_schemas()
        override: Dict[str, str] = {}
        override["family"] = self.family
        override["revision"] = self.revision
        override["memory_type"] = self.mem_type
        override["keyblob"] = "keyblob.bin" if self.keyblob else ""
        override["fcb"] = "fcb.bin" if self.fcb else ""
        override["xmcd"] = "xmcd.bin" if self.xmcd else ""
        override["ahab_container"] = "ahab_container.bin" if self.ahab_container else ""
        config = ConfigTemplate(
            f"Bootable Image Configuration for {self.family}.",
            schemas,
            override,
        ).export_to_yaml()
        write_file(
            config,
            os.path.join(output, f"bootable_image_{self.family}_{self.mem_type}.yaml"),
        )
        if self.keyblob:
            write_file(self.keyblob, os.path.join(output, "keyblob.bin"), mode="wb")
        if self.fcb:
            write_file(self.fcb.export(), os.path.join(output, override["fcb"]), mode="wb")
            write_file(self.fcb.create_config(), os.path.join(output, "fcb.yaml"))
        if self.xmcd:
            write_file(self.xmcd.export(), os.path.join(output, override["xmcd"]), mode="wb")
            write_file(self.xmcd.create_config(), os.path.join(output, "xmcd.yaml"))
        if self.ahab_container:
            write_file(
                self.ahab_container, os.path.join(output, override["ahab_container"]), mode="wb"
            )

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of all supported families by bootable image.

        :return: List of supported families.
        """
        return ["rt118x"]

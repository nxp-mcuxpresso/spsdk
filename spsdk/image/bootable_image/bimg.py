#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""

import os
import re
import sys
from copy import deepcopy
from typing import Any, Dict, List, Type, Union

from spsdk.exceptions import SPSDKValueError
from spsdk.image.bootable_image import BIMG_DATABASE_FILE, BIMG_SCH_FILE
from spsdk.image.fcb.fcb import FCB
from spsdk.utils.database import Database
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import load_binary, write_file
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config

BIMG_CLASSES = ["BootableImageRtxxx"]


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
    def load_from_config(cls, config: Dict, search_paths: List[str] = None) -> "BootableImage":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        bimg_cls = get_bimg_class(config["family"])
        return bimg_cls.load_from_config(config, search_paths=search_paths)

    def store_config(self, output: str) -> None:
        """Store bootable image into configuration and binary blocks.

        :param output: Path to output folder to store bootable image configuration.
        """

    def export(self) -> bytes:
        """Export bootable image.

        :return: Complete binary of bootable image.
        """
        return self.image_info().export()

    def parse(self, binary: bytes) -> None:
        """Parse binary into bootable image object.

        :param binary: Complete binary of bootable image.
        """

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
        return self.get_validation_schemas(self.family, self.mem_type, self.revision)

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
        return get_bimg_class(family).get_validation_schemas(family, mem_type, revision)

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
        return Database(BIMG_DATABASE_FILE).get_devices()

    @staticmethod
    def get_supported_memory_types(family: str, revision: str = "latest") -> List[str]:
        """Return list of supported memory types.

        :return: List of supported families.
        """
        database = Database(BIMG_DATABASE_FILE)
        return list(database.get_device_value("mem_types", family, revision).keys())


class BootableImageRtxxx(BootableImage):
    """Bootable Image class for RTxxx devices."""

    def __init__(
        self,
        family: str,
        mem_type: str,
        revision: str = "latest",
        keyblob: bytes = None,
        fcb: bytes = None,
        image_version: int = 0,
        keystore: bytes = None,
        app: bytes = None,
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
    def get_validation_schemas(
        family: str, mem_type: str, revision: str = "latest"
    ) -> List[Dict[str, Any]]:
        """Get validation schema for the family.

        :param family: Chip family
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: List of validation schema dictionaries.
        """
        ret = []
        bimg_obj = BootableImageRtxxx(family, mem_type, revision)
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(BIMG_SCH_FILE))
        sch_cfg["family_rev"]["properties"]["family"][
            "enum"
        ] = BootableImageRtxxx.get_supported_families()
        revisions = ["latest"]
        revisions.extend(bimg_obj.database.get_revisions(family))
        sch_cfg["family_rev"]["properties"]["revision"]["enum"] = revisions
        sch_cfg["family_rev"]["properties"]["memory_type"]["enum"] = list(bimg_obj.mem_types.keys())

        ret.append(sch_cfg["family_rev"])
        sch_cfg["keyblob"]["properties"]["keyblob"][
            "template_title"
        ] = "Bootable Image blocks definition"
        ret.append(sch_cfg["keyblob"])
        ret.append(sch_cfg["fcb"])
        ret.append(sch_cfg["image_version"])
        ret.append(sch_cfg["keystore"])
        ret.append(sch_cfg["application"])
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
    def load_from_config(cls, config: Dict, search_paths: List[str] = None) -> "BootableImageRtxxx":
        """Load bootable image from configuration.

        :param config: Configuration of Bootable image.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        check_config(config, cls.get_validation_schemas_family())
        chip_family = config["family"]
        mem_type = config["memory_type"]
        revision = config.get("revision", "latest")
        schemas = cls.get_validation_schemas(chip_family, mem_type, revision)
        check_config(config, schemas)
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
        fcb_block_mark = self.bimg_descr["fcb_mark"]
        if binary[:4] == fcb_block_mark:
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

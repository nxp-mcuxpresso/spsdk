#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Fault Analysis Mode certificate."""

import logging
import os
import struct
from typing import Any, Type

from typing_extensions import Self

import spsdk
from spsdk.exceptions import SPSDKError
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import write_file

logger = logging.getLogger(__name__)


class FaModeImage(FeatureBaseClass):
    """Fault Analysis Mode certificate class."""

    FEATURE = DatabaseManager.DAT
    SUB_FEATURE = "famode_cert"

    FAMODE_DATA_SIZE = 64
    FAMODE_DATA_FORMAT = "<LL56s"

    def __init__(self, family: FamilyRevision, image: MasterBootImage) -> None:
        """Constructor of Fault Analysis Image.

        :param family: The CPU family
        :param image: The MBI FA mode image
        """
        self.family = family
        self.mbi = image

    def __repr__(self) -> str:
        """Class representation text."""
        return f"Fault Analysis Mode Image for {self.family}"

    def __str__(self) -> str:
        """Class representation text."""
        ret = repr(self)
        ret += "\n" + str(self.mbi)
        return ret

    @classmethod
    def pre_check_config(cls, config: Config) -> None:
        """Check the input configuration.

        :param config: Feature configuration.
        :raises SPSDKError: In case of invalid configuration.
        """
        mbi_config = cls._modify_input_config(config)
        mbi_cls = MasterBootImage.get_mbi_class(mbi_config)
        mbi_cls.pre_check_config(config=mbi_config)

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mbi_class_name: str = "signed_xip"
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """

        def find_schema(key: str, schemas: list[dict[str, Any]]) -> dict[str, Any]:
            for schema in schemas:
                p: dict[str, Any] = schema["properties"]
                if key in p:
                    return schema
            raise SPSDKError("Non existing schema")

        # 1: Generate all configuration for FAMode Image
        db = get_db(family)
        famode_cfg_defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults", {})
        mbi_classes = cls.get_famode_classes(family)
        # Get signed as a good example
        schemas = mbi_classes[mbi_class_name].get_validation_schemas(family)
        update_validation_schema_family(
            sch=schemas[0]["properties"], devices=cls.get_supported_families(), family=family
        )
        find_schema("outputImageAuthenticationType", schemas)["properties"][
            "outputImageAuthenticationType"
        ]["enum"] = [
            "signed",
            "signed-nxp",
            "nxp_signed",
        ]
        find_schema("outputImageAuthenticationType", schemas)["properties"][
            "outputImageAuthenticationType"
        ]["template_value"] = mbi_class_name
        find_schema("masterBootOutputFile", schemas)["properties"]["masterBootOutputFile"][
            "template_value"
        ] = "famode.bin"

        for cfg_to_remove in famode_cfg_defaults.keys():
            try:
                sch = find_schema(cfg_to_remove, schemas)
            except SPSDKError:
                continue
            properties: dict[str, Any] = sch["properties"]
            if cfg_to_remove in properties:
                properties.pop(cfg_to_remove)
            if "required" in sch:
                required: list[str] = sch["required"]
                if cfg_to_remove in required:
                    required.remove(cfg_to_remove)

        return schemas

    @staticmethod
    def get_famode_classes(family: FamilyRevision) -> dict[str, Type["MasterBootImage"]]:
        """Get all Master Boot Image supported classes for chip family.

        :param family: Chip family.
        :raises SPSDKValueError: The invalid family.
        :return: Dictionary with key like image name and values are Tuple with it's MBI Class
            and target and authentication type.
        """
        db = get_db(family)
        ret: dict[str, Type["MasterBootImage"]] = {}

        images: list[str] = db.get_list(DatabaseManager.DAT, "famode_cert")

        for cls_name in images:
            ret[f"{cls_name}"] = MasterBootImage.create_mbi_class(cls_name, family)

        return ret

    @classmethod
    def _modify_input_config(cls, config: Config) -> Config:
        """Modify the input config to fit for FA MOde Image simplification against MBI.

        :param config: Input configuration.
        :return: Output Modified Configuration.
        """
        family = FamilyRevision.load_from_config(config)
        db = get_db(family)
        # Update defaults values for FA Mode Image
        if db.check_key(DatabaseManager.DAT, "famode_cfg_defaults"):
            defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults")
            for k, v in defaults.items():
                if v is None:
                    if k in config:
                        config.pop(k)
                else:
                    config[k] = v

        # Generate and store the data block (~application)
        socc = db.get_int(DatabaseManager.DAT, "socc")
        srk_set = 2 if "nxp" in config["outputImageAuthenticationType"] else 1
        data = struct.pack(cls.FAMODE_DATA_FORMAT, socc, srk_set, bytes(56))
        filename = os.path.join(spsdk.SPSDK_PLATFORM_DIRS.user_runtime_dir, "famode_data.bin")
        logger.debug(f"FAMode data binary path: {filename}")
        write_file(data, filename, "wb")
        config["inputImageFile"] = filename
        return config

    def check_famode_data(self) -> None:  # TODO Make a verifier
        """Check if the data are in FA mode format.

        :raises SPSDKError: In case that the data are not in FA mode format.
        """
        assert isinstance(self.mbi.app, bytes)
        socc, srk_set, fill = struct.unpack(self.FAMODE_DATA_FORMAT, self.mbi.app)
        db = get_db(self.family)
        req_socc = db.get_int(DatabaseManager.DAT, "socc")
        if socc != req_socc:
            raise SPSDKError(
                f"Invalid SOCC in FA mode data for {self.family}: 0x{socc:08X} != {req_socc:08X}"
            )
        if srk_set != (2 if "nxp" in self.mbi.IMAGE_TYPE.label.lower() else 1):
            raise SPSDKError(f"Invalid SRK set (OEM/NXP) in FA mode data: {srk_set}")
        if fill != bytes(56):
            raise SPSDKError("Invalid fill in FA mode data, should be all zeros!")

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load feature object from configuration.

        :param config: Configuration dictionary.
        :return: Initialized feature object.
        """
        modified_cfg = cls._modify_input_config(config=config)
        family = FamilyRevision.load_from_config(modified_cfg)
        image = MasterBootImage.load_from_config(modified_cfg)
        return cls(family=family, image=image)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Fault Analysis image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        self.mbi.app = b""
        cfg = self.mbi.get_config(data_path)
        # Update defaults values for FA Mode Image
        db = get_db(self.family)
        if db.check_key(DatabaseManager.DAT, "famode_cfg_defaults"):
            defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults")
            for k in defaults.keys():
                if k in cfg:
                    cfg.pop(k)
        return cfg

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse object from bytes array.

        :param data: Input bytes data.
        :param family: Optional family specification.
        :return: Initialized feature object.
        """
        mbi = MasterBootImage.parse(family=family, data=data)
        return cls(family=family, image=mbi)

    def export(self) -> bytes:
        """`Export` the Fault Analysis mode image to bytes.

        This method ensures the FA mode data is properly packed and included in the MBI export.
        :return: Exported bytes representation of the Fault Analysis mode image.
        """
        return self.mbi.export()

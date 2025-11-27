#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Fault Analysis Mode image handling utilities.

This module provides functionality for creating, managing, and processing
Fault Analysis Mode images used in NXP MCU security provisioning workflows.
The main component is the FaModeImage class which handles the structure
and operations of FA mode certificate images.
"""

import logging
import os
import struct
from inspect import isclass
from typing import Any, Type, Union

from typing_extensions import Self

import spsdk
from spsdk.exceptions import SPSDKError
from spsdk.image.mbi import mbi_mixin
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mbi.mbi_data import MbiImageTypeEnum
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import write_file

logger = logging.getLogger(__name__)


class FaModeImage(FeatureBaseClass):
    """Fault Analysis Mode image generator for NXP MCU security features.

    This class manages the creation and validation of Fault Analysis Mode certificates
    and images, providing secure boot functionality with fault analysis capabilities
    for supported NXP MCU families.

    :cvar FAMODE_DATA_SIZE: Size of fault analysis mode data in bytes (64).
    :cvar FAMODE_DATA_FORMAT: Binary format string for fault analysis data structure.
    """

    FEATURE = DatabaseManager.DAT
    SUB_FEATURE = "famode_cert"

    FAMODE_DATA_SIZE = 64
    FAMODE_DATA_FORMAT = "<LL56s"

    def __init__(self, family: FamilyRevision, image: MasterBootImage) -> None:
        """Initialize Fault Analysis Image.

        Creates a new instance of the Fault Analysis Image with the specified MCU/MPU family
        and Master Boot Image configured for FA mode.

        :param family: The target MCU/MPU family and revision information.
        :param image: The Master Boot Image configured for Fault Analysis mode.
        """
        self.family = family
        self.mbi = image

    def __repr__(self) -> str:
        """Get string representation of the Fault Analysis Mode Image.

        :return: String representation containing the family name.
        """
        return f"Fault Analysis Mode Image for {self.family}"

    def __str__(self) -> str:
        """Get string representation of the FAMode image.

        Provides a detailed string representation including the object's repr
        and the MBI (Master Boot Image) information.

        :return: String representation of the FAMode image object.
        """
        ret = repr(self)
        ret += "\n" + str(self.mbi)
        return ret

    @classmethod
    def pre_check_config(cls, config: Config) -> None:
        """Check the input configuration for FA mode image.

        The method modifies the input configuration, determines the appropriate MBI class,
        and performs pre-check validation using that class.

        :param config: Feature configuration to be validated.
        :raises SPSDKError: In case of invalid configuration.
        """
        mbi_config = cls._modify_input_config(config)
        mbi_cls = MasterBootImage.get_mbi_class(mbi_config)
        mbi_cls.pre_check_config(config=mbi_config)

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        This method retrieves validation schemas by first checking the configuration against basic
        schemas, then loading family revision and authentication type to get specific schemas.
        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration object containing family revision and authentication type.
        :return: List of validation schema dictionaries.
        """
        config.check(cls.get_validation_schemas_basic())
        return cls.get_validation_schemas(
            FamilyRevision.load_from_config(config),
            config.get_str("outputImageAuthenticationType"),
        )

    @staticmethod
    def get_real_class_name(family: FamilyRevision, mbi_class_name: str) -> str:
        """Get the real class name from famode certificate list.

        The method searches through the famode certificate list to find a matching class name
        based on whether the input MBI class name contains 'nxp'. It returns the first matching
        real class name or the original MBI class name if no match is found.

        :param family: The MCU/MPU family revision to get database for.
        :param mbi_class_name: The MBI class name to match against famode certificates.
        :return: Real class name from famode certificate list or original MBI class name.
        """
        db = get_db(family)
        famode_cert = db.get_list(DatabaseManager.DAT, "famode_cert", [])
        is_nxp = "nxp" in mbi_class_name.lower()

        for real_name in famode_cert:
            if ("nxp" in real_name.lower()) == is_nxp:
                return real_name
        return mbi_class_name

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mbi_class_name: str = "famode"
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas for FAMode image configuration.

        The method generates validation schemas by retrieving the base schemas from the appropriate
        MBI class and customizing them for FAMode usage. It updates family information, modifies
        authentication type options, sets default template values, and removes configuration
        options that have default values in the database.

        :param family: Target family and revision for schema generation.
        :param mbi_class_name: Name of the MBI class to use as base, defaults to "famode".
        :raises SPSDKError: When required schema is not found in the schema list.
        :return: List of validation schemas customized for FAMode image configuration.
        """

        def find_schema(key: str, schemas: list[dict[str, Any]]) -> dict[str, Any]:
            """Find schema containing the specified key.

            Searches through a list of schemas to find the one that contains the given key
            in its properties section.

            :param key: The key to search for in schema properties.
            :param schemas: List of schema dictionaries to search through.
            :raises SPSDKError: When no schema contains the specified key.
            :return: The schema dictionary that contains the key in its properties.
            """
            for schema in schemas:
                p: dict[str, Any] = schema["properties"]
                if key in p:
                    return schema
            raise SPSDKError("Non existing schema")

        # 1: Generate all configuration for FAMode Image
        db = get_db(family)
        famode_cfg_defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults", {})
        real_class_name = cls.get_real_class_name(family, mbi_class_name)
        mbi_classes = cls.get_famode_classes(family)
        # Get signed as a good example
        schemas = mbi_classes[real_class_name].get_validation_schemas(family)
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

        Creates dynamically generated MasterBootImage classes with appropriate mixins
        and configuration for the specified chip family's supported image types.

        :param family: Chip family to get supported MBI classes for.
        :raises SPSDKValueError: The invalid family.
        :return: Dictionary with image names as keys and corresponding MasterBootImage
            class types as values.
        """

        def create_famode_class(mbi_classes: dict, cls_name: str) -> type[MasterBootImage]:
            """Create a dynamically generated MasterBootImage class for FA mode.

            This method dynamically constructs a new class by combining MasterBootImage with
            specified mixins and setting required class attributes based on the provided
            class description.

            :param mbi_classes: Dictionary containing class descriptions with mixins and
                               image type information.
            :param cls_name: Name of the class to be created.
            :return: Dynamically created MasterBootImage class with mixed-in functionality.
            """
            class_descr = mbi_classes[cls_name]
            members = {
                "IMAGE_TYPE": MbiImageTypeEnum.from_label(class_descr["image_type"]),
                "IMAGE_TARGET": "xip",
                "IMAGE_AUTHENTICATIONS": "nxp_signed" if "nxp" in cls_name else "signed",
            }
            # Get all objects to be mixed together
            base_classes: list[Union[Type[MasterBootImage], Type[mbi_mixin.Mbi_Mixin]]] = [
                MasterBootImage
            ]
            for mixin in class_descr["mixins"]:
                mixin_cls: Type[mbi_mixin.Mbi_Mixin] = vars(mbi_mixin)[mixin]
                if isclass(mixin_cls) and issubclass(mixin_cls, mbi_mixin.Mbi_Mixin):
                    for member, init_value in mixin_cls.NEEDED_MEMBERS.items():
                        if member not in members:
                            members[member] = init_value
                base_classes.append(mixin_cls)

            return type(cls_name, tuple(base_classes), members)

        db = get_db(family)
        ret: dict[str, Type["MasterBootImage"]] = {}

        images: list[str] = db.get_list(DatabaseManager.DAT, "famode_cert")
        mbi_classes = db.get_dict(DatabaseManager.MBI, "mbi_classes")

        for cls_name in images:
            ret[f"{cls_name}"] = create_famode_class(mbi_classes, cls_name)

        return ret

    @classmethod
    def _modify_input_config(cls, config: Config) -> Config:
        """Modify the input config to fit for FA Mode Image simplification against MBI.

        The method updates configuration defaults from database, generates FA mode data block
        with SOCC and SRK set values, writes it to a temporary file, and updates the input
        image file path in configuration.

        :param config: Input configuration to be modified.
        :return: Modified configuration with FA mode specific settings and generated data file.
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

        Validates that the MBI application data conforms to FA mode format by checking:
        - SOCC (SoC Class) matches the required value for the family
        - SRK set is correctly configured (2 for NXP, 1 for OEM)
        - Fill bytes are properly zeroed (56 bytes of zeros)

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

        This method creates a FAMode image feature by parsing the configuration,
        determining the appropriate family and authentication type, and initializing
        the corresponding MBI class with proper mixins.

        :param config: Configuration dictionary containing family, revision, and authentication settings.
        :return: Initialized FAMode feature object with configured family and image.
        """
        modified_cfg = cls._modify_input_config(config=config)
        family = FamilyRevision.load_from_config(modified_cfg)
        famode_mbi_class = cls.get_famode_classes(family)[
            cls.get_real_class_name(
                family, modified_cfg.get_str("outputImageAuthenticationType", "signed")
            )
        ](family=family)

        for base in famode_mbi_class._get_mixins():
            base.mix_load_from_config(famode_mbi_class, modified_cfg)  # type: ignore

        return cls(family=family, image=famode_mbi_class)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Fault Analysis image.

        The method generates a configuration by first clearing the MBI application data, then
        retrieving the base MBI configuration and updating it with FA mode specific defaults
        from the database if available.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with FA mode specific settings.
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
        """Parse FAMode image object from bytes array.

        Creates a FAMode image by parsing the provided byte data into a Master Boot Image
        and wrapping it in the appropriate family context.

        :param data: Input bytes data containing the FAMode image.
        :param family: Target MCU family specification for parsing context.
        :return: Initialized FAMode image object.
        """
        mbi = MasterBootImage.parse(family=family, data=data)
        return cls(family=family, image=mbi)

    def export(self) -> bytes:
        """Export the Fault Analysis mode image to bytes.

        This method ensures the FA mode data is properly packed and included in the MBI export.

        :return: Exported bytes representation of the Fault Analysis mode image.
        """
        return self.mbi.export()

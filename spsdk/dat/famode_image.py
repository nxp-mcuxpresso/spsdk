#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Fault Analysis Mode certificate."""

import logging
import os
import struct
from typing import Any, Type

import spsdk
from spsdk.exceptions import SPSDKError
from spsdk.image.mbi.mbi import MasterBootImage, create_mbi_class
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import write_file
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class FaModeImage:
    """Fault Analysis Mode certificate class."""


FAMODE_DATA_SIZE = 64
FAMODE_DATA_FORMAT = "<LL56s"


def get_supported_families() -> list[str]:
    """Get list of supported families."""
    return get_families(DatabaseManager.DAT, "famode_cert")


def get_mbi_classes(family: str) -> dict[str, Type["MasterBootImage"]]:
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
        ret[f"{cls_name}"] = create_mbi_class(cls_name, family)

    return ret


def generate_config_templates(family: str) -> dict[str, str]:
    """Generate all possible configuration for selected family.

    :param family: Family description.
    :return: Dictionary of individual templates (key is name of template, value is template itself).
    """

    def find_schema(key: str, schemas: list[dict[str, Any]]) -> dict[str, Any]:
        for schema in schemas:
            p: dict[str, Any] = schema["properties"]
            if key in p:
                return schema
        raise SPSDKError("Non existing schema")

    ret: dict[str, str] = {}
    # 1: Generate all configuration for FAMode Image
    mbi_classes = get_mbi_classes(family)
    db = get_db(family)
    famode_cfg_defaults: dict[str, Any] = {}
    if db.check_key(DatabaseManager.DAT, "famode_cfg_defaults"):
        famode_cfg_defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults")

    for key, mbi in mbi_classes.items():
        schemas = mbi.get_validation_schemas(family)

        find_schema("outputImageAuthenticationType", schemas)["properties"][
            "outputImageAuthenticationType"
        ]["enum"] = [
            "signed",
            "signed-nxp",
            "nxp_signed",
        ]
        find_schema("outputImageAuthenticationType", schemas)["properties"][
            "outputImageAuthenticationType"
        ]["template_value"] = key
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

        yaml_data = CommentedConfig(
            f"Fault Analysis Mode Configuration template for {family}.",
            schemas,
        ).get_template()

        ret[key] = yaml_data

    return ret


def modify_input_config(config: dict[str, Any]) -> dict[str, Any]:
    """Modify the input config to fit for FA MOde Image simplification against MBI.

    :param config: Input configuration.
    :return: Output Modified Configuration.
    """
    family = config["family"]
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
    data = struct.pack(FAMODE_DATA_FORMAT, socc, srk_set, bytes(56))
    filename = os.path.join(spsdk.SPSDK_PLATFORM_DIRS.user_runtime_dir, "famode_data.bin")
    logger.debug(f"FAMode data binary path: {filename}")
    write_file(data, filename, "wb")
    config["inputImageFile"] = filename
    return config


def check_famode_data(mbi: MasterBootImage) -> None:
    """Check if the data are in FA mode format.

    :param mbi: MBI with FA mode data.
    :raises SPSDKError: In case that the data are not in FA mode format.
    """
    assert isinstance(mbi.app, bytes)
    socc, srk_set, fill = struct.unpack(FAMODE_DATA_FORMAT, mbi.app)
    db = get_db(mbi.family)
    req_socc = db.get_int(DatabaseManager.DAT, "socc")
    if socc != req_socc:
        raise SPSDKError(
            f"Invalid SOCC in FA mode data for {mbi.family}: 0x{socc:08X} != {req_socc:08X}"
        )
    if srk_set != (2 if "nxp" in mbi.IMAGE_TYPE[1].lower() else 1):
        raise SPSDKError(f"Invalid SRK set (OEM/NXP) in FA mode data: {srk_set}")
    if fill != bytes(56):
        raise SPSDKError("Invalid fill in FA mode data, should be all zeros!")


def create_config(mbi: MasterBootImage, output_folder: str) -> dict[str, Any]:
    """Create configuration file and its data files from the MBI class.

    The result will be modified to fit Fault Analysis mode image

    :param mbi: Master Boot Image object
    :param output_folder: Output folder to store the parsed data
    :returns: Configuration dictionary.
    """
    mbi.app = b""
    cfg = mbi.create_config(output_folder)
    # Update defaults values for FA Mode Image
    db = get_db(mbi.family)
    if db.check_key(DatabaseManager.DAT, "famode_cfg_defaults"):
        defaults = db.get_dict(DatabaseManager.DAT, "famode_cfg_defaults")
        for k in defaults.keys():
            if k in cfg:
                cfg.pop(k)
    return cfg

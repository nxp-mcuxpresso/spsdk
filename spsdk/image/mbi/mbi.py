#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import logging
import re
from inspect import isclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.mbi import mbi_mixin
from spsdk.utils.crypto.cert_blocks import CertBlockV1, CertBlockV21, CertBlockVx
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import get_key_by_val, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)

PLAIN_IMAGE = (0x00, "Plain Image (either XIP or Load-to-RAM)")
SIGNED_RAM_IMAGE = (0x01, "Plain Signed Load-to-RAM Image")
CRC_RAM_IMAGE = (0x02, "Plain CRC Load-to-RAM Image")
ENCRYPTED_RAM_IMAGE = (0x03, "Encrypted Load-to-RAM Image")
SIGNED_XIP_IMAGE = (0x04, "Plain Signed XIP Image")
CRC_XIP_IMAGE = (0x05, "Plain CRC XIP Image")
SIGNED_XIP_NXP_IMAGE = (0x08, "Plain Signed XIP Image NXP Keys")

DEBUG_TRACE_ENABLE = False

MAP_IMAGE_TARGETS = {
    "targets": {
        "xip": [
            "xip",
            "Internal flash (XIP)",
            "External flash (XIP)",
            "Internal Flash (XIP)",
            "External Flash (XIP)",
        ],
        "load_to_ram": ["load-to-ram", "RAM", "ram"],
    }
}

MAP_AUTHENTICATIONS = {
    "plain": ["plain", "Plain"],
    "crc": ["crc", "CRC"],
    "signed": ["signed", "Signed"],
    "nxp_signed": ["signed-nxp", "NXP Signed", "NXP signed"],
    "encrypted": ["signed-encrypted", "Encrypted + Signed", "encrypted"],
}


def create_mbi_class(name: str, family: str) -> Type["MasterBootImage"]:
    """Create Master Boot image class.

    :param name: Name of Class
    :param family: Name of chip family
    :return: Master Boot Image class
    """
    db = get_db(family)
    mbi_classes = db.get_dict(DatabaseManager.MBI, "mbi_classes")

    if not name in mbi_classes:
        raise SPSDKValueError(f"Unsupported MBI class to create: {name}")

    class_descr: Dict[str, Any] = mbi_classes[name]
    # Get all members to be added to class
    members = {"IMAGE_TYPE": globals()[class_descr["image_type"]]}
    # Get all objects to be mixed together
    base_classes: List[Union[Type[MasterBootImage], Type[mbi_mixin.Mbi_Mixin]]] = [MasterBootImage]
    for mixin in class_descr["mixins"]:
        mixin_cls: Type[mbi_mixin.Mbi_Mixin] = vars(mbi_mixin)[mixin]
        assert mixin_cls
        if isclass(mixin_cls) and issubclass(mixin_cls, mbi_mixin.Mbi_Mixin):
            for member, init_value in mixin_cls.NEEDED_MEMBERS.items():
                if not member in members:
                    members[member] = init_value
        base_classes.append(mixin_cls)

    mbi_cls = type(name, tuple(base_classes), members)

    return mbi_cls


# pylint: disable=too-many-ancestors
def get_mbi_class(config: Dict[str, Any]) -> Type["MasterBootImage"]:
    """Get Master Boot Image class.

    :raises SPSDKUnsupportedImageType: The invalid configuration.
    :return: MBI Class.
    """
    schema_cfg = get_schema_file(DatabaseManager.MBI)
    # Validate needed configuration to recognize MBI class
    check_config(config, [schema_cfg["image_type"], schema_cfg["family"]])
    family = config["family"]
    db = get_db(family)
    try:
        target = get_key_by_val(config["outputImageExecutionTarget"], MAP_IMAGE_TARGETS["targets"])
        authentication = get_key_by_val(
            config["outputImageAuthenticationType"], MAP_AUTHENTICATIONS
        )
        cls_name = db.get_str(DatabaseManager.MBI, ["images", target, authentication])
    except (KeyError, SPSDKValueError) as exc:
        raise SPSDKUnsupportedImageType(
            f"Memory target {target} and authentication type {authentication} is not supported for {family} MBI."
        ) from exc

    return create_mbi_class(cls_name, family)


def get_mbi_classes(family: str) -> Dict[str, Tuple[Type["MasterBootImage"], str, str]]:
    """Get all Master Boot Image supported classes for chip family.

    :param family: Chip family.
    :raises SPSDKValueError: The invalid family.
    :return: Dictionary with key like image name and values are Tuple with it's MBI Class
        and target and authentication type.
    """
    db = get_db(family)
    ret: Dict[str, Tuple[Type["MasterBootImage"], str, str]] = {}

    images: Dict[str, Dict[str, str]] = db.get_dict(DatabaseManager.MBI, "images")

    for target in images.keys():
        for authentication in images[target]:
            cls_name = images[target][authentication]

            ret[f"{family}_{target}_{authentication}"] = (
                create_mbi_class(cls_name, family),
                MAP_IMAGE_TARGETS["targets"][target][0],
                MAP_AUTHENTICATIONS[authentication][0],
            )

    return ret


def get_all_mbi_classes() -> List[Type["MasterBootImage"]]:
    """Get all Master Boot Image supported classes.

    :return: List with all MBI Classes.
    """
    mbi_families = mbi_get_supported_families()
    cls_list = []
    hash_set = set()
    for family in mbi_families:
        db = get_db(family, "latest")
        mbi_classes: Dict[str, Any] = db.get_dict(DatabaseManager.MBI, "mbi_classes")

        for mbi_cls_name in mbi_classes:
            cls = create_mbi_class(mbi_cls_name, family)
            if cls.hash() not in hash_set:
                hash_set.add(cls.hash())
                cls_list.append(cls)

    return cls_list


def mbi_generate_config_templates(family: str) -> Dict[str, str]:
    """Generate all possible configuration for selected family.

    :param family: Family description.
    :return: Dictionary of individual templates (key is name of template, value is template itself).
    """
    ret: Dict[str, str] = {}
    # 1: Generate all configuration for MBI
    try:
        mbi_classes = get_mbi_classes(family)
    except SPSDKValueError:
        return ret

    for key, mbi in mbi_classes.items():
        mbi_cls, target, authentication = mbi
        schemas = mbi_cls.get_validation_schemas()

        schemas[0]["properties"]["family"]["template_value"] = family
        schemas[1]["properties"]["outputImageExecutionTarget"]["enum"] = ["xip", "load-to-ram"]
        schemas[1]["properties"]["outputImageExecutionTarget"]["template_value"] = target
        schemas[1]["properties"]["outputImageAuthenticationType"]["enum"] = [
            "plain",
            "crc",
            "signed",
            "signed-encrypted",
            "signed-nxp",
        ]
        schemas[1]["properties"]["outputImageAuthenticationType"]["template_value"] = authentication

        yaml_data = CommentedConfig(
            f"Master Boot Image Configuration template for {family}, {mbi_cls.IMAGE_TYPE[1]}.",
            schemas,
        ).get_template()

        ret[key] = yaml_data

    return ret


def mbi_get_supported_families() -> List[str]:
    """Get supported families by MBI.

    :return: List of supported family names.
    """
    return get_families(DatabaseManager.MBI)


class MasterBootImage:
    """Master Boot Image Interface."""

    IMAGE_TYPE = PLAIN_IMAGE

    app: Optional[bytes]
    app_table: Optional[mbi_mixin.MultipleImageTable]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21, CertBlockVx]]
    collect_data: Callable[[], bytes]
    encrypt: Any  # encrypt(self, raw_image: bytes, revert: bool = False) -> bytes
    post_encrypt: Any  # post_encrypt(self, image: bytes, revert: bool = False) -> bytes
    sign: Any  # sign(self, image: bytes, revert: bool = False) -> bytes
    finalize: Any  # finalize(self, image: bytes, revert: bool = False) -> bytes
    disassemble_image: Callable[[bytes], None]

    @classmethod
    def _get_mixins(cls) -> List[Type[mbi_mixin.Mbi_Mixin]]:
        """Get the list of Mbi Mixin classes.

        :return: List of Mbi_Mixins.
        """
        return [x for x in cls.__bases__ if issubclass(x, mbi_mixin.Mbi_Mixin)]

    @classmethod
    def get_image_type(cls, device: str, data: bytes) -> int:
        """Get image type from MBI data and family.

        :param device: device family to be fetched from DB
        :param data: MBI raw data
        :return: Image type int representation
        """
        img_type = get_db(device).get_int(DatabaseManager.MBI, ["fixed_image_type"])
        if not img_type:
            return mbi_mixin.Mbi_MixinIvt.get_image_type(data)
        return img_type

    @classmethod
    def hash(cls) -> str:
        """Unique identifier for MasterBootImage class based on mixins.

        :return: Acronym for each MBI base class separated by "-"
        """
        class_names = [mixin.__name__ for mixin in cls.__bases__]

        acronyms = []

        for class_name in class_names:
            # Remove "Mbi_" if it exists at the beginning
            class_name = re.sub(r"^Mbi_", "", class_name)
            # Remove "Mixin" from the class name
            class_name = re.sub(r"Mixin", "", class_name)
            # Split the remaining class name by uppercase letters or numbers
            words = re.findall(r"[A-Z][a-z_0-9]*", class_name)

            # Create an acronym from the first letter of each word
            acronym = "".join(word[0].upper() for word in words)
            acronyms.append(acronym)

        return "-".join(acronyms)

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        """Initialization of MBI.

        :param kwargs: Various input parameters based on used dynamic class.
        """
        # Check if all needed class instance members are available (validation of class due to mixin problems)
        self.search_paths: Optional[List[str]] = None
        self.family = "Unknown"
        self.dek: Optional[str] = None
        for k_arg, v_arg in kwargs.items():
            setattr(self, k_arg, v_arg)

        for base in self._get_mixins():
            for member in base.NEEDED_MEMBERS:
                assert hasattr(self, member), f"{member} is missing"

    @property
    def total_len(self) -> int:
        """Compute Master Boot Image data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            ret += base.mix_len(self)  # type: ignore
        return ret

    @property
    def app_len(self) -> int:
        """Compute application data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            mix_app_len = base.mix_app_len(self)  # type: ignore
            if mix_app_len < 0:
                mix_app_len = base.mix_len(self)  # type: ignore
            ret += mix_app_len
        return ret

    @property
    def rkth(self) -> Optional[bytes]:
        """Get Root Key Table Hash from certificate block if present.

        :return: Root Key Table Hash as hex string.
        """
        if hasattr(self, "cert_block") and isinstance(self.cert_block, (CertBlockV1, CertBlockV21)):
            return self.cert_block.rkth
        return None

    def load_from_config(
        self, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        self.search_paths = search_paths
        self.family = config.get("family", "Unknown")
        for base in self._get_mixins():
            base.mix_load_from_config(self, config)  # type: ignore

    def export(self) -> bytes:
        """Export final bootable image.

        :return: Bootable Image in bytes.
        """
        # 1: Validate the input data
        self.validate()
        # 2: Collect all input data into raw image
        raw_image = self.collect_data()
        if DEBUG_TRACE_ENABLE:
            write_file(raw_image, "export_1_collect.bin", mode="wb")
        # 3: Optionally encrypt the image
        encrypted_image = self.encrypt(raw_image)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image, "export_2_encrypt.bin", mode="wb")
        # 4: Optionally do some post encrypt image updates
        encrypted_image = self.post_encrypt(encrypted_image)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image, "export_3_post_encrypt.bin", mode="wb")
        # 5: Optionally sign image
        signed_image = self.sign(encrypted_image)
        if DEBUG_TRACE_ENABLE:
            write_file(signed_image, "export_4_signed.bin", mode="wb")
        # 6: Finalize image
        final_image = self.finalize(signed_image)
        if DEBUG_TRACE_ENABLE:
            write_file(final_image, "export_5_finalized.bin", mode="wb")

        return final_image

    @staticmethod
    def parse(family: str, data: bytes, dek: Optional[str] = None) -> "MasterBootImage":
        """Parse the final image to individual fields.

        :param family: Device family
        :param data: Final Image in bytes
        :param dek: The decryption key for encrypted images
        :raises SPSDKParsingError: Cannot determinate the decoding class
        :return: MBI parsed class
        """
        # 1: Get the right class to parse MBI
        mbi_classes = get_mbi_classes(family)
        image_type = MasterBootImage.get_image_type(family, data)
        authentication = None
        target = None
        mbi_cls_type = None
        for cls_info in mbi_classes.values():
            if cls_info[0].IMAGE_TYPE[0] == image_type:
                mbi_cls_type = cls_info[0]
                target = cls_info[1]
                authentication = cls_info[2]
                logger.info(
                    "Detected MBI image:\n"
                    f"  Authentication:    {authentication}\n"
                    f"  Target:            {target}"
                )
                break

        if mbi_cls_type is None:
            raise SPSDKParsingError("Unsupported MBI type detected.")

        assert mbi_cls_type
        mbi_cls = mbi_cls_type()
        mbi_cls.family = family
        mbi_cls.dek = dek

        # 2: Parse individual mixins what is possible
        # Solve the order - Wait for the mixins that depends on other and run another round
        mixins_src = mbi_cls._get_mixins()
        while mixins_src:
            mixins = mixins_src.copy()
            mixins_src.clear()
            for mixin in mixins:
                logger.debug(f"Parsing: Mixin {mixin.__name__}.")
                for pre_parsed in mixin.PRE_PARSED:
                    if hasattr(mbi_cls, pre_parsed) and getattr(mbi_cls, pre_parsed) is None:
                        logger.debug(
                            f"Parsing: Mixin {mixin.__name__} has to wait to parse {pre_parsed} mixin."
                        )
                        mixins_src.append(mixin)
                        continue
                mixin.mix_parse(mbi_cls, data)  # type: ignore

        # 3: Revert finalize operation of image
        image = mbi_cls.finalize(data, revert=True)
        if DEBUG_TRACE_ENABLE:
            write_file(image, "parse_1_revert_finalize.bin", mode="wb")
        # 4: Revert optional sign of image
        unsigned_image = mbi_cls.sign(image, revert=True)
        if DEBUG_TRACE_ENABLE:
            write_file(unsigned_image, "parse_2_revert_sign.bin", mode="wb")
        # 5: Revert optional some post encrypt image updates
        encrypted_image = mbi_cls.post_encrypt(unsigned_image, revert=True)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image, "parse_3_revert_post_encrypt.bin", mode="wb")
        # 6: Revert optional encryption of the image
        decrypted_image = mbi_cls.encrypt(encrypted_image, revert=True)
        if DEBUG_TRACE_ENABLE:
            write_file(decrypted_image, "parse_4_revert_encrypt.bin", mode="wb")
        # 7: Disassembly rest of image
        mbi_cls.disassemble_image(decrypted_image)

        return mbi_cls

    def create_config(self, output_folder: str) -> Dict[str, Any]:
        """Create configuration file and its data files from the MBI class.

        :param output_folder: Output folder to store the parsed data
        :returns: Configuration dictionary.
        """
        cfg_values: Dict[str, Union[str, int]] = {}
        for mixin in self._get_mixins():
            cfg_values.update(mixin.mix_get_config(self, output_folder))  # type: ignore
        mbi_classes = get_mbi_classes(self.family)
        for mbi_class in mbi_classes.values():
            if mbi_class[0].__name__ == self.__class__.__name__:
                target = mbi_class[1]
                authentication = mbi_class[2]
                break

        assert target and authentication

        cfg_values["family"] = self.family
        cfg_values["masterBootOutputFile"] = f"mbi_{self.family}_{target}_{authentication}.bin"
        cfg_values["outputImageExecutionTarget"] = target
        cfg_values["outputImageAuthenticationType"] = authentication

        return cfg_values

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the validation schema for current image type.

        :return: Validation schema.
        """
        schemas = []
        schema_cfg = get_schema_file(DatabaseManager.MBI)
        family_schema = schema_cfg["family"]
        schemas.append(family_schema)
        schemas.append(schema_cfg["image_type"])
        schemas.append(schema_cfg["output_file"])
        for base in cls._get_mixins():
            for sch in base.VALIDATION_SCHEMAS:
                schemas.append(schema_cfg[sch])
            schemas.extend(base.mix_get_extra_validation_schemas())

        return schemas

    def validate(self) -> None:
        """Validate the setting of image."""
        for base in self._get_mixins():
            base.mix_validate(self)  # type: ignore

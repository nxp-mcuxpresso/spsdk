#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK Master Boot Image generation and management utilities.

This module provides functionality for creating, configuring, and managing
Master Boot Images (MBI) used in NXP MCU secure boot process. It includes
the main MasterBootImage class for image creation and configuration
template generation utilities.
"""

import logging
import re
from inspect import isclass
from typing import Any, Callable, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.cert_block.cert_blocks import CertBlockV1, CertBlockV21, CertBlockVx
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.mbi import mbi_mixin
from spsdk.image.mbi.mbi_data import MAP_AUTHENTICATIONS, MAP_IMAGE_TARGETS, MbiImageTypeEnum
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import get_key_by_val, write_file

logger = logging.getLogger(__name__)

DEBUG_TRACE_ENABLE = False

# pylint: disable=too-many-ancestors


def mbi_generate_config_templates(family: FamilyRevision) -> dict[str, str]:
    """Generate all possible MBI configuration templates for selected family.

    The method retrieves all available Master Boot Image classes for the specified
    family and generates configuration templates for each one. If no MBI classes
    are found for the family, an empty dictionary is returned.

    :param family: Family revision specification for template generation.
    :return: Dictionary mapping template names to their configuration content.
    """
    ret: dict[str, str] = {}
    # 1: Generate all configuration for MBI
    try:
        mbi_classes = MasterBootImage.get_mbi_classes(family)
    except SPSDKValueError:
        return ret

    for key, mbi in mbi_classes.items():
        mbi_cls, _, _ = mbi
        ret[key] = mbi_cls.get_config_template(family)

    return ret


class MasterBootImage(FeatureBaseClass):
    """Master Boot Image Interface.

    This class provides a unified interface for creating and managing Master Boot Images
    across NXP MCU portfolio. It handles image creation, authentication, encryption,
    and signing operations for different target types and authentication methods.

    :cvar FEATURE: Database feature identifier for MBI operations.
    :cvar IMAGE_TYPE: Default image type for plain images.
    :cvar IMAGE_TARGET: Default target location for image loading.
    :cvar IMAGE_AUTHENTICATIONS: Default authentication method.
    :cvar IMAGE_TYPES: Supported image target types and aliases.
    """

    FEATURE = DatabaseManager.MBI
    IMAGE_TYPE = MbiImageTypeEnum.PLAIN_IMAGE
    IMAGE_TARGET = "load_to_ram"
    IMAGE_AUTHENTICATIONS = "plain"

    app: Optional[bytes]
    app_table: Optional[mbi_mixin.MultipleImageTable]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21, CertBlockVx]]
    collect_data: Callable[[], BinaryImage]
    encrypt: Callable[[BinaryImage, bool], BinaryImage]
    post_encrypt: Callable[[BinaryImage, bool], BinaryImage]
    sign: Callable[[BinaryImage, bool], BinaryImage]
    finalize: Callable[[BinaryImage, bool], BinaryImage]
    disassemble_image: Callable[[bytes], None]

    IMAGE_TYPES = [
        "xip",
        "load-to-ram",
        "Internal flash (XIP)",
        "External flash (XIP)",
        "Internal Flash (XIP)",
        "External Flash (XIP)",
        "RAM",
        "ram",
    ]

    @classmethod
    def get_mbi_classes(cls, family: FamilyRevision) -> dict[str, tuple[Type[Self], str, str]]:
        """Get all Master Boot Image supported classes for chip family.

        The method retrieves MBI classes for all supported target and authentication combinations
        for the specified chip family from the database configuration.

        :param family: Chip family to get MBI classes for.
        :raises SPSDKValueError: The invalid family.
        :return: Dictionary with key like image name and values are Tuple with it's MBI Class
            and target and authentication type.
        """
        db = get_db(family)
        ret: dict[str, tuple[Type[Self], str, str]] = {}

        images: dict[str, dict[str, str]] = db.get_dict(DatabaseManager.MBI, "images")

        for target in images.keys():
            for authentication in images[target]:
                cls_name = images[target][authentication]

                ret[f"{family.name}_{target}_{authentication}"] = (
                    cls.create_mbi_class(cls_name, family),
                    MAP_IMAGE_TARGETS["targets"][target][0],
                    MAP_AUTHENTICATIONS[authentication][0],
                )

        return ret

    @classmethod
    def get_mbi_class(cls, config: dict[str, Any]) -> Type[Self]:
        """Get Master Boot Image class based on configuration.

        This method validates the configuration and determines the appropriate MBI class
        based on the image type, target family, execution target, and authentication type.

        :param config: Configuration dictionary containing image parameters including
                       outputImageExecutionTarget and outputImageAuthenticationType.
        :raises SPSDKUnsupportedImageType: When image type is not supported or when
                                           memory target and authentication combination
                                           is not supported for the specified family.
        :return: MBI Class type for the specified configuration.
        """
        # Validate needed configuration to recognize MBI class
        image_type = config.get("outputImageExecutionTarget", "Non-specified image type")
        if image_type not in cls.IMAGE_TYPES:
            raise SPSDKUnsupportedImageType(
                f"Unsupported image type: {image_type}, cannot get MBI class."
            )

        family = FamilyRevision.load_from_config(config)
        db = get_db(family)
        try:
            target = get_key_by_val(
                config["outputImageExecutionTarget"], MAP_IMAGE_TARGETS["targets"]
            )
        except (KeyError, SPSDKValueError) as exc:
            raise SPSDKUnsupportedImageType(
                f"Execution target '{config.get('outputImageExecutionTarget')}' is not supported. "
                f"Supported targets are: {', '.join([v[0] for v in MAP_IMAGE_TARGETS['targets'].values()])}"
            ) from exc

        try:
            authentication = get_key_by_val(
                config["outputImageAuthenticationType"], MAP_AUTHENTICATIONS
            )
        except (KeyError, SPSDKValueError) as exc:
            raise SPSDKUnsupportedImageType(
                f"Authentication type '{config.get('outputImageAuthenticationType')}' is not supported. "
                f"Supported authentication types are: {', '.join([v[0] for v in MAP_AUTHENTICATIONS.values()])}"
            ) from exc

        try:
            cls_name = db.get_str(DatabaseManager.MBI, ["images", target, authentication])
        except (KeyError, SPSDKValueError) as exc:
            raise SPSDKUnsupportedImageType(
                f"Memory target {target} and authentication type {authentication} is not supported for {family} MBI."
            ) from exc

        return cls.create_mbi_class(cls_name, family)

    @classmethod
    def create_mbi_class(cls, name: str, family: FamilyRevision) -> Type[Self]:
        """Create Master Boot Image class dynamically.

        This method creates a new MBI class by combining the base MasterBootImage class
        with appropriate mixins based on the configuration stored in the database for
        the specified family and class name.

        :param name: Name of the MBI class to create
        :param family: Chip family revision for database lookup
        :raises SPSDKValueError: When the specified MBI class name is not supported
        :return: Dynamically created Master Boot Image class
        """
        db = get_db(family)
        mbi_classes = db.get_dict(DatabaseManager.MBI, "mbi_classes")

        if name not in mbi_classes:
            raise SPSDKValueError(f"Unsupported MBI class to create: {name}")

        class_descr: dict[str, Any] = mbi_classes[name]
        authentication, target = cls._parse_name(name)
        # Get all members to be added to class
        members = {
            "IMAGE_TYPE": globals()["MbiImageTypeEnum"].from_label(class_descr["image_type"]),
            "IMAGE_TARGET": target,
            "IMAGE_AUTHENTICATIONS": authentication,
        }
        # Get all objects to be mixed together
        base_classes: list[Union[Type[MasterBootImage], Type[mbi_mixin.Mbi_Mixin]]] = [
            MasterBootImage
        ]
        mixins = mbi_mixin.get_all_mbi_mixins()
        for mixin in class_descr["mixins"]:
            mixin_cls: Type[mbi_mixin.Mbi_Mixin] = mixins[mixin]
            if isclass(mixin_cls) and issubclass(mixin_cls, mbi_mixin.Mbi_Mixin):
                for member, init_value in mixin_cls.NEEDED_MEMBERS.items():
                    if member not in members:
                        members[member] = init_value
            base_classes.append(mixin_cls)

        mbi_cls = type(name, tuple(base_classes), members)

        return mbi_cls

    @classmethod
    def _parse_name(cls, name: str) -> tuple[str, str]:
        """Parse configuration name into authentication and target tuple.

        The method extracts authentication type and target type from a configuration
        name string by matching against known authentication and target identifiers.

        :param name: Configuration name string to parse.
        :raises ValueError: Name does not contain known authentication or target type.
        :return: Tuple containing authentication type and target type strings.
        """
        auth = next(
            (
                MAP_AUTHENTICATIONS[auth_identifier][0]
                for auth_identifier in MAP_AUTHENTICATIONS
                if any(
                    name.startswith(auth_type)
                    for auth_type in MAP_AUTHENTICATIONS[auth_identifier] + [auth_identifier]
                )
            ),
            None,
        )
        if not auth:
            raise ValueError(f"Name {name} does not contain any known authentication type.")
        target = next(
            (
                MAP_IMAGE_TARGETS["targets"][target_identifier][0]
                for target_identifier in MAP_IMAGE_TARGETS["targets"]
                if any(
                    name.endswith(target_type)
                    for target_type in MAP_IMAGE_TARGETS["targets"][target_identifier]
                    + [target_identifier]
                )
            ),
            None,
        )
        if not target:
            raise ValueError(f"Name {name} does not contain any known target type.")
        return auth, target

    @classmethod
    def _get_mixins(cls) -> list[Type[mbi_mixin.Mbi_Mixin]]:
        """Get the list of Mbi Mixin classes.

        This method filters the base classes to return only those that are subclasses of Mbi_Mixin.

        :return: List of Mbi_Mixin classes that are base classes of the current class.
        """
        return [x for x in cls.__bases__ if issubclass(x, mbi_mixin.Mbi_Mixin)]

    @classmethod
    def get_image_type(cls, family: FamilyRevision, data: bytes) -> int:
        """Get image type from MBI data and family.

        The method retrieves the image type either from a fixed configuration in the database
        or dynamically determines it using the appropriate IVT mixin class based on the family.

        :param family: Device family revision to fetch configuration from database.
        :param data: Raw MBI binary data to analyze for image type.
        :return: Integer representation of the image type.
        """
        img_type = get_db(family).get_int(DatabaseManager.MBI, ["fixed_image_type"], -1)
        if img_type < 0:
            ivt_class_name = get_db(family).get_str(
                DatabaseManager.MBI, ["ivt_type"], "Mbi_MixinIvt"
            )
            return mbi_mixin.get_all_mbi_mixins()[ivt_class_name].get_image_type(data)
        return img_type

    @classmethod
    def hash(cls) -> str:
        """Generate unique identifier for MasterBootImage class based on mixins.

        Creates acronyms from base class names by removing common prefixes/suffixes
        and generating abbreviations from remaining words.

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

    def __init__(self, family: FamilyRevision, **kwargs: Any) -> None:
        """Initialize MBI (Master Boot Image) instance.

        Sets up the MBI object with the specified family revision and additional
        parameters. Validates that all required class members are present after
        initialization through mixins.

        :param family: The target MCU family and revision information.
        :param kwargs: Additional initialization parameters specific to the dynamic
            class implementation.
        :raises SPSDKValueError: When a required class member is missing after mixin
            initialization.
        """
        # Check if all needed class instance members are available (validation of class due to mixin problems)
        self.family = family
        self.dek: Optional[str] = None
        for k_arg, v_arg in kwargs.items():
            setattr(self, k_arg, v_arg)

        for base in self._get_mixins():
            base.mix_init(self)  # type: ignore
            for member in base.NEEDED_MEMBERS:
                if not hasattr(self, member):
                    raise SPSDKValueError(f"Missing member {member} in {self.__class__.__name__}")

    @property
    def total_len(self) -> int:
        """Compute Master Boot Image total data length.

        The method iterates through all available mixins and calculates their individual
        lengths to determine the final combined image data length.

        :return: Total length of the Master Boot Image data in bytes.
        """
        ret = 0
        for base in self._get_mixins():
            mixin_len = base.mix_len(self)  # type: ignore
            ret += mixin_len
            logger.debug(f"Mixin {base.__name__} length: {mixin_len}, total: {ret}")
        return ret

    @property
    def total_length_for_cert_block(self) -> int:
        """Compute total length for certificate block in Master Boot Image.

        The method iterates through all mixins and sums up lengths of those
        that should be counted in legacy certificate block length calculation.

        :return: Total length of certificate block data in bytes.
        """
        ret = 0
        for base in self._get_mixins():
            if base.COUNT_IN_LEGACY_CERT_BLOCK_LEN:
                ret += base.mix_len(self)  # type: ignore
        return ret

    @property
    def app_len(self) -> int:
        """Compute application data length.

        The method iterates through all mixins and accumulates their individual
        application data lengths to determine the total final image data length.

        :return: Final image data length in bytes.
        """
        ret = 0
        for base in self._get_mixins():
            ret += base.mix_app_len(self)  # type: ignore
        return ret

    @property
    def rkth(self) -> Optional[bytes]:
        """Get Root Key Table Hash from certificate block if present.

        The method extracts the Root Key Table Hash from the certificate block
        if it exists and is of supported type (CertBlockV1 or CertBlockV21).

        :return: Root Key Table Hash as bytes if certificate block is present and valid,
            None otherwise.
        """
        if hasattr(self, "cert_block") and isinstance(self.cert_block, (CertBlockV1, CertBlockV21)):
            return self.cert_block.rkth
        return None

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method retrieves the appropriate MBI class from configuration, validates the basic
        schemas, loads family revision information, and returns the complete validation schemas
        for the specific family.

        :param config: Valid configuration object containing MBI settings and family information.
        :return: List of validation schema dictionaries for the specified family.
        """
        mbi_cls = cls.get_mbi_class(config)
        config.check(mbi_cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return mbi_cls.get_validation_schemas(family)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from dictionary.

        Creates an MBI instance from configuration data by determining the appropriate
        MBI class based on family information and applying mixin configurations.

        :param config: Configuration object containing MBI settings and family information.
        :return: Configured MBI instance of the appropriate class type.
        """
        family = FamilyRevision.load_from_config(config)
        mbi_cls = cls.get_mbi_class(config)(family=family)

        for base in mbi_cls._get_mixins():
            base.mix_load_from_config(mbi_cls, config)  # type: ignore
        return mbi_cls

    def export_image(self) -> BinaryImage:
        """Export final bootable image.

        The method processes the MBI image through a complete pipeline: validates input data,
        collects raw image data, optionally encrypts the image, applies post-encryption updates,
        optionally signs the image, and finalizes it into a bootable format.

        :return: Final bootable image ready for deployment.
        """
        BinaryImage(
            name="MBI Image",
            description=f"MBI Image: {self.IMAGE_TYPE.description} for {self.family}",
        )
        # 1: Validate the input data
        self.validate()
        # 2: Collect all input data into raw image
        raw_image = self.collect_data()
        if DEBUG_TRACE_ENABLE:
            write_file(raw_image.export(), "export_1_collect.bin", mode="wb")
        # 3: Optionally encrypt the image
        encrypted_image = self.encrypt(raw_image, False)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image.export(), "export_2_encrypt.bin", mode="wb")
        # 4: Optionally do some post encrypt image updates
        encrypted_image = self.post_encrypt(encrypted_image, False)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image.export(), "export_3_post_encrypt.bin", mode="wb")
        # 5: Optionally sign image
        signed_image = self.sign(encrypted_image, False)
        if DEBUG_TRACE_ENABLE:
            write_file(signed_image.export(), "export_4_signed.bin", mode="wb")
        # 6: Finalize image
        final_image = self.finalize(signed_image, False)
        if DEBUG_TRACE_ENABLE:
            write_file(final_image.export(), "export_5_finalized.bin", mode="wb")

        return final_image

    def export(self) -> bytes:
        """Export final bootable image.

        :return: Bootable image in bytes.
        """
        return self.export_image().export()

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: FamilyRevision = FamilyRevision("Unknown"),
        dek: Optional[str] = None,
    ) -> Self:
        """Parse the final image to individual fields.

        This method performs reverse engineering of an MBI image by detecting the appropriate
        MBI class type, parsing mixins in dependency order, and then reversing the image
        creation process (finalize, sign, post-encrypt, encrypt operations) to extract
        the original components.

        :param data: Final Image in bytes
        :param family: Device family revision for MBI class detection
        :param dek: The decryption key for encrypted images
        :raises SPSDKParsingError: Cannot determinate the decoding class
        :return: MBI parsed class instance with extracted image components
        """
        # 1: Get the right class to parse MBI
        mbi_classes = cls.get_mbi_classes(family)
        image_type = cls.get_image_type(family, data)
        authentication = None
        target = None
        mbi_cls_type = None
        for cls_info in mbi_classes.values():
            if cls_info[0].IMAGE_TYPE.tag == image_type:
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
        mbi_cls = mbi_cls_type(family=family)
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

        input_image = BinaryImage("MBI to parse", binary=data)
        # 3: Revert finalize operation of image
        image = mbi_cls.finalize(input_image, True)
        if DEBUG_TRACE_ENABLE:
            write_file(image.export(), "parse_1_revert_finalize.bin", mode="wb")
        # 4: Revert optional sign of image
        unsigned_image = mbi_cls.sign(image, True)
        if DEBUG_TRACE_ENABLE:
            write_file(unsigned_image.export(), "parse_2_revert_sign.bin", mode="wb")
        # 5: Revert optional some post encrypt image updates
        encrypted_image = mbi_cls.post_encrypt(unsigned_image, True)
        if DEBUG_TRACE_ENABLE:
            write_file(encrypted_image.export(), "parse_3_revert_post_encrypt.bin", mode="wb")
        # 6: Revert optional encryption of the image
        decrypted_image = mbi_cls.encrypt(encrypted_image, True)
        if DEBUG_TRACE_ENABLE:
            write_file(decrypted_image.export(), "parse_4_revert_encrypt.bin", mode="wb")
        # 7: Disassembly rest of image
        mbi_cls.disassemble_image(decrypted_image.export())

        return mbi_cls

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration file and its data files from the MBI class.

        The method generates a configuration dictionary by collecting settings from all mixins
        and adding MBI-specific configuration values including family, target, and authentication
        information.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with MBI settings.
        """
        cfg_values = Config()
        for mixin in self._get_mixins():
            cfg_values.update(mixin.mix_get_config(self, data_path))  # type: ignore
        mbi_classes = self.get_mbi_classes(self.family)
        for mbi_class in mbi_classes.values():
            if mbi_class[0].__name__ == self.__class__.__name__:
                target = mbi_class[1]
                authentication = mbi_class[2]
                break

        assert isinstance(target, str) and isinstance(authentication, str)

        cfg_values["family"] = self.family.name
        cfg_values["revision"] = self.family.revision
        cfg_values["masterBootOutputFile"] = f"mbi_{self.family.name}_{target}_{authentication}.bin"
        cfg_values["outputImageExecutionTarget"] = target
        cfg_values["outputImageAuthenticationType"] = authentication

        return cfg_values

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Create the validation family schema for current image type.

        The method retrieves the general schema file, updates the family validation schema
        with supported families for the current class, and returns it as a list.

        :return: List containing the family validation schema dictionary.
        """
        schema_family = get_schema_file("general")["family"]
        update_validation_schema_family(schema_family["properties"], cls.get_supported_families())
        return [schema_family]

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema for current image type.

        The method builds a comprehensive validation schema by combining family-specific schemas,
        image type configurations, and mixin schemas. It dynamically updates execution targets
        and authentication types based on the family's supported configurations.

        :param family: Family description containing revision and chip information.
        :return: List of validation schema dictionaries for the image type.
        """
        schemas = []
        schema_cfg = get_schema_file(DatabaseManager.MBI)
        schema_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            schema_family["properties"], cls.get_supported_families(), family
        )
        schemas.append(schema_family)
        schema_image_type = schema_cfg["image_type"]
        schema_image_type["properties"]["outputImageExecutionTarget"][
            "template_value"
        ] = cls.IMAGE_TARGET
        schema_image_type["properties"]["outputImageAuthenticationType"][
            "template_value"
        ] = cls.IMAGE_AUTHENTICATIONS
        images: dict[str, dict[str, str]] = get_db(family).get_dict(DatabaseManager.MBI, "images")
        schema_image_type["properties"]["outputImageExecutionTarget"]["enum_template"] = [
            MAP_IMAGE_TARGETS["targets"][target][0] for target in images.keys()
        ]
        authentication_types = []
        for target in images.keys():
            for authentication in images[target]:
                authentication_types.append(MAP_AUTHENTICATIONS[authentication][0])
        schema_image_type["properties"]["outputImageAuthenticationType"]["enum_template"] = list(
            set(authentication_types)
        )
        schemas.append(schema_image_type)
        schemas.append(schema_cfg["output_file"])
        for base in cls._get_mixins():
            schemas.extend(base.mix_get_validation_schemas(family))

        return schemas

    def validate(self) -> None:
        """Validate the setting of image.

        Iterates through all available mixins and calls their validation methods
        to ensure the image configuration is correct and complete.

        :raises SPSDKError: If any mixin validation fails or image settings are invalid.
        """
        for base in self._get_mixins():
            base.mix_validate(self)  # type: ignore

    def __repr__(self) -> str:
        """Return string representation of MBI object.

        Provides a human-readable string containing the family name and image type
        description for debugging and logging purposes.

        :return: String representation in format "MBI class {family}, {description}".
        """
        return f"MBI class {self.family}, {self.IMAGE_TYPE.description}"

    def __str__(self) -> str:
        """Get string representation of MBI class instance.

        Creates a formatted string containing the family name, image type description,
        and a list of all available mixins for this MBI instance.

        :return: Formatted string with MBI class information and available mixins.
        """
        ret = (
            f"MBI class for {self.family}, {self.IMAGE_TYPE.description}:\n" " List of mixins:\n - "
        )
        ret += "\n - ".join([x.__name__.replace("Mbi_Mixin", "") for x in self._get_mixins()])

        return ret

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

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
    """Generate all possible configuration for selected family.

    :param family: Family description.
    :return: Dictionary of individual templates (key is name of template, value is template itself).
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
    """Master Boot Image Interface."""

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

        :param family: Chip family.
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
        """Get Master Boot Image class.

        :raises SPSDKUnsupportedImageType: The invalid configuration.
        :return: MBI Class.
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
            authentication = get_key_by_val(
                config["outputImageAuthenticationType"], MAP_AUTHENTICATIONS
            )
            cls_name = db.get_str(DatabaseManager.MBI, ["images", target, authentication])
        except (KeyError, SPSDKValueError) as exc:
            raise SPSDKUnsupportedImageType(
                f"Memory target {target} and authentication type {authentication} is not supported for {family} MBI."
            ) from exc

        return cls.create_mbi_class(cls_name, family)

    @classmethod
    def create_mbi_class(cls, name: str, family: FamilyRevision) -> Type[Self]:
        """Create Master Boot image class.

        :param name: Name of Class
        :param family: Name of chip family
        :return: Master Boot Image class
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
        for mixin in class_descr["mixins"]:
            mixin_cls: Type[mbi_mixin.Mbi_Mixin] = vars(mbi_mixin)[mixin]
            if isclass(mixin_cls) and issubclass(mixin_cls, mbi_mixin.Mbi_Mixin):
                for member, init_value in mixin_cls.NEEDED_MEMBERS.items():
                    if member not in members:
                        members[member] = init_value
            base_classes.append(mixin_cls)

        mbi_cls = type(name, tuple(base_classes), members)

        return mbi_cls

    @classmethod
    def _parse_name(cls, name: str) -> tuple[str, str]:
        """Parse configuration name into authentication, target tuple."""
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

        :return: List of Mbi_Mixins.
        """
        return [x for x in cls.__bases__ if issubclass(x, mbi_mixin.Mbi_Mixin)]

    @classmethod
    def get_image_type(cls, family: FamilyRevision, data: bytes) -> int:
        """Get image type from MBI data and family.

        :param family: device family to be fetched from DB
        :param data: MBI raw data
        :return: Image type int representation
        """
        img_type = get_db(family).get_int(DatabaseManager.MBI, ["fixed_image_type"], -1)
        if img_type < 0:
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

    def __init__(self, family: FamilyRevision, **kwargs: Any) -> None:
        """Initialization of MBI.

        :param kwargs: Various input parameters based on used dynamic class.
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
        """Compute Master Boot Image data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            mixin_len = base.mix_len(self)  # type: ignore
            ret += mixin_len
            logger.debug(f"Mixin {base.__name__} length: {mixin_len}, total: {ret}")
        return ret

    @property
    def total_length_for_cert_block(self) -> int:
        """Compute Master Boot Image data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            if base.COUNT_IN_LEGACY_CERT_BLOCK_LEN:
                ret += base.mix_len(self)  # type: ignore
        return ret

    @property
    def app_len(self) -> int:
        """Compute application data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            ret += base.mix_app_len(self)  # type: ignore
        return ret

    @property
    def rkth(self) -> Optional[bytes]:
        """Get Root Key Table Hash from certificate block if present.

        :return: Root Key Table Hash as hex string.
        """
        if hasattr(self, "cert_block") and isinstance(self.cert_block, (CertBlockV1, CertBlockV21)):
            return self.cert_block.rkth
        return None

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
        """
        mbi_cls = cls.get_mbi_class(config)
        config.check(mbi_cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return mbi_cls.get_validation_schemas(family)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        family = FamilyRevision.load_from_config(config)
        mbi_cls = cls.get_mbi_class(config)(family=family)

        for base in mbi_cls._get_mixins():
            base.mix_load_from_config(mbi_cls, config)  # type: ignore
        return mbi_cls

    def export_image(self) -> BinaryImage:
        """Export final bootable image.

        :return: Bootable Image in Binary Image format.
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

        :return: Bootable Image in bytes.
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

        :param data: Final Image in bytes
        :param family: Device family
        :param dek: The decryption key for encrypted images
        :raises SPSDKParsingError: Cannot determinate the decoding class
        :return: MBI parsed class
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

        :param data_path: Path to store the data files of configuration.
        :returns: Configuration dictionary.
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

        :return: Validation schema.
        """
        schema_family = get_schema_file("general")["family"]
        update_validation_schema_family(schema_family["properties"], cls.get_supported_families())
        return [schema_family]

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema for current image type.

        :param family: Family description.
        :return: Validation schema.
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
        """Validate the setting of image."""
        for base in self._get_mixins():
            base.mix_validate(self)  # type: ignore

    def __repr__(self) -> str:
        return f"MBI class {self.family}, {self.IMAGE_TYPE.description}"

    def __str__(self) -> str:
        ret = (
            f"MBI class for {self.family}, {self.IMAGE_TYPE.description}:\n" " List of mixins:\n - "
        )
        ret += "\n - ".join([x.__name__.replace("Mbi_Mixin", "") for x in self._get_mixins()])

        return ret

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import datetime
import logging
import os
from copy import deepcopy
from inspect import isclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union

from Crypto.Cipher import AES

from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image import IMG_DATA_FOLDER, MBIMG_SCH_FILE, mbi_mixin
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils.crypto.cert_blocks import CertBlockV2, CertBlockV31
from spsdk.utils.misc import align_block, get_key_by_val, load_configuration, write_file
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas, check_config

logger = logging.getLogger(__name__)

PLAIN_IMAGE = (0x00, "Plain Image (either XIP or Load-to-RAM)")
SIGNED_RAM_IMAGE = (0x01, "Plain Signed Load-to-RAM Image")
CRC_RAM_IMAGE = (0x02, "Plain CRC Load-to-RAM Image")
ENCRYPTED_RAM_IMAGE = (0x03, "Encrypted Load-to-RAM Image")
SIGNED_XIP_IMAGE = (0x04, "Plain Signed XIP Image")
CRC_XIP_IMAGE = (0x05, "Plain CRC XIP Image")
SIGNED_XIP_NXP_IMAGE = (0x08, "Plain Signed XIP Image NXP Keys")

DEVICE_FILE = os.path.join(IMG_DATA_FOLDER, "database.yaml")

DEBUG_TRACE_ENABLE = False


# pylint: disable=too-many-ancestors
def get_mbi_class(config: Dict[str, Any]) -> Type["MasterBootImage"]:
    """Get Master Boot Image class.

    :raises SPSDKUnsupportedImageType: The invalid configuration.
    :return: MBI Class.
    """
    schema_cfg = ValidationSchemas.get_schema_file(MBIMG_SCH_FILE)
    device_cfg = load_configuration(DEVICE_FILE)
    # Validate needed configuration to recognize MBI class
    check_config(config, [schema_cfg["image_type"], schema_cfg["family"]])
    try:
        target = get_key_by_val(
            config["outputImageExecutionTarget"], device_cfg["map_tables"]["targets"]
        )
        authentication = get_key_by_val(
            config["outputImageAuthenticationType"], device_cfg["map_tables"]["authentication"]
        )
        family = config["family"]

        cls_name = device_cfg["devices"][family]["images"][target][authentication]
    except (KeyError, SPSDKValueError) as exc:
        raise SPSDKUnsupportedImageType(
            "The type of requested Master boot image is not supported for that device."
        ) from exc

    return globals()[cls_name]


def get_mbi_classes(family: str) -> Dict[str, Tuple[Type["MasterBootImage"], str, str]]:
    """Get all Master Boot Image supported classes for chip family.

    :param family: Chip family.
    :raises SPSDKValueError: The invalid family.
    :return: Dictionary with key like image name and values are Tuple with it's MBI Class
        and target and authentication type.
    """
    device_cfg = load_configuration(DEVICE_FILE)
    if not family in device_cfg["devices"]:
        raise SPSDKValueError("Not supported family for Master Boot Image")

    ret: Dict[str, Tuple[Type["MasterBootImage"], str, str]] = {}

    images: Dict[str, Dict[str, str]] = device_cfg["devices"][family]["images"]

    for target in images.keys():
        for authentication in images[target]:
            cls_name = images[target][authentication]

            ret[f"{family}_{target}_{authentication}"] = (
                globals()[cls_name],
                device_cfg["map_tables"]["targets"][target][0],
                device_cfg["map_tables"]["authentication"][authentication][0],
            )

    return ret


def get_all_mbi_classes() -> List[Type["MasterBootImage"]]:
    """Get all Master Boot Image supported classes.

    :return: List with all MBI Classes.
    """
    ret: Set[Type["MasterBootImage"]] = set()

    for var in globals():
        obj = globals()[var]
        if isclass(obj) and issubclass(obj, MasterBootImage) and obj is not MasterBootImage:
            ret.add(obj)

    return sorted(ret, key=lambda x: x.__name__)


def mbi_generate_config_templates(family: str) -> Dict[str, str]:
    """Generate all possible configuration for selected family.

    :param family: Family description.
    :raises SPSDKError: [description]
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

        override = {}
        override["family"] = family
        override["outputImageExecutionTarget"] = target
        override["outputImageAuthenticationType"] = authentication
        yaml_data = CommentedConfig(
            f"Master Boot Image Configuration template for {family}, {mbi_cls.IMAGE_TYPE[1]}.",
            schemas,
            override,
        ).export_to_yaml()

        ret[key] = yaml_data

    return ret


def mbi_get_supported_families() -> List[str]:
    """Get supported families by MBI.

    :return: List of supported family names.
    """
    device_cfg = load_configuration(DEVICE_FILE)
    devices: Dict[str, Any] = device_cfg["devices"]
    return list(devices.keys())


class MasterBootImage:
    """Master Boot Image Interface."""

    IMAGE_TYPE = PLAIN_IMAGE

    app: Optional[bytes]
    app_table: Optional[mbi_mixin.MultipleImageTable]
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

    def __init__(self) -> None:
        """Initialization of MBI."""
        # Check if all needed class instance members are available (validation of class due to mixin problems)
        self.search_paths: Optional[List[str]] = None
        self.family = "Unknown"
        self.dek: Optional[str] = None
        for base in self._get_mixins():
            for member in base.NEEDED_MEMBERS:
                assert hasattr(self, member)

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
        image_type = mbi_mixin.Mbi_MixinIvt.get_image_type(data=data)
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

        if mbi_cls_type == None:
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
                    if hasattr(mbi_cls, pre_parsed) and getattr(mbi_cls, pre_parsed) == None:
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

    def create_config(self, output_folder: str) -> None:
        """Create configuration file and its data files from the MBI class.

        :param output_folder: Output folder to store the parsed data
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

        val_schemas = self.get_validation_schemas()
        cfg_values["family"] = self.family
        cfg_values["outputImageExecutionTarget"] = target
        cfg_values["outputImageAuthenticationType"] = authentication

        yaml_data = CommentedConfig(
            main_title=(
                f"Master Boot Image ({self.__class__.__name__}) recreated configuration from :"
                f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
            ),
            schemas=val_schemas,
            values=cfg_values,
            export_template=False,
        ).export_to_yaml()

        write_file(yaml_data, os.path.join(output_folder, "mbi_config.yaml"))

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Create the list of supported families by this class.

        :return: List of supported families.
        """
        ret = set()
        device_cfg = load_configuration(DEVICE_FILE)
        devices: Dict[str, Dict] = device_cfg["devices"]
        for device, dev_val in devices.items():
            images: Dict[str, Dict[str, str]] = dev_val["images"]
            for image in images.values():
                for klass in image.values():
                    if klass == cls.__name__:
                        ret.add(device)

        return list(ret)

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the validation schema for current image type.

        :return: Validation schema.
        """
        schemas = []
        schema_cfg = ValidationSchemas.get_schema_file(MBIMG_SCH_FILE)
        family_schema = deepcopy(schema_cfg["family"])
        family_schema["properties"]["family"]["enum"] = cls.get_supported_families()
        schemas.append(family_schema)
        schemas.append(deepcopy(schema_cfg["image_type"]))
        schemas.append(deepcopy(schema_cfg["output_file"]))
        for base in cls._get_mixins():
            for sch in base.VALIDATION_SCHEMAS:
                schemas.append(deepcopy(schema_cfg[sch]))
            schemas.extend(deepcopy(base.mix_get_extra_validation_schemas()))

        return schemas

    def validate(self) -> None:
        """Validate the setting of image."""
        for base in self._get_mixins():
            base.mix_validate(self)  # type: ignore


########################################################################################################################
# Master Boot Image Class (LPC55)
########################################################################################################################


# pylint: disable=invalid-name
# pylint: disable=abstract-method
class Mbi_PlainXip(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain XiP Image for LPC55xxx family."""

    def __init__(self, app: Optional[bytes] = None, trust_zone: Optional[TrustZone] = None) -> None:
        """Constructor for Master Boot Plain XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        super().__init__()


class Mbi_CrcXip(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for LPC55xxx family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(self, app: Optional[bytes] = None, trust_zone: Optional[TrustZone] = None) -> None:
        """Constructor for Master Boot CRC XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        super().__init__()


class Mbi_CrcRam(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for LPC55xxx family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
    ) -> None:
        """Constructor for Master Boot CRC XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        super().__init__()


class Mbi_SignedXip(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinCertBlockV2,
    mbi_mixin.Mbi_ExportMixinAppTrustZoneCertBlock,
    mbi_mixin.Mbi_ExportMixinRsaSign,
):
    """Master Boot Signed XiP Image for LPC55xxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        cert_block: Optional[CertBlockV2] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Constructor for Master Boot Signed XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param cert_block: Certification block of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.signature_provider = signature_provider
        super().__init__()


class Mbi_SignedRam(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinCertBlockV2,
    mbi_mixin.Mbi_ExportMixinAppTrustZoneCertBlock,
    mbi_mixin.Mbi_ExportMixinRsaSign,
):
    """Master Boot Signed RAM Image for LPC55xxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Constructor for Master Boot Signed XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.cert_block = cert_block
        self.signature_provider = signature_provider
        super().__init__()


########################################################################################################################
# Master Boot Image Class (i.MXRT5xx/i.MXRT6xx)
########################################################################################################################


class Mbi_PlainRamRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain Image for RTxxx."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot Plain XiP Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.user_hw_key_enabled = hwk
        super().__init__()


class Mbi_PlainSignedRamRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinRelocTable,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinCertBlockV2,
    mbi_mixin.Mbi_MixinHmacMandatory,
    mbi_mixin.Mbi_MixinKeyStore,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZoneCertBlock,
    mbi_mixin.Mbi_ExportMixinRsaSign,
    mbi_mixin.Mbi_ExportMixinHmacKeyStoreFinalize,
):
    """Master Boot Plain Signed RAM Image for RTxxx family."""

    IMAGE_TYPE = SIGNED_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[mbi_mixin.MultipleImageTable] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        signature_provider: Optional[SignatureProvider] = None,
        hmac_key: Optional[Union[bytes, str]] = None,
        key_store: Optional[KeyStore] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot Plain Signed RAM Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param app_table: Application table for additional application binaries, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param hmac_key: HMAC key of image, defaults to None
        :param key_store: Optional KeyStore object for image, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.app_table = app_table
        self.load_address = load_addr
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.signature_provider = signature_provider
        self.hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key
        self.key_store = key_store
        self.user_hw_key_enabled = hwk
        super().__init__()


class Mbi_CrcRamRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinRelocTable,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for RTxxx family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[mbi_mixin.MultipleImageTable] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot CRC RAM Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param app_table: Application table for additional application binaries, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.app_table = app_table
        self.tz = trust_zone or TrustZone.enabled()
        self.user_hw_key_enabled = hwk
        self.load_address = load_addr
        super().__init__()


class Mbi_EncryptedRamRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinRelocTable,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinCertBlockV2,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_MixinKeyStore,
    mbi_mixin.Mbi_MixinHmacMandatory,
    mbi_mixin.Mbi_MixinCtrInitVector,
    mbi_mixin.Mbi_ExportMixinRsaSign,
    mbi_mixin.Mbi_ExportMixinHmacKeyStoreFinalize,
):
    """Master Boot Encrypted RAM Image for RTxxx family."""

    IMAGE_TYPE = ENCRYPTED_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[mbi_mixin.MultipleImageTable] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        signature_provider: Optional[SignatureProvider] = None,
        hmac_key: Optional[Union[bytes, str]] = None,
        key_store: Optional[KeyStore] = None,
        ctr_init_vector: Optional[bytes] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot Encrypted RAM Image for RTxxx family..

        :param app: Application image data, defaults to None
        :param app_table: Application table for additional application binaries, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        :param key_store: Optional KeyStore object for image, defaults to None
        :param hmac_key: HMAC key of image, defaults to None
        :param ctr_init_vector: Counter initialization vector of image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.load_address = load_addr
        self.app_table = app_table
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.signature_provider = signature_provider
        self.user_hw_key_enabled = hwk
        self.key_store = key_store
        self.hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key
        self.store_ctr_init_vector(ctr_init_vector)
        self.img_len = 0
        super().__init__()

    def collect_data(self) -> bytes:
        """Collect basic data to create image.

        :return: Collected raw image.
        """
        assert self.cert_block
        self.cert_block.alignment = 4  # type: ignore

        self.img_len = (
            self.total_len + self.cert_block.signature_size + 56 + 16
        )  # Encrypted IVT + IV

        image = self.update_ivt(
            app_data=self.get_app_data() + self.tz.export(),
            total_len=self.img_len,
            crc_val_cert_offset=self.get_app_length(),
        )
        return image

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        # Re -parse decrypted TZ if needed
        if self.tz.type == TrustZoneType.CUSTOM:
            self.tz = TrustZone.from_binary(
                family=self.family, raw_data=image[-TrustZone.get_preset_data_size(self.family) :]
            )

        tz_len = len(self.tz.export())
        if tz_len:
            image = image[:-tz_len]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)

    def encrypt(self, image: bytes, revert: bool = False) -> bytes:
        """Encrypt image if needed.

        :param image: Input raw image to encrypt.
        :param revert: Revert the operation if possible.
        :return: Encrypted image.
        """
        if revert and not (self.hmac_key and self.ctr_init_vector):
            logger.warning("Cannot parse the encrypted image without decrypting key!")
            return image

        assert self.hmac_key and self.ctr_init_vector
        key = self.hmac_key
        if not self.key_store or self.key_store.key_source == KeySourceType.OTP:
            key = KeyStore.derive_enc_image_key(key)
        aes = AES.new(key, AES.MODE_CTR, initial_value=self.ctr_init_vector, nonce=bytes())
        logger.debug(f"Encryption key: {self.hmac_key.hex()}")
        logger.debug(f"Encryption IV: {self.ctr_init_vector.hex()}")

        if revert:
            decrypted_data = aes.decrypt(image)
            return decrypted_data

        encrypted_data = aes.encrypt(image + self.tz.export())
        return encrypted_data

    def post_encrypt(self, image: bytes, revert: bool = False) -> bytes:
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :param revert: Revert the operation if possible.
        :return: Updated encrypted image.
        """
        assert self.cert_block and isinstance(self.cert_block, CertBlockV2)
        if revert:
            cert_blk_offset = mbi_mixin.Mbi_MixinIvt.get_cert_block_offset(image)
            cert_blk_size = self.cert_block.expected_size
            # Restore original part of encrypted IVT
            org_image = image[
                cert_blk_offset + cert_blk_size : cert_blk_offset + cert_blk_size + 56
            ]
            # Add rest of original encrypted image
            org_image += image[56:cert_blk_offset]
            # optionally add TrustZone data
            org_image += image[cert_blk_offset + cert_blk_size + 56 + 16 :]
            return org_image

        enc_ivt = self.update_ivt(
            app_data=image[: self.HMAC_OFFSET],
            total_len=self.img_len,
            crc_val_cert_offset=self.get_app_length(),
        )

        # Create encrypted cert block (Encrypted IVT table + IV)
        encrypted_header = image[:56] + self.ctr_init_vector

        self.cert_block.image_length = (
            len(image) + len(self.cert_block.export()) + len(encrypted_header)
        )
        enc_cert = self.cert_block.export() + encrypted_header
        return (
            enc_ivt
            + image[self.HMAC_OFFSET : self.get_app_length()]  # header  # encrypted image
            + enc_cert  # certificate + encoded image header + CTR init vector
            + image[self.get_app_length() :]  # TZ encoded data
        )


class Mbi_PlainXipRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain XiP Image for RTxxx."""

    def __init__(
        self, app: Optional[bytes] = None, trust_zone: Optional[TrustZone] = None, hwk: bool = False
    ) -> None:
        """Constructor for Master Boot Plain XiP Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.user_hw_key_enabled = hwk
        super().__init__()


class Mbi_PlainSignedXipRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinCertBlockV2,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZoneCertBlock,
    mbi_mixin.Mbi_ExportMixinRsaSign,
):
    """Master Boot Plain Signed XiP Image for RTxxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        signature_provider: Optional[SignatureProvider] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot Plain Signed XiP Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.cert_block = cert_block
        self.signature_provider = signature_provider
        self.user_hw_key_enabled = hwk
        super().__init__()


class Mbi_CrcXipRtxxx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinTrustZone,
    mbi_mixin.Mbi_MixinHwKey,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for RTxxx."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot CRC XiP Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.user_hw_key_enabled = hwk
        super().__init__()


########################################################################################################################
# Master Boot Image Class (LPC55x3x)
########################################################################################################################
class Mbi_PlainRamLpc55s3x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain RAM Image for LPC55s3x family."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Plain RAM Image for LPC55s3x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.tz = trust_zone or TrustZone.enabled()
        self.firmware_version = firmware_version
        self.load_address = load_addr
        super().__init__()


class Mbi_CrcRamLpc55s3x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for LPC55s3x family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Signed RAM Image for LPC55s3x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        super().__init__()


class Mbi_PlainXipSignedLpc55s3x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifest,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image for LPC55s3x family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        firmware_version: int = 0,
        load_addr: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Constructor for Master Boot Signed XIP Image for LPC55s3x family.

        :param app: Application image data, defaults to None
        :param firmware_version: Firmware version of image, defaults to 0
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.firmware_version = firmware_version
        self.load_address = load_addr
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        super().__init__()


class Mbi_CrcXipLpc55s3x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for LPC55s3x family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Signed RAM Image for LPC55s3x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        super().__init__()


########################################################################################################################
# Master Boot Image Class (KW45xx/K32W1xx)
########################################################################################################################
class Mbi_PlainXipKw45xx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinImageSubType,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain RAM Image for KW45xx/K32W1xx family."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        trust_zone: Optional[TrustZone] = None,
        firmware_version: int = 0,
        image_subtype: Optional[mbi_mixin.Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
    ) -> None:
        """Constructor for Master Boot Plain RAM Image for KW45xx/K32W1xx family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param trust_zone: TrustZone object, defaults to None
        :param firmware_version: Firmware version of image, defaults to 0
        :param image_subtype: Selection of image subtype (MAIN/NBU), default to None(MAIN)
        """
        self.app = align_block(app) if app else None
        self.load_address = load_addr
        self.tz = trust_zone or TrustZone.enabled()
        self.firmware_version = firmware_version
        self.set_image_subtype(image_subtype)
        super().__init__()


class Mbi_PlainXipSignedKw45xx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifest,
    mbi_mixin.Mbi_MixinNoSignature,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image for KW45xx/K32W1xx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        firmware_version: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
        no_signature: Optional[bool] = None,
    ) -> None:
        """Constructor for Master Boot Signed XIP Image for KW45xx/K32W1xx family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param nxp_image: If it set, the image is generated as NXP.
        :param no_signature: If it set, the signature is not appended
        """
        self.app = align_block(app) if app else None
        self.load_address = load_addr
        self.no_signature = no_signature
        self.firmware_version = firmware_version
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        super().__init__()


class Mbi_PlainXipSignedNxpKw45xx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifest,
    mbi_mixin.Mbi_MixinImageSubType,
    mbi_mixin.Mbi_MixinNoSignature,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image by NXP Keys for KW45xx/K32W1xx family."""

    IMAGE_TYPE = SIGNED_XIP_NXP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        firmware_version: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
        image_subtype: Optional[mbi_mixin.Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
        no_signature: Optional[bool] = None,
    ) -> None:
        """Constructor for Master Boot Signed XIP Image for KW45xx/K32W1xx family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param image_subtype: Selection of image subtype (MAIN/NBU), default to None(MAIN)
        :param nxp_image: If it set, the image is generated as NXP.
        :param no_signature: If it set, the signature is not appended
        """
        self.app = align_block(app) if app else None
        self.load_address = load_addr
        self.no_signature = no_signature
        self.firmware_version = firmware_version
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        self.set_image_subtype(image_subtype)
        super().__init__()


class Mbi_CrcXipKw45xx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinImageSubType,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for KW45xx/K32W1xx family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        trust_zone: Optional[TrustZone] = None,
        firmware_version: int = 0,
        image_subtype: Optional[mbi_mixin.Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
    ) -> None:
        """Constructor for Master Boot CRC XiP Image for KW45xx/K32W1xx family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param trust_zone: TrustZone object, defaults to None
        :param firmware_version: Firmware version of image, defaults to 0
        :param image_subtype: Selection of image subtype (MAIN/NBU), default to None(MAIN)
        """
        self.app = align_block(app) if app else None
        self.load_address = load_addr
        self.tz = trust_zone or TrustZone.enabled()
        self.firmware_version = firmware_version
        self.set_image_subtype(image_subtype)
        super().__init__()


########################################################################################################################
# Master Boot Image Class (MCXNX)
########################################################################################################################
class Mbi_CrcXipMcxNx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for mcxnx family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        firmware_version: int = 0,
        load_addr: Optional[int] = None,
    ) -> None:
        """Constructor for Master Boot CRC XiP Image for mcxnx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.firmware_version = firmware_version
        self.load_address = load_addr
        self.app_ext_memory_align = 0x1000
        super().__init__()


class Mbi_PlainXipSignedMcxNx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifestMcxNx,
    mbi_mixin.Mbi_MixinImageSubType,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image for mcxnx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        firmware_version: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifestMcxNx] = None,
        signature_provider: Optional[SignatureProvider] = None,
        image_subtype: Optional[mbi_mixin.Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx] = None,
        load_addr: Optional[int] = None,
    ) -> None:
        """Constructor for Master Boot Signed XIP Image for mcxnx family.

        :param app: Application image data, defaults to None
        :param firmware_version: Firmware version of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        :param image_subtype: Selection of image subtype (MAIN/RECOVERY), default to None(MAIN)
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.firmware_version = firmware_version
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        self.set_image_subtype(image_subtype)
        self.load_address = load_addr
        self.app_ext_memory_align = 0x1000
        super().__init__()


class Mbi_PlainRamMcxNx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain RAM Image for mcxnx family."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Plain RAM Image for mcxnx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        self.app_ext_memory_align = 0x1000
        super().__init__()


class Mbi_CrcRamMcxNx(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for mcxnx family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Signed RAM Image for mcxnx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        super().__init__()


########################################################################################################################
# Master Boot Image Class (RW61x)
########################################################################################################################
class Mbi_PlainRamRw61x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain RAM Image for RW61x family."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Plain RAM Image for RW61x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.firmware_version = firmware_version
        self.load_address = load_addr
        super().__init__()


class Mbi_CrcRamRw61x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for RW61x family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot Signed RAM Image for RW61x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        super().__init__()


class Mbi_PlainSignedRamRw61x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifest,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Plain Signed RAM Image for RW61x family."""

    IMAGE_TYPE = SIGNED_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
        trust_zone: Optional[TrustZone] = None,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Constructor for Master Boot Plain Signed RAM Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        :param trust_zone: TrustZone object, defaults to None
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000

        self.load_address = load_addr
        self.firmware_version = firmware_version
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        super().__init__()


class Mbi_PlainExtXipSignedRw61x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinCertBlockV31,
    mbi_mixin.Mbi_MixinManifest,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppCertBlockManifest,
    mbi_mixin.Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image stored in external memory for RW61x family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
        trust_zone: Optional[TrustZone] = None,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[mbi_mixin.MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Constructor for Master Boot Signed XIP Image for RW61x family.

        :param app: Application image data, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        :param trust_zone: TrustZone object, defaults to None
        :param cert_block: Certification block of image, defaults to None
        :param manifest: Manifest of image, defaults to None
        :param signature_provider: Signature provider to sign final image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.load_address = load_addr
        self.firmware_version = firmware_version
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.manifest = manifest
        self.signature_provider = signature_provider
        super().__init__()


class Mbi_CrcExtXipRw61x(
    MasterBootImage,
    mbi_mixin.Mbi_MixinApp,
    mbi_mixin.Mbi_MixinIvt,
    mbi_mixin.Mbi_MixinTrustZoneMandatory,
    mbi_mixin.Mbi_MixinLoadAddress,
    mbi_mixin.Mbi_MixinFwVersion,
    mbi_mixin.Mbi_ExportMixinAppTrustZone,
    mbi_mixin.Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for RW61x family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: int = 0,
        firmware_version: int = 0,
    ) -> None:
        """Constructor for Master Boot CRC XiP Image stored in external memory for RW61x family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address of image, defaults to 0
        :param firmware_version: Firmware version of image, defaults to 0
        """
        self.app = align_block(app) if app else None
        self.app_ext_memory_align = 0x1000
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.firmware_version = firmware_version
        super().__init__()

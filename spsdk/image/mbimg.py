#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""


from copy import deepcopy
from inspect import isclass
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

from Crypto.Cipher import AES
from ruamel.yaml import YAML

from spsdk.crypto import SignatureProvider
from spsdk.exceptions import SPSDKValueError
from spsdk.image import IMG_DATA_FOLDER, MBIMG_SCH_FILE
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi_mixin import (
    MasterBootImageManifest,
    Mbi_ExportMixinAppCertBlockManifest,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinAppTrustZoneCertBlock,
    Mbi_ExportMixinCrcSign,
    Mbi_ExportMixinEccSign,
    Mbi_ExportMixinHmacKeyStoreFinalize,
    Mbi_ExportMixinRsaSign,
    Mbi_ExportMixinSignDigestFinalize,
    Mbi_Mixin,
    Mbi_MixinApp,
    Mbi_MixinCertBlockV2,
    Mbi_MixinCertBlockV31,
    Mbi_MixinCtrInitVector,
    Mbi_MixinFwVersion,
    Mbi_MixinHmacMandatory,
    Mbi_MixinHwKey,
    Mbi_MixinImageSubType,
    Mbi_MixinIvt,
    Mbi_MixinKeyStore,
    Mbi_MixinLoadAddress,
    Mbi_MixinManifest,
    Mbi_MixinNoSignature,
    Mbi_MixinNXPImage,
    Mbi_MixinRelocTable,
    Mbi_MixinSignDigest,
    Mbi_MixinTrustZone,
    Mbi_MixinTrustZoneMandatory,
    MultipleImageTable,
)
from spsdk.image.trustzone import TrustZone
from spsdk.utils.crypto.cert_blocks import CertBlockV2, CertBlockV31
from spsdk.utils.misc import align_block, get_key_by_val
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config

PLAIN_IMAGE = (0x00, "Plain Image (either XIP or Load-to-RAM)")
SIGNED_RAM_IMAGE = (0x01, "Plain Signed Load-to-RAM Image")
CRC_RAM_IMAGE = (0x02, "Plain CRC Load-to-RAM Image")
ENCRYPTED_RAM_IMAGE = (0x03, "Encrypted Load-to-RAM Image")
SIGNED_XIP_IMAGE = (0x04, "Plain Signed XIP Image")
CRC_XIP_IMAGE = (0x05, "Plain CRC XIP Image")

DEVICE_FILE = IMG_DATA_FOLDER + "/database.yml"

# pylint: disable=too-many-ancestors
def get_mbi_class(config: Dict[str, Any]) -> Type["MasterBootImage"]:
    """Get Master Boot Image class.

    :raises SPSDKUnsupportedImageType: The invalid configuration.
    :return: MBI Class.
    """
    schema_cfg = ValidationSchemas.get_schema_file(MBIMG_SCH_FILE)
    with open(DEVICE_FILE) as f:
        device_cfg = YAML(typ="safe").load(f)
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
    with open(DEVICE_FILE) as f:
        device_cfg = YAML(typ="safe").load(f)
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
        yaml_data = ConfigTemplate(
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
    with open(DEVICE_FILE) as f:
        device_cfg = YAML(typ="safe").load(f)
    devices: Dict[str, Any] = device_cfg["devices"]
    return list(devices.keys())


class MasterBootImage:
    """Master Boot Image Interface."""

    IMAGE_TYPE = PLAIN_IMAGE

    @classmethod
    def _get_mixins(cls) -> List[Type[Mbi_Mixin]]:
        """Get the list of Mbi Mixin classes.

        :return: List of Mbi_Mixins.
        """
        return [x for x in cls.__bases__ if issubclass(x, Mbi_Mixin)]

    def __init__(self) -> None:
        """Initialization of MBI."""
        # Check if all needed class instance members are available (validation of class due to mixin problems)
        self.search_paths: Optional[List[str]] = None
        for base in self._get_mixins():
            for member in base.NEEDED_MEMBERS:
                assert hasattr(self, member)

    @property
    def total_len(self) -> int:
        """Compute final application data length.

        :return: Final image data length.
        """
        ret = 0
        for base in self._get_mixins():
            ret += base.mix_len(self)  # type: ignore
        return ret

    @property
    def app_len(self) -> int:
        """Application data length.

        :return: Application data length.
        """
        return self.total_len

    def load_from_config(
        self, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        self.search_paths = search_paths
        for base in self._get_mixins():
            base.mix_load_from_config(self, config)  # type: ignore

    collect_data: Any  # collect_data(self) -> bytes
    encrypt: Any  # encrypt(self, raw_image: bytes) -> bytes
    post_encrypt: Any  # post_encrypt(self, image: bytes) -> bytes
    sign: Any  # sign(self, image: bytes) -> bytes
    finalize: Any  # finalize(self, image: bytes) -> bytes

    def export(self) -> bytes:
        """Export final bootable image.

        :return: Bootable Image in bytes.
        """
        # 1: Validate the input data
        self.validate()
        # 2: Collect all input data into raw image
        raw_image = self.collect_data()
        # 3: Optionally encrypt the image
        encrypted_image = self.encrypt(raw_image)
        # 4: Optionally do some post encrypt image updates
        encrypted_image = self.post_encrypt(encrypted_image)
        # 5: Optionally sign image
        signed_image = self.sign(encrypted_image)
        # 6: Finalize image
        final_image = self.finalize(signed_image)

        return final_image

    def parse(self, data: bytes) -> None:
        """Parse the final image to individual fields.

        :param data: Final Image in bytes.
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Create the list of supported families by this class.

        :return: List of supported families.
        """
        ret = set()
        with open(DEVICE_FILE) as f:
            device_cfg = YAML(typ="safe").load(f)

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
    MasterBootImage, Mbi_MixinApp, Mbi_MixinIvt, Mbi_MixinTrustZone, Mbi_ExportMixinAppTrustZone
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinLoadAddress,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinCertBlockV2,
    Mbi_ExportMixinAppTrustZoneCertBlock,
    Mbi_ExportMixinRsaSign,
):
    """Master Boot Signed XiP Image for LPC55xxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        cert_block: Optional[CertBlockV2] = None,
        priv_key_data: Optional[bytes] = None,
    ) -> None:
        """Constructor for Master Boot Signed XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param cert_block: Certification block of image, defaults to None
        :param priv_key_data: Private key used to sign image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.priv_key_data = priv_key_data
        super().__init__()


class Mbi_SignedRam(
    MasterBootImage,
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinLoadAddress,
    Mbi_MixinCertBlockV2,
    Mbi_ExportMixinAppTrustZoneCertBlock,
    Mbi_ExportMixinRsaSign,
):
    """Master Boot Signed RAM Image for LPC55xxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        priv_key_data: Optional[bytes] = None,
    ) -> None:
        """Constructor for Master Boot Signed XiP Image for LPC55xxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param priv_key_data: Private key used to sign image, defaults to None
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.cert_block = cert_block
        self.priv_key_data = priv_key_data
        super().__init__()


########################################################################################################################
# Master Boot Image Class (i.MXRT5xx/i.MXRT6xx)
########################################################################################################################


class Mbi_PlainRamRtxxx(
    MasterBootImage,
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinLoadAddress,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZone,
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
    Mbi_MixinApp,
    Mbi_MixinRelocTable,
    Mbi_MixinLoadAddress,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinCertBlockV2,
    Mbi_MixinHmacMandatory,
    Mbi_MixinKeyStore,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZoneCertBlock,
    Mbi_ExportMixinRsaSign,
    Mbi_ExportMixinHmacKeyStoreFinalize,
):
    """Master Boot Plain Signed RAM Image for RTxxx family."""

    IMAGE_TYPE = SIGNED_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[MultipleImageTable] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        priv_key_data: Optional[bytes] = None,
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
        :param priv_key_data: Private key used to sign image, defaults to None
        :param hmac_key: HMAC key of image, defaults to None
        :param key_store: Optional KeyStore object for image, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.app_table = app_table
        self.load_address = load_addr
        self.tz = trust_zone or TrustZone.enabled()
        self.cert_block = cert_block
        self.priv_key_data = priv_key_data
        self.hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key
        self.key_store = key_store
        self.user_hw_key_enabled = hwk
        super().__init__()

    @property
    def app_len(self) -> int:
        """Application data length.

        :return: Application data length.
        """
        assert self.cert_block
        return self.get_app_length() + len(self.cert_block.export()) + len(self.tz.export())


class Mbi_CrcRamRtxxx(
    MasterBootImage,
    Mbi_MixinApp,
    Mbi_MixinRelocTable,
    Mbi_MixinLoadAddress,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC RAM Image for RTxxx family."""

    IMAGE_TYPE = CRC_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[MultipleImageTable] = None,
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
    Mbi_MixinApp,
    Mbi_MixinRelocTable,
    Mbi_MixinLoadAddress,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinCertBlockV2,
    Mbi_MixinHwKey,
    Mbi_MixinKeyStore,
    Mbi_MixinHmacMandatory,
    Mbi_MixinCtrInitVector,
    Mbi_ExportMixinRsaSign,
    Mbi_ExportMixinHmacKeyStoreFinalize,
):
    """Master Boot Encrypted RAM Image for RTxxx family."""

    IMAGE_TYPE = ENCRYPTED_RAM_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        app_table: Optional[MultipleImageTable] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        priv_key_data: Optional[bytes] = None,
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
        :param priv_key_data: Private key used to sign image, defaults to None
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
        self.priv_key_data = priv_key_data
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
        self.cert_block.alignment = 4  # type: ignore   # this value is used by elf-to-sb-gui

        self.img_len = (
            self.total_len + self.cert_block.signature_size + 56 + 16
        )  # Encrypted IVT + IV

        return self.update_ivt(
            app_data=self.get_app_data() + self.tz.export(),
            total_len=self.img_len,
            crc_val_cert_offset=self.get_app_length(),
        )

    def encrypt(self, raw_image: bytes) -> bytes:
        """Encrypt image if needed.

        :param raw_image: Input raw image to encrypt.
        :return: Encrypted image.
        """
        assert self.hmac_key and self.ctr_init_vector
        key = self.hmac_key
        if not self.key_store or self.key_store.key_source == KeySourceType.OTP:
            key = KeyStore.derive_enc_image_key(key)
        aes = AES.new(key, AES.MODE_CTR, initial_value=self.ctr_init_vector, nonce=bytes())
        return aes.encrypt(raw_image + self.tz.export())

    def post_encrypt(self, image: bytes) -> bytes:
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :return: Updated encrypted image.
        """
        assert self.cert_block
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZone,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZone,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinLoadAddress,
    Mbi_MixinTrustZone,
    Mbi_MixinCertBlockV2,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZoneCertBlock,
    Mbi_ExportMixinRsaSign,
):
    """Master Boot Plain Signed XiP Image for RTxxx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        trust_zone: Optional[TrustZone] = None,
        load_addr: Optional[int] = None,
        cert_block: Optional[CertBlockV2] = None,
        priv_key_data: Optional[bytes] = None,
        hwk: bool = False,
    ) -> None:
        """Constructor for Master Boot Plain Signed XiP Image for RTxxx family.

        :param app: Application image data, defaults to None
        :param trust_zone: TrustZone object, defaults to None
        :param load_addr: Load/Execution address in RAM of image, defaults to 0
        :param cert_block: Certification block of image, defaults to None
        :param priv_key_data: Private key used to sign image, defaults to None
        :param hwk: Enable HW user mode keys, defaults to false
        """
        self.app = align_block(app) if app else None
        self.tz = trust_zone or TrustZone.enabled()
        self.load_address = load_addr
        self.cert_block = cert_block
        self.priv_key_data = priv_key_data
        self.user_hw_key_enabled = hwk
        super().__init__()


class Mbi_CrcXipRtxxx(
    MasterBootImage,
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinLoadAddress,
    Mbi_MixinTrustZone,
    Mbi_MixinHwKey,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZoneMandatory,
    Mbi_MixinLoadAddress,
    Mbi_MixinFwVersion,
    Mbi_ExportMixinAppTrustZone,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZoneMandatory,
    Mbi_MixinLoadAddress,
    Mbi_MixinFwVersion,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinCertBlockV31,
    Mbi_MixinManifest,
    Mbi_MixinLoadAddress,
    Mbi_MixinFwVersion,
    Mbi_ExportMixinAppCertBlockManifest,
    Mbi_ExportMixinEccSign,
):
    """Master Boot Signed XIP Image for LPC55s3x family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        firmware_version: int = 0,
        load_addr: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[MasterBootImageManifest] = None,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinTrustZoneMandatory,
    Mbi_MixinLoadAddress,
    Mbi_MixinFwVersion,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinLoadAddress,
    Mbi_MixinTrustZoneMandatory,
    Mbi_MixinImageSubType,
    Mbi_ExportMixinAppTrustZone,
):
    """Master Boot Plain RAM Image for KW45xx/K32W1xx family."""

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        trust_zone: Optional[TrustZone] = None,
        firmware_version: int = 0,
        image_subtype: Optional[Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
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
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinLoadAddress,
    Mbi_MixinCertBlockV31,
    Mbi_MixinManifest,
    Mbi_MixinImageSubType,
    Mbi_MixinSignDigest,
    Mbi_MixinNXPImage,
    Mbi_MixinNoSignature,
    Mbi_ExportMixinAppCertBlockManifest,
    Mbi_ExportMixinEccSign,
    Mbi_ExportMixinSignDigestFinalize,
):
    """Master Boot Signed XIP Image for KW45xx/K32W1xx family."""

    IMAGE_TYPE = SIGNED_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        firmware_version: int = 0,
        cert_block: Optional[CertBlockV31] = None,
        manifest: Optional[MasterBootImageManifest] = None,
        signature_provider: Optional[SignatureProvider] = None,
        image_subtype: Optional[Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
        attach_sign_digest: Optional[bool] = None,
        nxp_image: Optional[bool] = None,
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
        :param attach_sign_digest: Additional signature digest.
            Possible values are: None, 'sha256' and 'sha384', defaults to None
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
        self.attach_sign_digest = self.get_sign_digest() if attach_sign_digest else None
        if nxp_image:
            self.change_to_nxp_image()
        super().__init__()


class Mbi_CrcXipKw45xx(
    MasterBootImage,
    Mbi_MixinApp,
    Mbi_MixinIvt,
    Mbi_MixinLoadAddress,
    Mbi_MixinTrustZoneMandatory,
    Mbi_MixinImageSubType,
    Mbi_ExportMixinAppTrustZone,
    Mbi_ExportMixinCrcSign,
):
    """Master Boot CRC XiP Image for KW45xx/K32W1xx family."""

    IMAGE_TYPE = CRC_XIP_IMAGE

    def __init__(
        self,
        app: Optional[bytes] = None,
        load_addr: Optional[int] = None,
        trust_zone: Optional[TrustZone] = None,
        firmware_version: int = 0,
        image_subtype: Optional[Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx] = None,
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

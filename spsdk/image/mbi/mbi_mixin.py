#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import logging
import os
import struct
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from crcmod.predefined import mkPredefinedCrcFun

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.hmac import hmac
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.signature_provider import (
    SignatureProvider,
    get_signature_provider,
    try_to_verify_public_key,
)
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt
from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi.mbi_classes import (
    MasterBootImageManifest,
    MasterBootImageManifestCrc,
    MasterBootImageManifestDigest,
    MultipleImageEntry,
    MultipleImageTable,
    T_Manifest,
)
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils.crypto.cert_blocks import CertBlockV1, CertBlockV21, CertBlockVx
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    Endianness,
    align_block,
    find_file,
    load_binary,
    load_configuration,
    load_hex_string,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)

# ****************************************************************************************************
#                                             Mbi Mixins
# ****************************************************************************************************


# pylint: disable=invalid-name
class Mbi_Mixin:
    """Base class for Master BOtt Image Mixin classes."""

    VALIDATION_SCHEMAS: List[str] = []
    NEEDED_MEMBERS: Dict[str, Any] = {}
    PRE_PARSED: List[str] = []
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = True

    def mix_len(self) -> int:  # pylint: disable=no-self-use
        """Compute length of individual mixin.

        :return: Length of atomic Mixin.
        """
        return 0

    def mix_app_len(self) -> int:  # pylint: disable=no-self-use
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return 0

    @classmethod
    def mix_get_extra_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Get extra-non standard validation schemas from mixin.

        :return: List of additional validation schemas.
        """
        return []

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """

    def mix_validate(self) -> None:
        """Validate the setting of image."""

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        return {}


class Mbi_MixinApp(Mbi_Mixin):
    """Master Boot Image App class."""

    VALIDATION_SCHEMAS: List[str] = ["app"]
    NEEDED_MEMBERS: Dict[str, Any] = {"_app": bytes(), "app_ext_memory_align": 0x1000}

    _app: bytes
    app_ext_memory_align: int
    search_paths: Optional[List[str]]

    @property
    def app(self) -> bytes:
        """Application data."""
        return self._app

    @app.setter
    def app(self, app: bytes) -> None:
        """Application data."""
        self._app = align_block(app)

    def mix_len(self) -> int:
        """Get size of plain input application image.

        :return: Length of application.
        """
        assert self.app
        return len(self.app)

    def mix_app_len(self) -> int:
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        assert self.app
        return len(self.app)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.load_binary_image_file(config["inputImageFile"])

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        if self.app:
            filename = "application.bin"
            write_file(self.app, os.path.join(output_folder, filename), mode="wb")
            config["inputImageFile"] = filename
        return config

    def load_binary_image_file(self, path: str) -> None:
        """Load binary image from file (S19,HEX,BIN).

        :param path: File path
        :raises SPSDKError: If invalid data file is detected.
        """
        app_align = self.app_ext_memory_align if hasattr(self, "app_ext_memory_align") else 0
        image = BinaryImage.load_binary_image(find_file(path, search_paths=self.search_paths))
        if app_align and image.absolute_address % app_align != 0:
            raise SPSDKError(
                f"Invalid input binary file {path}. It has to be aligned to {hex(app_align)}."
            )
        self.app = image.export()


class Mbi_MixinTrustZone(Mbi_Mixin):
    """Master Boot Image Trust Zone class."""

    VALIDATION_SCHEMAS: List[str] = ["trust_zone"]
    NEEDED_MEMBERS: Dict[str, Any] = {"trust_zone": TrustZone.enabled(), "family": "Unknown"}
    PRE_PARSED: List[str] = ["cert_block"]

    family: str
    trust_zone: TrustZone
    search_paths: Optional[List[str]]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        :return: Length of TrustZone.
        """
        return len(self.trust_zone.export())

    def _load_preset_file(self, preset_file: str) -> None:
        _preset_file = find_file(preset_file, search_paths=self.search_paths)
        try:
            tz_config = load_configuration(_preset_file)
            self.trust_zone = TrustZone.from_config(tz_config)
        except SPSDKError:
            tz_bin = load_binary(_preset_file)
            self.trust_zone = TrustZone.from_binary(family=self.family, raw_data=tz_bin)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        enabled_trustzone = config.get("enableTrustZone", False)
        if enabled_trustzone:
            trustzone_preset_file = config.get("trustZonePresetFile", None)
            if trustzone_preset_file:
                self._load_preset_file(trustzone_preset_file)
            else:
                self.trust_zone = TrustZone.enabled()
        else:
            self.trust_zone = TrustZone.disabled()

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["enableTrustZone"] = bool(self.trust_zone.type != TrustZoneType.DISABLED)
        if self.trust_zone.type == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        tz_type = Mbi_MixinIvt.get_tz_type(data)
        if tz_type not in TrustZoneType.tags():
            raise SPSDKParsingError("Invalid TrustZone type")

        if tz_type == TrustZoneType.CUSTOM:
            # load custom data
            tz_data_size = TrustZone.get_preset_data_size(self.family)
            if hasattr(self, "cert_block"):
                assert self.cert_block
                tz_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size
                tz_data = data[tz_offset : tz_offset + tz_data_size]
            else:
                tz_data = data[-tz_data_size:]
            trust_zone = TrustZone.from_binary(family=self.family, raw_data=tz_data)
        elif tz_type == TrustZoneType.ENABLED:
            trust_zone = TrustZone.enabled()
        else:
            trust_zone = TrustZone.disabled()

        self.trust_zone = trust_zone


class Mbi_MixinTrustZoneMandatory(Mbi_MixinTrustZone):
    """Master Boot Image Trust Zone class for devices where is Trustzone mandatory."""

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        trustzone_preset_file = config.get("trustZonePresetFile", None)
        if trustzone_preset_file:
            self._load_preset_file(trustzone_preset_file)
        else:
            self.trust_zone = TrustZone.enabled()

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The TrustZone configuration is invalid.
        """
        if not self.trust_zone or self.trust_zone.type == TrustZoneType.DISABLED:
            raise SPSDKError("The Trust Zone MUST be used.")


class Mbi_MixinLoadAddress(Mbi_Mixin):
    """Master Boot Image load address class."""

    VALIDATION_SCHEMAS: List[str] = ["load_addr"]
    NEEDED_MEMBERS: Dict[str, Any] = {"load_address": 0}

    load_address: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        value = config.get("outputImageExecutionAddress")
        assert value is not None
        self.load_address = value_to_int(value)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        assert self.load_address is not None
        config["outputImageExecutionAddress"] = hex(self.load_address)
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.load_address = Mbi_MixinIvt.get_load_address(data)


class Mbi_MixinFwVersion(Mbi_Mixin):
    """Master Boot Image FirmWare Version class."""

    VALIDATION_SCHEMAS: List[str] = ["firmware_version"]
    NEEDED_MEMBERS: Dict[str, Any] = {"manifest": None}

    firmware_version: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["firmwareVersion"] = self.firmware_version
        return config


class Mbi_MixinImageVersion(Mbi_Mixin):
    """Master Boot Image Image Version class."""

    VALIDATION_SCHEMAS: List[str] = ["image_version"]
    NEEDED_MEMBERS: Dict[str, Any] = {"image_version": 0}
    image_version_to_image_type: bool = True

    image_version: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.image_version = value_to_int(config.get("imageVersion", 0))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["imageVersion"] = self.image_version
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.image_version = Mbi_MixinIvt.get_image_version(data)


class Mbi_MixinImageSubType(Mbi_Mixin):
    """Master Boot Image SubType class."""

    class Mbi_ImageSubTypeKw45xx(SpsdkEnum):
        """Supported MAIN and NBU subtypes for KW45xx and K32W1xx."""

        MAIN = (0x00, "MAIN", "Default (main) application image")
        NBU = (0x01, "NBU", "NBU (Narrowband Unit) image")

    class Mbi_ImageSubTypeMcxn9xx(SpsdkEnum):
        """Supported MAIN and NBU subtypes for MCXN9xx."""

        MAIN = (0x00, "MAIN", "Default (main) application image")
        RECOVERY = (0x01, "RECOVERY", "Recovery image")

    VALIDATION_SCHEMAS: List[str] = ["image_subtype"]
    NEEDED_MEMBERS: Dict[str, Any] = {"image_subtype": 0}

    image_subtype: Optional[int]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.set_image_subtype(config.get("outputImageSubtype", "main"))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.mb_xip_384_384_recovery_crctest
        """
        config: Dict[str, Any] = {}
        assert self.image_subtype is not None
        config["outputImageSubtype"] = Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.from_tag(
            self.image_subtype
        ).label
        return config

    def set_image_subtype(self, image_subtype: Optional[Union[str, int]]) -> None:
        """Convert string value to int by enum table and store to class."""
        if image_subtype is None:
            image_subtype_int = (
                Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.MAIN.tag
                or Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx.MAIN.tag
            )
        elif isinstance(image_subtype, str):
            image_subtype_int = (
                Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.get_tag(image_subtype)
                if image_subtype.upper() in Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.labels()
                else Mbi_MixinImageSubType.Mbi_ImageSubTypeMcxn9xx.get_tag(image_subtype)
            )
        else:
            image_subtype_int = image_subtype
        self.image_subtype = image_subtype_int

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.image_subtype = Mbi_MixinIvt.get_sub_type(data)


class Mbi_MixinIvt(Mbi_Mixin):
    """Master Boot Image Interrupt Vector table class."""

    # IVT table offsets
    IVT_IMAGE_LENGTH_OFFSET = 0x20
    IVT_IMAGE_FLAGS_OFFSET = 0x24
    IVT_CRC_CERTIFICATE_OFFSET = 0x28
    IVT_LOAD_ADDR_OFFSET = 0x34

    IVT_IMAGE_FLAGS_IMAGE_TYPE_MASK = 0x3F
    IVT_IMAGE_FLAGS_TZ_TYPE_MASK = 0x03
    IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT = 13
    IVT_IMAGE_FLAGS_IMG_VER_MASK = 0xFFFF
    IVT_IMAGE_FLAGS_IMG_VER_SHIFT = 16
    IVT_IMAGE_FLAGS_SUB_TYPE_MASK = 0x03
    IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT = 6

    # flag indication presence of boot image version (Used by some devices)
    _BOOT_IMAGE_VERSION_FLAG = 0x400
    # flag that image contains relocation table
    _RELOC_TABLE_FLAG = 0x800
    # enableHwUserModeKeys : flag for controlling secure hardware key bus. If enabled(1), then it is possible to access
    # keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
    _HW_USER_KEY_EN_FLAG = 0x1000
    # flag for image type, if the image contains key-store
    _KEY_STORE_FLAG = 0x8000

    trust_zone: TrustZone
    IMAGE_TYPE: Tuple[int, str]
    load_address: Optional[int]
    user_hw_key_enabled: Optional[bool]
    app_table: Optional["MultipleImageTable"]
    key_store: Optional[KeyStore]
    image_version: Optional[int]
    image_version_to_image_type: bool
    image_subtype: Optional[int]

    def create_flags(self) -> int:
        """Create flags of image.

        :return: Image type flags
        """
        flags = int(self.IMAGE_TYPE[0])
        if hasattr(self, "trust_zone"):
            flags |= self.trust_zone.type.tag << self.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT

        if hasattr(self, "image_subtype"):
            assert self.image_subtype is not None
            flags |= self.image_subtype << self.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT

        if hasattr(self, "user_hw_key_enabled") and self.user_hw_key_enabled:
            flags |= self._HW_USER_KEY_EN_FLAG

        if hasattr(self, "key_store") and self.key_store and len(self.key_store.export()) > 0:
            flags |= self._KEY_STORE_FLAG

        if hasattr(self, "app_table") and self.app_table:
            flags |= self._RELOC_TABLE_FLAG

        if (
            hasattr(self, "image_version")
            and self.image_version
            and hasattr(self, "image_version_to_image_type")
            and self.image_version_to_image_type
        ):
            flags |= self._BOOT_IMAGE_VERSION_FLAG
            flags |= self.image_version << 16
        return flags

    def update_ivt(
        self,
        app_data: bytes,
        total_len: int,
        crc_val_cert_offset: int = 0,
    ) -> bytes:
        """Update IVT table in application image.

        :param app_data: Application data that should be modified.
        :param total_len: Total length of bootable image
        :param crc_val_cert_offset: CRC value or Certification block offset
        :return: Updated whole application image
        """
        data = bytearray(app_data)
        # Total length of image
        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = struct.pack(
            "<I", total_len
        )
        # flags
        data[self.IVT_IMAGE_FLAGS_OFFSET : self.IVT_IMAGE_FLAGS_OFFSET + 4] = struct.pack(
            "<I", self.create_flags()
        )
        # CRC value or Certification block offset
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )
        # Execution address
        load_addr = self.load_address if hasattr(self, "load_address") else 0
        data[self.IVT_LOAD_ADDR_OFFSET : self.IVT_LOAD_ADDR_OFFSET + 4] = struct.pack(
            "<I", load_addr
        )

        return bytes(data)

    def clean_ivt(self, app_data: bytes) -> bytes:
        """Clean IVT table from added information.

        :param app_data: Application data that should be cleaned.
        :return: Cleaned application image
        """
        data = bytearray(app_data)
        # Total length of image
        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = bytes(4)
        # flags
        data[self.IVT_IMAGE_FLAGS_OFFSET : self.IVT_IMAGE_FLAGS_OFFSET + 4] = bytes(4)
        # CRC value or Certification block offset
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = bytes(4)
        # Execution address
        data[self.IVT_LOAD_ADDR_OFFSET : self.IVT_LOAD_ADDR_OFFSET + 4] = bytes(4)

        return bytes(data)

    def update_crc_val_cert_offset(self, app_data: bytes, crc_val_cert_offset: int) -> bytes:
        """Update value just of CRC/Certificate offset field.

        :param app_data: Input binary array.
        :param crc_val_cert_offset: CRC/Certificate offset value.
        :return: Updated binary array.
        """
        data = bytearray(app_data)
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )
        return data

    @staticmethod
    def check_total_length(data: bytes) -> None:
        """Check total length field from raw data.

        :param data: Raw MBI image data.
        :raises SPSDKParsingError: Insufficient length of image has been detected.
        """
        total_len = int.from_bytes(
            data[Mbi_MixinIvt.IVT_IMAGE_LENGTH_OFFSET : Mbi_MixinIvt.IVT_IMAGE_LENGTH_OFFSET + 4],
            Endianness.LITTLE.value,
        )

        if total_len < len(data):
            raise SPSDKParsingError("Insufficient length of input raw data!")

    @staticmethod
    def get_flags(data: bytes) -> int:
        """Get the Image flags from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Image Flags
        """
        Mbi_MixinIvt.check_total_length(data)

        flags = int.from_bytes(
            data[Mbi_MixinIvt.IVT_IMAGE_FLAGS_OFFSET : Mbi_MixinIvt.IVT_IMAGE_FLAGS_OFFSET + 4],
            Endianness.LITTLE.value,
        )

        return flags

    @staticmethod
    def get_cert_block_offset(data: bytes) -> int:
        """Get the certificate block offset from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Certificate block offset
        """
        Mbi_MixinIvt.check_total_length(data)

        return int.from_bytes(
            data[
                Mbi_MixinIvt.IVT_CRC_CERTIFICATE_OFFSET : Mbi_MixinIvt.IVT_CRC_CERTIFICATE_OFFSET
                + 4
            ],
            Endianness.LITTLE.value,
        )

    @staticmethod
    def get_load_address(data: bytes) -> int:
        """Get the load address from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Load address
        """
        Mbi_MixinIvt.check_total_length(data)

        return int.from_bytes(
            data[Mbi_MixinIvt.IVT_LOAD_ADDR_OFFSET : Mbi_MixinIvt.IVT_LOAD_ADDR_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @staticmethod
    def get_image_type(data: bytes) -> int:
        """Get the Image type from raw data.

        :param data: Raw MBI image data.
        :return: Image type
        """
        return Mbi_MixinIvt.get_flags(data) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_IMAGE_TYPE_MASK

    @staticmethod
    def get_tz_type(data: bytes) -> int:
        """Get the Image TrustZone type settings from raw data.

        :param data: Raw MBI image data.
        :return: TrustZone type.
        """
        flags = Mbi_MixinIvt.get_flags(data)
        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_TZ_TYPE_MASK

    @staticmethod
    def get_image_version(data: bytes) -> int:
        """Get the Image firmware version from raw data.

        :param data: Raw MBI image data.
        :return: Firmware version.
        """
        flags = Mbi_MixinIvt.get_flags(data)
        if flags & Mbi_MixinIvt._BOOT_IMAGE_VERSION_FLAG == 0:
            return 0

        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_IMG_VER_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_IMG_VER_MASK

    @staticmethod
    def get_sub_type(data: bytes) -> int:
        """Get the Image sub type from raw data.

        :param data: Raw MBI image data.
        :return: Image sub type.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return (
            flags >> Mbi_MixinIvt.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT
        ) & Mbi_MixinIvt.IVT_IMAGE_FLAGS_SUB_TYPE_MASK

    @staticmethod
    def get_hw_key_enabled(data: bytes) -> bool:
        """Get the HW key enabled setting from raw data.

        :param data: Raw MBI image data.
        :return: HW key enabled or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._HW_USER_KEY_EN_FLAG)

    @staticmethod
    def get_key_store_presented(data: bytes) -> int:
        """Get the KeyStore present flag from raw data.

        :param data: Raw MBI image data.
        :return: KeyStore is included or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._KEY_STORE_FLAG)

    @staticmethod
    def get_app_table_presented(data: bytes) -> int:
        """Get the Multiple Application table present flag from raw data.

        :param data: Raw MBI image data.
        :return: Multiple Application table is included or not.
        """
        flags = Mbi_MixinIvt.get_flags(data)

        return bool(flags & Mbi_MixinIvt._RELOC_TABLE_FLAG)


class Mbi_MixinBca(Mbi_Mixin):
    """Master Boot Image Boot Configuration Area."""

    VALIDATION_SCHEMAS: List[str] = ["firmware_version"]

    # BCA table offsets
    IMG_DIGEST_SIZE = 32
    IMG_DIGEST_OFFSET = 0x360
    IMG_SIGNATURE_OFFSET = IMG_DIGEST_OFFSET + IMG_DIGEST_SIZE
    IMG_BCA_OFFSET = 0x3C0
    IMG_BCA_IMAGE_LENGTH_OFFSET = IMG_BCA_OFFSET + 0x20
    IMG_BCA_FW_VERSION_OFFSET = IMG_BCA_OFFSET + 0x24
    IMG_FCB_OFFSET = 0x400
    IMG_FCB_SIZE = 16
    IMG_ISK_OFFSET = IMG_FCB_OFFSET + IMG_FCB_SIZE
    IMG_ISK_HASH_OFFSET = 0x4A0
    IMG_ISK_HASH_SIZE = 128
    IMG_WPC_BLOCK_OFFSET = IMG_ISK_HASH_OFFSET + IMG_ISK_HASH_SIZE
    IMG_WPC_BLOCK_SIZE = 736
    IMG_DUKB_BLOCK_OFFSET = IMG_WPC_BLOCK_OFFSET + IMG_WPC_BLOCK_SIZE
    IMG_DUKB_BLOCK_SIZE = 0x400

    IMG_DATA_START = 0xC00
    IMG_SIGNED_HEADER_END = IMG_FCB_OFFSET

    firmware_version: Optional[int]

    def mix_len(self) -> int:
        """Length of the image.

        :return: length in bytes
        """
        return (
            self.IMG_DIGEST_OFFSET
            + (self.IMG_FCB_OFFSET - self.IMG_BCA_OFFSET)
            - self.IMG_DATA_START
        )

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["firmwareVersion"] = self.firmware_version
        return config

    def update_bca(
        self,
        app_data: bytes,
        total_len: int,
    ) -> bytes:
        """Update BCA table in application image.

        :param app_data: Application data that should be modified.
        :param total_len: Total length of bootable image
        :return: Updated whole application image
        """
        data = bytearray(app_data)
        # Total length of image
        data[self.IMG_BCA_IMAGE_LENGTH_OFFSET : self.IMG_BCA_IMAGE_LENGTH_OFFSET + 4] = struct.pack(
            "<I", total_len
        )
        # Firmware version
        data[self.IMG_BCA_FW_VERSION_OFFSET : self.IMG_BCA_FW_VERSION_OFFSET + 4] = struct.pack(
            "<I", self.firmware_version
        )

        return bytes(data)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.firmware_version = struct.unpack(
            "<I", data[self.IMG_BCA_FW_VERSION_OFFSET : self.IMG_BCA_FW_VERSION_OFFSET + 4]
        )[0]


class Mbi_MixinRelocTable(Mbi_Mixin):
    """Master Boot Image Relocation table class."""

    VALIDATION_SCHEMAS: List[str] = ["app_table"]
    NEEDED_MEMBERS: Dict[str, Any] = {"app_table": None, "_app": None}

    app_table: Optional[MultipleImageTable]
    app: Optional[bytes]
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of additional binaries block.

        :return: Length of additional binaries block.
        """
        return len(self.app_table.export(0)) if self.app_table else 0

    def mix_app_len(self) -> int:
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return len(self.app_table.export(0)) if self.app_table else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        app_table = config.get("applicationTable", None)
        if app_table is None:
            return

        self.app_table = MultipleImageTable()
        for entry in app_table:
            image = load_binary(entry.get("binary"), search_paths=self.search_paths)
            dst_addr = value_to_int(entry.get("destAddress"))
            load = entry.get("load")
            image_entry = MultipleImageEntry(
                image, dst_addr, MultipleImageEntry.LTI_LOAD if load else 0
            )
            self.app_table.add_entry(image_entry)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        if self.app_table:
            cfg_table = []
            for entry in self.app_table.entries:
                entry_cfg: Dict[str, Union[str, int]] = {}
                entry_cfg["destAddress"] = entry.dst_addr
                filename = f"mit_{hex(entry.dst_addr)}.bin"
                write_file(entry.image, os.path.join(output_folder, filename))
                entry_cfg["binary"] = filename
                entry_cfg["load"] = entry.is_load
                cfg_table.append(entry_cfg)
            config["applicationTable"] = cfg_table
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Application table configuration is invalid.
        """
        if self.app_table and len(self.app_table.entries) == 0:
            raise SPSDKError("The application relocation table MUST has at least one record.")

    def disassembly_app_data(self, data: bytes) -> bytes:
        """Disassembly Application data to application and optionally Multiple Application Table.

        :return: Application data without Multiple Application Table which will be stored in class.
        """
        self.app_table = MultipleImageTable.parse(data)
        if self.app_table:
            return data[: self.app_table.start_address]

        return data


class Mbi_MixinManifest(Mbi_MixinTrustZoneMandatory):
    """Master Boot Image Manifest class."""

    manifest_class = MasterBootImageManifest
    manifest: Optional[MasterBootImageManifest]

    VALIDATION_SCHEMAS: List[str] = ["trust_zone", "firmware_version"]
    NEEDED_MEMBERS: Dict[str, Any] = {"manifest": None, "cert_block": None, "family": "Unknown"}
    PRE_PARSED: List[str] = ["cert_block"]

    family: str
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    firmware_version: Optional[int]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        assert self.manifest
        return self.manifest.total_length

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The manifest configuration is invalid.
        """
        super().mix_validate()
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV21)
        manifest_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size
        self.manifest = self.manifest_class.parse(self.family, data[manifest_offset:])
        self.firmware_version = self.manifest.firmware_version
        if self.manifest.trust_zone:
            self.trust_zone = self.manifest.trust_zone
        else:
            self.trust_zone = TrustZone.disabled()


class Mbi_MixinManifestCrc(Mbi_MixinManifest):
    """Master Boot Image Manifest class with CRC."""

    manifest_class = MasterBootImageManifestCrc
    manifest: Optional[MasterBootImageManifestCrc]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))

        self.manifest = self.manifest_class(
            self.firmware_version,
            self.trust_zone,
        )


class Mbi_MixinManifestDigest(Mbi_MixinManifest):
    """Master Boot Image Manifest class for devices supporting ImageDigest functionality."""

    manifest_class = MasterBootImageManifestDigest
    manifest: Optional[MasterBootImageManifestDigest]

    VALIDATION_SCHEMAS: List[str] = ["trust_zone", "firmware_version", "digest_hash_algo"]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        assert self.manifest

        hash_length = 0
        if self.manifest.flags & self.manifest.DIGEST_PRESENT_FLAG:
            hash_algo = {
                1: EnumHashAlgorithm.SHA256,
                2: EnumHashAlgorithm.SHA384,
                3: EnumHashAlgorithm.SHA512,
            }[self.manifest.flags & self.manifest.HASH_TYPE_MASK]
            hash_length = self.manifest.get_hash_size(hash_algo)
        return self.manifest.total_length + hash_length

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = value_to_int(config.get("firmwareVersion", 0))
        digest_hash_algorithm = (
            EnumHashAlgorithm.from_label(config["manifestDigestHashAlgorithm"])
            if "manifestDigestHashAlgorithm" in config
            else None
        )
        # Backward compatibility code (in case that new manifestDigestHashAlgorithm doesn't exist
        # try to load old one ):
        if not digest_hash_algorithm:
            digest_hash_algorithm_length = config.get("manifestSigningHashLength", None)
            if digest_hash_algorithm_length:
                digest_hash_algorithm = {
                    32: EnumHashAlgorithm.SHA256,
                    48: EnumHashAlgorithm.SHA384,
                    64: EnumHashAlgorithm.SHA512,
                }[digest_hash_algorithm_length]

        self.manifest = self.manifest_class(
            self.firmware_version, self.trust_zone, digest_hash_algo=digest_hash_algorithm
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.manifest
        config = super().mix_get_config(output_folder=output_folder)
        config["firmwareVersion"] = self.firmware_version
        if "digest_hash_algo" in self.VALIDATION_SCHEMAS:
            config["manifestDigestHashAlgorithm"] = self.manifest.digest_hash_algo
        return config


class Mbi_MixinCertBlockV1(Mbi_Mixin):
    """Master Boot Image certification block V1 class."""

    VALIDATION_SCHEMAS: List[str] = ["cert_block_v1", "signature_provider"]
    NEEDED_MEMBERS: Dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV1]
    signature_provider: Optional[SignatureProvider]
    search_paths: Optional[List[str]]
    total_len: Any
    key_store: Optional[KeyStore]
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of Certificate Block V1.

        :return: Length of Certificate Block V1.
        """
        return len(self.cert_block.export()) if self.cert_block else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV1.from_config(config, self.search_paths)
        private_key_file_name = config.get(
            "signPrivateKey", config.get("mainRootCertPrivateKeyFile")
        )
        signature_provider_config = config.get("signProvider")

        self.signature_provider = get_signature_provider(
            sp_cfg=signature_provider_config,
            local_file_key=private_key_file_name,
            search_paths=self.search_paths,
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.cert_block
        filename = "cert_block_v1.yaml"
        crt_blck_cfg = self.cert_block.create_config(output_folder)
        write_file(crt_blck_cfg, os.path.join(output_folder, filename))
        config = {}
        config["certBlock"] = filename
        config["signPrivateKey"] = "Cannot get from parse"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of Certificate block v1 is invalid.
        """
        if not self.cert_block or not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Certification block is missing")
        if not self.signature_provider:
            raise SPSDKError("Signature provider is not defined")

        public_key = self.cert_block.certificates[-1].get_public_key()
        try_to_verify_public_key(self.signature_provider, public_key.export())

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        offset = Mbi_MixinIvt.get_cert_block_offset(data)
        if hasattr(self, "hmac_key"):
            offset += self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(data):
                offset += KeyStore.KEY_STORE_SIZE

        self.cert_block = CertBlockV1.parse(data[offset:])
        self.cert_block.alignment = 4
        self.signature_provider = None


class Mbi_MixinCertBlockV21(Mbi_Mixin):
    """Master Boot Image certification block V3.1 class."""

    VALIDATION_SCHEMAS: List[str] = ["cert_block_v21", "signature_provider"]
    NEEDED_MEMBERS: Dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV21]
    signature_provider: Optional[SignatureProvider]
    search_paths: Optional[List[str]]

    def mix_len(self) -> int:
        """Get length of Certificate Block V2.1.

        :return: Length of Certificate Block V2.1.
        """
        assert self.cert_block and self.signature_provider
        return self.cert_block.expected_size + self.signature_provider.signature_length

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV21.from_config(config, search_paths=self.search_paths)

        private_key_file_name = config.get(
            "signPrivateKey", config.get("mainRootCertPrivateKeyFile")
        )
        signature_provider_config = config.get("signProvider")

        self.signature_provider = get_signature_provider(
            sp_cfg=signature_provider_config,
            local_file_key=private_key_file_name,
            search_paths=self.search_paths,
        )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.cert_block
        filename = "cert_block_v21.yaml"
        crt_blck_cfg = self.cert_block.create_config(output_folder)
        write_file(crt_blck_cfg, os.path.join(output_folder, filename))
        config = {}
        config["certBlock"] = filename
        config["signPrivateKey"] = "Cannot get from parse"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The configuration of Certificate v3.1 is invalid.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")

        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")
        public_key = (
            self.cert_block.isk_certificate.isk_cert.export()
            if self.cert_block.isk_certificate and self.cert_block.isk_certificate.isk_cert
            else self.cert_block.root_key_record.root_public_key
        )
        try_to_verify_public_key(self.signature_provider, public_key)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.cert_block = CertBlockV21.parse(data[Mbi_MixinIvt.get_cert_block_offset(data) :])
        self.signature_provider = None


class Mbi_MixinCertBlockVx(Mbi_Mixin):
    """Master Boot Image certification block for MC55xx class."""

    VALIDATION_SCHEMAS: List[str] = ["cert_block_vX", "signature_provider"]
    NEEDED_MEMBERS: Dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: CertBlockVx
    add_hash: bool
    signature_provider: Optional[SignatureProvider]
    search_paths: Optional[List[str]]
    IMG_ISK_OFFSET: int

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockVx.from_config(config, search_paths=self.search_paths)

        private_key_file_name = config.get(
            "signPrivateKey", config.get("mainRootCertPrivateKeyFile")
        )
        self.signature_provider = get_signature_provider(
            sp_cfg=config.get("signProvider"),
            local_file_key=private_key_file_name,
            search_paths=self.search_paths,
        )

        self.add_hash = config.get("addCertHash", True)

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The configuration of certificate block is invalid.
        """
        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.cert_block = CertBlockVx.parse(data[self.IMG_ISK_OFFSET :])
        self.signature_provider = None


class Mbi_MixinHwKey(Mbi_Mixin):
    """Master Boot Image HW key user modes enable class."""

    VALIDATION_SCHEMAS: List[str] = ["hw_key"]
    NEEDED_MEMBERS: Dict[str, Any] = {"user_hw_key_enabled": False}

    user_hw_key_enabled: Optional[bool]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.user_hw_key_enabled = config["enableHwUserModeKeys"]

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["enableHwUserModeKeys"] = bool(self.user_hw_key_enabled)
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not isinstance(self.user_hw_key_enabled, bool):
            raise SPSDKError("User HW Key is not Boolean type.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.user_hw_key_enabled = Mbi_MixinIvt.get_hw_key_enabled(data)


class Mbi_MixinKeyStore(Mbi_Mixin):
    """Master Boot Image KeyStore class."""

    VALIDATION_SCHEMAS: List[str] = ["key_store"]
    NEEDED_MEMBERS: Dict[str, Any] = {"key_store": None, "_hmac_key": None}
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = False

    key_store: Optional[KeyStore]
    hmac_key: Optional[bytes]
    search_paths: Optional[List[str]]
    HMAC_OFFSET: int
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of KeyStore block.

        :return: Length of KeyStore block.
        """
        return (
            len(self.key_store.export())
            if self.key_store and self.key_store.key_source == KeySourceType.KEYSTORE
            else 0
        )

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        key_store_file = config.get("keyStoreFile", None)

        self.key_store = None
        if key_store_file:
            key_store_data = load_binary(key_store_file, search_paths=self.search_paths)
            self.key_store = KeyStore(KeySourceType.KEYSTORE, key_store_data)

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        file_name = None
        if self.key_store:
            file_name = "key_store.bin"
            write_file(self.key_store.export(), os.path.join(output_folder, file_name), mode="wb")

        config["keyStoreFile"] = file_name
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.key_store and not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("When is used KeyStore, the HMAC key MUST by also used.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        key_store_present = Mbi_MixinIvt.get_key_store_presented(data)
        self.key_store = None
        if key_store_present:
            key_store_offset = self.HMAC_OFFSET + self.HMAC_SIZE
            self.key_store = KeyStore(
                KeySourceType.KEYSTORE,
                data[key_store_offset : key_store_offset + KeyStore.KEY_STORE_SIZE],
            )


class Mbi_MixinHmac(Mbi_Mixin):
    """Master Boot Image HMAC class."""

    VALIDATION_SCHEMAS: List[str] = ["hmac"]
    NEEDED_MEMBERS: Dict[str, Any] = {"_hmac_key": None}
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = False

    # offset in the image, where the HMAC table is located
    HMAC_OFFSET = 64
    # size of HMAC table in bytes
    HMAC_SIZE = 32
    # length of user key or master key, in bytes
    _HMAC_KEY_LENGTH = 32

    _hmac_key: Optional[bytes]
    search_paths: Optional[List[str]]
    dek: Optional[str]

    @property
    def hmac_key(self) -> Optional[bytes]:
        """HMAC key in bytes."""
        return self._hmac_key

    @hmac_key.setter
    def hmac_key(self, hmac_key: Optional[Union[bytes, str]]) -> None:
        """HMAC key in bytes."""
        self._hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key

    def mix_len(self) -> int:
        """Get length of HMAC block.

        :return: Length of HMAC block.
        """
        return self.HMAC_SIZE if self.hmac_key else 0

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        hmac_key_raw = config.get("outputImageEncryptionKeyFile")
        if hmac_key_raw:
            self.hmac_key = load_hex_string(
                hmac_key_raw, expected_size=self.HMAC_SIZE, search_paths=self.search_paths
            )

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        config["outputImageEncryptionKeyFile"] = "The HMAC key cannot be restored"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if self.hmac_key:
            length = len(self.hmac_key)
            if length != self._HMAC_KEY_LENGTH:
                raise SPSDKError(f"Invalid size of HMAC key 32 != {length}.")

    def compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC hash.

        :param data: Data to be hashed.
        :return: Result HMAC hash of input data.
        """
        if not self.hmac_key:
            return bytes()

        key = KeyStore.derive_hmac_key(self.hmac_key)
        result = hmac(key, data)
        assert len(result) == self.HMAC_SIZE
        return result

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if self.dek:
            self.hmac_key = load_hex_string(
                source=self.dek,
                expected_size=self._HMAC_KEY_LENGTH,
                search_paths=self.search_paths,
            )


class Mbi_MixinHmacMandatory(Mbi_MixinHmac):
    """Master Boot Image HMAC class (Mandatory use)."""

    VALIDATION_SCHEMAS: List[str] = ["hmac_mandatory"]

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("HMAC Key MUST exists.")
        super().mix_validate()


class Mbi_MixinCtrInitVector(Mbi_Mixin):
    """Master Boot Image initial vector for encryption counter."""

    VALIDATION_SCHEMAS: List[str] = ["ctr_init_vector"]
    NEEDED_MEMBERS: Dict[str, Any] = {"_ctr_init_vector": random_bytes(16)}
    PRE_PARSED: List[str] = ["cert_block"]
    # length of counter initialization vector
    _CTR_INIT_VECTOR_SIZE = 16

    _ctr_init_vector: bytes
    search_paths: Optional[List[str]]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    HMAC_SIZE: int

    @property
    def ctr_init_vector(self) -> Optional[bytes]:
        """Counter init vector."""
        return self._ctr_init_vector

    @ctr_init_vector.setter
    def ctr_init_vector(self, ctr_iv: Optional[bytes]) -> None:
        """Stores the Counter init vector, if not specified the random value is used.

        param ctr_iv: Counter Initial Vector.
        """
        if ctr_iv and isinstance(ctr_iv, bytes):
            self._ctr_init_vector = ctr_iv
        else:
            self._ctr_init_vector = random_bytes(self._CTR_INIT_VECTOR_SIZE)

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        ctr_init_vector_cfg = config.get("CtrInitVector", None)
        ctr_init_vector = (
            load_hex_string(ctr_init_vector_cfg, self._CTR_INIT_VECTOR_SIZE, self.search_paths)
            if ctr_init_vector_cfg
            else None
        )
        self.ctr_init_vector = ctr_init_vector

    def mix_get_config(self, output_folder: str) -> Dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: Dict[str, Any] = {}
        assert self.ctr_init_vector
        config["CtrInitVector"] = self.ctr_init_vector.hex()
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.ctr_init_vector:
            raise SPSDKError("Initial vector for encryption counter MUST exists.")
        if len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE:
            raise SPSDKError("Invalid size of Initial vector for encryption counter.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV1)
        iv_offset = Mbi_MixinIvt.get_cert_block_offset(data) + self.cert_block.expected_size + 56
        if hasattr(self, "hmac_key"):
            iv_offset += self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(data):
                iv_offset += KeyStore.KEY_STORE_SIZE
        self.ctr_init_vector = data[iv_offset : iv_offset + self._CTR_INIT_VECTOR_SIZE]


class Mbi_MixinNoSignature(Mbi_Mixin):
    """Master Boot Image No Signature."""

    VALIDATION_SCHEMAS: List[str] = ["no_signature"]
    NEEDED_MEMBERS: Dict[str, Any] = {"no_signature": False}

    no_signature: Optional[bool]

    def mix_load_from_config(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.no_signature = config.get("noSignature", False)


########################################################################################################################
# Export image Mixins
########################################################################################################################


class Mbi_ExportMixin:
    """Base MBI Export Mixin class."""

    def collect_data(self) -> BinaryImage:  # pylint: disable=no-self-use
        """Collect basic data to create image.

        :return: Collected raw image.
        """
        return BinaryImage(name="General")

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """

    def encrypt(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Encrypt image if needed.

        :param image: Input raw image to encrypt.
        :param revert: Revert the operation if possible.
        :return: Encrypted image.
        """
        return image

    def post_encrypt(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :param revert: Revert the operation if possible.
        :return: Updated encrypted image.
        """
        return image

    def sign(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Sign image (by signature or CRC).

        :param image: Image to sign.
        :param revert: Revert the operation if possible.
        :return: Optionally signed image.
        """
        return image

    def finalize(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Finalize the image for export.

        This part could add HMAC/KeyStore etc.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        return image


class Mbi_ExportMixinApp(Mbi_ExportMixin):
    """Export Mixin to handle simple application data."""

    app: Optional[bytes]
    total_len: Any
    update_ivt: Callable[[bytes, int, int], bytes]

    def collect_data(self) -> BinaryImage:
        """Collect application data including update IVT.

        :return: Image with updated IVT.
        """
        assert self.app
        return BinaryImage(name="Application", binary=self.update_ivt(self.app, self.total_len, 0))


class Mbi_ExportMixinAppTrustZone(Mbi_ExportMixin):
    """Export Mixin to handle simple application data and TrustZone."""

    app: Optional[bytes]
    trust_zone: TrustZone
    total_len: Any
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert self.app and self.trust_zone
        ret = BinaryImage(name="Application Block")
        app = self.update_ivt(self.app, self.total_len, 0)
        ret.append_image(BinaryImage(name="Application", binary=app))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(len(app)))
            )
        tz = self.trust_zone.export()
        if len(tz):
            ret.append_image(BinaryImage(name="TrustZone Settings", binary=tz))

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        tz_len = len(self.trust_zone.export())
        if tz_len:
            image = image[:-tz_len]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)


class Mbi_ExportMixinAppTrustZoneCertBlock(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block."""

    app: Optional[bytes]
    trust_zone: TrustZone
    total_len: int
    total_length_for_cert_block: int
    app_len: int
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert (
            self.app
            and self.trust_zone
            and self.cert_block
            and isinstance(self.cert_block, CertBlockV1)
        )
        ret = BinaryImage(name="Application Block")

        self.cert_block.alignment = 4
        self.cert_block.image_length = self.total_length_for_cert_block
        app = self.update_ivt(
            self.app, self.total_len + self.cert_block.signature_size, self.app_len
        )
        ret.append_image(BinaryImage(name="Application", binary=app))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(len(app)))
            )
        ret.append_image(BinaryImage(name="Certification Block", binary=self.cert_block.export()))
        tz = self.trust_zone.export()
        if len(tz):
            ret.append_image(BinaryImage(name="TrustZone Settings", binary=tz))

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        image = image[: -Mbi_MixinIvt.get_cert_block_offset(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)


class Mbi_ExportMixinAppCertBlockManifest(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, Certification block and Manifest."""

    app: Optional[bytes]
    app_len: int
    total_len: int
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    manifest: Optional[T_Manifest]  # type: ignore  # we don't use regular bound method
    disassembly_app_data: Callable[[bytes], bytes]
    data_to_sign: Optional[bytes]

    def collect_data(self) -> BinaryImage:
        """Collect application data, Certification Block and Manifest including update IVT.

        :raises SPSDKError: When either application data or certification block or manifest is missing
        :return: Image with updated IVT and added Certification Block with Manifest.
        """
        if not (self.app and self.manifest and self.cert_block):
            raise SPSDKError(
                "Either application data or certification block or manifest is missing"
            )
        assert len(self.manifest.export()) == self.manifest.total_length

        ret = BinaryImage(name="Application Block")
        app = self.update_ivt(self.app, self.total_len, self.app_len)
        ret.append_image(BinaryImage(name="Application", binary=app))
        ret.append_image(BinaryImage(name="Certification Block", binary=self.cert_block.export()))
        image_manifest = BinaryImage(name="Manifest", binary=self.manifest.export())
        # in case of crc manifest add crc
        ret.append_image(image_manifest)

        if isinstance(self.manifest, MasterBootImageManifestCrc):
            self.manifest.compute_crc(ret.export()[:-4])
            image_manifest.binary = self.manifest.export()

        # ret.append_image(image_manifest)
        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        if self.cert_block:
            image = image[: Mbi_MixinIvt.get_cert_block_offset(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)

    def finalize(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        if (
            self.manifest
            and self.manifest.flags
            and self.manifest.DIGEST_PRESENT_FLAG
            and self.manifest.digest_hash_algo is not None
        ):
            if revert:
                image.binary = image.binary[
                    : -self.manifest.get_hash_size(self.manifest.digest_hash_algo)
                ]
            else:
                calculated_hash = get_hash(self.data_to_sign, self.manifest.digest_hash_algo)
                logger.debug(f"Adding manifest hash to the image: {calculated_hash.hex()}")
                image.append_image(
                    BinaryImage(
                        "Manifest Hash",
                        binary=calculated_hash,
                    )
                )
        return image


class Mbi_ExportMixinCrcSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by CRC."""

    IVT_CRC_CERTIFICATE_OFFSET: int
    update_crc_val_cert_offset: Callable[[bytes, int], bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do simple calculation of CRC and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by CRC in IVT table.
        """
        if revert:
            return image

        input_image = image.export()
        # calculate CRC using MPEG2 specification over all of data (app and trustzone)
        # expect for 4 bytes at CRC_BLOCK_OFFSET
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        crc = crc32_function(input_image[: self.IVT_CRC_CERTIFICATE_OFFSET])
        crc = crc32_function(input_image[self.IVT_CRC_CERTIFICATE_OFFSET + 4 :], crc)
        image_with_crc = image.get_image_by_absolute_address(self.IVT_CRC_CERTIFICATE_OFFSET)
        # Recreate data with valid CRC value
        assert image_with_crc.binary
        image_with_crc.binary = self.update_crc_val_cert_offset(image_with_crc.binary, crc)
        return image


class Mbi_ExportMixinRsaSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by RSA."""

    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of RSA signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by RSA signature at end of image.
        """
        if hasattr(self, "no_signature") and self.no_signature:
            return image

        if revert:
            assert self.cert_block and isinstance(self.cert_block, CertBlockV1) and image.binary
            image.binary = image.binary[: -self.cert_block.signature_size]
            return image

        assert self.signature_provider
        signature = self.signature_provider.get_signature(image.export())
        image.append_image(BinaryImage(name="RSA signature", binary=signature))
        return image


class Mbi_ExportMixinEccSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]
    data_to_sign: Optional[bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of ECC signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by ECC signature at end of image.
        """
        if hasattr(self, "no_signature") and self.no_signature:
            return image

        if revert:
            assert self.cert_block and isinstance(self.cert_block, CertBlockV21) and image.binary
            image.binary = image.binary[: -self.cert_block.signature_size]
            return image

        assert self.signature_provider
        self.data_to_sign = image.export()
        signature = self.signature_provider.get_signature(self.data_to_sign)
        image.append_image(BinaryImage(name="ECC signature", binary=signature))
        return image


class Mbi_ExportMixinHmacKeyStoreFinalize(Mbi_ExportMixin):
    """Export Mixin to handle finalize by HMAC and optionally KeyStore."""

    compute_hmac: Callable[[bytes], bytes]
    HMAC_OFFSET: int
    HMAC_SIZE: int
    key_store: Optional[KeyStore]

    def finalize(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        raw_image = image.export()
        if revert:
            end_of_hmac_keystore = self.HMAC_OFFSET + self.HMAC_SIZE
            if Mbi_MixinIvt.get_key_store_presented(raw_image):
                end_of_hmac_keystore += KeyStore.KEY_STORE_SIZE
            image.binary = raw_image[: self.HMAC_OFFSET] + raw_image[end_of_hmac_keystore:]
            return image

        hmac_value = self.compute_hmac(raw_image[: self.HMAC_OFFSET])

        hmac_fits_between_images = self.HMAC_OFFSET in [x.offset for x in image.sub_images]
        ret = BinaryImage(name=image.name)

        if hmac_fits_between_images:
            for subimage in image.sub_images:
                if subimage.offset == self.HMAC_OFFSET:
                    ret.append_image(BinaryImage("HMAC", binary=hmac_value))
                    if self.key_store:
                        ret.append_image(BinaryImage("KeyStore", binary=self.key_store.export()))
                ret.append_image(subimage)
        else:
            # here must be splitted the Binary image that contains the HMAC offset address
            for subimage in image.sub_images:
                if (
                    subimage.offset <= self.HMAC_OFFSET
                    and self.HMAC_OFFSET < subimage.offset + len(subimage)
                ):
                    # Split this image
                    assert len(subimage.sub_images) == 0 and subimage.binary
                    offset = self.HMAC_OFFSET - subimage.offset
                    ret.append_image(
                        BinaryImage(name=subimage.name + " part 1", binary=subimage.binary[:offset])
                    )
                    ret.append_image(BinaryImage("HMAC", binary=hmac_value))
                    if self.key_store:
                        ret.append_image(BinaryImage("KeyStore", binary=self.key_store.export()))
                    ret.append_image(
                        BinaryImage(name=subimage.name + " part 2", binary=subimage.binary[offset:])
                    )
                    continue
                ret.append_image(subimage)

        return ret


class Mbi_ExportMixinAppBca(Mbi_ExportMixin):
    """Export Mixin to handle simple application data with BCA."""

    app: Optional[bytes]
    update_bca: Callable[[bytes, int], bytes]
    total_len: int

    IMG_DIGEST_OFFSET: int
    IMG_SIGNATURE_OFFSET: int
    IMG_BCA_OFFSET: int
    IMG_ISK_OFFSET: int
    IMG_ISK_HASH_OFFSET: int
    IMG_WPC_BLOCK_OFFSET: int
    IMG_DUKB_BLOCK_OFFSET: int
    IMG_DATA_START: int

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert self.app
        binary = self.update_bca(self.app, self.total_len)

        ret = BinaryImage("Application Block")
        ret.append_image(BinaryImage("Vector Table", binary=binary[: self.IMG_DIGEST_OFFSET]))
        ret.append_image(
            BinaryImage(
                "Image Hash", binary=binary[self.IMG_DIGEST_OFFSET : self.IMG_SIGNATURE_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "ECC signature", binary=binary[self.IMG_SIGNATURE_OFFSET : self.IMG_BCA_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "Boot Config Area (BCA)", binary=binary[self.IMG_BCA_OFFSET : self.IMG_ISK_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "ISK Certificate", binary=binary[self.IMG_ISK_OFFSET : self.IMG_ISK_HASH_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "ISK Hash", binary=binary[self.IMG_ISK_HASH_OFFSET : self.IMG_WPC_BLOCK_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "WPC Certification block",
                binary=binary[self.IMG_WPC_BLOCK_OFFSET : self.IMG_DUKB_BLOCK_OFFSET],
            )
        )
        ret.append_image(
            BinaryImage(
                "DUK Certification block",
                binary=binary[self.IMG_DUKB_BLOCK_OFFSET : self.IMG_DATA_START],
            )
        )
        ret.append_image(BinaryImage("Application Image", binary=binary[self.IMG_DATA_START :]))

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        self.app = image


class Mbi_ExportMixinEccSignVx(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    app: Optional[bytes]
    signature_provider: Optional[SignatureProvider]
    no_signature: Optional[bool]
    add_hash: bool
    cert_block: CertBlockVx

    IMG_DIGEST_OFFSET: int
    IMG_BCA_OFFSET: int
    IMG_SIGNED_HEADER_END: int
    IMG_DATA_START: int
    IMG_DIGEST_SIZE: int
    IMG_ISK_OFFSET: int
    IMG_ISK_HASH_OFFSET: int
    IMG_ISK_HASH_SIZE: int

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of ECC signature and digest and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by ECC signature and SHA256 digest.
        """
        if revert:
            return image  # return the image as is, because signature is not extending image

        if hasattr(self, "no_signature") and self.no_signature:
            return image
        assert self.signature_provider

        input_image = image.export()
        data_to_sign = (
            input_image[: self.IMG_DIGEST_OFFSET]
            + input_image[self.IMG_BCA_OFFSET : self.IMG_SIGNED_HEADER_END]
            + input_image[self.IMG_DATA_START :]
        )
        image_digest = get_hash(data_to_sign)
        signature = self.signature_provider.get_signature(data_to_sign)
        assert signature

        image.find_sub_image("Image Hash").binary = image_digest
        image.find_sub_image("ECC signature").binary = signature
        image.find_sub_image("ISK Certificate").binary = self.cert_block.export()
        if self.add_hash:
            image.find_sub_image("ISK Hash").binary = self.cert_block.cert_hash

        logger.info(f"Cert block info: {str(self.cert_block)}")
        return image


class Mbi_ExportMixinAppTrustZoneCertBlockEncrypt(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block."""

    app: Optional[bytes]
    trust_zone: TrustZone
    total_len: int
    app_len: int
    family: str
    update_ivt: Callable[[bytes, int, int], bytes]
    clean_ivt: Callable[[bytes], bytes]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]
    HMAC_OFFSET: int
    hmac_key: Optional[bytes]
    ctr_init_vector: bytes
    key_store: Optional[KeyStore]

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        assert (
            self.app
            and self.trust_zone
            and self.cert_block
            and isinstance(self.cert_block, CertBlockV1)
        )
        self.cert_block.alignment = 4
        ret = BinaryImage(name="Application Block")
        app = self.update_ivt(self.app, self.img_len, self.app_len)
        ret.append_image(BinaryImage(name="Application", binary=app))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(len(app)))
            )
        tz = self.trust_zone.export()
        if len(tz):
            ret.append_image(BinaryImage(name="TrustZone Settings", binary=tz))

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        # Re -parse decrypted TZ if needed
        if self.trust_zone.type == TrustZoneType.CUSTOM:
            self.trust_zone = TrustZone.from_binary(
                family=self.family, raw_data=image[-TrustZone.get_preset_data_size(self.family) :]
            )

        tz_len = len(self.trust_zone.export())
        if tz_len:
            image = image[:-tz_len]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.clean_ivt(image)

    @property
    def img_len(self) -> int:
        """Image length of encrypted legacy image."""
        assert self.cert_block
        # Encrypted IVT + IV
        return self.total_len + self.cert_block.signature_size + 56 + 16

    def encrypt(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
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

        logger.debug(f"Encryption key: {self.hmac_key.hex()}")
        logger.debug(f"Encryption IV: {self.ctr_init_vector.hex()}")

        if revert:
            return BinaryImage(
                name="Decrypted image data",
                binary=aes_ctr_decrypt(
                    key=key, encrypted_data=image.export(), nonce=self.ctr_init_vector
                ),
            )

        return BinaryImage(
            name="Encrypted Application",
            binary=aes_ctr_encrypt(key=key, plain_data=image.export(), nonce=self.ctr_init_vector),
        )

    def post_encrypt(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Optionally do some post encrypt image updates.

        :param image: Encrypted image.
        :param revert: Revert the operation if possible.
        :return: Updated encrypted image.
        """
        assert self.cert_block and isinstance(self.cert_block, CertBlockV1)
        image_bytes = image.export()
        if revert:
            cert_blk_offset = Mbi_MixinIvt.get_cert_block_offset(image_bytes)
            cert_blk_size = self.cert_block.expected_size
            # Restore original part of encrypted IVT
            org_image = image_bytes[
                cert_blk_offset + cert_blk_size : cert_blk_offset + cert_blk_size + 56
            ]
            # Add rest of original encrypted image
            org_image += image_bytes[56:cert_blk_offset]
            # optionally add TrustZone data
            org_image += image_bytes[cert_blk_offset + cert_blk_size + 56 + 16 :]
            return BinaryImage("Encrypted Image", binary=org_image)

        enc_ivt = self.update_ivt(
            image_bytes[: self.HMAC_OFFSET],
            self.img_len,
            self.app_len,
        )
        self.cert_block.image_length = (
            len(image_bytes) + len(self.cert_block.export()) + 56 + len(self.ctr_init_vector)
        )

        ret = BinaryImage("Encrypted application block")
        # Create encrypted cert block (Encrypted IVT table + IV)
        ret.append_image(BinaryImage(name="Encrypted IVT with mbi info", binary=enc_ivt))
        ret.append_image(
            BinaryImage(
                name="Encrypted rest of application",
                binary=image_bytes[self.HMAC_OFFSET : self.app_len],
            )
        )
        ret.append_image(BinaryImage(name="Certification block", binary=self.cert_block.export()))
        ret.append_image(BinaryImage(name="Original Encrypted IVT", binary=image_bytes[:56]))
        ret.append_image(
            BinaryImage(name="Counter Initialization Vector", binary=self.ctr_init_vector)
        )
        if self.trust_zone.export():
            ret.append_image(
                BinaryImage(name="Encrypted TrustZone", binary=image_bytes[self.app_len :])
            )

        return ret

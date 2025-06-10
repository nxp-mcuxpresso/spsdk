#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import logging
import os
import struct
from typing import Any, Callable, Optional, Union

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt
from spsdk.crypto.utils import get_hash_type_from_signature_size
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKTypeError
from spsdk.image.bca.bca import BCA
from spsdk.image.cert_block.cert_blocks import CertBlockV1, CertBlockV21, CertBlockVx
from spsdk.image.fcf.fcf import FCF
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi.mbi_classes import (
    MasterBootImageManifest,
    MasterBootImageManifestCrc,
    MasterBootImageManifestDigest,
    MultipleImageEntry,
    MultipleImageTable,
    T_Manifest,
)
from spsdk.image.mbi.mbi_data import MbiImageTypeEnum
from spsdk.image.trustzone import TrustZone, TrustZoneType
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Endianness, align_block, load_binary, load_hex_string, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)

# ****************************************************************************************************
#                                             Mbi Mixins
# ****************************************************************************************************


# pylint: disable=invalid-name
class Mbi_Mixin:
    """Base class for Master BOtt Image Mixin classes."""

    VALIDATION_SCHEMAS: list[str] = []
    NEEDED_MEMBERS: dict[str, Any] = {}
    PRE_PARSED: list[str] = []
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = True

    family: FamilyRevision

    def mix_init(self) -> None:
        """Initialize mixin."""

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
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from mixin.

        :param family: Family revision to get schemas
        :return: List of validation schemas.
        """
        schema_cfg = get_schema_file(DatabaseManager.MBI)
        return [schema_cfg[x] for x in cls.VALIDATION_SCHEMAS]

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """

    def mix_validate(self) -> None:
        """Validate the setting of image."""

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        return {}


class Mbi_MixinApp(Mbi_Mixin):
    """Master Boot Image App class."""

    VALIDATION_SCHEMAS: list[str] = ["app"]
    NEEDED_MEMBERS: dict[str, Any] = {"_app": bytes(), "app_ext_memory_align": 0x1000}

    _app: bytes
    app_ext_memory_align: int

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
        return len(self._app)

    def mix_app_len(self) -> int:
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return len(self._app)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.load_binary_image_file(config.get_input_file_name("inputImageFile"))

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
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
        image = BinaryImage.load_binary_image(path)
        if app_align and image.absolute_address % app_align != 0:
            raise SPSDKError(
                f"Invalid input binary file {path}. It has to be aligned to {hex(app_align)}."
            )
        self.app = image.export()

    def mix_validate(self) -> None:
        """Validate the app.

        :raises SPSDKError: The application format is invalid.
        """
        if len(self.app) < 0x38:
            raise SPSDKError("The application minimal size is 0x38, this input has lower size.")
        sp = int.from_bytes(self.app[:4], "little")
        pc = int.from_bytes(self.app[4:8], "little")
        # Illegal Operation additional test for DSC devices
        dsc_iop = int.from_bytes(self.app[8:12], "little")
        if len(set([sp, pc, dsc_iop])) == 1:
            raise SPSDKError("The first 3 vectors of interrupt vector table cannot be same")


class Mbi_MixinTrustZone(Mbi_Mixin):
    """Master Boot Image Trust Zone class."""

    VALIDATION_SCHEMAS: list[str] = ["trust_zone"]
    NEEDED_MEMBERS: dict[str, Any] = {
        "trust_zone": None,
        "family": "Unknown",
        "revision": "latest",
    }
    PRE_PARSED: list[str] = ["cert_block"]

    trust_zone: Optional[TrustZone]
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    ivt_table: "Mbi_MixinIvt"

    @property
    def tz_type(self) -> TrustZoneType:
        """Trustzone type."""
        if self.trust_zone is None:
            return TrustZoneType.DISABLED
        if self.trust_zone.is_customized:
            return TrustZoneType.CUSTOM
        return TrustZoneType.ENABLED

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        :return: Length of TrustZone.
        """
        return (
            len(self.trust_zone) if self.trust_zone and self.tz_type == TrustZoneType.CUSTOM else 0
        )

    def _load_preset_file(self, preset_file: str) -> None:
        try:
            self.trust_zone = TrustZone.load_from_config(Config.create_from_file(preset_file))
        except SPSDKError:
            self.trust_zone = TrustZone.parse(load_binary(preset_file), family=self.family)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.trust_zone = None
        if config.get("enableTrustZone", False):
            if config.get("trustZonePresetFile"):
                self._load_preset_file(config.get_input_file_name("trustZonePresetFile"))
                if self.tz_type != TrustZoneType.CUSTOM:
                    logger.warning(
                        "The TrustZone data are not added to the image as they have default values."
                    )
            else:
                self.trust_zone = TrustZone(self.family)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        config["enableTrustZone"] = bool(self.trust_zone)
        if self.trust_zone and self.trust_zone.is_customized == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        tz_type = self.ivt_table.get_tz_type(data)
        if tz_type not in TrustZoneType.tags():
            raise SPSDKParsingError("Invalid TrustZone type")

        self.trust_zone = None

        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)

        if tz_type == TrustZoneType.CUSTOM:
            # load custom data
            tz_data_size = TrustZone.get_preset_data_size(self.family)
            if hasattr(self, "cert_block"):
                assert isinstance(self.cert_block, (CertBlockV1, CertBlockV21))
                tz_offset = (
                    self.ivt_table.get_cert_block_offset(data) + self.cert_block.expected_size
                )
                tz_data = data[tz_offset : tz_offset + tz_data_size]
            else:
                tz_data = data[-tz_data_size:]
            self.trust_zone = TrustZone.parse(tz_data, family=self.family)


class Mbi_MixinTrustZoneMandatory(Mbi_MixinTrustZone):
    """Master Boot Image Trust Zone class for devices where is Trustzone mandatory."""

    VALIDATION_SCHEMAS: list[str] = ["trust_zone_mandatory"]
    trust_zone: Optional[TrustZone]
    family: FamilyRevision

    def mix_init(self) -> None:
        """Initialize mixin."""
        if self.trust_zone is None:
            self.trust_zone = TrustZone(family=self.family)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        if config.get("trustZonePresetFile"):
            self._load_preset_file(config.get_input_file_name("trustZonePresetFile"))
            if self.tz_type != TrustZoneType.CUSTOM:
                logger.warning(
                    "The TrustZone data are not added to the image as they have default values."
                )
        else:
            self.trust_zone = TrustZone(self.family)

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The TrustZone configuration is invalid.
        """
        if not self.trust_zone:
            raise SPSDKError("The Trust Zone MUST be used.")

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        if self.trust_zone and self.trust_zone.is_customized == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config


class Mbi_MixinLoadAddress(Mbi_Mixin):
    """Master Boot Image load address class."""

    VALIDATION_SCHEMAS: list[str] = ["load_addr"]

    load_address: Optional[int]
    ivt_table: "Mbi_MixinIvt"

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.load_address = config.get_int("outputImageExecutionAddress", 0)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        if self.load_address is None:
            raise SPSDKError("The load address is not defined.")
        config["outputImageExecutionAddress"] = hex(self.load_address)
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.load_address = self.ivt_table.get_load_address_from_data(data)


class Mbi_MixinFwVersion(Mbi_Mixin):
    """Master Boot Image FirmWare Version class."""

    VALIDATION_SCHEMAS: list[str] = ["firmware_version"]
    NEEDED_MEMBERS: dict[str, Any] = {"manifest": None}

    firmware_version: Optional[int]

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.firmware_version = config.get_int("firmwareVersion", 0)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        config["firmwareVersion"] = self.firmware_version
        return config


class Mbi_MixinImageVersion(Mbi_Mixin):
    """Master Boot Image Image Version class."""

    VALIDATION_SCHEMAS: list[str] = ["image_version"]
    NEEDED_MEMBERS: dict[str, Any] = {"image_version": 0}
    image_version_to_image_type: bool = True

    image_version: Optional[int]
    ivt_table: "Mbi_MixinIvt"

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.image_version = config.get_int("imageVersion", 0)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        config["imageVersion"] = self.image_version
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.image_version = self.ivt_table.get_image_version(data)


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

    VALIDATION_SCHEMAS: list[str] = ["image_subtype"]
    NEEDED_MEMBERS: dict[str, Any] = {"image_subtype": 0}

    image_subtype: Optional[int]
    ivt_table: "Mbi_MixinIvt"

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.set_image_subtype(config.get_str("outputImageSubtype", "main"))

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.mb_xip_384_384_recovery_crctest
        """
        config: dict[str, Any] = {}
        if self.image_subtype is None:
            raise SPSDKError("The image subtype is not defined.")
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
        self.image_subtype = self.ivt_table.get_sub_type(data)


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

    trust_zone: Optional[TrustZone]
    IMAGE_TYPE: MbiImageTypeEnum
    load_address: Optional[int]
    user_hw_key_enabled: Optional[bool]
    app_table: Optional["MultipleImageTable"]
    key_store: Optional[KeyStore]
    image_version: Optional[int]
    image_version_to_image_type: bool
    image_subtype: Optional[int]
    tz_type: Optional[TrustZoneType]

    @property
    def ivt_table(self) -> Self:
        """Get ivt table itself.

        :return: Current mixin IVT object.
        """
        return self

    def create_flags(self) -> int:
        """Create flags of image.

        :return: Image type flags
        """
        flags = int(self.IMAGE_TYPE.tag)

        if hasattr(self, "tz_type"):
            assert self.tz_type
            flags |= self.tz_type.tag << self.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT

        if hasattr(self, "image_subtype"):
            if self.image_subtype is None:
                raise SPSDKError("The image subtype is not defined.")
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
        # flags
        data[self.IVT_IMAGE_FLAGS_OFFSET : self.IVT_IMAGE_FLAGS_OFFSET + 4] = struct.pack(
            "<I", self.create_flags()
        )

        # Execution address
        load_addr = self.load_address if hasattr(self, "load_address") else 0
        data[self.IVT_LOAD_ADDR_OFFSET : self.IVT_LOAD_ADDR_OFFSET + 4] = struct.pack(
            "<I", load_addr
        )

        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = struct.pack(
            "<I", total_len
        )

        # CRC value or Certification block offset
        crc_val_cert_offset = 0 if int(self.IMAGE_TYPE.tag) == 0 else crc_val_cert_offset
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
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

    @classmethod
    def check_total_length(cls, data: bytes) -> None:
        """Check total length field from raw data.

        :param data: Raw MBI image data.
        :raises SPSDKParsingError: Insufficient length of image has been detected.
        """
        if len(data) < 0x38:  # Minimum size of IVT table
            raise SPSDKParsingError("Insufficient length of input raw data!")

        total_len = int.from_bytes(
            data[cls.IVT_IMAGE_LENGTH_OFFSET : cls.IVT_IMAGE_LENGTH_OFFSET + 4],
            Endianness.LITTLE.value,
        )
        if total_len > len(data):
            raise SPSDKParsingError("Insufficient length of input raw data!")

    @classmethod
    def get_flags(cls, data: bytes) -> int:
        """Get the Image flags from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Image Flags
        """
        cls.check_total_length(data)
        return cls.get_flags_from_data(data)

    @classmethod
    def get_flags_from_data(cls, data: bytes) -> int:
        """Get the Image flags from raw data.

        :param data: Raw MBI image data.
        :return: Image Flags
        """
        return int.from_bytes(
            data[cls.IVT_IMAGE_FLAGS_OFFSET : cls.IVT_IMAGE_FLAGS_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_cert_block_offset(cls, data: bytes) -> int:
        """Get the certificate block offset from raw data.

        During getting of cert block offset, the length is also validated.

        :param data: Raw MBI image data.
        :return: Certificate block offset
        """
        cls.check_total_length(data)
        return cls.get_cert_block_offset_from_data(data)

    @classmethod
    def get_cert_block_offset_from_data(cls, data: bytes) -> int:
        """Get the certificate block offset from raw data.

        :param data: Raw MBI image data.
        :return: Certificate block offset
        """
        return int.from_bytes(
            data[cls.IVT_CRC_CERTIFICATE_OFFSET : cls.IVT_CRC_CERTIFICATE_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_load_address(cls, data: bytes) -> int:
        """Get the load address from raw data.

        During getting of flags, the length is also validated.

        :param data: Raw MBI image data.
        :return: Load address
        """
        cls.check_total_length(data)

        return cls.get_load_address_from_data(data)

    @classmethod
    def get_load_address_from_data(cls, data: bytes) -> int:
        """Get the load address from raw data.

        :param data: Raw MBI image data.
        :return: Load address
        """
        return int.from_bytes(
            data[cls.IVT_LOAD_ADDR_OFFSET : cls.IVT_LOAD_ADDR_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_image_type(cls, data: bytes) -> int:
        """Get the Image type from raw data.

        :param data: Raw MBI image data.
        :return: Image type
        """
        return cls.get_flags_from_data(data) & cls.IVT_IMAGE_FLAGS_IMAGE_TYPE_MASK

    @classmethod
    def get_tz_type(cls, data: bytes) -> int:
        """Get the Image TrustZone type settings from raw data.

        :param data: Raw MBI image data.
        :return: TrustZone type.
        """
        flags = cls.get_flags_from_data(data)
        return (flags >> cls.IVT_IMAGE_FLAGS_TZ_TYPE_SHIFT) & cls.IVT_IMAGE_FLAGS_TZ_TYPE_MASK

    @classmethod
    def get_image_version(cls, data: bytes) -> int:
        """Get the Image firmware version from raw data.

        :param data: Raw MBI image data.
        :return: Firmware version.
        """
        flags = cls.get_flags_from_data(data)
        if flags & cls._BOOT_IMAGE_VERSION_FLAG == 0:
            return 0

        return (flags >> cls.IVT_IMAGE_FLAGS_IMG_VER_SHIFT) & cls.IVT_IMAGE_FLAGS_IMG_VER_MASK

    @classmethod
    def get_sub_type(cls, data: bytes) -> int:
        """Get the Image sub type from raw data.

        :param data: Raw MBI image data.
        :return: Image sub type.
        """
        flags = cls.get_flags_from_data(data)

        return (flags >> cls.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT) & cls.IVT_IMAGE_FLAGS_SUB_TYPE_MASK

    @classmethod
    def get_hw_key_enabled(cls, data: bytes) -> bool:
        """Get the HW key enabled setting from raw data.

        :param data: Raw MBI image data.
        :return: HW key enabled or not.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._HW_USER_KEY_EN_FLAG)

    @classmethod
    def get_key_store_presented(cls, data: bytes) -> int:
        """Get the KeyStore present flag from raw data.

        :param data: Raw MBI image data.
        :return: KeyStore is included or not.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._KEY_STORE_FLAG)

    @classmethod
    def get_app_table_presented(cls, data: bytes) -> int:
        """Get the Multiple Application table present flag from raw data.

        :param data: Raw MBI image data.
        :return: Multiple Application table is included or not.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._RELOC_TABLE_FLAG)


class Mbi_MixinIvtZeroTotalLength(Mbi_MixinIvt):
    """Master Boot Image Interrupt Vector table class for XIP image."""

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
        logger.debug(f"Setting total length to 0. Ignoring {total_len}")
        return super().update_ivt(
            app_data=app_data, total_len=0, crc_val_cert_offset=crc_val_cert_offset
        )

    @classmethod
    def check_total_length(cls, data: bytes) -> None:
        """Check total length field from raw data.

        :param data: Raw MBI image data.
        :raises SPSDKParsingError: Insufficient length of image has been detected.
        """
        total_len = int.from_bytes(
            data[cls.IVT_IMAGE_LENGTH_OFFSET : cls.IVT_IMAGE_LENGTH_OFFSET + 4],
            Endianness.LITTLE.value,
        )
        if total_len != 0 and total_len > len(data):
            raise SPSDKParsingError("Insufficient length of input raw data!")


class Mbi_MixinRelocTable(Mbi_Mixin):
    """Master Boot Image Relocation table class."""

    VALIDATION_SCHEMAS: list[str] = ["app_table"]
    NEEDED_MEMBERS: dict[str, Any] = {"app_table": None, "_app": None}

    app_table: Optional[MultipleImageTable]
    app: Optional[bytes]

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

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        if "applicationTable" not in config:
            return

        app_table = config.get_list_of_configs("applicationTable")

        self.app_table = MultipleImageTable()
        for entry in app_table:
            image = load_binary(entry.get_input_file_name("binary"))
            dst_addr = entry.get_int("destAddress")
            load = entry.get("load")
            image_entry = MultipleImageEntry(
                image, dst_addr, MultipleImageEntry.LTI_LOAD if load else 0
            )
            self.app_table.add_entry(image_entry)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        if self.app_table:
            cfg_table = []
            for entry in self.app_table.entries:
                entry_cfg: dict[str, Union[str, int]] = {}
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

    VALIDATION_SCHEMAS: list[str] = ["trust_zone_mandatory", "firmware_version"]
    NEEDED_MEMBERS: dict[str, Any] = {
        "trust_zone": None,
        "manifest": None,
        "cert_block": None,
        "family": "Unknown",
        "revision": "latest",
    }
    PRE_PARSED: list[str] = ["cert_block"]

    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    firmware_version: Optional[int]
    ivt_table: Mbi_MixinIvt

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")
        return self.manifest.total_length

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: The manifest configuration is invalid.
        """
        super().mix_validate()
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = config.get_int("firmwareVersion", 0)

        self.manifest = self.manifest_class(self.firmware_version, self.trust_zone)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV21)
        manifest_offset = self.ivt_table.get_cert_block_offset(data) + self.cert_block.expected_size
        self.manifest = self.manifest_class.parse(self.family, data[manifest_offset:])
        self.firmware_version = self.manifest.firmware_version
        self.trust_zone = self.manifest.trust_zone or TrustZone(self.family)


class Mbi_MixinManifestCrc(Mbi_MixinManifest):
    """Master Boot Image Manifest class with CRC."""

    manifest_class = MasterBootImageManifestCrc
    manifest: Optional[MasterBootImageManifestCrc]

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = config.get_int("firmwareVersion", 0)

        self.manifest = self.manifest_class(
            self.firmware_version,
            self.trust_zone,
        )


class Mbi_MixinManifestDigest(Mbi_MixinManifest):
    """Master Boot Image Manifest class for devices supporting ImageDigest functionality."""

    manifest_class = MasterBootImageManifestDigest
    manifest: Optional[MasterBootImageManifestDigest]

    VALIDATION_SCHEMAS: list[str] = [
        "trust_zone_mandatory",
        "firmware_version",
    ]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        :return: Length of Manifest block.
        """
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")

        hash_length = 0
        if self.manifest.flags & self.manifest.DIGEST_PRESENT_FLAG:
            hash_algo = {
                1: EnumHashAlgorithm.SHA256,
                2: EnumHashAlgorithm.SHA384,
                3: EnumHashAlgorithm.SHA512,
            }[self.manifest.flags & self.manifest.HASH_TYPE_MASK]
            hash_length = self.manifest.get_hash_size(hash_algo)
        return self.manifest.total_length + hash_length

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        super().mix_load_from_config(config)
        self.firmware_version = config.get_int("firmwareVersion", 0)
        digest_hash_algorithm = None
        # Decide on hash algorithm based on the hash used in certificate block
        if self.cert_block:
            digest_hash_algorithm = get_hash_type_from_signature_size(
                self.cert_block.signature_size
            )

        self.manifest = self.manifest_class(
            self.firmware_version, self.trust_zone, digest_hash_algo=digest_hash_algorithm
        )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")
        config = super().mix_get_config(output_folder=output_folder)
        config["firmwareVersion"] = self.firmware_version

        return config


class Mbi_MixinCertBlockV1(Mbi_Mixin):
    """Master Boot Image certification block V1 class."""

    VALIDATION_SCHEMAS: list[str] = ["cert_block_v1", "signer"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV1]
    signature_provider: Optional[SignatureProvider]
    total_len: Any
    key_store: Optional[KeyStore]
    ivt_table: Mbi_MixinIvt
    get_key_store_presented: Callable[[bytes], int]
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of Certificate Block V1.

        :return: Length of Certificate Block V1.
        """
        return len(self.cert_block.export()) if self.cert_block else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV1.load_from_config(config)
        self.signature_provider = get_signature_provider(config)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        if not self.cert_block:
            raise SPSDKError("Certificate block is missing")
        filename = "cert_block_v1.yaml"
        write_file(
            self.cert_block.get_config_yaml(output_folder), os.path.join(output_folder, filename)
        )
        config = {}
        config["certBlock"] = filename
        config["signer"] = "Cannot get from parse"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of Certificate block v1 is invalid.
        """
        if not self.cert_block or not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Certificate block is missing")
        if not self.signature_provider:
            raise SPSDKError("Signature provider is not defined")

        public_key = self.cert_block.certificates[-1].get_public_key()
        self.signature_provider.try_to_verify_public_key(public_key)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        offset = self.ivt_table.get_cert_block_offset(data)
        if hasattr(self, "hmac_key"):
            offset += self.HMAC_SIZE
            if self.ivt_table.get_key_store_presented(data):
                offset += KeyStore.KEY_STORE_SIZE

        self.cert_block = CertBlockV1.parse(data[offset:], self.family)
        self.cert_block.alignment = 4
        self.signature_provider = None


class Mbi_MixinCertBlockV21(Mbi_Mixin):
    """Master Boot Image certification block V3.1 class."""

    VALIDATION_SCHEMAS: list[str] = ["cert_block_v21", "signer"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV21]
    signature_provider: Optional[SignatureProvider]
    ivt_table: Mbi_MixinIvt

    def mix_len(self) -> int:
        """Get length of Certificate Block V2.1.

        :return: Length of Certificate Block V2.1.
        """
        if not (self.cert_block and self.signature_provider):
            raise SPSDKError("Certification block or signature provider is missing")
        return self.cert_block.expected_size + self.signature_provider.signature_length

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockV21.load_from_config(config)
        self.signature_provider = get_signature_provider(config)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        if not self.cert_block:
            raise SPSDKError("Certificate block is missing")
        filename = "cert_block_v21.yaml"
        write_file(
            self.cert_block.get_config_yaml(output_folder), os.path.join(output_folder, filename)
        )
        config = {}
        config["certBlock"] = filename
        config["signer"] = "Cannot get from parse"
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
        self.signature_provider.try_to_verify_public_key(public_key)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.cert_block = CertBlockV21.parse(
            data[self.ivt_table.get_cert_block_offset(data) :], self.family
        )
        self.signature_provider = None


class Mbi_MixinCertBlockVx(Mbi_Mixin):
    """Master Boot Image certification block for MC55xx class."""

    VALIDATION_SCHEMAS: list[str] = ["cert_block_vX", "signer", "just_header"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: CertBlockVx
    add_hash: bool
    just_header: bool
    signature_provider: Optional[SignatureProvider]
    IMG_ISK_OFFSET: int

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.cert_block = CertBlockVx.load_from_config(config)

        self.signature_provider = get_signature_provider(config)
        self.add_hash = config.get("addCertHash", True)
        self.just_header = config.get("justHeader", False)

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
        self.cert_block = CertBlockVx.parse(data[self.IMG_ISK_OFFSET :], self.family)
        self.signature_provider = None


class Mbi_MixinBca(Mbi_Mixin):
    """Master Boot Image BCA class."""

    VALIDATION_SCHEMAS: list[str] = ["bca"]
    NEEDED_MEMBERS: dict[str, Any] = {"bca": None}

    BCA_OFFSET = 0x3C0

    app: bytes
    bca: Optional[BCA]
    total_len: Any

    def mix_len(self) -> int:
        """Get length of BCA.

        :return: Length of BCA.
        """
        return self.bca.SIZE if self.bca else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        logger.debug("Load default BCA configuration from application")
        Mbi_MixinBca.mix_parse(self, self.app)

        if "bca" in config:
            if isinstance(config["bca"], dict):
                logger.info("Updating BCA config from direct configuration")
                bca_config = config.get_config("bca")
                if self.bca:
                    self.bca.registers.load_from_config(bca_config)
                else:
                    self.bca = BCA.load_from_config(
                        Config(
                            {
                                "family": self.family.name,
                                "revision": self.family.revision,
                                "bca": bca_config,
                            }
                        )
                    )
                return
            try:
                bca_config = config.load_sub_config("bca")
                if self.bca:
                    self.bca.registers.load_from_config(bca_config["bca"])
                else:
                    self.bca = BCA.load_from_config(bca_config)
                logger.info("Updating BCA from YAML configuration")
            except (SPSDKError, SPSDKTypeError):
                bca_file = config.get_input_file_name("bca")
                bca_bin = load_binary(bca_file, config.search_paths)
                if len(bca_bin) != BCA.SIZE:
                    raise SPSDKError(  # pylint: disable=raise-missing-from
                        f"Invalid BCA binary file size. Expected {BCA.SIZE} bytes."
                    )
                self.bca = BCA.parse(bca_bin, family=self.family)
                logger.info(f"Successfully loaded BCA from binary file: {bca_file}")

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config = {}
        if self.bca:
            bca_cfg = self.bca.get_config_yaml()
            filename = "bca.yaml"
            write_file(bca_cfg, os.path.join(output_folder, filename))
            config["bca"] = filename
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of BCA is invalid.
        """
        if self.bca and not isinstance(self.bca, BCA):
            raise SPSDKError("Validation failed: BCA is invalid format")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        try:
            self.bca = BCA.parse(data[self.BCA_OFFSET :], family=self.family)
        except SPSDKError:
            self.bca = None

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from BCA mixin.

        :param family: Family revision to get schemas
        """
        bca_dict = BCA.get_validation_schemas(family)[1]["properties"]["bca"]
        bca_dict["skip_in_template"] = True

        bca_file = {
            "type": "string",
            "format": "file",
            "description": "Path to BCA configuration or binary file",
            "template_value": "path/to/bca.yaml",
        }

        ret = {
            "type": "object",
            "properties": {"bca": {"oneOf": [bca_dict, bca_file]}},
        }
        ret["title"] = "BCA Configuration (Boot Configuration Array)"
        ret["description"] = (
            "Boot Configuration Area settings. Default values are always loaded from application first.\n"
            "BCA can be provided in one of three ways:\n"
            "1. As a nested dictionary under the 'bca' key - copy values directly from the BCA.YAML template\n"
            "2. As a path to a YAML file containing BCA configuration - use 'bca: path/to/bca.yaml'\n"
            "3. As a path to a binary BCA file - use 'bca: path/to/bca.bin'\n\n"
            "If any BCA configuration is provided, it will update the application values accordingly. "
            "The binary option completely replaces the BCA content, while the YAML and dictionary options "
            "selectively update BCA register values."
        )

        return [ret]


class Mbi_MixinFcf(Mbi_Mixin):
    """Master Boot Image FCF class."""

    VALIDATION_SCHEMAS: list[str] = ["fcf"]
    NEEDED_MEMBERS: dict[str, Any] = {"fcf": None}

    FCF_OFFSET = 0x400

    app: bytes
    fcf: Optional[FCF]
    total_len: Any

    def mix_len(self) -> int:
        """Get length of FCF.

        :return: Length of FCF.
        """
        return self.fcf.SIZE if self.fcf else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        logger.debug("Load default FCF configuration from application")
        Mbi_MixinFcf.mix_parse(self, self.app)

        if "fcf" in config:
            if isinstance(config["fcf"], dict):
                logger.info("Updating FCF config from direct configuration")
                fcf_config = config.get_config("fcf")
                if self.fcf:
                    self.fcf.registers.load_from_config(fcf_config)
                else:
                    self.fcf = FCF.load_from_config(
                        Config(
                            {
                                "family": self.family.name,
                                "revision": self.family.revision,
                                "fcf": fcf_config,
                            }
                        )
                    )
                return
            try:
                fcf_cfg = config.load_sub_config("fcf")
                if self.fcf:
                    self.fcf.registers.load_from_config(fcf_cfg["fcf"])
                else:
                    self.fcf = FCF.load_from_config(fcf_cfg)
                logger.info("Updating FCF from YAML configuration")
            except (SPSDKError, SPSDKTypeError):
                fcf_file = config.get_input_file_name("fcf")
                fcf_bin = load_binary(fcf_file, config.search_paths)
                if len(fcf_bin) != FCF.SIZE:
                    raise SPSDKError(  # pylint: disable=raise-missing-from
                        f"Invalid FCF binary file size. Expected {FCF.SIZE} bytes."
                    )
                self.fcf = FCF.parse(fcf_bin, family=self.family)
                logger.info(f"Successfully loaded FCF from binary file: {fcf_file}")

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        assert self.fcf
        fcf_cfg = self.fcf.get_config_yaml()
        filename = "fcf.yaml"
        write_file(fcf_cfg, os.path.join(output_folder, filename))
        config = {}
        config["fcf"] = filename
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Configuration of FCF is invalid.
        """
        if not self.fcf or not isinstance(self.fcf, FCF):
            raise SPSDKError("Validation failed: FCF is missing")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        self.fcf = FCF.parse(data[self.FCF_OFFSET :], family=self.family)

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from FCF mixin.

        :param family: Family revision to get schemas
        """
        fcf_dict = FCF.get_validation_schemas(family)[1]["properties"]["fcf"]
        fcf_dict["skip_in_template"] = True
        fcf_file = {
            "type": "string",
            "format": "file",
            "description": "Path to FCF configuration or binary file",
            "template_value": "path/to/fcf.yaml",
        }

        ret = {
            "type": "object",
            "properties": {"fcf": {"oneOf": [fcf_dict, fcf_file]}},
        }
        ret["title"] = "FCF Configuration (Flash Configuration Field)"
        ret["description"] = (
            "Flash Configuration Field settings. Default values are always loaded from application first.\n"
            "FCF can be provided in one of three ways:\n"
            "1. As a nested dictionary under the 'fcf' key - copy values directly from the FCF.YAML template\n"
            "2. As a path to a YAML file containing FCF configuration - use 'fcf: path/to/fcf.yaml'\n"
            "3. As a path to a binary FCF file - use 'fcf: path/to/fcf.bin'\n\n"
            "If any FCF configuration is provided, it will update the application values accordingly. "
            "The binary option completely replaces the FCF content, while the YAML and dictionary options "
            "selectively update FCF register values."
        )

        return [ret]


class Mbi_MixinHwKey(Mbi_Mixin):
    """Master Boot Image HW key user modes enable class."""

    VALIDATION_SCHEMAS: list[str] = ["hw_key"]
    NEEDED_MEMBERS: dict[str, Any] = {"user_hw_key_enabled": False}

    user_hw_key_enabled: Optional[bool]
    ivt_table: Mbi_MixinIvt

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.user_hw_key_enabled = config.get("enableHwUserModeKeys", False)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
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
        self.user_hw_key_enabled = self.ivt_table.get_hw_key_enabled(data)


class Mbi_MixinKeyStore(Mbi_Mixin):
    """Master Boot Image KeyStore class."""

    VALIDATION_SCHEMAS: list[str] = ["key_store"]
    NEEDED_MEMBERS: dict[str, Any] = {"key_store": None, "_hmac_key": None}
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = False

    key_store: Optional[KeyStore]
    hmac_key: Optional[bytes]
    ivt_table: Mbi_MixinIvt
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

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.key_store = None
        if "keyStoreFile" in config:
            self.key_store = KeyStore(
                KeySourceType.KEYSTORE, load_binary(config.get_input_file_name("keyStoreFile"))
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
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
        key_store_present = self.ivt_table.get_key_store_presented(data)
        self.key_store = None
        if key_store_present:
            key_store_offset = self.HMAC_OFFSET + self.HMAC_SIZE
            self.key_store = KeyStore(
                KeySourceType.KEYSTORE,
                data[key_store_offset : key_store_offset + KeyStore.KEY_STORE_SIZE],
            )


class Mbi_MixinHmac(Mbi_Mixin):
    """Master Boot Image HMAC class."""

    VALIDATION_SCHEMAS: list[str] = ["hmac"]
    NEEDED_MEMBERS: dict[str, Any] = {"_hmac_key": None}
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = False

    # offset in the image, where the HMAC table is located
    HMAC_OFFSET = 64
    # size of HMAC table in bytes
    HMAC_SIZE = 32
    # length of user key or master key, in bytes
    _HMAC_KEY_LENGTH = 32

    _hmac_key: Optional[bytes]
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

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.hmac_key = None
        if "outputImageEncryptionKeyFile" in config:
            self.hmac_key = config.load_symmetric_key(
                "outputImageEncryptionKeyFile", expected_size=self.HMAC_SIZE
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
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
        if len(result) != self.HMAC_SIZE:
            raise SPSDKError("Invalid size of HMAC result.")
        return result

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        if self.dek:
            self.hmac_key = load_hex_string(source=self.dek, expected_size=self._HMAC_KEY_LENGTH)


class Mbi_MixinHmacMandatory(Mbi_MixinHmac):
    """Master Boot Image HMAC class (Mandatory use)."""

    VALIDATION_SCHEMAS: list[str] = ["hmac_mandatory"]

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("HMAC Key MUST exists.")
        super().mix_validate()


class Mbi_MixinCtrInitVector(Mbi_Mixin):
    """Master Boot Image initial vector for encryption counter."""

    VALIDATION_SCHEMAS: list[str] = ["ctr_init_vector"]
    NEEDED_MEMBERS: dict[str, Any] = {"_ctr_init_vector": random_bytes(16)}
    PRE_PARSED: list[str] = ["cert_block"]
    # length of counter initialization vector
    _CTR_INIT_VECTOR_SIZE = 16

    _ctr_init_vector: bytes
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    ivt_table: Mbi_MixinIvt
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

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.ctr_init_vector = None

        if "CtrInitVector" in config:
            self.ctr_init_vector = config.load_symmetric_key(
                "CtrInitVector", self._CTR_INIT_VECTOR_SIZE
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        """
        config: dict[str, Any] = {}
        self.mix_validate()
        assert isinstance(self.ctr_init_vector, bytes)
        config["CtrInitVector"] = self.ctr_init_vector.hex()
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        raise SPSDKError: Invalid HW key enabled member type.
        """
        if not self.ctr_init_vector:
            raise SPSDKError("Initial vector for encryption counter MUST exist.")
        if len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE:
            raise SPSDKError("Invalid size of Initial vector for encryption counter.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        :param data: Final Image in bytes.
        """
        assert isinstance(self.cert_block, CertBlockV1)
        iv_offset = self.ivt_table.get_cert_block_offset(data) + self.cert_block.expected_size + 56
        if hasattr(self, "hmac_key"):
            iv_offset += self.HMAC_SIZE
            if self.ivt_table.get_key_store_presented(data):
                iv_offset += KeyStore.KEY_STORE_SIZE
        self.ctr_init_vector = data[iv_offset : iv_offset + self._CTR_INIT_VECTOR_SIZE]


########################################################################################################################
# Export image Mixins
########################################################################################################################


class Mbi_ExportMixin:
    """Base MBI Export Mixin class."""

    family: FamilyRevision

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
    clean_ivt: Callable[[bytes], bytes]
    ivt_table: Mbi_MixinIvt
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]
    bca: Optional[BCA]
    fcf: Optional[FCF]
    BCA_OFFSET: int
    FCF_OFFSET: int
    total_len: Any

    def collect_data(self) -> BinaryImage:
        """Collect application data including update of bca and fcf.

        :return: Image with updated bca and fcf.
        """
        if not self.app:
            raise SPSDKError("Application data is missing")

        ret = BinaryImage(name="Application Block")

        binary = (
            self.ivt_table.update_ivt(self.app, self.total_len, 0)
            if hasattr(self, "ivt_table")
            else self.app
        )
        bca_present = hasattr(self, "bca") and self.bca is not None
        fcf_present = hasattr(self, "fcf") and self.fcf is not None

        if bca_present or fcf_present:
            offset = self.BCA_OFFSET if bca_present else self.FCF_OFFSET
            ret.append_image(BinaryImage(name="Application IVT", binary=binary[:offset]))

            if bca_present:
                assert self.bca
                ret.append_image(BinaryImage(name="BCA Settings", binary=self.bca.export()))
                offset += self.bca.SIZE
            if fcf_present:
                assert self.fcf
                ret.append_image(BinaryImage(name="FCF Settings", binary=self.fcf.export()))
                offset += self.fcf.SIZE

            ret.append_image(BinaryImage(name="Application", binary=binary[offset:]))
        else:
            ret.append_image(BinaryImage(name="Application", binary=binary))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(ret.size))
            )

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)

        self.app = self.clean_ivt(image) if hasattr(self, "clean_ivt") else image


class Mbi_ExportMixinAppTrustZone(Mbi_ExportMixinApp):
    """Export Mixin to handle simple application data and TrustZone."""

    trust_zone: Optional[TrustZone]
    tz_type: TrustZoneType
    family: FamilyRevision

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        ret = super().collect_data()
        if self.trust_zone:
            if self.tz_type == TrustZoneType.CUSTOM:
                ret.append_image(
                    BinaryImage(name="TrustZone Settings", binary=self.trust_zone.export())
                )
        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        elif tz_type == TrustZoneType.CUSTOM:
            tz_len = TrustZone.get_preset_data_size(self.family)
            self.trust_zone = TrustZone.parse(image[-tz_len:], self.family)
            image = image[:-tz_len]
        super().disassemble_image(image)


class Mbi_ExportMixinAppTrustZoneCertBlock(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block."""

    app: Optional[bytes]
    family: FamilyRevision
    trust_zone: Optional[TrustZone]
    total_len: int
    total_length_for_cert_block: int
    app_len: int
    ivt_table: Mbi_MixinIvt
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]
    tz_type: TrustZoneType

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        if not (self.app and self.cert_block):
            raise SPSDKError("Application data or Certificate block is missing")
        if not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Only CertBlockV1 is supported")
        ret = BinaryImage(name="Application Block")

        self.cert_block.alignment = 4
        self.cert_block.image_length = self.total_length_for_cert_block
        app = self.ivt_table.update_ivt(
            self.app, self.total_len + self.cert_block.signature_size, self.app_len
        )
        ret.append_image(BinaryImage(name="Application", binary=app))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(len(app)))
            )
        ret.append_image(BinaryImage(name="Certification Block", binary=self.cert_block.export()))

        if self.trust_zone:
            if self.tz_type == TrustZoneType.CUSTOM:
                ret.append_image(
                    BinaryImage(name="TrustZone Settings", binary=self.trust_zone.export())
                )
        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        # Re -parse TZ if needed
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        if tz_type == TrustZoneType.CUSTOM:
            tz_len = TrustZone.get_preset_data_size(self.family)
            self.trust_zone = TrustZone.parse(data=image[-tz_len:], family=self.family)
            image = image[:-tz_len]
        image = image[: -self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)


class Mbi_ExportMixinAppTrustZoneCertBlockV2(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, TrustZone and Certification block V21."""

    app: Optional[bytes]
    app_len: int
    total_len: int
    ivt_table: Mbi_MixinIvt
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    disassembly_app_data: Callable[[bytes], bytes]
    data_to_sign: Optional[bytes]
    trust_zone: Optional[TrustZone]
    tz_type: TrustZoneType

    def collect_data(self) -> BinaryImage:
        """Collect application data, Certification Block and Manifest including update IVT.

        :raises SPSDKError: When either application data or certification block or manifest is missing
        :return: Image with updated IVT and added Certification Block with Manifest.
        """
        if not (self.app and self.cert_block):
            raise SPSDKError("Either application data or certification block is missing")

        ret = BinaryImage(name="Application Block")
        app = self.ivt_table.update_ivt(self.app, self.total_len, self.app_len)
        ret.append_image(BinaryImage(name="Application", binary=app))
        ret.append_image(BinaryImage(name="Certification Block", binary=self.cert_block.export()))

        if self.trust_zone:
            trust_zone = BinaryImage(name="TZ Data", binary=self.trust_zone.export())
            ret.append_image(trust_zone)

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        if self.cert_block:
            image = image[: self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)


class Mbi_ExportMixinAppCertBlockManifest(Mbi_ExportMixin):
    """Export Mixin to handle simple application data, Certification block and Manifest."""

    app: Optional[bytes]
    app_len: int
    total_len: int
    ivt_table: Mbi_MixinIvt
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
        if len(self.manifest.export()) != self.manifest.total_length:
            raise SPSDKError("Manifest length is invalid.")

        # Check if the manifest digest is present and if manifest hash is same as certificate block hash
        if isinstance(self.manifest, MasterBootImageManifestDigest) and self.cert_block:
            if (
                self.manifest.digest_hash_algo
                and self.manifest.digest_hash_algo
                != get_hash_type_from_signature_size(self.cert_block.signature_size)
            ):
                logger.error(
                    "Manifest digest algorithm is different than hash in certificate block! Image won't boot"
                )
        ret = BinaryImage(name="Application Block")
        app = self.ivt_table.update_ivt(self.app, self.total_len, self.app_len)
        ret.append_image(BinaryImage(name="Application", binary=app))
        ret.append_image(BinaryImage(name="Certification Block", binary=self.cert_block.export()))
        image_manifest = BinaryImage(name="Manifest", binary=self.manifest.export())
        # in case of crc manifest add crc
        ret.append_image(image_manifest)

        if isinstance(self.manifest, MasterBootImageManifestCrc):
            self.manifest.compute_crc(ret.export()[:-4])
            image_manifest.binary = self.manifest.export()

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        if self.cert_block:
            image = image[: self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)

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
        # except for 4 bytes at CRC_BLOCK_OFFSET
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        crc = crc_obj.calculate(input_image[: self.IVT_CRC_CERTIFICATE_OFFSET])
        crc_obj.initial_value = crc
        crc = crc_obj.calculate(input_image[self.IVT_CRC_CERTIFICATE_OFFSET + 4 :])
        image_with_crc = image.get_image_by_absolute_address(self.IVT_CRC_CERTIFICATE_OFFSET)
        # Recreate data with valid CRC value
        if not image_with_crc.binary:
            raise SPSDKError("CRC offset is not valid")
        image_with_crc.binary = self.update_crc_val_cert_offset(image_with_crc.binary, crc)
        return image


class Mbi_ExportMixinRsaSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by RSA."""

    signature_provider: Optional[SignatureProvider]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of RSA signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by RSA signature at end of image.
        """
        if revert:
            if not (self.cert_block and image.binary):
                raise SPSDKError("Certificate block or image is missing")
            if not isinstance(self.cert_block, CertBlockV1):
                raise SPSDKError("Only CertBlockV1 is supported")
            image.binary = image.binary[: -self.cert_block.signature_size]
            return image
        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")
        signature = self.signature_provider.get_signature(image.export())
        image.append_image(BinaryImage(name="RSA signature", binary=signature))
        return image


class Mbi_ExportMixinEccSign(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    signature_provider: Optional[SignatureProvider]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]
    data_to_sign: Optional[bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of ECC signature and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by ECC signature at end of image.
        """
        if revert:
            if not (self.cert_block and image.binary):
                raise SPSDKError("Certificate block or image is missing")
            if not isinstance(self.cert_block, CertBlockV21):
                raise SPSDKError("Only CertBlockV21 is supported")
            image.binary = image.binary[: -self.cert_block.signature_size]
            return image
        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")
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
    ivt_table: Mbi_MixinIvt

    def finalize(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Finalize the image for export by adding HMAC a optionally KeyStore.

        :param image: Input image.
        :param revert: Revert the operation if possible.
        :return: Finalized image suitable for export.
        """
        raw_image = image.export()
        if revert:
            end_of_hmac_keystore = self.HMAC_OFFSET + self.HMAC_SIZE
            if self.ivt_table.get_key_store_presented(raw_image):
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
                    if not (subimage.binary and len(subimage.sub_images) == 0):
                        raise SPSDKError("Invalid image structure")
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


class Mbi_ExportMixinAppBcaFcf(Mbi_ExportMixin):
    """Export Mixin to handle application data with optional BCA and FCF."""

    app: bytes
    bca: BCA
    fcf: FCF

    total_len: int
    just_header: bool

    # Vx chip boot image offsets.
    IMG_DIGEST_OFFSET = 0x360
    IMG_SIGNATURE_OFFSET = 0x380
    IMG_BCA_OFFSET = 0x3C0
    IMG_FCF_OFFSET = 0x400
    IMG_ISK_OFFSET = 0x410
    IMG_ISK_HASH_OFFSET = 0x4A0
    IMG_WPC_ROOT_CA_CERT_HASH_OFFSET = 0x5E0
    IMG_WPC_MFG_CA_CERT_OFFSET = 0x600
    IMG_DUK_BLOCK_OFFSET = 0x800
    IMG_DATA_START = 0xC00

    @property
    def image_size(self) -> int:
        """Image size used in BCA."""
        bca_size = self.IMG_FCF_OFFSET - self.IMG_BCA_OFFSET
        app_len = len(self.app) - self.IMG_DATA_START
        return self.IMG_DIGEST_OFFSET + bca_size + app_len

    def check_fcf(self) -> None:
        """Validate FCF configuration and verify only lifecycle value has been modified.

        This method performs two validations:
        1. Verifies the lifecycle value is supported by checking against the enum values
        defined in the FCF LIFECYCLE register
        2. Ensures that no FCF registers other than LIFECYCLE have been modified from their
        reset values

        The FCF (Flash Configuration Field) is a critical security component where typically
        only the lifecycle value should be changed.

        :raises SPSDKError: If the lifecycle value is not supported or if any other FCF register
            has been modified from its reset value
        """
        # Get lifecycle register and its valid enum values from FCF object
        lifecycle_reg = self.fcf.registers.find_reg("LIFECYCLE")
        lifecycle_bitfield = lifecycle_reg.find_bitfield("LIFECYCLE_STATE")
        valid_enums = lifecycle_bitfield.get_enums()
        # Get valid enum values
        valid_values = {enum_val.value for enum_val in valid_enums}
        if lifecycle_bitfield.get_value() not in valid_values:
            supported_values = ", ".join(
                [f"{enum_val.name} (0x{enum_val.value:02X})" for enum_val in valid_enums]
            )
            logger.error(f"Supported lifecycle values: {supported_values}")
            raise (
                SPSDKError(
                    f"Unsupported lifecycle value: 0x{lifecycle_bitfield.get_value():02X}. "
                    ""
                    "Please use one of the supported values."
                )
            )

    def collect_data(self) -> BinaryImage:
        """Collect application data and update BCA (if present) and FCF.

        :return: Binary Image with updated BCA (if present) and FCF.
        """
        if not self.app:
            raise SPSDKError("Application data is missing")

        binary = self.app

        # Apply FCF check
        self.check_fcf()

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
        bca_binary = (
            self.bca.export()
            if hasattr(self, "bca") and self.bca
            else binary[self.IMG_BCA_OFFSET : self.IMG_FCF_OFFSET]
        )
        ret.append_image(BinaryImage("Boot Config Area", binary=bca_binary))
        fcf_binary = (
            self.fcf.export()
            if hasattr(self, "fcf") and self.fcf
            else binary[self.IMG_FCF_OFFSET : self.IMG_ISK_OFFSET]
        )
        ret.append_image(BinaryImage("Flash Config Field", binary=fcf_binary))
        ret.append_image(
            BinaryImage(
                "ISK Certificate", binary=binary[self.IMG_ISK_OFFSET : self.IMG_ISK_HASH_OFFSET]
            )
        )
        ret.append_image(
            BinaryImage(
                "ISK Hash",
                binary=binary[self.IMG_ISK_HASH_OFFSET : self.IMG_WPC_ROOT_CA_CERT_HASH_OFFSET],
            )
        )
        ret.append_image(
            BinaryImage(
                "WPC Root CA certificate hash",
                binary=binary[
                    self.IMG_WPC_ROOT_CA_CERT_HASH_OFFSET : self.IMG_WPC_MFG_CA_CERT_OFFSET
                ],
            )
        )
        ret.append_image(
            BinaryImage(
                "WPC MFG CA certificate",
                binary=binary[self.IMG_WPC_MFG_CA_CERT_OFFSET : self.IMG_DUK_BLOCK_OFFSET],
            )
        )

        # Early return if just_header flag is set
        if hasattr(self, "just_header") and self.just_header:
            return ret

        ret.append_image(
            BinaryImage(
                "DUK block (DUCKB)",
                binary=binary[self.IMG_DUK_BLOCK_OFFSET : self.IMG_DATA_START],
            )
        )
        ret.append_image(BinaryImage("Application Image", binary=binary[self.IMG_DATA_START :]))

        return ret

    def disassemble_image(self, image: bytes) -> None:
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        self.app = image


class Mbi_ExportMixinCrcSignBca(Mbi_ExportMixin):
    """Export Mixin to handle sign by CRC in BCA."""

    app: bytes
    bca: BCA
    image_size: int
    IMG_DATA_START: int

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do simple calculation of CRC and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by CRC of application.
        """
        if revert:
            return image

        if not hasattr(self, "bca") or self.bca is None:
            raise SPSDKError("BCA is not initialized")

        input_image = image.export()
        # self.bca.registers.find_reg("IMAGE_SIZE").set_value(self.image_size)

        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        crc_len = len(input_image[self.IMG_DATA_START :])
        crc = crc_obj.calculate(input_image[self.IMG_DATA_START :])

        self.bca.registers.find_reg("CRC_START_ADDRESS").set_value(self.IMG_DATA_START)
        self.bca.registers.find_reg("CRC_BYTE_COUNT").set_value(crc_len)
        self.bca.registers.find_reg("CRC_EXPECTED_VALUE").set_value(crc)

        image.find_sub_image("Boot Config Area").binary = self.bca.export()
        return image


class Mbi_ExportMixinEccSignVx(Mbi_ExportMixin):
    """Export Mixin to handle sign by ECC."""

    app: Optional[bytes]
    signature_provider: Optional[SignatureProvider]
    add_hash: bool
    cert_block: CertBlockVx
    bca: BCA
    image_size: int

    IMG_DIGEST_OFFSET: int
    IMG_BCA_OFFSET: int
    IMG_FCF_OFFSET: int
    IMG_DATA_START: int

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Do calculation of ECC signature and digest and return updated image with it.

        :param image: Input raw image.
        :param revert: Revert the operation if possible.
        :return: Image enriched by ECC signature and SHA256 digest.
        """
        if revert:
            return image  # return the image as is, because signature is not extending image

        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")

        self.bca.registers.find_reg("IMAGE_SIZE").set_value(self.image_size)
        image.find_sub_image("Boot Config Area").binary = self.bca.export()

        input_image = image.export()
        data_to_sign = (
            input_image[: self.IMG_DIGEST_OFFSET]
            + input_image[self.IMG_BCA_OFFSET : self.IMG_FCF_OFFSET]
            + input_image[self.IMG_DATA_START :]
        )
        image_digest = get_hash(data_to_sign)
        signature = self.signature_provider.get_signature(data_to_sign)
        if not signature:
            raise SPSDKError("Unable to get signature")

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
    trust_zone: Optional[TrustZone]
    total_len: int
    app_len: int
    ivt_table: Mbi_MixinIvt
    cert_block: Optional[Union[CertBlockV1, CertBlockV21]]
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]
    HMAC_OFFSET: int
    hmac_key: Optional[bytes]
    ctr_init_vector: bytes
    key_store: Optional[KeyStore]
    tz_type: TrustZoneType

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        :return: Image with updated IVT and added TrustZone.
        """
        if not (self.app and self.cert_block):
            raise SPSDKError("Application data or Certificate block is missing")
        if not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Only CertBlockV1 is supported")
        self.cert_block.alignment = 4
        ret = BinaryImage(name="Application Block")
        app = self.ivt_table.update_ivt(self.app, self.img_len, self.app_len)
        ret.append_image(BinaryImage(name="Application", binary=app))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(len(app)))
            )

        if self.trust_zone:
            if self.tz_type == TrustZoneType.CUSTOM:
                ret.append_image(
                    BinaryImage(name="TrustZone Settings", binary=self.trust_zone.export())
                )
        return ret

    def disassemble_image(self, image: bytes) -> None:
        """Disassemble image to individual parts from image.

        :param image: Image.
        """
        # Re -parse decrypted TZ if needed
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        if tz_type == TrustZoneType.CUSTOM:
            self.trust_zone = TrustZone.parse(
                data=image[-TrustZone.get_preset_data_size(self.family) :], family=self.family
            )
            image = image[: -len(self.trust_zone)]

        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)

    @property
    def img_len(self) -> int:
        """Image length of encrypted legacy image."""
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")
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

        if not (self.hmac_key and self.ctr_init_vector):
            raise SPSDKError("HMAC key or IV is missing")
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
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")
        if not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Only CertBlockV1 is supported")
        image_bytes = image.export()
        if revert:
            cert_blk_offset = self.ivt_table.get_cert_block_offset_from_data(image_bytes)
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

        enc_ivt = self.ivt_table.update_ivt(
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
        if self.tz_type == TrustZoneType.CUSTOM:
            ret.append_image(
                BinaryImage(name="Encrypted TrustZone", binary=image_bytes[self.app_len :])
            )

        return ret

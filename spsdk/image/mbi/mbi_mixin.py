#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Master Boot Image mixin classes and utilities.

This module provides a comprehensive set of mixin classes for building and exporting
Master Boot Images (MBI) across different NXP MCU families. It includes mixins for
handling various MBI components like TrustZone, certificates, encryption, signing,
and hardware-specific features.
"""

# pylint: disable=too-many-public-methods,too-many-lines

import importlib
import inspect
import logging
import os
import pkgutil
import struct
from typing import Any, Callable, Optional, Type, Union

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt
from spsdk.crypto.utils import get_hash_type_from_signature_size
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKTypeError
from spsdk.image.ahab.ahab_container import AHABContainerV2
from spsdk.image.ahab.ahab_data import create_chip_config
from spsdk.image.ahab.ahab_iae import ImageArrayEntryV2
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
from spsdk.image.mbi.utils import get_ahab_supported_hashes, get_mbi_ahab_validation_schemas
from spsdk.image.trustzone import TrustZone, TrustZoneType, TrustZoneV2
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import (
    Endianness,
    align_block,
    bytes_to_print,
    load_binary,
    load_hex_string,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


def get_all_mbi_mixins() -> dict[str, Type]:
    """Get all classes inheriting from MBI mixin base classes.

    This function finds all classes that inherit from any of the specified
    mixin base classes, including classes that inherit from classes that
    inherit from these base classes. Only processes modules in the same
    directory as this module.

    :return: Dictionary mapping class qualified names to class types of all mixin classes.
    """
    # Base mixin classes to search for
    base_mixins = [Mbi_Mixin, Mbi_ExportMixin]

    all_mixins = {}
    current_dir = os.path.dirname(os.path.abspath(__file__))
    package_name = __name__.rsplit(".", 1)[0]

    for _, module_name, _ in pkgutil.iter_modules([current_dir]):
        try:
            full_module_name = f"{package_name}.{module_name}"
            module = importlib.import_module(full_module_name)

            for _, obj in inspect.getmembers(module, inspect.isclass):
                for base_mixin in base_mixins:
                    if issubclass(obj, base_mixin) and obj not in base_mixins:
                        all_mixins[obj.__qualname__] = obj
                        break
        except (ImportError, AttributeError, TypeError):
            # Skip modules that can't be inspected
            continue
    return all_mixins


# ****************************************************************************************************
#                                             Mbi Mixins
# ****************************************************************************************************


# pylint: disable=invalid-name
class Mbi_Mixin:
    """Base class for Master Boot Image Mixin classes.

    This class provides the foundation for implementing modular components that can be
    mixed into Master Boot Image configurations. Each mixin represents a specific
    functionality or data section that contributes to the final boot image structure.

    :cvar VALIDATION_SCHEMAS: List of schema names used for configuration validation.
    :cvar NEEDED_MEMBERS: Dictionary of required member variables for the mixin.
    :cvar PRE_PARSED: List of pre-parsed configuration fields.
    :cvar COUNT_IN_LEGACY_CERT_BLOCK_LEN: Flag indicating if mixin counts in legacy certificate block length.
    """

    VALIDATION_SCHEMAS: list[str] = []
    NEEDED_MEMBERS: dict[str, Any] = {}
    PRE_PARSED: list[str] = []
    COUNT_IN_LEGACY_CERT_BLOCK_LEN: bool = True

    family: FamilyRevision

    def mix_init(self) -> None:
        """Initialize the mixin component.

        This method sets up the initial state and configuration for the mixin
        functionality within the MBI (Master Boot Image) context.
        """

    def mix_len(self) -> int:  # pylint: disable=no-self-use
        """Compute length of individual mixin.

        :return: Length of atomic Mixin in bytes.
        """
        return 0

    def mix_app_len(self) -> int:  # pylint: disable=no-self-use
        """Compute application data length of individual mixin.

        This method returns the default application data length for an atomic mixin,
        which is zero for the base implementation.

        :return: Application data length of atomic Mixin in bytes.
        """
        return 0

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from mixin.

        The method retrieves validation schemas for MBI (Master Boot Image) configuration
        based on the class's VALIDATION_SCHEMAS attribute.

        :param family: Family revision to get schemas for.
        :return: List of validation schema dictionaries.
        """
        schema_cfg = get_schema_file(DatabaseManager.MBI)
        return [schema_cfg[x] for x in cls.VALIDATION_SCHEMAS]

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration of mixin from dictionary.

        :param config: Dictionary with configuration fields.
        """

    def mix_validate(self) -> None:
        """Validate the setting of image.

        Performs validation checks on the current image configuration to ensure
        all settings are properly configured and consistent.

        :raises SPSDKError: Invalid image configuration or settings.
        """

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to individual fields.

        This method takes binary data representing a final image and parses it into
        the individual fields of the MBI (Master Boot Image) structure.

        :param data: Final Image in bytes to be parsed.
        """

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :return: Dictionary containing mixin configuration data.
        """
        return {}


class Mbi_MixinApp(Mbi_Mixin):
    """Master Boot Image Application Mixin.

    This mixin class handles application binary data within Master Boot Image (MBI) structures,
    providing functionality to load, validate, and manage application images for secure boot
    processes across NXP MCU portfolio.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for configuration validation.
    :cvar NEEDED_MEMBERS: Required class members with their default values for proper mixin
        initialization.
    """

    VALIDATION_SCHEMAS: list[str] = ["app"]
    NEEDED_MEMBERS: dict[str, Any] = {"_app": bytes(), "app_ext_memory_align": 0x1000}

    _app: bytes
    app_ext_memory_align: int

    @property
    def app(self) -> bytes:
        """Get application data.

        :return: Raw application data as bytes.
        """
        return self._app

    @app.setter
    def app(self, app: bytes) -> None:
        """Set application data.

        The method sets the application data and aligns it to proper block boundaries.

        :param app: Raw application data bytes to be set.
        """
        self._app = align_block(app)

    def mix_len(self) -> int:
        """Get size of plain input application image.

        :return: Length of application in bytes.
        """
        return len(self._app)

    def mix_app_len(self) -> int:
        """Compute application data length of individual mixin.

        :return: Application data length of atomic Mixin.
        """
        return len(self._app)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        :param config: Configuration object containing input file settings.
        :raises SPSDKError: If the input image file cannot be loaded or is invalid.
        """
        self.load_binary_image_file(config.get_input_file_name("inputImageFile"))

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        The method extracts configuration data from the mixin and optionally writes the application
        binary to the specified output folder if present.

        :param output_folder: Output folder to store the application binary file.
        :return: Dictionary containing the mixin configuration with input image file reference.
        """
        config: dict[str, Any] = {}
        if self.app:
            filename = "application.bin"
            write_file(self.app, os.path.join(output_folder, filename), mode="wb")
            config["inputImageFile"] = filename
        return config

    def load_binary_image_file(self, path: str) -> None:
        """Load binary image from file (S19, HEX, BIN).

        The method loads a binary image from the specified file and validates alignment
        requirements if app_ext_memory_align is configured. The loaded image data is
        stored in the app attribute.

        :param path: Path to the binary image file to load.
        :raises SPSDKError: If invalid data file is detected or alignment requirements are not met.
        """
        app_align = self.app_ext_memory_align if hasattr(self, "app_ext_memory_align") else 0
        image = BinaryImage.load_binary_image(path)
        if app_align and image.absolute_address % app_align != 0:
            raise SPSDKError(
                f"Invalid input binary file {path}. It has to be aligned to {hex(app_align)}."
            )
        self.app = image.export()

    def mix_validate(self) -> None:
        """Validate the application format and interrupt vector table.

        Performs validation checks on the application binary to ensure it meets
        minimum size requirements and has valid interrupt vector table entries.
        The method verifies that the stack pointer, program counter, and DSC
        illegal operation vectors are not identical.

        :raises SPSDKError: The application format is invalid or minimum size
            requirements are not met.
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
    """Master Boot Image TrustZone mixin class.

    This mixin provides TrustZone functionality for Master Boot Images, managing
    TrustZone configuration, validation, and integration with certificate blocks.
    The class handles both preset and custom TrustZone configurations.

    :cvar VALIDATION_SCHEMAS: Configuration validation schemas for TrustZone.
    :cvar NEEDED_MEMBERS: Required class members for TrustZone functionality.
    :cvar PRE_PARSED: List of pre-parsed configuration elements.
    """

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
        """Get the TrustZone configuration type for this MBI.

        Determines the TrustZone type based on the current trust_zone configuration.
        Returns DISABLED if no TrustZone is configured, CUSTOM if a customized
        configuration exists, or ENABLED for standard TrustZone configuration.

        :return: The TrustZone type indicating current configuration state.
        """
        if self.trust_zone is None:
            return TrustZoneType.DISABLED
        if self.trust_zone.is_customized:
            return TrustZoneType.CUSTOM
        return TrustZoneType.ENABLED

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        The method returns the length of the TrustZone array if it exists and the type is CUSTOM,
        otherwise returns 0.

        :return: Length of TrustZone array, or 0 if not applicable.
        """
        return (
            len(self.trust_zone) if self.trust_zone and self.tz_type == TrustZoneType.CUSTOM else 0
        )

    def _load_preset_file(self, preset_file: str) -> None:
        """Load preset file for TrustZone configuration.

        Attempts to load the preset file as a configuration file first. If that fails,
        falls back to loading it as a binary TrustZone file and parses it directly.

        :param preset_file: Path to the preset file (config or binary format).
        :raises SPSDKError: When binary file cannot be loaded or parsed as TrustZone.
        """
        try:
            cfg = Config.create_from_file(preset_file)
        except SPSDKError:
            self.trust_zone = TrustZone.parse(load_binary(preset_file), family=self.family)
            return
        self.trust_zone = TrustZone.load_from_config(cfg)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        Loads TrustZone configuration settings from the provided configuration dictionary.
        If TrustZone is enabled, either loads preset file or creates default TrustZone instance.

        :param config: Configuration dictionary containing TrustZone settings.
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

        This method generates configuration data for the mixin, including TrustZone settings.
        If a custom TrustZone configuration is present, it exports the configuration to a binary
        file in the specified output folder.

        :param output_folder: Output folder to store generated configuration files.
        :return: Dictionary containing the mixin configuration with TrustZone settings.
        """
        config: dict[str, Any] = {}
        config["enableTrustZone"] = bool(self.trust_zone)
        if self.trust_zone and self.trust_zone.is_customized == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize TrustZone configuration.

        The method analyzes the TrustZone type from the IVT table and initializes the appropriate
        TrustZone object based on the detected type (enabled, custom, or none).

        :param data: Final Image in bytes containing the binary data to parse.
        :raises SPSDKParsingError: Invalid TrustZone type detected in the binary data.
        """
        tz_type = self.ivt_table.get_tz_type(data)
        if tz_type not in TrustZoneType.tags():
            raise SPSDKParsingError("Invalid TrustZone type")

        self.trust_zone = None

        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)

        if tz_type == TrustZoneType.CUSTOM:
            tz_data = None
            # load custom data
            tz_data_size = len(TrustZone(self.family))
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
    """Master Boot Image Trust Zone mixin for devices where TrustZone is mandatory.

    This mixin extends the base TrustZone functionality to enforce TrustZone configuration
    for devices that require it. It automatically initializes TrustZone settings and
    validates that TrustZone configuration is present during image creation.

    :cvar VALIDATION_SCHEMAS: List of validation schemas used for configuration validation.
    """

    VALIDATION_SCHEMAS: list[str] = ["trust_zone_mandatory"]
    trust_zone: Optional[TrustZone]
    family: FamilyRevision

    def mix_init(self) -> None:
        """Initialize the mixin component.

        Sets up the TrustZone configuration if it hasn't been initialized yet. Creates a new
        TrustZone instance using the current family setting when trust_zone is None.
        """
        if self.trust_zone is None:
            self.trust_zone = TrustZone(family=self.family)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        This method processes the configuration to set up TrustZone settings. If a TrustZone
        preset file is specified, it loads the preset and warns if default values are used.
        Otherwise, it initializes a default TrustZone configuration for the family.

        :param config: Configuration object containing TrustZone setup parameters.
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

        The method exports trust zone configuration to a binary file if customized and returns
        the configuration dictionary with the file reference.

        :param output_folder: Output folder to store the trust zone binary file.
        :return: Configuration dictionary containing trust zone preset file reference if applicable.
        """
        config: dict[str, Any] = {}
        if self.trust_zone and self.trust_zone.is_customized == TrustZoneType.CUSTOM:
            filename = "trust_zone.bin"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            config["trustZonePresetFile"] = filename

        return config


class Mbi_MixinTrustZoneV2(Mbi_Mixin):
    """Master Boot Image TrustZone version 2 mixin class.

    This mixin provides TrustZone version 2 functionality for Master Boot Images,
    handling configuration, validation, and management of TrustZone security settings
    for NXP MCU devices.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for TrustZone v2.
    :cvar NEEDED_MEMBERS: Required member variables and their default values.
    """

    VALIDATION_SCHEMAS: list[str] = ["trust_zone_2"]
    NEEDED_MEMBERS: dict[str, Any] = {
        "trust_zone": None,
        "family": "Unknown",
        "revision": "latest",
    }

    trust_zone: Optional[TrustZoneV2]
    ivt_table: "Mbi_MixinIvt"

    @property
    def tz_type(self) -> TrustZoneType:
        """Get the TrustZone type for this MBI.

        Determines whether TrustZone is enabled with custom configuration or just enabled
        with default settings.

        :return: TrustZone type indicating custom or enabled configuration.
        """
        if self.trust_zone and self.trust_zone.is_customized:
            return TrustZoneType.CUSTOM
        return TrustZoneType.ENABLED

    def mix_len(self) -> int:
        """Get length of TrustZone array.

        :return: Length of TrustZone array, or 0 if TrustZone is not set.
        """
        return len(self.trust_zone) if self.trust_zone else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        Loads trust zone configuration from the provided config dictionary. If a trust zone
        preset file is specified, it attempts to load it first as a config file, then falls
        back to parsing it as a binary file if that fails.

        :param config: Dictionary with configuration fields.
        :raises SPSDKError: When trust zone configuration cannot be loaded from preset file.
        """
        self.trust_zone = None
        if config.get("trustZonePresetFile"):
            preset_file = config.get_input_file_name("trustZonePresetFile")
            try:
                self.trust_zone = TrustZoneV2.load_from_config(Config.create_from_file(preset_file))
            except SPSDKError:
                self.trust_zone = TrustZoneV2.parse(load_binary(preset_file), family=self.family)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        Exports trust zone configuration to files and returns configuration dictionary with
        references to the exported files.

        :param output_folder: Output folder to store the exported trust zone files.
        :return: Configuration dictionary containing trust zone preset file reference.
        """
        config: dict[str, Any] = {}
        if self.trust_zone:
            filename = "trust_zone.bin"
            filename_yaml = "trust_zone.yaml"
            write_file(self.trust_zone.export(), os.path.join(output_folder, filename), mode="wb")
            write_file(
                self.trust_zone.get_config_yaml(),
                os.path.join(output_folder, filename_yaml),
                mode="w",
            )
            config["trustZonePresetFile"] = filename_yaml

        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        This method extracts and validates TrustZone configuration from the binary data,
        setting up the trust_zone attribute based on the detected TrustZone type.

        :param data: Final Image in bytes.
        :raises SPSDKParsingError: Invalid TrustZone type or Trust Zone block not found.
        """
        tz_type = self.ivt_table.get_tz_type(data)
        if tz_type not in TrustZoneType.tags():
            raise SPSDKParsingError("Invalid TrustZone type")

        self.trust_zone = None

        if tz_type == TrustZoneType.CUSTOM:
            tz_offset = TrustZoneV2.find_trustzone_block_offset(data)
            if tz_offset is None:
                raise SPSDKParsingError("Trust Zone block not found")
            self.trust_zone = TrustZoneV2.parse(data[tz_offset:], family=self.family)


class Mbi_MixinLoadAddress(Mbi_Mixin):
    """Master Boot Image load address mixin.

    This mixin handles the management of load addresses for Master Boot Images,
    providing functionality to load, configure, and parse execution addresses
    from configuration data and binary image data.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for load address configuration.
    """

    VALIDATION_SCHEMAS: list[str] = ["load_addr"]

    load_address: Optional[int]
    ivt_table: "Mbi_MixinIvt"

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method extracts the output image execution address from the provided
        configuration and sets the load_address attribute.

        :param config: Configuration object containing MBI settings.
        """
        self.load_address = config.get_int("outputImageExecutionAddress", 0)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        The method retrieves configuration data including the output image execution address
        based on the load address. The load address must be defined before calling this method.

        :param output_folder: Output folder to store files.
        :raises SPSDKError: The load address is not defined.
        :return: Dictionary containing mixin configuration with execution address.
        """
        config: dict[str, Any] = {}
        if self.load_address is None:
            raise SPSDKError("The load address is not defined.")
        config["outputImageExecutionAddress"] = hex(self.load_address)
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        This method extracts the load address from the provided binary data using the IVT table
        and stores it in the load_address attribute.

        :param data: Final Image in bytes containing the binary data to be parsed.
        """
        self.load_address = self.ivt_table.get_load_address_from_data(data)


class Mbi_MixinFwVersion(Mbi_Mixin):
    """Master Boot Image Firmware Version Mixin.

    This mixin class provides firmware version management functionality for Master Boot Images,
    handling configuration loading and retrieval of firmware version information.

    :cvar VALIDATION_SCHEMAS: List of validation schemas used for firmware version validation.
    :cvar NEEDED_MEMBERS: Dictionary defining required members for the mixin functionality.
    """

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
        :return: Dictionary containing mixin configuration with firmware version.
        """
        config: dict[str, Any] = {}
        config["firmwareVersion"] = self.firmware_version
        return config


class Mbi_MixinImageVersion(Mbi_Mixin):
    """Master Boot Image version management mixin.

    This mixin provides functionality for handling image version information in Master Boot Images,
    including loading version data from configuration, parsing version from binary data, and
    managing version-related operations through the IVT table.

    :cvar VALIDATION_SCHEMAS: List of validation schemas used for image version validation.
    :cvar NEEDED_MEMBERS: Dictionary defining required members with default values.
    :cvar image_version_to_image_type: Flag indicating if image version maps to image type.
    """

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
        :return: Dictionary containing mixin configuration with image version.
        """
        config: dict[str, Any] = {}
        config["imageVersion"] = self.image_version
        return config

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and set individual image fields.

        This method extracts the image version from the provided binary data using
        the IVT (Interrupt Vector Table) and stores it in the image_version attribute.

        :param data: Complete binary image data to be parsed.
        """
        self.image_version = self.ivt_table.get_image_version(data)


class Mbi_MixinImageSubType(Mbi_Mixin):
    """Master Boot Image SubType mixin class.

    This mixin provides functionality for managing image subtypes in Master Boot Images,
    supporting different subtype configurations for various NXP MCU families including
    KW45xx, K32W1xx, and MCXN9xx series.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for image subtype.
    :cvar NEEDED_MEMBERS: Dictionary defining required members with default values.
    """

    class Mbi_ImageSubTypeKw45xx(SpsdkEnum):
        """MBI image subtype enumeration for KW45xx and K32W1xx MCU families.

        This enumeration defines the supported image subtypes for Master Boot Image (MBI)
        format used in KW45xx and K32W1xx microcontrollers, including main application
        and NBU (Narrowband Unit) image types.
        """

        MAIN = (0x00, "MAIN", "Default (main) application image")
        NBU = (0x01, "NBU", "NBU (Narrowband Unit) image")

    class Mbi_ImageSubTypeMcxn9xx(SpsdkEnum):
        """MBI image subtype enumeration for MCXN9xx devices.

        This enumeration defines the supported image subtypes for MCXN9xx series
        microcontrollers, including main application and recovery image types.
        """

        MAIN = (0x00, "MAIN", "Default (main) application image")
        RECOVERY = (0x01, "RECOVERY", "Recovery image")

    VALIDATION_SCHEMAS: list[str] = ["image_subtype"]
    NEEDED_MEMBERS: dict[str, Any] = {"image_subtype": 0}

    image_subtype: Optional[int]
    ivt_table: "Mbi_MixinIvt"

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method loads the output image subtype from the provided configuration,
        defaulting to "main" if not specified.

        :param config: Configuration object containing the settings to load.
        """
        self.set_image_subtype(config.get_str("outputImageSubtype", "main"))

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :raises SPSDKError: When the image subtype is not defined.
        :return: Dictionary containing the mixin configuration with output image subtype.
        """
        config: dict[str, Any] = {}
        if self.image_subtype is None:
            raise SPSDKError("The image subtype is not defined.")
        config["outputImageSubtype"] = Mbi_MixinImageSubType.Mbi_ImageSubTypeKw45xx.from_tag(
            self.image_subtype
        ).label
        return config

    def set_image_subtype(self, image_subtype: Optional[Union[str, int]]) -> None:
        """Set image subtype for MBI mixin.

        Converts string representation of image subtype to integer value using appropriate
        enum table based on the target MCU family and stores it in the class instance.

        :param image_subtype: Image subtype as string name, integer value, or None for default.
        """
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

        This method extracts the image subtype from the provided binary data using
        the IVT (Interrupt Vector Table) and stores it in the image_subtype attribute.

        :param data: Final Image in bytes to be parsed.
        """
        self.image_subtype = self.ivt_table.get_sub_type(data)


class Mbi_MixinIvt(Mbi_Mixin):
    """Master Boot Image Interrupt Vector Table mixin class.

    This mixin provides functionality for handling IVT (Interrupt Vector Table) operations
    in Master Boot Images, including flag management, offset definitions, and IVT table
    manipulation for NXP MCU boot images.

    :cvar IVT_IMAGE_LENGTH_OFFSET: Offset for image length field in IVT table.
    :cvar IVT_IMAGE_FLAGS_OFFSET: Offset for image flags field in IVT table.
    :cvar IVT_CRC_CERTIFICATE_OFFSET: Offset for CRC certificate field in IVT table.
    :cvar IVT_LOAD_ADDR_OFFSET: Offset for load address field in IVT table.
    """

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
        """Get IVT table itself.

        Returns the current mixin IVT object instance for method chaining or direct access.

        :return: Current mixin IVT object.
        """
        return self

    def create_flags(self) -> int:
        """Create flags of image.

        Constructs image type flags by combining base image type with optional features
        like TrustZone type, image subtype, hardware key enablement, key store presence,
        relocation table, and boot image version.

        :raises SPSDKError: When image subtype is not defined but required.
        :return: Combined image type flags as integer value.
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

        The method modifies the Interrupt Vector Table (IVT) fields including image flags,
        load address, image length, and CRC/certificate offset in the provided application data.

        :param app_data: Application data that should be modified.
        :param total_len: Total length of bootable image.
        :param crc_val_cert_offset: CRC value or Certification block offset.
        :return: Updated whole application image.
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
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )

        return bytes(data)

    def clean_ivt(self, app_data: bytes) -> bytes:
        """Clean IVT table from added information.

        The method removes specific fields from the IVT (Interrupt Vector Table) by zeroing out
        the image length, flags, CRC/certificate offset, and execution address fields.

        :param app_data: Application data that should be cleaned.
        :return: Cleaned application image with zeroed IVT fields.
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
        """Update CRC/Certificate offset field value in binary data.

        This method modifies the CRC/Certificate offset field at a specific position
        in the provided binary data using little-endian byte order.

        :param app_data: Input binary array to be modified.
        :param crc_val_cert_offset: New CRC/Certificate offset value to set.
        :return: Updated binary array with modified CRC/Certificate offset field.
        """
        data = bytearray(app_data)
        data[self.IVT_CRC_CERTIFICATE_OFFSET : self.IVT_CRC_CERTIFICATE_OFFSET + 4] = struct.pack(
            "<I", crc_val_cert_offset
        )
        return data

    def update_total_length(self, app_data: bytes, total_length: int) -> bytes:
        """Update total length field in the IVT table.

        This method modifies the application data by updating the image length field
        in the Interrupt Vector Table (IVT) at the predefined offset.

        :param app_data: Application data containing the IVT table to be modified.
        :param total_length: New total length value to be written to the IVT.
        :return: Modified application data with updated total length field.
        """
        data = bytearray(app_data)
        data[self.IVT_IMAGE_LENGTH_OFFSET : self.IVT_IMAGE_LENGTH_OFFSET + 4] = struct.pack(
            "<I", total_length
        )
        return bytes(data)

    @classmethod
    def check_total_length(cls, data: bytes) -> None:
        """Check total length field from raw MBI image data.

        Validates that the input data contains sufficient bytes for a valid MBI image by checking
        both the minimum IVT table size and comparing the declared image length with actual data size.

        :param data: Raw MBI image data to validate.
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

        The method extracts flags from MBI image data and validates the total length
        during the process.

        :param data: Raw MBI image data.
        :raises SPSDKError: Invalid data length or format.
        :return: Image flags value.
        """
        cls.check_total_length(data)
        return cls.get_flags_from_data(data)

    @classmethod
    def get_flags_from_data(cls, data: bytes) -> int:
        """Get the Image flags from raw data.

        Extracts the image flags from the specified offset in the MBI image data using little-endian byte order.

        :param data: Raw MBI image data as bytes.
        :return: Image flags as integer value.
        """
        return int.from_bytes(
            data[cls.IVT_IMAGE_FLAGS_OFFSET : cls.IVT_IMAGE_FLAGS_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_cert_block_offset(cls, data: bytes) -> int:
        """Get the certificate block offset from raw data.

        The method validates the total length of the data and extracts the certificate
        block offset from the MBI image data.

        :param data: Raw MBI image data to extract certificate block offset from.
        :return: Certificate block offset value.
        """
        cls.check_total_length(data)
        return cls.get_cert_block_offset_from_data(data)

    @classmethod
    def get_cert_block_offset_from_data(cls, data: bytes) -> int:
        """Get the certificate block offset from raw MBI image data.

        This method extracts the certificate block offset from the IVT (Interrupt Vector Table)
        section of the MBI image data using little-endian byte order.

        :param data: Raw MBI image data containing the IVT structure.
        :return: Certificate block offset as integer value.
        """
        return int.from_bytes(
            data[cls.IVT_CRC_CERTIFICATE_OFFSET : cls.IVT_CRC_CERTIFICATE_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_load_address(cls, data: bytes) -> int:
        """Get the load address from raw MBI image data.

        The method validates the total length of the data before extracting the load address.

        :param data: Raw MBI image data to extract load address from.
        :return: Load address value extracted from the MBI image data.
        """
        cls.check_total_length(data)

        return cls.get_load_address_from_data(data)

    @classmethod
    def get_load_address_from_data(cls, data: bytes) -> int:
        """Get the load address from raw MBI image data.

        Extracts the load address from the Interrupt Vector Table (IVT) at the predefined offset
        within the provided raw MBI image data.

        :param data: Raw MBI image data containing the IVT structure.
        :return: Load address as integer value extracted from the IVT.
        """
        return int.from_bytes(
            data[cls.IVT_LOAD_ADDR_OFFSET : cls.IVT_LOAD_ADDR_OFFSET + 4],
            Endianness.LITTLE.value,
        )

    @classmethod
    def get_image_type(cls, data: bytes) -> int:
        """Get the Image type from raw data.

        Extracts the image type by applying the image type mask to the flags obtained from the raw MBI data.

        :param data: Raw MBI image data as bytes.
        :return: Image type as integer value.
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

        Extracts the firmware version from the MBI image flags by checking the version flag
        and applying appropriate bit shifts and masks to retrieve the version value.

        :param data: Raw MBI image data as bytes.
        :return: Firmware version as integer, returns 0 if version flag is not set.
        """
        flags = cls.get_flags_from_data(data)
        if flags & cls._BOOT_IMAGE_VERSION_FLAG == 0:
            return 0

        return (flags >> cls.IVT_IMAGE_FLAGS_IMG_VER_SHIFT) & cls.IVT_IMAGE_FLAGS_IMG_VER_MASK

    @classmethod
    def get_sub_type(cls, data: bytes) -> int:
        """Get the Image sub type from raw data.

        Extracts the sub type information from the image flags field in the raw MBI data
        by applying appropriate bit shifting and masking operations.

        :param data: Raw MBI image data.
        :return: Image sub type as integer value.
        """
        flags = cls.get_flags_from_data(data)

        return (flags >> cls.IVT_IMAGE_FLAGS_SUB_TYPE_SHIFT) & cls.IVT_IMAGE_FLAGS_SUB_TYPE_MASK

    @classmethod
    def get_hw_key_enabled(cls, data: bytes) -> bool:
        """Get the HW key enabled setting from raw data.

        This method extracts and checks the hardware key enablement flag from the
        provided MBI image data by analyzing the flags field.

        :param data: Raw MBI image data as bytes.
        :return: True if hardware key is enabled, False otherwise.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._HW_USER_KEY_EN_FLAG)

    @classmethod
    def get_key_store_presented(cls, data: bytes) -> int:
        """Get the KeyStore present flag from raw data.

        :param data: Raw MBI image data.
        :return: True if KeyStore is included, False otherwise.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._KEY_STORE_FLAG)

    @classmethod
    def get_app_table_presented(cls, data: bytes) -> int:
        """Get the Multiple Application table present flag from raw data.

        :param data: Raw MBI image data.
        :return: True if Multiple Application table is included, False otherwise.
        """
        flags = cls.get_flags_from_data(data)

        return bool(flags & cls._RELOC_TABLE_FLAG)


class Mbi_MixinIvtZeroTotalLength(Mbi_MixinIvt):
    """Master Boot Image Interrupt Vector table mixin for XIP images with zero total length.

    This mixin class extends the base IVT functionality to handle XIP (Execute In Place) images
    that require the total length field in the IVT to be set to zero, regardless of the actual
    image size. It provides specialized handling for images that don't need length validation
    during boot process.
    """

    def update_ivt(
        self,
        app_data: bytes,
        total_len: int,
        crc_val_cert_offset: int = 0,
    ) -> bytes:
        """Update IVT table in application image.

        This method overrides the parent implementation by setting the total length to 0,
        effectively ignoring the provided total_len parameter as indicated by the debug log.

        :param app_data: Application data that should be modified.
        :param total_len: Total length of bootable image (will be ignored and set to 0).
        :param crc_val_cert_offset: CRC value or Certification block offset.
        :return: Updated whole application image with modified IVT table.
        """
        logger.debug(f"Setting total length to 0. Ignoring {total_len}")
        return super().update_ivt(
            app_data=app_data, total_len=0, crc_val_cert_offset=crc_val_cert_offset
        )

    @classmethod
    def check_total_length(cls, data: bytes) -> None:
        """Check total length field from raw data.

        Validates that the total length field in the MBI image header matches or is compatible
        with the actual data length provided.

        :param data: Raw MBI image data to validate.
        :raises SPSDKParsingError: Insufficient length of image has been detected.
        """
        total_len = int.from_bytes(
            data[cls.IVT_IMAGE_LENGTH_OFFSET : cls.IVT_IMAGE_LENGTH_OFFSET + 4],
            Endianness.LITTLE.value,
        )
        if total_len != 0 and total_len > len(data):
            raise SPSDKParsingError("Insufficient length of input raw data!")


class Mbi_MixinRelocTable(Mbi_Mixin):
    """Master Boot Image Relocation Table Mixin.

    This mixin handles relocation table functionality for Master Boot Images, managing
    multiple image entries with their destination addresses and load flags. It provides
    configuration loading, validation, and export capabilities for application tables
    containing relocatable image data.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for this mixin.
    :cvar NEEDED_MEMBERS: Dictionary of required member variables and their defaults.
    """

    VALIDATION_SCHEMAS: list[str] = ["app_table"]
    NEEDED_MEMBERS: dict[str, Any] = {"app_table": None, "_app": None}

    app_table: Optional[MultipleImageTable]
    app: Optional[bytes]

    def mix_len(self) -> int:
        """Get length of additional binaries block.

        The method calculates the length by exporting the application table if it exists,
        otherwise returns 0 for cases where no application table is present.

        :return: Length of additional binaries block in bytes.
        """
        return len(self.app_table.export(0)) if self.app_table else 0

    def mix_app_len(self) -> int:
        """Compute application data length of individual mixin.

        The method calculates the length of exported application table data if the table exists,
        otherwise returns 0.

        :return: Application data length of atomic Mixin in bytes.
        """
        return len(self.app_table.export(0)) if self.app_table else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method processes the applicationTable configuration section to create
        a MultipleImageTable with image entries. Each entry contains binary data,
        destination address, and load type information.

        :param config: Configuration object containing applicationTable section.
        :raises SPSDKError: Invalid configuration or missing binary files.
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

        Extracts configuration data from the application table and writes binary files
        to the specified output folder for each table entry.

        :param output_folder: Output folder to store the generated binary files.
        :return: Dictionary containing the mixin configuration with application table data.
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

        This method checks if the application table configuration is valid by ensuring
        that when an application table exists, it contains at least one entry.

        :raises SPSDKError: Application table configuration is invalid - the application
            relocation table must have at least one record when present.
        """
        if self.app_table and len(self.app_table.entries) == 0:
            raise SPSDKError("The application relocation table MUST has at least one record.")

    def disassembly_app_data(self, data: bytes) -> bytes:
        """Disassemble application data to extract application and Multiple Application Table.

        The method parses the input data to extract a Multiple Application Table if present,
        and returns the application data portion while storing the table in the class instance.

        :param data: Raw application data bytes that may contain Multiple Application Table.
        :return: Application data without Multiple Application Table portion.
        """
        self.app_table = MultipleImageTable.parse(data)
        if self.app_table:
            return data[: self.app_table.start_address]

        return data


class Mbi_MixinManifest(Mbi_MixinTrustZoneMandatory):
    """Master Boot Image Manifest mixin class.

    This mixin provides manifest management functionality for Master Boot Images,
    including manifest creation, validation, and binary parsing capabilities.
    It extends trust zone mandatory functionality with firmware versioning
    and certificate block handling.

    :cvar VALIDATION_SCHEMAS: List of validation schemas required for this mixin.
    :cvar NEEDED_MEMBERS: Dictionary of required member variables and their defaults.
    :cvar PRE_PARSED: List of members that need pre-parsing during configuration.
    """

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

        :raises SPSDKError: The Image manifest must exist.
        :return: Length of Manifest block.
        """
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")
        return self.manifest.total_length

    def mix_validate(self) -> None:
        """Validate the settings of the MBI image.

        This method performs validation checks on the image configuration, ensuring
        that all required components are properly set, including the mandatory manifest.

        :raises SPSDKError: The image manifest is missing or the configuration is invalid.
        """
        super().mix_validate()
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        This method loads configuration settings from the provided config object,
        sets the firmware version, and initializes the manifest with the current
        firmware version and trust zone settings.

        :param config: Configuration object containing the settings to load.
        :raises SPSDKValueError: If configuration contains invalid values.
        """
        super().mix_load_from_config(config)
        self.firmware_version = config.get_int("firmwareVersion", 0)

        self.manifest = self.manifest_class(self.firmware_version, self.trust_zone)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual MBI fields.

        The method extracts the manifest from the binary data using the certificate block
        and IVT table offsets, then initializes firmware version and trust zone properties
        from the parsed manifest data.

        :param data: Complete MBI binary image data to be parsed.
        :raises AssertionError: If cert_block is not an instance of CertBlockV21.
        """
        assert isinstance(self.cert_block, CertBlockV21)
        manifest_offset = self.ivt_table.get_cert_block_offset(data) + self.cert_block.expected_size
        self.manifest = self.manifest_class.parse(self.family, data[manifest_offset:])
        self.firmware_version = self.manifest.firmware_version
        self.trust_zone = self.manifest.trust_zone or TrustZone(self.family)


class Mbi_MixinManifestCrc(Mbi_MixinManifest):
    """Master Boot Image Manifest mixin with CRC support.

    This mixin extends the base manifest functionality to include CRC-based
    Master Boot Image manifest handling, providing firmware version management
    and trust zone configuration.

    :cvar manifest_class: Reference to MasterBootImageManifestCrc class.
    """

    manifest_class = MasterBootImageManifestCrc
    manifest: Optional[MasterBootImageManifestCrc]

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        Loads the firmware version from configuration and initializes the manifest
        with the specified firmware version and trust zone settings.

        :param config: Configuration object containing the settings to load.
        :raises SPSDKValueError: If configuration contains invalid values.
        """
        super().mix_load_from_config(config)
        self.firmware_version = config.get_int("firmwareVersion", 0)

        self.manifest = self.manifest_class(
            self.firmware_version,
            self.trust_zone,
        )


class Mbi_MixinManifestDigest(Mbi_MixinManifest):
    """Master Boot Image Manifest mixin for devices supporting ImageDigest functionality.

    This mixin extends the base manifest functionality to handle image digest operations
    for Master Boot Images on devices that support digest validation. It manages manifest
    creation with configurable hash algorithms and provides digest-aware length calculations.

    :cvar VALIDATION_SCHEMAS: List of validation schema names required for this manifest type.
    """

    manifest_class = MasterBootImageManifestDigest
    manifest: Optional[MasterBootImageManifestDigest]

    VALIDATION_SCHEMAS: list[str] = [
        "trust_zone_mandatory",
        "firmware_version",
    ]

    def mix_len(self) -> int:
        """Get length of Manifest block.

        Calculates the total length of the manifest block including the manifest itself
        and optional hash digest if present based on the manifest flags.

        :raises SPSDKError: If the image manifest does not exist.
        :return: Total length of manifest block in bytes including optional hash.
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

        Loads configuration settings and initializes the manifest with firmware version,
        trust zone settings, and appropriate hash algorithm based on certificate block.

        :param config: Configuration object containing firmware settings and parameters.
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

        The method retrieves the mixin configuration including firmware version and validates
        that the image manifest exists before processing.

        :param output_folder: Output folder to store files.
        :raises SPSDKError: The Image manifest must exist.
        :return: Dictionary containing the mixin configuration with firmware version.
        """
        if not self.manifest:
            raise SPSDKError("The Image manifest must exists.")
        config = super().mix_get_config(output_folder=output_folder)
        config["firmwareVersion"] = self.firmware_version

        return config


class Mbi_MixinCertBlockV1(Mbi_Mixin):
    """Master Boot Image certification block V1 mixin.

    This mixin provides functionality for handling Certificate Block V1 operations
    in Master Boot Images, including configuration loading, validation, and export
    capabilities for secure boot implementations.

    :cvar VALIDATION_SCHEMAS: Configuration validation schema names.
    :cvar NEEDED_MEMBERS: Required member variables for mixin functionality.
    """

    VALIDATION_SCHEMAS: list[str] = ["cert_block_v1", "signer"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV1]
    signature_provider: Optional[SignatureProvider]
    total_len: int
    key_store: Optional[KeyStore]
    ivt_table: Mbi_MixinIvt
    get_key_store_presented: Callable[[bytes], int]
    HMAC_SIZE: int

    def mix_len(self) -> int:
        """Get length of Certificate Block V1.

        :return: Length of Certificate Block V1 in bytes, or 0 if no certificate block exists.
        """
        return len(self.cert_block.export()) if self.cert_block else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        Loads certificate block and signature provider from the provided configuration.

        :param config: Configuration dictionary containing certificate block and signature provider settings.
        """
        self.cert_block = CertBlockV1.load_from_config(config)
        self.signature_provider = get_signature_provider(config)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        The method generates a YAML configuration file for the certificate block and returns
        a configuration dictionary containing the certificate block filename and signer information.

        :param output_folder: Output folder to store the generated configuration files.
        :raises SPSDKError: Certificate block is missing.
        :return: Configuration dictionary with certificate block filename and signer details.
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

        This method checks that the certificate block is present and is of type CertBlockV1,
        verifies that a signature provider is defined, and validates that the signature
        provider can work with the public key from the last certificate in the chain.

        :raises SPSDKError: Certificate block is missing, not CertBlockV1 type, or signature
            provider is not defined.
        """
        if not self.cert_block or not isinstance(self.cert_block, CertBlockV1):
            raise SPSDKError("Certificate block is missing")
        if not self.signature_provider:
            raise SPSDKError("Signature provider is not defined")

        public_key = self.cert_block.certificates[-1].get_public_key()
        self.signature_provider.try_to_verify_public_key(public_key)

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual MBI fields.

        This method parses the provided binary data to extract certificate block information,
        calculates the appropriate offset based on HMAC and key store presence, and initializes
        the certificate block and signature provider fields.

        :param data: Complete MBI binary image data to be parsed.
        :raises SPSDKError: If the certificate block parsing fails.
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
    """Master Boot Image certification block V2.1 mixin class.

    This mixin provides functionality for handling certification blocks version 2.1
    in Master Boot Images, including configuration management, validation, and
    signature provider integration.

    :cvar VALIDATION_SCHEMAS: Configuration validation schema names.
    :cvar NEEDED_MEMBERS: Required member variables for mixin functionality.
    """

    VALIDATION_SCHEMAS: list[str] = ["cert_block_v21", "signer"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: Optional[CertBlockV21]
    signature_provider: Optional[SignatureProvider]
    ivt_table: Mbi_MixinIvt

    def mix_len(self) -> int:
        """Get length of Certificate Block V2.1.

        The method calculates the total length by combining the expected size of the
        certificate block and the signature length from the signature provider.

        :raises SPSDKError: When certification block or signature provider is missing.
        :return: Length of Certificate Block V2.1.
        """
        if not (self.cert_block and self.signature_provider):
            raise SPSDKError("Certification block or signature provider is missing")
        return self.cert_block.expected_size + self.signature_provider.signature_length

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method initializes certificate block and signature provider from the provided
        configuration data.

        :param config: Dictionary with configuration fields.
        :raises SPSDKError: Invalid configuration data or missing required fields.
        """
        self.cert_block = CertBlockV21.load_from_config(config)
        self.signature_provider = get_signature_provider(config)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        The method generates a YAML configuration file for the certificate block and returns
        a configuration dictionary with the certificate block filename and signer information.

        :param output_folder: Output folder to store the generated configuration files.
        :raises SPSDKError: Certificate block is missing.
        :return: Configuration dictionary containing certificate block filename and signer info.
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
        """Validate the settings of the MBI image.

        This method verifies that the certification block and signature provider are properly
        configured, and ensures that the signature provider's public key matches the key
        from either the ISK certificate or the root key record.

        :raises SPSDKError: When certification block is missing, signature provider is missing,
                           or when the signature provider's public key verification fails.
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
        """Parse the binary data to extract and initialize individual certificate fields.

        This method extracts the certificate block from the provided binary data using
        the IVT table offset and initializes the signature provider to None.

        :param data: Complete binary image data containing certificate information.
        :raises SPSDKError: If certificate block parsing fails or data is invalid.
        """
        self.cert_block = CertBlockV21.parse(
            data[self.ivt_table.get_cert_block_offset(data) :], self.family
        )
        self.signature_provider = None


class Mbi_MixinAhab(Mbi_Mixin):
    """Master Boot Image AHAB mixin class.

    This mixin provides AHAB (Advanced High-Assurance Boot) container support for Master Boot Images,
    including validation schemas, configuration management, and CRC check functionality for secure
    boot operations across NXP MCU portfolio.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for AHAB configuration.
    :cvar NEEDED_MEMBERS: Required member dictionary specifying AHAB container dependency.
    """

    VALIDATION_SCHEMAS: list[str] = [
        "ahab_sign_support",
        "ahab_sign_support_add_image_hash_type",
        "ahab_sign_support_add_core_id",
    ]
    NEEDED_MEMBERS: dict[str, Any] = {"ahab": None}

    FEATURE: str

    ahab: AHABContainerV2
    ivt_table: Mbi_MixinIvt
    app: bytes
    app_crc: bool
    trust_zone: Optional[TrustZone]
    tz_type: TrustZoneType
    load_address: int
    image_version: int

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from mixin.

        This method retrieves validation schemas for MBI (Master Boot Image) AHAB
        (Advanced High Assurance Boot) configuration based on the specified family revision.

        :param family: Family revision to get schemas for.
        :return: List of validation schemas dictionaries.
        """
        schema_cfg = get_mbi_ahab_validation_schemas(
            create_chip_config(family, feature=DatabaseManager.MBI, base_key=["ahab"])
        )
        return [schema_cfg[x] for x in cls.VALIDATION_SCHEMAS]

    @property
    def crc_check_record(self) -> Optional[ImageArrayEntryV2]:
        """Check if CRC is included in AHAB container.

        This method examines the AHAB (Advanced High-Assurance Boot) container to determine if it
        contains a CRC check record as its last image array entry. The CRC record is used to verify
        data integrity of the boot image.

        :return: The CRC check image array entry if present, otherwise None.
        """
        # Verify AHAB container exists and has an image array
        if not hasattr(self, "ahab") or not self.ahab or not self.ahab.image_array:
            return None

        # Check if the last entry in image array is a CRC check type
        last_entry = self.ahab.image_array[-1]
        if last_entry.flags_image_type_name == "crc_check":
            assert isinstance(last_entry, ImageArrayEntryV2)
            return last_entry
        return None

    def mix_len(self) -> int:
        """Get length of Certificate Block V2.1.

        :raises SPSDKError: When certification block or signature provider is missing.
        :return: Length of Certificate Block V2.1.
        """
        if not self.ahab:
            raise SPSDKError("Certification block or signature provider is missing")
        return len(self.ahab)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary and initialize AHAB container with image entries.

        The method creates an AHAB container with the main application image and optionally
        adds TrustZone and CRC check images based on configuration settings.

        :param config: Configuration dictionary containing AHAB settings, core ID, and hash type.
        """
        chip_config = create_chip_config(self.family, feature=self.FEATURE, base_key=["ahab"])
        self.ahab = AHABContainerV2(chip_config)
        self.ahab.load_from_config_generic(config)
        core_id = chip_config.core_ids.from_label(config.get_str("core_id", "cortex-m33"))
        hash_type = ImageArrayEntryV2.FLAGS_HASH_ALGORITHM_TYPE.from_label(
            config.get_str("image_hash_type", "sha384")
        )
        data_iae_flags = ImageArrayEntryV2.create_flags(
            image_type=ImageArrayEntryV2.get_image_types(self.ahab.chip_config, core_id.tag)
            .from_label("executable")
            .tag,
            core_id=core_id.tag,
            hash_type=hash_type,
        )
        data_image = ImageArrayEntryV2(
            chip_config=self.ahab.chip_config,
            image=self.app,
            image_offset=0,
            load_address=self.load_address,
            entry_point=0,
            flags=data_iae_flags,
            image_name="MCU Boot Image",
        )
        self.ahab.image_array.append(data_image)

        if self.trust_zone and self.tz_type == TrustZoneType.CUSTOM:
            tz_iae_flags = ImageArrayEntryV2.create_flags(
                image_type=ImageArrayEntryV2.get_image_types(self.ahab.chip_config, core_id.tag)
                .from_label("tz_data")
                .tag,
                core_id=core_id.tag,
                hash_type=hash_type,
            )
            tz_image = ImageArrayEntryV2(
                chip_config=self.ahab.chip_config,
                image=self.trust_zone.export(),
                image_offset=data_image.image_size,
                load_address=0,
                entry_point=0,
                flags=tz_iae_flags,
                image_name="TrustZone preset data Image",
            )
            self.ahab.image_array.append(tz_image)

        if self.app_crc:
            crc_iae_flags = ImageArrayEntryV2.create_flags(
                image_type=ImageArrayEntryV2.get_image_types(self.ahab.chip_config, core_id.tag)
                .from_label("crc_check")
                .tag,
                core_id=core_id.tag,
                hash_type=hash_type,
            )
            crc_image = ImageArrayEntryV2(
                chip_config=self.ahab.chip_config,
                image=bytes(4),
                image_offset=4,
                load_address=0,
                entry_point=0,
                flags=crc_iae_flags,
                image_name="CRC fact all data check",
            )
            self.ahab.image_array.append(crc_image)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        Creates a configuration dictionary for the AHAB container with image hash type
        and core ID settings when multiple options are available.

        :param output_folder: Output folder to store files.
        :raises SPSDKError: When AHAB container is missing.
        :return: Configuration dictionary with AHAB container settings.
        """
        if not self.ahab:
            raise SPSDKError("Ahab container is missing")

        config = self.ahab._create_config(index=0, data_path=output_folder)

        if len(get_ahab_supported_hashes(self.family)) > 1:
            config["image_hash_type"] = (
                self.ahab.image_array[0].get_hash_from_flags(self.ahab.image_array[0].flags).label
            )
        if len(self.ahab.chip_config.base.core_ids) > 1:
            config["core_id"] = self.ahab.image_array[0].flags_core_id_name

        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        Checks if the AHAB container is present in the image configuration.

        :raises SPSDKError: When AHAB container is missing from the image.
        """
        if not self.ahab:
            raise SPSDKError("Ahab container is missing")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual fields.

        The method extracts the AHAB container from the binary data at the calculated
        offset and parses it using the chip configuration. If the instance has an
        image_version attribute, it updates it with the software version from AHAB.

        :param data: Final Image in bytes to be parsed.
        :raises SPSDKError: If AHAB container parsing fails.
        :raises SPSDKValueError: If the data format is invalid or corrupted.
        """
        ahab_offset = Mbi_MixinIvt.get_cert_block_offset_from_data(data)
        self.ahab = AHABContainerV2.parse(
            data,
            chip_config=create_chip_config(self.family, feature=self.FEATURE, base_key=["ahab"]),
            offset=ahab_offset,
        )
        if hasattr(self, "image_version"):
            self.image_version = self.ahab.sw_version


class Mbi_MixinAppCrc(Mbi_Mixin):
    """Master Boot Image mixin for CRC application support.

    This mixin provides functionality for adding CRC check records to Master Boot Images,
    enabling application integrity verification during boot process. It manages CRC
    configuration and validation schemas for AHAB signing operations.

    :cvar VALIDATION_SCHEMAS: List of validation schemas for CRC support.
    :cvar NEEDED_MEMBERS: Dictionary defining required member variables and defaults.
    """

    VALIDATION_SCHEMAS: list[str] = ["ahab_sign_support_add_crc"]
    NEEDED_MEMBERS: dict[str, Any] = {"app_crc": False}
    app_crc: bool
    crc_check_record: Optional[ImageArrayEntryV2]

    def mix_len(self) -> int:
        """Get length of mix-in data.

        The method returns the length of additional data that needs to be included
        in the image based on whether application CRC is enabled.

        :return: Length of mix-in data in bytes (4 if app_crc is enabled, 0 otherwise).
        """
        if self.app_crc:
            return 4

        return 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method loads the CRC check configuration setting from the provided
        configuration dictionary and sets the app_crc attribute accordingly.

        :param config: Configuration dictionary containing MBI settings.
        """
        self.app_crc = config.get_bool("add_crc_check", False)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :return: Dictionary containing mixin configuration with CRC check settings.
        """
        config = {}
        config["add_crc_check"] = bool(self.crc_check_record is not None)

        return config


class Mbi_MixinCertBlockVx(Mbi_Mixin):
    """Master Boot Image certification block mixin for MC55xx family devices.

    This mixin provides certification block functionality for Master Boot Images,
    including configuration loading, validation, and binary parsing capabilities.
    It manages certificate blocks, signature providers, and related settings for
    secure boot operations on MC55xx devices.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for configuration.
    :cvar NEEDED_MEMBERS: Dictionary defining required member attributes.
    """

    VALIDATION_SCHEMAS: list[str] = ["cert_block_vX", "signer", "just_header"]
    NEEDED_MEMBERS: dict[str, Any] = {"cert_block": None, "signature_provider": None}

    cert_block: CertBlockVx
    add_hash: bool
    just_header: bool
    signature_provider: Optional[SignatureProvider]
    IMG_ISK_OFFSET: int

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        This method initializes the MBI mixin with configuration data including
        certificate block, signature provider, and various flags.

        :param config: Dictionary with configuration fields containing certificate
            block data, signature provider settings, addCertHash flag, and justHeader flag.
        """
        self.cert_block = CertBlockVx.load_from_config(config)

        self.signature_provider = get_signature_provider(config)
        self.add_hash = config.get("addCertHash", True)
        self.just_header = config.get("justHeader", False)

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Signature provider is missing.
        """
        if not self.signature_provider:
            raise SPSDKError("Signature provider is missing")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual MBI fields.

        This method extracts the certificate block from the provided binary data
        and resets the signature provider to prepare for further processing.

        :param data: Complete MBI binary image data in bytes format.
        """
        self.cert_block = CertBlockVx.parse(data[self.IMG_ISK_OFFSET :], self.family)
        self.signature_provider = None


class Mbi_MixinBca(Mbi_Mixin):
    """Master Boot Image BCA mixin class.

    This mixin provides Boot Configuration Area (BCA) functionality for Master Boot Images,
    handling BCA parsing, configuration loading, and validation operations.

    :cvar VALIDATION_SCHEMAS: List of validation schemas required for BCA operations.
    :cvar NEEDED_MEMBERS: Dictionary defining required member variables for the mixin.
    :cvar BCA_OFFSET: Memory offset where BCA data is located in the image.
    """

    VALIDATION_SCHEMAS: list[str] = ["bca"]
    NEEDED_MEMBERS: dict[str, Any] = {"bca": None}

    BCA_OFFSET = 0x3C0

    app: bytes
    bca: Optional[BCA]
    total_len: int

    def mix_len(self) -> int:
        """Get length of BCA.

        :return: Length of BCA in bytes, or 0 if BCA is not present.
        """
        return self.bca.SIZE if self.bca else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary and update BCA settings.

        The method loads default BCA configuration from the application and then
        updates it based on the provided configuration. It supports three formats:
        direct dictionary configuration, YAML sub-configuration, or binary file.

        :param config: Configuration object containing BCA settings in various formats.
        :raises SPSDKError: When BCA binary file has invalid size.
        :raises SPSDKTypeError: When configuration format is invalid.
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

        The method generates configuration data for the mixin, including BCA (Boot Configuration Area)
        settings if present. When BCA is configured, it writes the BCA configuration to a YAML file
        in the specified output folder.

        :param output_folder: Output folder to store configuration files.
        :return: Dictionary containing configuration data with file references.
        """
        config = {}
        if self.bca:
            bca_cfg = self.bca.get_config_yaml()
            filename = "bca.yaml"
            write_file(bca_cfg, os.path.join(output_folder, filename))
            config["bca"] = filename
        return config

    def mix_validate(self) -> None:
        """Validate the settings of the MBI image.

        This method performs validation checks on the image configuration,
        specifically verifying that the BCA (Boot Configuration Area) is properly
        formatted if present.

        :raises SPSDKError: Configuration of BCA is invalid.
        """
        if self.bca and not isinstance(self.bca, BCA):
            raise SPSDKError("Validation failed: BCA is invalid format")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual MBI fields.

        The method attempts to parse the Boot Configuration Area (BCA) from the provided
        binary data at the predefined offset. If parsing fails, the BCA field is set to None.

        :param data: Binary data containing the Master Boot Image to be parsed.
        :raises SPSDKError: When BCA parsing fails due to invalid or corrupted data.
        """
        try:
            self.bca = BCA.parse(data[self.BCA_OFFSET :], family=self.family)
        except SPSDKError:
            self.bca = None

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from BCA mixin.

        Creates validation schemas for Boot Configuration Array (BCA) settings that can be used
        in configuration files. The schemas support three input formats: nested dictionary,
        YAML file path, or binary file path.

        :param family: Family revision to get schemas for.
        :return: List containing validation schema dictionary for BCA configuration.
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
    """Master Boot Image FCF mixin class.

    This mixin class provides FCF (Flash Configuration Field) functionality for Master Boot Images,
    handling FCF data parsing, configuration loading, and validation. The FCF contains critical
    flash configuration settings that must be properly configured for device operation.

    :cvar VALIDATION_SCHEMAS: List of validation schemas used for FCF configuration.
    :cvar NEEDED_MEMBERS: Dictionary defining required FCF member attributes.
    :cvar FCF_OFFSET: Standard offset position for FCF data in flash memory.
    """

    VALIDATION_SCHEMAS: list[str] = ["fcf"]
    NEEDED_MEMBERS: dict[str, Any] = {"fcf": None}

    FCF_OFFSET = 0x400

    app: bytes
    fcf: Optional[FCF]
    total_len: int

    def mix_len(self) -> int:
        """Get length of FCF.

        :return: Length of FCF in bytes, or 0 if FCF is not present.
        """
        return self.fcf.SIZE if self.fcf else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method loads FCF (Flash Configuration Field) configuration from various sources:
        - Direct dictionary configuration
        - YAML configuration file
        - Binary FCF file
        First loads default FCF from application, then updates with provided configuration.

        :param config: Configuration object with FCF fields and search paths.
        :raises SPSDKError: Invalid FCF binary file size or configuration errors.
        :raises SPSDKTypeError: Type mismatch in configuration data.
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

        This method extracts the FCF (Flash Configuration Field) configuration,
        writes it to a YAML file in the specified output folder, and returns
        a configuration dictionary containing the filename reference.

        :param output_folder: Output folder path where the FCF YAML file will be stored.
        :return: Configuration dictionary with FCF filename reference.
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
        """Parse the binary data to individual fields.

        This method extracts and parses the FCF (Flash Configuration Field) from the
        provided binary data at the predefined offset.

        :param data: Final image binary data to be parsed.
        :raises SPSDKError: If FCF parsing fails or data is invalid.
        """
        self.fcf = FCF.parse(data[self.FCF_OFFSET :], family=self.family)

    @classmethod
    def mix_get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas from FCF mixin.

        This method constructs validation schemas for Flash Configuration Field (FCF) settings,
        supporting multiple input formats including nested dictionaries, YAML files, and binary files.

        :param family: Family revision to get schemas for.
        :return: List containing validation schema dictionary for FCF configuration.
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
    """Master Boot Image hardware key user mode enablement mixin.

    This mixin provides functionality for managing hardware key user mode settings
    in Master Boot Images, including configuration loading, validation, and binary
    parsing of hardware key enablement flags.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for this mixin.
    :cvar NEEDED_MEMBERS: Default values for required mixin members.
    """

    VALIDATION_SCHEMAS: list[str] = ["hw_key"]
    NEEDED_MEMBERS: dict[str, Any] = {"user_hw_key_enabled": False}

    user_hw_key_enabled: Optional[bool]
    ivt_table: Mbi_MixinIvt

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method loads hardware user mode keys enablement setting from the provided
        configuration dictionary.

        :param config: Dictionary with configuration fields.
        """
        self.user_hw_key_enabled = config.get("enableHwUserModeKeys", False)

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :return: Dictionary containing mixin configuration with hardware user mode keys setting.
        """
        config: dict[str, Any] = {}
        config["enableHwUserModeKeys"] = bool(self.user_hw_key_enabled)
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        :raises SPSDKError: Invalid HW key enabled member type.
        """
        if not isinstance(self.user_hw_key_enabled, bool):
            raise SPSDKError("User HW Key is not Boolean type.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary to individual fields.

        This method extracts hardware key enablement information from the provided
        binary data using the IVT table.

        :param data: Final Image in bytes.
        """
        self.user_hw_key_enabled = self.ivt_table.get_hw_key_enabled(data)


class Mbi_MixinKeyStore(Mbi_Mixin):
    """Master Boot Image KeyStore mixin class.

    This mixin provides KeyStore functionality for Master Boot Image operations,
    handling keystore file loading, configuration management, and validation
    for secure boot processes.

    :cvar VALIDATION_SCHEMAS: List of validation schemas used for keystore validation.
    :cvar NEEDED_MEMBERS: Dictionary defining required member variables for the mixin.
    :cvar COUNT_IN_LEGACY_CERT_BLOCK_LEN: Flag indicating if keystore counts in legacy
        certificate block length calculation.
    """

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

        The method calculates the length of the exported KeyStore data if a KeyStore
        is present and configured with KEYSTORE source type, otherwise returns 0.

        :return: Length of KeyStore block in bytes, or 0 if no KeyStore or different source type.
        """
        return (
            len(self.key_store.export())
            if self.key_store and self.key_store.key_source == KeySourceType.KEYSTORE
            else 0
        )

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        This method initializes the key store from the configuration if a keyStoreFile
        is specified in the config.

        :param config: Configuration object containing setup fields including optional keyStoreFile.
        :raises SPSDKError: If the keystore file cannot be loaded or is invalid.
        """
        self.key_store = None
        if "keyStoreFile" in config:
            self.key_store = KeyStore(
                KeySourceType.KEYSTORE, load_binary(config.get_input_file_name("keyStoreFile"))
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        The method exports key store data to a binary file in the specified output folder
        and returns configuration dictionary with the file reference.

        :param output_folder: Output folder to store the key store file.
        :return: Configuration dictionary containing keyStoreFile path or None if no key store exists.
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

        :raises SPSDKError: When KeyStore is used but HMAC key is not provided.
        """
        if self.key_store and not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("When is used KeyStore, the HMAC key MUST by also used.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and initialize individual MBI fields.

        The method examines the binary data to determine if a key store is present
        and initializes the key_store attribute accordingly. If a key store is found,
        it extracts the key store data from the appropriate offset in the binary.

        :param data: Complete MBI binary image data to be parsed.
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
    """Master Boot Image HMAC mixin class.

    This mixin provides HMAC (Hash-based Message Authentication Code) functionality for Master Boot
    Images, enabling secure authentication and integrity verification of boot images.

    :cvar VALIDATION_SCHEMAS: List of validation schemas supported by this mixin.
    :cvar HMAC_OFFSET: Offset in the image where the HMAC table is located.
    :cvar HMAC_SIZE: Size of HMAC table in bytes.
    """

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
        """Get HMAC key in bytes.

        :return: HMAC key as bytes if available, None otherwise.
        """
        return self._hmac_key

    @hmac_key.setter
    def hmac_key(self, hmac_key: Optional[Union[bytes, str]]) -> None:
        """Set HMAC key for authentication.

        Converts string representation of HMAC key to bytes if needed, or stores the provided bytes directly.

        :param hmac_key: HMAC key as hexadecimal string or raw bytes, None to clear the key.
        """
        self._hmac_key = bytes.fromhex(hmac_key) if isinstance(hmac_key, str) else hmac_key

    def mix_len(self) -> int:
        """Get length of HMAC block.

        The method returns the HMAC block size if an HMAC key is present, otherwise returns 0.

        :return: Length of HMAC block in bytes, or 0 if no HMAC key is configured.
        """
        return self.HMAC_SIZE if self.hmac_key else 0

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        This method initializes the HMAC key from the configuration. If an output image
        encryption key file is specified in the config, it loads the symmetric key with
        the expected HMAC size.

        :param config: Configuration object containing fields for MBI setup.
        :raises SPSDKError: If the encryption key file cannot be loaded or has invalid size.
        """
        self.hmac_key = None
        if "outputImageEncryptionKeyFile" in config:
            self.hmac_key = config.load_symmetric_key(
                "outputImageEncryptionKeyFile", expected_size=self.HMAC_SIZE
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :return: Dictionary containing mixin configuration with encryption key information.
        """
        config: dict[str, Any] = {}
        config["outputImageEncryptionKeyFile"] = "The HMAC key cannot be restored"
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        Validates that the HMAC key, if present, has the correct length of 32 bytes.

        :raises SPSDKError: Invalid HMAC key length.
        """
        if self.hmac_key:
            length = len(self.hmac_key)
            if length != self._HMAC_KEY_LENGTH:
                raise SPSDKError(f"Invalid size of HMAC key 32 != {length}.")

    def compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC hash for the provided data.

        The method uses the stored HMAC key to generate a hash-based message authentication code.
        If no HMAC key is available, returns empty bytes.

        :param data: Data to be hashed.
        :raises SPSDKError: Invalid size of HMAC result.
        :return: Result HMAC hash of input data, or empty bytes if no HMAC key is set.
        """
        if not self.hmac_key:
            return bytes()

        key = KeyStore.derive_hmac_key(self.hmac_key)
        result = hmac(key, data)
        if len(result) != self.HMAC_SIZE:
            raise SPSDKError("Invalid size of HMAC result.")
        return result

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to individual fields.

        The method extracts and processes HMAC key from DEK if available.

        :param data: Final Image in bytes.
        """
        if self.dek:
            self.hmac_key = load_hex_string(source=self.dek, expected_size=self._HMAC_KEY_LENGTH)


class Mbi_MixinHmacMandatory(Mbi_MixinHmac):
    """Master Boot Image HMAC mixin with mandatory key validation.

    This mixin extends the base HMAC functionality by enforcing that an HMAC key
    must be present during validation. It provides stricter validation rules
    for scenarios where HMAC authentication is required rather than optional.

    :cvar VALIDATION_SCHEMAS: List of validation schema names for mandatory HMAC.
    """

    VALIDATION_SCHEMAS: list[str] = ["hmac_mandatory"]

    def mix_validate(self) -> None:
        """Validate the setting of image.

        Checks if HMAC key exists and performs additional validation through parent class.

        :raises SPSDKError: If HMAC key is missing or other validation errors occur.
        """
        if not self.hmac_key:  # pylint: disable=no-member
            raise SPSDKError("HMAC Key MUST exists.")
        super().mix_validate()


class Mbi_MixinCtrInitVector(Mbi_Mixin):
    """Master Boot Image mixin for encryption counter initialization vector management.

    This mixin provides functionality for handling counter initialization vectors
    used in encryption operations within Master Boot Images. It manages the
    generation, validation, and configuration of counter initial vectors with
    support for both user-specified and randomly generated values.

    :cvar VALIDATION_SCHEMAS: List of validation schemas for this mixin.
    :cvar NEEDED_MEMBERS: Required member variables with default values.
    :cvar PRE_PARSED: List of pre-parsed configuration elements.
    """

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
        """Get counter initialization vector.

        :return: Counter initialization vector bytes if set, None otherwise.
        """
        return self._ctr_init_vector

    @ctr_init_vector.setter
    def ctr_init_vector(self, ctr_iv: Optional[bytes]) -> None:
        """Set Counter initialization vector for encryption.

        If no vector is provided, a random vector of appropriate size is generated
        and used instead.

        :param ctr_iv: Counter Initial Vector bytes, if None random vector is generated.
        """
        if ctr_iv and isinstance(ctr_iv, bytes):
            self._ctr_init_vector = ctr_iv
        else:
            self._ctr_init_vector = random_bytes(self._CTR_INIT_VECTOR_SIZE)

    def mix_load_from_config(self, config: Config) -> None:
        """Load configuration from dictionary.

        The method initializes the CTR initialization vector from the provided configuration.
        If 'CtrInitVector' is present in config, it loads the symmetric key with the required size.

        :param config: Configuration object containing fields for MBI setup.
        :raises SPSDKError: If the CTR initialization vector cannot be loaded properly.
        """
        self.ctr_init_vector = None

        if "CtrInitVector" in config:
            self.ctr_init_vector = config.load_symmetric_key(
                "CtrInitVector", self._CTR_INIT_VECTOR_SIZE
            )

    def mix_get_config(self, output_folder: str) -> dict[str, Any]:
        """Get the configuration of the mixin.

        :param output_folder: Output folder to store files.
        :raises AssertionError: When CTR initialization vector is not bytes type.
        :return: Dictionary containing mixin configuration with CTR initialization vector.
        """
        config: dict[str, Any] = {}
        self.mix_validate()
        assert isinstance(self.ctr_init_vector, bytes)
        config["CtrInitVector"] = self.ctr_init_vector.hex()
        return config

    def mix_validate(self) -> None:
        """Validate the setting of image.

        The method validates that the counter initialization vector exists and has the correct size
        for encryption counter operations.

        :raises SPSDKError: Initial vector for encryption counter doesn't exist or has invalid size.
        """
        if not self.ctr_init_vector:
            raise SPSDKError("Initial vector for encryption counter MUST exist.")
        if len(self.ctr_init_vector) != self._CTR_INIT_VECTOR_SIZE:
            raise SPSDKError("Invalid size of Initial vector for encryption counter.")

    def mix_parse(self, data: bytes) -> None:
        """Parse the binary data to extract and populate individual MBI fields.

        This method extracts the CTR initialization vector from the binary data by calculating
        its offset based on certificate block, HMAC, and key store positions within the image.

        :param data: Complete MBI binary image data to parse.
        :raises AssertionError: If cert_block is not an instance of CertBlockV1.
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
    """MBI Export Mixin for Master Boot Image processing.

    This mixin class provides the core functionality for exporting and processing Master Boot Images
    (MBI) across different NXP MCU families. It defines the standard workflow for image creation
    including data collection, encryption, signing, and disassembly operations.

    :cvar family: Target MCU family and revision for the MBI operations.
    """

    family: FamilyRevision

    def collect_data(self) -> BinaryImage:  # pylint: disable=no-self-use
        """Collect basic data to create image.

        This method creates a basic binary image with a general name as a foundation
        for image creation in the MBI (Master Boot Image) context.

        :return: Collected raw binary image with default configuration.
        """
        return BinaryImage(name="General")

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts from image.

        This method parses the provided image bytes and extracts its constituent
        components for further processing or analysis.

        :param image: Raw image data to be disassembled into individual parts.
        """

    def encrypt(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Encrypt image if needed.

        This method provides a base implementation for image encryption. In the base class,
        it returns the image unchanged. Subclasses should override this method to implement
        actual encryption functionality.

        :param image: Input raw image to encrypt.
        :param revert: Revert the operation if possible.
        :return: Encrypted image or original image if no encryption is applied.
        """
        return image

    def post_encrypt(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Perform optional post-encryption image modifications.

        This method allows for additional processing of the encrypted image data
        after the main encryption operation has been completed. By default, it
        returns the image unchanged, but can be overridden in subclasses.

        :param image: The encrypted binary image to be processed.
        :param revert: If True, attempt to revert previous post-encryption operations.
        :return: The processed binary image, potentially modified.
        """
        return image

    def sign(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Sign image using signature or CRC verification.

        This method provides a unified interface for signing binary images across different
        MBI (Master Boot Image) implementations. The actual signing behavior depends on the
        specific MBI type and configuration.

        :param image: Binary image data to be signed.
        :param revert: If True, attempts to revert the signing operation when supported.
        :return: Binary image with applied signature or CRC, or unchanged if no signing required.
        """
        return image

    def finalize(
        self, image: BinaryImage, revert: bool = False
    ) -> BinaryImage:  # pylint: disable=no-self-use
        """Finalize the image for export.

        This method performs final processing steps on the image before export,
        which may include adding HMAC authentication, KeyStore data, or other
        security-related components.

        :param image: Input binary image to be finalized.
        :param revert: Flag to revert the finalization operation if supported.
        :return: Finalized binary image ready for export.
        """
        return image


class Mbi_ExportMixinApp(Mbi_ExportMixin):
    """MBI Export Mixin for application data handling.

    This mixin class provides functionality for collecting and processing application data
    in Master Boot Image (MBI) format, including support for Boot Configuration Area (BCA)
    and Flash Configuration Field (FCF) components.

    :cvar APP_BLOCK_NAME: Name identifier for the application block.
    :cvar APP_IMAGE_NAME: Name identifier for the application image.
    """

    APP_BLOCK_NAME = "Application Block"
    APP_IMAGE_NAME = "Application"

    app: Optional[bytes]
    clean_ivt: Callable[[bytes], bytes]
    ivt_table: Mbi_MixinIvt
    app_table: MultipleImageTable
    disassembly_app_data: Callable[[bytes], bytes]
    bca: Optional[BCA]
    fcf: Optional[FCF]
    BCA_OFFSET: int
    FCF_OFFSET: int
    total_len: int

    def collect_data(self) -> BinaryImage:
        """Collect application data including update of BCA and FCF.

        The method processes application binary data and integrates Boot Configuration Area (BCA)
        and Flash Configuration Field (FCF) if present. It handles IVT table updates and creates
        a structured binary image with proper component separation.

        :raises SPSDKError: Application data is missing.
        :return: Binary image with updated BCA and FCF components properly positioned.
        """
        if not self.app:
            raise SPSDKError("Application data is missing")

        ret = BinaryImage(name=Mbi_ExportMixinApp.APP_BLOCK_NAME)

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

            ret.append_image(
                BinaryImage(name=Mbi_ExportMixinApp.APP_IMAGE_NAME, binary=binary[offset:])
            )
        else:
            ret.append_image(BinaryImage(name=Mbi_ExportMixinApp.APP_IMAGE_NAME, binary=binary))

        if hasattr(self, "app_table") and self.app_table:
            ret.append_image(
                BinaryImage(name="Relocation Table", binary=self.app_table.export(ret.size))
            )

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image into individual parts.

        The method extracts application data and cleans the IVT (Interrupt Vector Table)
        if the respective methods are available in the class implementation.

        :param image: Raw binary image data to be disassembled.
        """
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)

        self.app = self.clean_ivt(image) if hasattr(self, "clean_ivt") else image


class Mbi_ExportMixinAppTrustZone(Mbi_ExportMixinApp):
    """MBI Export Mixin for application data with TrustZone support.

    This mixin extends the basic application export functionality to handle
    TrustZone configuration and data processing for NXP MCU images.

    :cvar TRUST_ZONE_IMAGE_NAME: Default name for TrustZone preset data section.
    """

    trust_zone: Optional[TrustZone]
    tz_type: TrustZoneType
    family: FamilyRevision
    TRUST_ZONE_IMAGE_NAME = "TrustZone Preset data"

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        The method extends the parent's collect_data functionality by appending custom TrustZone
        data when configured. If TrustZone is set to CUSTOM type, the exported TrustZone binary
        is added to the collected image data.

        :return: Image with updated IVT and added TrustZone data if applicable.
        """
        ret = super().collect_data()
        if self.trust_zone:
            if self.tz_type == TrustZoneType.CUSTOM:
                ret.append_image(
                    BinaryImage(
                        name=Mbi_ExportMixinAppTrustZone.TRUST_ZONE_IMAGE_NAME,
                        binary=self.trust_zone.export(),
                    )
                )
        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image to individual parts and extract TrustZone configuration.

        The method analyzes the image to determine TrustZone type and extracts the TrustZone
        configuration if present. It handles enabled, custom, and disabled TrustZone types
        appropriately before calling the parent disassemble method.

        :param image: Binary image data to be disassembled.
        """
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        elif tz_type == TrustZoneType.CUSTOM:
            tz_len = len(TrustZone(self.family))
            self.trust_zone = TrustZone.parse(image[-tz_len:], self.family)
            image = image[:-tz_len]
        super().disassemble_image(image)


class Mbi_ExportMixinAppTrustZoneV2(Mbi_ExportMixinAppTrustZone):
    """Export Mixin for handling application data with TrustZone version 2 support.

    This class extends the base TrustZone mixin to specifically handle TrustZone V2
    format, providing enhanced data collection and image disassembly capabilities
    with proper 4-byte alignment requirements for TrustZone V2 operations.
    """

    # Override the type annotation for trust_zone
    trust_zone: Optional[TrustZoneV2]  # type: ignore

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone configuration into a binary image.

        This method gathers the application and TrustZone data, ensures proper 4-byte alignment
        for TrustZone V2, and updates the IVT table with correct offsets when TrustZone is
        enabled. The TrustZone offset is stored in the application's CRC location.

        :raises SPSDKError: When TrustZone image is not found but trust_zone is enabled.
        :raises SPSDKError: When Application image is not found but trust_zone is enabled.
        :return: Binary image containing collected application and TrustZone data.
        """
        ret = super().collect_data()
        ret.alignment = 4  # Ensure 4-byte alignment for TrustZone V2
        if self.trust_zone:
            tz_image = ret.find_sub_image(Mbi_ExportMixinAppTrustZone.TRUST_ZONE_IMAGE_NAME)
            if not tz_image or not tz_image.binary:
                raise SPSDKError("TrustZone image not found")
            app_image = ret.find_sub_image(Mbi_ExportMixinApp.APP_IMAGE_NAME)
            if not app_image or not app_image.binary:
                raise SPSDKError("Application image not found")
            app_image.binary = self.ivt_table.update_ivt(
                app_image.binary,
                total_len=len(app_image.binary) + len(tz_image.binary),
                # What was previously the CRC location is now offset to TZ Data
                crc_val_cert_offset=len(app_image.binary),
            )

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image into individual parts and extract TrustZone configuration.

        The method parses the image to identify TrustZone type from IVT table and extracts
        TrustZone block if present. For custom TrustZone type, it locates and parses the
        TrustZone block, then continues with standard image disassembly.

        :param image: Binary image data to be disassembled.
        :raises SPSDKError: Cannot find TrustZone block when custom TrustZone type is detected.
        """
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.CUSTOM:
            tz_offset = TrustZoneV2.find_trustzone_block_offset(image)
            if tz_offset is None:
                raise SPSDKError("Cannot find TrustZone block")

            self.trust_zone = TrustZoneV2.parse(image[tz_offset:], self.family)
            image = image[:tz_offset]

        Mbi_ExportMixinApp.disassemble_image(self, image)


class Mbi_ExportMixinAppTrustZoneCertBlock(Mbi_ExportMixin):
    """MBI Export Mixin for application data with TrustZone and certification block support.

    This mixin class handles the export and assembly of Master Boot Image (MBI) components
    including application data, TrustZone settings, and certification blocks. It manages
    the collection and organization of these components into a complete binary image with
    proper IVT updates and alignment requirements.
    """

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

        The method assembles the complete Master Boot Image by combining the application data,
        certificate block, optional relocation table, and TrustZone settings. It updates the
        IVT (Interrupt Vector Table) with proper addresses and lengths before creating the final
        binary image structure.

        :raises SPSDKError: Application data or Certificate block is missing.
        :raises SPSDKError: Unsupported certificate block type (only CertBlockV1 supported).
        :return: Complete binary image with updated IVT and all required components.
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
        """Disassemble image into individual components.

        Parses the input image and extracts its components including TrustZone configuration,
        certificate blocks, and application data. Updates the object's trust_zone and app
        attributes based on the parsed data.

        :param image: Binary image data to be disassembled.
        """
        # Re -parse TZ if needed
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        if tz_type == TrustZoneType.CUSTOM:
            tz_len = len(TrustZone(self.family))
            self.trust_zone = TrustZone.parse(data=image[-tz_len:], family=self.family)
            image = image[:-tz_len]
        image = image[: -self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)


class Mbi_ExportMixinAppTrustZoneCertBlockV2(Mbi_ExportMixin):
    """Export Mixin for MBI images with application data, TrustZone and Certification Block V21.

    This mixin provides functionality to collect and disassemble MBI (Master Boot Image)
    components including application data, TrustZone configuration, and Certification
    Block V21. It handles the assembly of these components into a complete binary image
    with proper IVT (Interrupt Vector Table) updates and supports disassembly of
    existing images back into individual components.
    """

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

        The method combines application data with certification block and optional trust zone data
        into a single binary image. The IVT (Interrupt Vector Table) is updated with proper
        lengths and addresses before creating the final image structure.

        :raises SPSDKError: When either application data or certification block is missing.
        :return: Binary image containing updated IVT, application data, certification block,
            and optional trust zone data.
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
        """Disassemble image into individual parts.

        The method extracts application data from the image by removing certificate block
        if present and cleaning the IVT table. It also processes application data through
        disassembly if the method is available.

        :param image: Binary image data to be disassembled.
        :raises SPSDKError: If image disassembly fails or image format is invalid.
        """
        if self.cert_block:
            image = image[: self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)


class Mbi_ExportMixinAppCertBlockManifest(Mbi_ExportMixin):
    """MBI Export Mixin for application data with certification block and manifest.

    This mixin handles the collection and assembly of Master Boot Image components including
    application data, certification blocks, and manifests. It provides functionality to
    validate component integrity, update IVT tables, and export complete binary images
    with proper structure for NXP MCU boot processes.
    """

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

        The method validates that all required components (application data, certification block,
        and manifest) are present, checks manifest length validity, and verifies hash algorithm
        consistency between manifest and certificate block. It then creates a binary image with
        updated IVT, application data, certification block, and manifest. For CRC manifests,
        the CRC is computed and updated.

        :raises SPSDKError: When application data, certification block, or manifest is missing.
        :raises SPSDKError: When manifest length is invalid.
        :return: Binary image with updated IVT and added Certification Block with Manifest.
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
        """Disassemble image into individual parts.

        The method extracts application data from the image by removing certificate block
        if present and cleaning the IVT table. It also processes application data through
        disassembly if the method is available.

        :param image: Binary image data to be disassembled.
        :raises SPSDKError: If image disassembly fails due to invalid format.
        """
        if self.cert_block:
            image = image[: self.ivt_table.get_cert_block_offset_from_data(image)]
        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)

    def finalize(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Finalize the image for export by adding manifest hash.

        The method adds a calculated hash to the image based on the manifest's digest
        hash algorithm when the digest present flag is set. The operation can be
        reverted by removing the hash from the end of the image.

        :param image: Input binary image to be finalized.
        :param revert: If True, removes the hash from the image instead of adding it.
        :return: Finalized binary image with hash appended or removed.
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
    """MBI Export Mixin for CRC-based signing operations.

    This mixin class provides CRC-based signing functionality for Master Boot Image (MBI) export
    operations. It implements MPEG2 CRC32 calculation over image data and updates the IVT table
    with the computed CRC value for image integrity verification.

    :cvar IVT_CRC_CERTIFICATE_OFFSET: Offset in IVT table where CRC value is stored.
    :cvar update_crc_val_cert_offset: Callable to update CRC value at certificate offset.
    """

    IVT_CRC_CERTIFICATE_OFFSET: int
    update_crc_val_cert_offset: Callable[[bytes, int], bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Sign binary image with CRC32 checksum.

        Calculates CRC32 using MPEG2 specification over the entire image data except
        for the 4-byte CRC field at the certificate offset in the IVT table, then
        updates the image with the calculated CRC value.

        :param image: Input binary image to be signed with CRC.
        :param revert: If True, returns original image without CRC calculation.
        :return: Binary image with updated CRC32 checksum in IVT table.
        :raises SPSDKError: Invalid CRC offset in the image.
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


class Mbi_ExportMixinCrcSignEnd(Mbi_ExportMixin):
    """MBI Export Mixin for CRC signature handling at image end.

    This mixin provides functionality to sign Master Boot Images by calculating
    and appending a CRC32 checksum at the end of the image data. It handles both
    signing operations and revert operations for CRC-based image authentication.
    """

    ivt_table: Mbi_MixinIvt

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Sign binary image with CRC32 checksum.

        Calculates CRC32-MPEG checksum for the binary image data and appends it to the image.
        Updates the IVT table total length to include the CRC. Can also revert the signing
        process by removing the last 4 bytes (CRC) from the image.

        :param image: Binary image to be signed with CRC checksum.
        :param revert: If True, removes the CRC from image instead of adding it.
        :raises SPSDKError: Application image not found in the binary image.
        :return: Binary image with appended CRC checksum or with CRC removed if revert is True.
        """
        if revert and image.binary:
            image.binary = image.binary[:-4]
            return image

        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        image.alignment = 4  # Ensure 4-byte alignment
        total_data = image.export()

        app_image = image.find_sub_image(Mbi_ExportMixinApp.APP_IMAGE_NAME)
        if not app_image or not app_image.binary:
            raise SPSDKError("Application image not found")
        app_image.binary = self.ivt_table.update_total_length(
            app_image.binary, total_length=len(total_data) + 4
        )
        data_to_sign = image.export()
        crc = crc_obj.calculate(data_to_sign)

        image.append_image(
            BinaryImage(
                name=Mbi_ExportMixinAppTzCrcAhab.CRC_IMAGE_NAME, binary=struct.pack("<I", crc)
            )
        )
        return image


class Mbi_ExportMixinRsaSign(Mbi_ExportMixin):
    """MBI Export Mixin for RSA signature operations.

    This mixin provides RSA signature functionality for Master Boot Image (MBI) export operations,
    including signature generation and verification capabilities with support for different
    certificate block versions.
    """

    signature_provider: Optional[SignatureProvider]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Calculate RSA signature and return updated image with signature.

        The method either adds an RSA signature to the end of the image or reverts
        the operation by removing the signature from the image.

        :param image: Input raw image to be signed or unsigned.
        :param revert: Revert the operation by removing signature if True.
        :raises SPSDKError: Certificate block or image is missing for revert operation.
        :raises SPSDKError: Only CertBlockV1 is supported for revert operation.
        :raises SPSDKError: Signature provider is missing for signing operation.
        :return: Image with RSA signature appended or signature removed.
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
    """Export Mixin for ECC signature operations in MBI images.

    This mixin provides functionality to add and remove ECC signatures from MBI
    (Master Boot Image) binary images. It handles the signature calculation process
    using configurable signature providers and certificate blocks, supporting both
    signing operations and signature reversion for testing purposes.
    """

    signature_provider: Optional[SignatureProvider]
    cert_block: Optional[Union[CertBlockV21, CertBlockV1]]
    data_to_sign: Optional[bytes]

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Calculate ECC signature and return updated image with signature.

        The method either adds an ECC signature to the end of the image or reverts
        the operation by removing the signature from the image.

        :param image: Input raw binary image to be signed or unsigned.
        :param revert: If True, removes signature from image; if False, adds signature.
        :raises SPSDKError: Certificate block or image is missing for revert operation.
        :raises SPSDKError: Unsupported certificate block type (only CertBlockV21 supported).
        :raises SPSDKError: Signature provider is missing for signing operation.
        :return: Image with ECC signature appended or signature removed.
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
    """MBI Export Mixin for HMAC and KeyStore finalization.

    This mixin provides functionality to finalize Master Boot Image (MBI) exports by computing
    and embedding HMAC authentication values and optionally including KeyStore data. It handles
    both standard finalization and revert operations, managing binary image structure including
    sub-image splitting when HMAC data needs to be inserted at specific offsets.
    """

    compute_hmac: Callable[[bytes], bytes]
    HMAC_OFFSET: int
    HMAC_SIZE: int
    key_store: Optional[KeyStore]
    ivt_table: Mbi_MixinIvt

    def finalize(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Finalize the image for export by adding HMAC and optionally KeyStore.

        The method processes the input image to add HMAC authentication and optional KeyStore data.
        When reverting, it removes previously added HMAC and KeyStore sections. During normal operation,
        it computes HMAC for the image data and inserts it at the designated offset, splitting existing
        sub-images if necessary.

        :param image: Input binary image to be finalized.
        :param revert: If True, removes HMAC and KeyStore from the image instead of adding them.
        :raises SPSDKError: Invalid image structure when splitting sub-images.
        :return: Finalized binary image with HMAC and optional KeyStore added or removed.
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
    """MBI Export Mixin for application data with BCA and FCF components.

    This mixin class handles the export functionality for Master Boot Image (MBI) files that contain
    application data along with Boot Configuration Area (BCA) and Flash Configuration Field (FCF)
    components. It provides image layout management, validation, and data assembly for Vx chip
    boot images with predefined memory offsets and structure.

    :cvar IMG_DIGEST_OFFSET: Offset for image digest in boot image layout (0x360).
    :cvar IMG_SIGNATURE_OFFSET: Offset for image signature in boot image layout (0x380).
    :cvar IMG_BCA_OFFSET: Offset for Boot Configuration Area in boot image layout (0x3C0).
    :cvar IMG_FCF_OFFSET: Offset for Flash Configuration Field in boot image layout (0x400).
    :cvar IMG_ISK_OFFSET: Offset for Image Signing Key in boot image layout (0x410).
    :cvar IMG_ISK_HASH_OFFSET: Offset for ISK hash in boot image layout (0x4A0).
    :cvar IMG_WPC_ROOT_CA_CERT_HASH_OFFSET: Offset for WPC root CA certificate hash (0x5E0).
    :cvar IMG_WPC_MFG_CA_CERT_OFFSET: Offset for WPC manufacturing CA certificate (0x600).
    :cvar IMG_DUK_BLOCK_OFFSET: Offset for Device Unique Key block in boot image layout (0x800).
    :cvar IMG_DATA_START: Starting offset for application data in boot image layout (0xC00).
    """

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
        """Calculate the total image size used in Boot Configuration Area (BCA).

        The method computes the image size by combining the BCA size (calculated from
        FCF and BCA offsets) with the application length (from data start to end) and
        adding the digest offset.

        :return: Total image size in bytes including BCA, application data and digest.
        """
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

        :raises SPSDKError: If the lifecycle value is not supported or if any other FCF
            register has been modified from its reset value.
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

        The method assembles a complete binary image by extracting and organizing various
        components from the application data including vector table, image hash, ECC signature,
        Boot Config Area, Flash Config Field, certificates, and application image. If BCA or
        FCF objects are available, their exported data is used; otherwise, the original
        binary data is preserved.

        :raises SPSDKError: Application data is missing.
        :return: Binary Image with updated BCA (if present) and FCF containing all
                 application components.
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
        """Disassemble image into individual parts.

        The method extracts and stores the application data from the provided image bytes.

        :param image: Raw image data to be disassembled into components.
        """
        self.app = image


class Mbi_ExportMixinCrcSignBca(Mbi_ExportMixin):
    """MBI Export Mixin for CRC-based signing in Boot Configuration Area.

    This mixin provides functionality to sign Master Boot Images using CRC32 checksum
    calculation and embedding the signature information into the Boot Configuration Area (BCA).
    The mixin calculates CRC32-MPEG checksum of the application data and updates the BCA
    registers with CRC parameters including start address, byte count, and expected value.
    """

    app: bytes
    bca: BCA
    image_size: int
    IMG_DATA_START: int

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Calculate CRC32 for image data and update Boot Config Area.

        The method computes CRC32-MPEG checksum for the image data starting from IMG_DATA_START
        offset and updates the Boot Config Area registers with CRC parameters and expected value.

        :param image: Input binary image to be signed with CRC.
        :param revert: If True, returns original image without CRC calculation.
        :raises SPSDKError: When Boot Config Area is not initialized.
        :return: Binary image with updated Boot Config Area containing CRC information.
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
    """MBI Export Mixin for ECC signature handling.

    This mixin provides ECC signature functionality for Master Boot Image (MBI) export operations.
    It handles the complete signing process including image digest calculation, ECC signature
    generation, and certificate block integration for secure boot images.

    :cvar IMG_DIGEST_OFFSET: Offset position for image digest in the binary layout.
    :cvar IMG_BCA_OFFSET: Offset position for Boot Configuration Area in the binary layout.
    :cvar IMG_FCF_OFFSET: Offset position for Flash Configuration Field in the binary layout.
    :cvar IMG_DATA_START: Starting position of image data in the binary layout.
    """

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
        """Calculate ECC signature and digest for the image.

        The method updates the Boot Config Area with image size, calculates hash from
        specific image sections, generates ECC signature, and enriches the image with
        signature data and certificates.

        :param image: Input raw binary image to be signed.
        :param revert: If True, returns original image without signing.
        :return: Image enriched by ECC signature, SHA256 digest and certificates.
        :raises SPSDKError: When signature provider is missing or unable to get signature.
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


class Mbi_ExportMixinAppTzCrcAhab(Mbi_ExportMixin):
    """MBI export mixin for application data with TrustZone, CRC checksum and AHAB container.

    This mixin handles the collection and organization of Master Boot Image (MBI) data that includes
    application binary, optional TrustZone configuration, CRC-32 checksum validation, and AHAB
    (Advanced High Assurance Boot) container for secure boot operations. It manages the proper
    layout and offset calculations for all components within the final boot image.

    :cvar CRC_IMAGE_NAME: Name identifier for CRC checksum section in the image.
    :cvar AHAB_IMAGE_NAME: Name identifier for AHAB container section in the image.
    """

    app: bytes
    trust_zone: TrustZoneV2
    tz_type: TrustZoneType
    ivt_table: Mbi_MixinIvt
    total_len: int
    image_version: int
    ahab: AHABContainerV2
    crc_check_record: Optional[ImageArrayEntryV2]
    CRC_IMAGE_NAME = "CRC-32 MPEG checksum"
    AHAB_IMAGE_NAME = "AHAB Container"

    def collect_data(self) -> BinaryImage:
        """Collect application data and TrustZone including update IVT.

        This method assembles a complete MBI (Master Boot Image) by collecting application data,
        TrustZone configuration, CRC records, and AHAB container. It updates the IVT table with
        proper offsets and configures the AHAB image array entries with relative offsets to the
        AHAB container.

        :return: Binary image containing the complete MBI structure with all components properly
            aligned and configured.
        """
        ret = BinaryImage("MBI - App/TZ/CRC/AHAB", alignment=4)

        # Get application data
        app_block = Mbi_ExportMixinApp.collect_data(self)  # type: ignore
        ret.append_image(app_block)

        # Get app image and its offset
        app_image = app_block.find_sub_image(Mbi_ExportMixinApp.APP_IMAGE_NAME)
        app_offset = app_image.absolute_address

        # Initial offset after application
        current_offset = self.ahab.image_array[0].image_size

        # TrustZone section (if needed)
        tz_offset = None
        if self.trust_zone and self.tz_type == TrustZoneType.CUSTOM:
            tz_offset = current_offset
            ret.append_image(
                BinaryImage(
                    name=Mbi_ExportMixinAppTrustZone.TRUST_ZONE_IMAGE_NAME,
                    binary=self.trust_zone.export(),
                    offset=tz_offset,
                )
            )
            current_offset += self.ahab.image_array[1].image_size

        # CRC section (if needed)
        crc_offset = None
        if self.crc_check_record:
            crc_offset = current_offset
            ret.append_image(
                BinaryImage(Mbi_ExportMixinAppTzCrcAhab.CRC_IMAGE_NAME, size=4, offset=crc_offset)
            )
            current_offset += 4

        # AHAB container section
        ahab_offset = current_offset
        ret.append_image(
            BinaryImage(
                Mbi_ExportMixinAppTzCrcAhab.AHAB_IMAGE_NAME, size=len(self.ahab), offset=ahab_offset
            )
        )

        # Update IVT with AHAB container address
        app_image.binary = self.ivt_table.update_ivt(
            app_data=app_image.export(),
            total_len=self.total_len,
            crc_val_cert_offset=ahab_offset,
        )

        if hasattr(self, "image_version"):
            self.ahab.sw_version = self.image_version

        # Now update all the AHAB image array entries with the relative offsets
        # Note: offsets are relative to AHAB container, so they'll be negative values
        self.ahab.image_array[0].image = app_image.binary
        self.ahab.image_array[0].image_offset = app_offset - ahab_offset

        if tz_offset is not None:
            self.ahab.image_array[1].image = self.trust_zone.export()
            self.ahab.image_array[1].image_offset = tz_offset - ahab_offset

        if crc_offset is not None:
            crc_index = 1 if tz_offset is None else 2
            self.ahab.image_array[crc_index].image_offset = crc_offset - ahab_offset

        for img_entry in self.ahab.image_array:
            img_entry.image_hash = None
            img_entry.update_fields()

        return ret

    def disassemble_image(self, image: bytes) -> None:  # pylint: disable=no-self-use
        """Disassemble image into individual components.

        This method parses the provided image and extracts its constituent parts
        using both AHAB export functionality and TrustZone v2 mixing capabilities.

        :param image: Binary image data to be disassembled.
        """
        Mbi_ExportMixinApp.disassemble_image(self, self.ahab.image_array[0].image)  # type: ignore
        Mbi_MixinTrustZoneV2.mix_parse(self, image)  # type: ignore

    def sign(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Sign the image with CRC calculation and AHAB signature.

        Performs CRC32-MPEG calculation over the image data (excluding the CRC block itself)
        and updates the AHAB (Advanced High Assurance Boot) container with proper signatures
        and hash values. The method also logs SRK (Super Root Key) hash information for
        verification purposes.

        :param image: Input binary image to be signed.
        :param revert: If True, returns the original image without modifications.
        :return: Signed binary image with updated CRC and AHAB signature block.
        """
        if revert:
            return image

        if self.crc_check_record:
            # ---------  Compute CRC field  -------------
            input_image = image.export()
            # calculate CRC using MPEG2 specification over all of data (app and trustzone)
            # except for 4 bytes at CRC_BLOCK_OFFSET
            crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
            crc_image = image.find_sub_image(Mbi_ExportMixinAppTzCrcAhab.CRC_IMAGE_NAME)
            crc_offset = crc_image.absolute_address
            logger.debug(f"CRC offset: {hex(crc_offset)}")
            crc = crc_obj.calculate(input_image[:crc_offset])
            logger.debug(f"CRC value: {hex(crc)}")
            crc_image.binary = crc.to_bytes(4, "little")
            self.crc_check_record.image = crc_image.binary

        # ---------  Update AHAB  and do final sign  -------------
        for img_entry in self.ahab.image_array:
            img_entry.image_hash = None  # Reset image hash
        self.ahab.update_fields()
        # Sign AHAB
        self.ahab.sign_itself()

        if self.ahab.signature_block and self.ahab.signature_block.srk_assets:
            srkh0 = self.ahab.srk_hash0
            logger.info(f"SRK Hash #0 (full): {srkh0.hex()}")
            logger.info(  # pylint: disable=logging-not-lazy
                "SRK Hash #0 (truncated): " + bytes_to_print(srkh0, max_length=48)
            )
            if self.ahab.signature_block.srk_assets.srk_count > 1:
                srkh1 = self.ahab.srk_hash1
                logger.info(f"SRK Hash #1 (full): {srkh1.hex()}")
                logger.info(  # pylint: disable=logging-not-lazy
                    "SRK Hash #1 (truncated): " + bytes_to_print(srkh1, max_length=48)
                )
        # Export the AHAB Block
        ahab_image = image.find_sub_image(Mbi_ExportMixinAppTzCrcAhab.AHAB_IMAGE_NAME)
        ahab_image.binary = self.ahab.export()
        return image


class Mbi_ExportMixinAppTrustZoneCertBlockEncrypt(Mbi_ExportMixin):
    """MBI Export Mixin for encrypted application data with TrustZone and certification block support.

    This mixin extends the base MBI export functionality to handle encrypted application images
    that include TrustZone configurations and certification blocks. It manages the collection,
    encryption, and disassembly of MBI images with CertBlockV1 support and various TrustZone
    types including custom configurations.

    :cvar HMAC_OFFSET: Offset for HMAC calculation in the image structure.
    """

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

        The method assembles the final binary image by updating the IVT table with application data,
        optionally adding relocation table and TrustZone settings based on configuration.

        :raises SPSDKError: Application data or Certificate block is missing.
        :raises SPSDKError: Certificate block is not CertBlockV1 type.
        :return: Binary image with updated IVT and optionally added TrustZone settings.
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
        """Disassemble image into individual components.

        The method parses the image to extract TrustZone configuration, application data,
        and other components. It handles different TrustZone types (enabled, custom) and
        processes the image accordingly by removing TrustZone data and cleaning the IVT.

        :param image: Binary image data to be disassembled.
        """
        # Re -parse decrypted TZ if needed
        tz_type = TrustZoneType.from_tag(self.ivt_table.get_tz_type(image))
        self.trust_zone = None
        if tz_type == TrustZoneType.ENABLED:
            self.trust_zone = TrustZone(self.family)
        if tz_type == TrustZoneType.CUSTOM:
            self.trust_zone = TrustZone.parse(
                data=image[-len(TrustZone(self.family)) :], family=self.family
            )
            image = image[: -len(self.trust_zone)]

        if hasattr(self, "disassembly_app_data"):
            image = self.disassembly_app_data(image)
        self.app = self.ivt_table.clean_ivt(image)

    @property
    def img_len(self) -> int:
        """Get image length of encrypted legacy image.

        Calculates the total length including the base image, certificate block signature,
        encrypted IVT, and initialization vector.

        :raises SPSDKError: When certification block is missing.
        :return: Total image length in bytes including all components.
        """
        if not self.cert_block:
            raise SPSDKError("Certification block is missing")
        # Encrypted IVT + IV
        return self.total_len + self.cert_block.signature_size + 56 + 16

    def encrypt(self, image: BinaryImage, revert: bool = False) -> BinaryImage:
        """Encrypt or decrypt image data using AES-CTR algorithm.

        The method performs AES-CTR encryption/decryption on the provided image data using
        HMAC key and initialization vector. When revert is True, it decrypts the image.
        The encryption key may be derived from the HMAC key depending on key store configuration.

        :param image: Input binary image to encrypt or decrypt.
        :param revert: If True, decrypt the image instead of encrypting it.
        :raises SPSDKError: When HMAC key or initialization vector is missing.
        :return: New BinaryImage containing encrypted or decrypted data.
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
        """Perform post-encryption image updates and restructuring.

        This method reorganizes the encrypted image by updating the IVT table with new offsets
        and lengths, then reconstructs the image with proper block ordering including the
        certification block and initialization vector. Can also revert the operation to
        restore the original encrypted image structure.

        :param image: The encrypted binary image to be processed.
        :param revert: If True, reverts the post-encryption changes to restore original structure.
        :raises SPSDKError: If certification block is missing or not CertBlockV1 type.
        :return: Restructured encrypted image with updated layout and blocks.
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

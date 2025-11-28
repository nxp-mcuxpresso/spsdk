#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK High Assurance Boot (HAB) utility functions.

This module provides helper functions for HAB image creation and processing,
including operations for extracting boot parameters, calculating offsets,
and handling application images for NXP MCUs with HAB security features.
"""

import logging

from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db

logger = logging.getLogger(__name__)


def aead_nonce_len(app_data_len: int) -> int:
    """Calculate the nonce length for AEAD encryption.

    The nonce length is determined based on the application data length. This is used during
    the HAB (High Assurance Boot) encryption process. The implementation is based on the CST
    (Code Signing Tool) algorithm.

    :param app_data_len: Length of the application data in bytes.
    :return: Calculated nonce length in bytes.
    """
    if app_data_len < 0x10000:
        len_bytes = 2
    elif app_data_len < 0x1000000:
        len_bytes = 3
    else:
        len_bytes = 4
    return 16 - 1 - len_bytes  # AES_BLOCK_BYTES - FLAG_BYTES - len_bytes


def get_reset_vector(data: bytes) -> int:
    """Extract the application reset vector from the binary image.

    The reset vector is stored at bytes 4-7 in little-endian format and represents the address
    where execution begins after a reset.

    :param data: Binary data containing the vector table.
    :return: The reset vector address as an integer.
    """
    return int.from_bytes(data[4:8], "little")


def get_stack_pointer(data: bytes) -> int:
    """Extract the initial stack pointer value from the binary image.

    The stack pointer is stored at bytes 0-3 in little-endian format and represents the initial
    stack pointer value used by the application.

    :param data: Binary data containing the vector table.
    :return: The stack pointer address as an integer.
    """
    return int.from_bytes(data[0:4], "little")


def get_entrypoint_address(config: Config) -> int:
    """Determine the entrypoint address for the application.

    This function determines the entrypoint address using the following priority:
    1. Use explicit entrypoint address from configuration if provided
    2. Use execution_start_address from the binary image if available
    3. Fall back to the reset vector from the binary image
    The function will log warnings if there are mismatches between different address sources.

    :param config: Configuration object containing application settings and file paths.
    :return: The determined entrypoint address.
    """
    options = config.get_config("options")
    entrypoint_address = options.get("entryPointAddress")
    app_image = get_app_image(config)
    if entrypoint_address is not None:
        if (
            app_image.execution_start_address is not None
            and entrypoint_address != app_image.execution_start_address
        ):
            logger.warning(
                f"Given entrypoint address {entrypoint_address:#x} does not match the "
                f"execution start address {app_image.execution_start_address:#x}."
            )
        return entrypoint_address
    reset_vector = get_reset_vector(app_image.export())
    if app_image.execution_start_address is not None:
        if app_image.execution_start_address != reset_vector:
            logger.warning(
                f"Execution start address {app_image.execution_start_address:#x} "
                f"doesn't match the reset vector {reset_vector:#x} of the application."
            )
        return app_image.execution_start_address
    return reset_vector


def get_ivt_offset_from_cfg(config: Config) -> int:
    """Determine the IVT (Image Vector Table) offset from configuration.

    The IVT offset is either explicitly provided in the configuration as 'ivtOffset'
    or retrieved from the device database based on the family and boot device.

    :param config: Configuration object containing device family and boot device information.
    :return: The IVT offset value in bytes.
    """
    options = config.get_config("options")
    if "ivtOffset" in options:
        return options["ivtOffset"]
    db = get_db(FamilyRevision.load_from_config(options))
    return db.get_int(
        DatabaseManager.BOOTABLE_IMAGE,
        ["mem_types", options["bootDevice"], "segments", "hab_container"],
    )


def get_initial_load_size(config: Config) -> int:
    """Determine the initial load size for the bootable image.

    The initial load size represents how much of the image is loaded initially by the
    bootloader before transferring control to the application. It is either:
    1. Explicitly provided in the configuration as 'initialLoadSize'
    2. Retrieved from the device database based on the family and boot device

    :param config: Configuration object containing device family and boot device information.
    :return: The initial load size in bytes.
    """
    options = config.get_config("options")
    if "initialLoadSize" in options:
        return options["initialLoadSize"]
    db = get_db(FamilyRevision.load_from_config(options))
    return db.get_int(
        DatabaseManager.HAB,
        ["mem_types", options["bootDevice"], "initial_load_size"],
    )


def get_app_image(config: Config) -> BinaryImage:
    """Load the application binary image from the configuration.

    This function retrieves the input image file from the configuration
    and loads it as a BinaryImage object.

    :param config: Configuration object containing HAB configuration.
    :return: Loaded BinaryImage object.
    """
    return BinaryImage.load_binary_image(config.get_input_file_name("inputImageFile"))


def get_header_version(config: Config) -> int:
    """Get header version from HAB configuration.

    Parses the header version from string format to integer representation.
    The version string is converted by removing dots and interpreting as hexadecimal.
    Example: "4.2" -> 0x42 -> 66

    :param config: Configuration object containing HAB configuration data.
    :raises SPSDKTypeError: Input version if wrong type.
    :return: Version as integer value.
    """
    version = config.get_config("sections/0/Header").get_str("Header_Version")
    if isinstance(version, str):
        return int(version.replace(".", ""), 16)
    assert isinstance(version, int)
    return version

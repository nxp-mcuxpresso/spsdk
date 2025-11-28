#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Development HSM base class module.

This module provides the abstract base class for Development Hardware Security Module
implementations used in SPSDK for secure provisioning operations.
The DevHsm class serves as the foundation for various HSM implementations,
defining the common interface and basic functionality required for secure
key management and cryptographic operations in development environments.
"""

import abc
import os
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKNotImplementedError, SPSDKValueError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import load_hex_string, write_file


class DevHsm(FeatureBaseClass):
    """SPSDK Device Hardware Security Module (HSM) base class.

    This abstract base class provides the foundation for Device HSM operations across
    NXP MCU portfolio, managing secure provisioning workflows including master share
    generation, key management, and secure boot file creation. It handles device buffer
    operations and provides standardized interface for HSM-related security functions.

    :cvar DEVBUFF_SIZE: Size of the device buffer (256 bytes).
    :cvar DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE: Input buffer size for master share generation.
    :cvar DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE: Output buffer size for encrypted share.
    :cvar DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE: Output buffer size for encrypted master share.
    :cvar DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE: Output buffer size for customer certificate public key.
    :cvar DEVBUFF_HSM_GENKEY_KEYBLOB_SIZE: Size of HSM generated key blob.
    :cvar DEVBUFF_HSM_GENKEY_KEYBLOB_PUK_SIZE: Size of HSM generated key blob public key.
    :cvar DEVBUFF_CUST_MK_SK_KEY_SIZE: Size of customer master key.
    :cvar DEVBUFF_DATA_BLOCK_SIZE: Size of data block buffer.
    :cvar DEVBUFF_SB_SIGNATURE_SIZE: Size of secure boot signature.
    :cvar RESET_TIMEOUT: Timeout for device reset operations in milliseconds.
    """

    FEATURE = DatabaseManager.DEVHSM

    F_DEVHSM = DatabaseManager.DEVHSM
    F_BUFFER = DatabaseManager.COMM_BUFFER
    DEVBUFF_SIZE = 0x100

    DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE = 16
    DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE = 48
    DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE = 64
    DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE = 64
    DEVBUFF_HSM_GENKEY_KEYBLOB_SIZE = 48
    DEVBUFF_HSM_GENKEY_KEYBLOB_PUK_SIZE = 64
    DEVBUFF_CUST_MK_SK_KEY_SIZE = 32
    DEVBUFF_DATA_BLOCK_SIZE = 256
    DEVBUFF_SB_SIGNATURE_SIZE = 64

    RESET_TIMEOUT = 500  # timeout for reset in milliseconds

    def __init__(self, family: FamilyRevision, workspace: Optional[str] = None) -> None:
        """Device HSM base class constructor.

        Initialize Device HSM with specified chip family and optional workspace directory.
        Creates workspace directory if it doesn't exist.

        :param family: Chip family and revision information.
        :param workspace: Optional path to workspace directory for HSM operations.
        :raises OSError: When workspace directory cannot be created.
        """
        self.database = get_db(family)

        self.workspace = workspace
        self.family = family
        self.devbuff_base = self.database.get_int(self.F_BUFFER, "address")

        if self.workspace and not os.path.isdir(self.workspace):
            os.makedirs(self.workspace)

    @abc.abstractmethod
    def create_sb(self) -> None:
        """Create SB file.

        This method generates a Secure Binary (SB) file using the configured DevHSM parameters
        and writes it to the specified output location.

        :raises SPSDKError: If SB file creation fails due to configuration or processing errors.
        """

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Object data in bytes format to be parsed.
        :raises SPSDKNotImplementedError: If parsing is not implemented.
        """
        raise SPSDKNotImplementedError("Not implemented")

    @abc.abstractmethod
    def oem_generate_master_share(self, oem_share_input: bytes) -> tuple[bytes, bytes, bytes]:
        """Generate OEM master share on device with encryption.

        This method processes the OEM share input to generate encrypted master share
        outputs using the device's hardware security module capabilities.

        :param oem_share_input: Input data for OEM share generation.
        :return: Tuple containing three encrypted master share output components.
        """

    @abc.abstractmethod
    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device.

        This method configures the OEM (Original Equipment Manufacturer) master share
        on the target device using either an OEM seed or an encrypted OEM share.

        :param oem_seed: Optional seed value for generating the OEM master share.
        :param enc_oem_share: Optional encrypted OEM share data to be set on device.
        :return: Response data from the device after setting the master share.
        """

    def store_temp_res(self, file_name: str, data: bytes, group: Optional[str] = None) -> None:
        """Store temporary files into workspace.

        The method saves data to a file in the workspace directory. If a group is specified,
        the file will be stored in a corresponding subfolder that will be created if it
        doesn't exist.

        :param file_name: Name of file to store the data.
        :param data: Binary data to store in the file.
        :param group: Optional subfolder name for organizing files, defaults to None.
        """
        if not self.workspace:
            return
        group_dir = os.path.join(self.workspace, group or "")
        if not os.path.isdir(group_dir):
            os.mkdir(group_dir)

        filename = os.path.join(self.workspace, group or "", file_name)
        write_file(data, filename, mode="wb")

    def get_devbuff_base_address(self, index: int) -> int:
        """Get devbuff base address for specified index.

        Calculates the base address for a device buffer at the given index by adding
        the index offset to the base devbuff address.

        :param index: Device buffer index (0-9).
        :raises SPSDKValueError: Invalid index provided (must be 0-9).
        :return: Base address of the device buffer at specified index.
        """
        # pylint:disable=superfluous-parens; Not superfluous, readability counts
        if not (0 <= index < 10):
            raise SPSDKValueError(f"Invalid index: {index}. Expected 0-9.")
        return self.devbuff_base + index * self.DEVBUFF_SIZE

    def get_keyblob_offset(self) -> int:
        """Get keyblob offset based on family.

        :return: The keyblob offset value from the database configuration.
        """
        return self.database.get_int(self.F_DEVHSM, "key_blob_offset")

    def command_order(self) -> bool:
        """Get command order configuration for the device family.

        Retrieves the boolean configuration value that determines the command ordering
        behavior for the specific device family from the database.

        :return: True if command ordering is enabled for the family, False otherwise.
        """
        return self.database.get_bool(self.F_DEVHSM, "order")

    def get_keyblob_position(self) -> int:
        """Get keyblob position from database.

        :return: Position of the keyblob command in the database as an integer value.
        """
        return self.database.get_int(self.F_DEVHSM, "key_blob_command_position")

    def get_devbuff_wrapped_cust_mk_sk_key_size(self) -> int:
        """Get the size of wrapped customer master key SK.

        This method retrieves the size configuration for the device buffer wrapped
        customer master key Symmetric Key from the database.

        :return: Size of wrapped customer master key SK in bytes.
        """
        return self.database.get_int(self.F_DEVHSM, "devbuff_wrapped_cust_mk_sk_key_size")

    @staticmethod
    def get_oem_share_input(
        binary: Optional[str] = None, search_paths: Optional[list[str]] = None
    ) -> bytes:
        """Get OEM share input data from file.

        Loads 16-byte OEM share input data from either a text file containing hex string
        or a binary file.

        :param binary: Path to binary or text file containing OEM share input data.
        :param search_paths: List of paths where to search for the file, defaults to None.
        :return: 16-byte binary array loaded from file.
        :raises SPSDKValueError: When invalid input value is recognized.
        """
        return load_hex_string(
            source=binary, expected_size=16, search_paths=search_paths, name="OEM SHARE INPUT"
        )

    def __repr__(self) -> str:
        """Return string representation of DevHSM object.

        :return: String representation of the DevHSM instance.
        """
        return "DevHSM"

    def __str__(self) -> str:
        """Return string representation of the DevHSM instance.

        :return: String containing class name and target family.
        """
        return f"{self.__class__.__name__} for {self.family}"

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used as a baseclass for DEVHSM."""

import abc
import os
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKNotImplementedError, SPSDKValueError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import DatabaseManager, get_families
from spsdk.utils.misc import load_hex_string, write_file


class DevHsm(BaseClass):
    """Base class for DEVHSM."""

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
    DEVBUFF_WRAPPED_CUST_MK_SK_KEY_SIZE = 48
    DEVBUFF_DATA_BLOCK_SIZE = 256
    DEVBUFF_SB_SIGNATURE_SIZE = 64

    RESET_TIMEOUT = 500  # timeout for reset in milliseconds

    def __init__(self, family: str, workspace: Optional[str] = None) -> None:
        """Device HSM base class constructor.

        :param family: chip family
        :workspace: optional path to workspace
        """
        self.database = DatabaseManager().db.devices.get(family).revisions.get("latest")

        self.workspace = workspace
        self.family = family
        self.devbuff_base = self.database.get_int(self.F_BUFFER, "address")

        if self.workspace and not os.path.isdir(self.workspace):
            os.mkdir(self.workspace)

    @abc.abstractmethod
    def __repr__(self) -> str:
        """String representation."""

    @abc.abstractmethod
    def __str__(self) -> str:
        """String object representation."""

    @abc.abstractmethod
    def create_sb(self) -> None:
        """Create SB file."""

    @abc.abstractmethod
    def export(self) -> bytes:
        """Export final SB file."""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array."""
        raise SPSDKNotImplementedError("Not implemented")

    @abc.abstractmethod
    def oem_generate_master_share(self, oem_share_input: bytes) -> tuple[bytes, bytes, bytes]:
        """Generate on device Encrypted OEM master share outputs."""

    @abc.abstractmethod
    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device."""

    @classmethod
    @abc.abstractmethod
    def generate_config_template(cls, family: str) -> str:
        """Generate configuration for selected family."""

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get the list of supported families by Device HSM.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.DEVHSM)

    def store_temp_res(self, file_name: str, data: bytes, group: Optional[str] = None) -> None:
        """Storing temporary files into workspace.

        :param file_name: Name of file to store the data.
        :param data: Data to store.
        :param group: Subfolder name, defaults to None
        """
        if not self.workspace:
            return
        group_dir = os.path.join(self.workspace, group or "")
        if not os.path.isdir(group_dir):
            os.mkdir(group_dir)

        filename = os.path.join(self.workspace, group or "", file_name)
        write_file(data, filename, mode="wb")

    def get_devbuff_base_address(self, index: int) -> int:
        """Get devbuff base address."""
        # pylint:disable=superfluous-parens; Not superfluous, readability counts
        if not (0 <= index < 4):
            raise SPSDKValueError(f"Invalid index: {index}. Expected 0-3.")
        return self.devbuff_base + index * self.DEVBUFF_SIZE

    def get_keyblob_offset(self) -> int:
        """Update keyblob offset based on family."""
        return self.database.get_int(self.F_DEVHSM, "key_blob_offset")

    def command_order(self) -> bool:
        """Update command order based on family."""
        return self.database.get_bool(self.F_DEVHSM, "order")

    def get_keyblob_position(self) -> int:
        """Get keyblob position from database."""
        return self.database.get_int(self.F_DEVHSM, "key_blob_command_position")

    @staticmethod
    def get_cust_mk_sk(key: str, search_paths: Optional[list[str]] = None) -> bytes:
        """Get binary from text or binary file.

        :param key: Binary customer master key symmetric key file.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Binary array loaded from file.
        :raises SPSDKValueError: When invalid input value is recognized.
        """
        return load_hex_string(
            source=key, expected_size=32, search_paths=search_paths, name="CUST_MK_SK INPUT"
        )

    @staticmethod
    def get_oem_share_input(
        binary: Optional[str] = None, search_paths: Optional[list[str]] = None
    ) -> bytes:
        """Get binary from text or binary file.

        :param binary: Path to binary file.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Binary array loaded from file.
        :raises SPSDKValueError: When invalid input value is recognized.
        """
        return load_hex_string(
            source=binary, expected_size=16, search_paths=search_paths, name="OEM SHARE INPUT"
        )

    @staticmethod
    def get_oem_master_share(
        binary: Optional[str], search_paths: Optional[list[str]] = None
    ) -> Optional[bytes]:
        """Get binary from text or binary file.

        :param binary: Path to binary file.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Binary array loaded from file.
        :raises SPSDKValueError: When invalid input value is recognized.
        """
        if not binary:
            return None
        return load_hex_string(
            source=binary, expected_size=64, search_paths=search_paths, name="OEM ENC MASTER SHARE"
        )

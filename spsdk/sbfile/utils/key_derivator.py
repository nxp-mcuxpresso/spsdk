#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for key derivation functionality for SB3.1 encryption."""

import abc
import functools
import logging
from typing import Any, Optional, Union

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.http_client import HTTPClientBase
from spsdk.utils.misc import Endianness, find_file, load_text
from spsdk.utils.service_provider import ServiceProvider
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class KeyDerivationMode(SpsdkEnum):
    """Modes for Key derivation.

    Defines the different operation modes used during key derivation process.
    """

    KDK = (1, "KDK", "Key Derivation Key mode")
    BLK = (2, "BLK", "Block Key Derivation mode")


class SB31KeyDerivator(ServiceProvider):
    """Engine for generating derived keys.

    Base class that implements the key derivation protocol for SB3.1 format.
    """

    legacy_identifier_name = "kd_type"
    plugin_identifier = "spsdk.sb31kdp"

    def __init__(self, *args: str, **kwargs: str) -> None:
        """Initialize the KeyDerivator.

        :param args: Positional arguments passed to parent class
        :param kwargs: Keyword arguments with configuration options
        """
        super().__init__(*args, **kwargs)
        self._configured = False
        self.kdk = bytes()
        self.timestamp = 0
        self.kdk_access_rights = 0
        self.key_length = 0

    @abc.abstractmethod
    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using the implementation-specific method.

        :param data: Input data for CMAC calculation
        :return: Calculated CMAC value
        """

    def _derive_kdk(self) -> bytes:
        """Derive the KeyDerivationKey from PCK and timestamp.

        Uses the configured parameters to derive a key derivation key.

        :return: Derived key derivation key
        """
        derivation_data_func = functools.partial(
            self._get_key_derivation_data,
            derivation_constant=self.timestamp,
            mode=KeyDerivationMode.KDK,
        )
        result = self.remote_cmac(data=derivation_data_func(iteration=1))
        if self.key_length == 256:
            result += self.remote_cmac(data=derivation_data_func(iteration=2))
        return result

    def get_block_key(self, block_number: int) -> bytes:
        """Derive key for particular block.

        :param block_number: The number of the block for key derivation
        :return: Derived key for the specified block
        """
        derivation_data_func = functools.partial(
            self._get_key_derivation_data,
            derivation_constant=block_number,
            mode=KeyDerivationMode.BLK,
        )
        result = cmac(key=self.kdk, data=derivation_data_func(iteration=1))
        if self.key_length == 256:
            result += cmac(key=self.kdk, data=derivation_data_func(iteration=2))
        return result

    def configure(self, timestamp: int, kdk_access_rights: int, key_length: int = 256) -> None:
        """Configure the key derivator with required parameters.

        Sets up necessary configuration and derives the key derivation key.

        :param timestamp: Timestamp value for key derivation
        :param kdk_access_rights: Access rights for the key derivation key
        :param key_length: Length of encryption key in bits, defaults to 256
        """
        self.timestamp = timestamp
        self.kdk_access_rights = kdk_access_rights
        self.key_length = key_length
        self._configured = True
        self.kdk = self._derive_kdk()
        logger.info(f"SB3KDK: {self.kdk.hex()}")

    def _get_key_derivation_data(
        self,
        derivation_constant: int,
        mode: KeyDerivationMode,
        iteration: int,
    ) -> bytes:
        """Generate data for AES key derivation.

        Composes the data structure used for key derivation according to the protocol.

        :param derivation_constant: Number for the key derivation
        :param mode: Mode for key derivation (KDK or BLK)
        :param iteration: Iteration of the key derivation
        :return: Data used for key derivation
        :raises SPSDKError: When key derivator is not configured or configured incorrectly
        """
        if not self._configured:
            raise SPSDKError("Key Derivator is not configured.")
        if mode not in KeyDerivationMode:
            raise SPSDKError("Invalid mode")
        if self.kdk_access_rights not in [0, 1, 2, 3]:
            raise SPSDKError("Invalid kdk access rights")
        if self.key_length not in [128, 256]:
            raise SPSDKError("Invalid key length")

        label = int.to_bytes(derivation_constant, length=12, byteorder=Endianness.LITTLE.value)
        context = bytes(8)
        context += int.to_bytes(
            self.kdk_access_rights << 6, length=1, byteorder=Endianness.BIG.value
        )
        context += b"\x01" if mode == KeyDerivationMode.KDK else b"\x10"
        context += bytes(1)
        key_option = 0x20 if self.key_length == 128 else 0x21
        context += int.to_bytes(key_option, length=1, byteorder=Endianness.BIG.value)
        length = int.to_bytes(self.key_length, length=4, byteorder=Endianness.BIG.value)
        i = int.to_bytes(iteration, length=4, byteorder=Endianness.BIG.value)
        result = label + context + length + i
        return result


class LocalKeyDerivator(SB31KeyDerivator):
    """Key derivator that uses a locally stored key file.

    Performs key derivation using a key stored in a local file.
    """

    identifier = "file"

    def __init__(
        self,
        file_path: Optional[str] = None,
        key_data: Optional[bytes] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize local key derivator.

        :param file_path: Path to the file containing the key
        :param search_paths: Additional paths to search for the key file
        """
        super().__init__()
        if key_data is None and file_path is None:
            raise SPSDKError("Either file_path or key_data must be provided")
        if file_path:
            file_path = find_file(file_path=file_path, search_paths=search_paths)
            self.pck = bytes.fromhex(load_text(file_path).strip())
        if key_data:
            self.pck = key_data
        assert self.pck is not None, "Key data must be provided"
        logger.info(f"SB3PCK: {self.pck.hex()}")

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using locally stored key.

        :param data: Input data for CMAC calculation
        :return: Calculated CMAC value
        """
        return cmac(key=self.pck, data=data)


class RemoteKeyDerivator(HTTPClientBase, SB31KeyDerivator):
    """Key derivator that uses a remote service over HTTP.

    Delegates key derivation operations to a remote service.
    """

    identifier = "proxy"
    api_version = "1.0"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        url_prefix: str = "api",
        timeout: int = 60,
        **kwargs: Union[str, int, bool],
    ) -> None:
        """Initialize remote key derivator.

        :param host: Hostname of the remote service
        :param port: Port number of the remote service
        :param url_prefix: URL prefix for API endpoints
        :param timeout: Request timeout in seconds
        :param kwargs: Additional configuration options
        """
        super().__init__(
            host=host, port=int(port), url_prefix=url_prefix, timeout=timeout, **kwargs  # type: ignore[arg-type]
        )

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using the remote service.

        :param data: Input data for CMAC calculation
        :return: Calculated CMAC value from the remote service
        """
        response = self._handle_request(
            method=self.Method.GET, url="/cmac", json_data={"data": data.hex()}
        )
        response_data = self._check_response(response=response, names_types=[("data", str)])
        return bytes.fromhex(response_data["data"])


def get_sb31_key_derivator(
    kd_cfg: Optional[str] = None,
    local_file_key: Optional[str] = None,
    search_paths: Optional[list[str]] = None,
    **kwargs: Any,
) -> SB31KeyDerivator:
    """Factory function to create an appropriate key derivator.

    Creates either a service-based or file-based key derivator based on the provided parameters.

    :param kd_cfg: Path to key derivator configuration file
    :param local_file_key: Path to local key file
    :param search_paths: Additional paths to search for keys
    :param kwargs: Additional arguments passed to the key derivator
    :return: Configured key derivator instance
    :raises SPSDKError: When no configuration is provided or key derivator creation fails
    """
    if kd_cfg:
        # config string might still be a path to local file
        try:
            file = find_file(file_path=kd_cfg, search_paths=search_paths)
            return LocalKeyDerivator(file_path=file, search_paths=search_paths)
        except SPSDKError:
            # if config string doesn't contain a file path, try other options
            pass

        # config string might still be a plain key as hexstring
        try:
            key_data = bytes.fromhex(kd_cfg)
            return LocalKeyDerivator(key_data=key_data)
        except ValueError:
            # If it's not a hex string, try other options
            pass

        params = SB31KeyDerivator.convert_params(kd_cfg)
        params.update(**kwargs)
        key_derivation_provider = SB31KeyDerivator.create(params=params)
    elif local_file_key:
        key_derivation_provider = LocalKeyDerivator(
            file_path=local_file_key, search_paths=search_paths
        )
    else:
        raise SPSDKError("No key derivator configuration is provided")

    if not key_derivation_provider:
        raise SPSDKError(f"Cannot create signature provider from: {kd_cfg or local_file_key}")

    return key_derivation_provider

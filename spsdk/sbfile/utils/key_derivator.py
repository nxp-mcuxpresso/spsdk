#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB3.1 key derivation utilities.

This module provides functionality for deriving encryption keys used in
Secure Binary 3.1 (SB3.1) file format. It supports both local and remote
key derivation modes with CMAC-based key generation algorithms.
"""

import abc
import functools
import logging
from typing import Any, Optional, Union

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.http_client import HTTPClientBase
from spsdk.utils.misc import Endianness, find_file, load_hex_string
from spsdk.utils.service_provider import ServiceProvider
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class KeyDerivationMode(SpsdkEnum):
    """Key derivation mode enumeration for SPSDK operations.

    This enumeration defines the available modes for key derivation processes,
    including Key Derivation Key (KDK) mode and Block Key Derivation (BLK) mode.
    """

    KDK = (1, "KDK", "Key Derivation Key mode")
    BLK = (2, "BLK", "Block Key Derivation mode")


class SB31KeyDerivator(ServiceProvider):
    """SB3.1 Key Derivation Engine.

    Abstract base class that implements the key derivation protocol for SB3.1 secure boot format.
    This class provides the foundation for generating derived keys used in SB3.1 file encryption
    and authentication, supporting both 128-bit and 256-bit key lengths.

    :cvar legacy_identifier_name: Legacy identifier for plugin compatibility.
    :cvar plugin_identifier: Plugin system identifier for service discovery.
    """

    legacy_identifier_name = "kd_type"
    plugin_identifier = "spsdk.sb31kdp"

    def __init__(self, *args: str, **kwargs: str) -> None:
        """Initialize the KeyDerivator.

        Sets up a new KeyDerivator instance with default configuration values.
        All key derivation parameters are initialized to their default states.

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

        :param data: Input data for CMAC calculation.
        :return: Calculated CMAC value.
        """

    def _derive_kdk(self) -> bytes:
        """Derive the KeyDerivationKey from PCK and timestamp.

        Uses the configured parameters to derive a key derivation key. For 256-bit keys,
        two iterations are performed and the results are concatenated.

        :return: Derived key derivation key as bytes.
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

        The method uses CMAC-based key derivation with the block number as derivation constant.
        For 256-bit keys, two CMAC iterations are performed and concatenated.

        :param block_number: The number of the block for key derivation.
        :return: Derived key for the specified block as bytes.
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

        :param timestamp: Timestamp value for key derivation.
        :param kdk_access_rights: Access rights for the key derivation key.
        :param key_length: Length of encryption key in bits, defaults to 256.
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

        Composes the data structure used for key derivation according to the protocol
        specification. The method combines derivation constant, access rights, mode,
        key options, and iteration into a structured byte sequence.

        :param derivation_constant: Number for the key derivation (12 bytes, little endian)
        :param mode: Mode for key derivation (KDK or BLK)
        :param iteration: Iteration of the key derivation (4 bytes, big endian)
        :return: Data used for key derivation as bytes sequence
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
    """Local key derivator for SB3.1 secure boot operations.

    This class implements key derivation functionality using cryptographic keys
    stored in local files or provided as direct hex string data. It supports
    both 128-bit and 256-bit PCK (Part Common Key) formats and
    handles automatic key size detection during loading.

    :cvar identifier: String identifier for this derivator type.
    """

    identifier = "file"

    def __init__(
        self,
        file_path: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
        data: Optional[str] = None,
        **kwargs: str,
    ) -> None:
        """Initialize the Local Key Derivator.

        Initializes a key derivator that can load Part Common Key (PCK) from either
        a file or direct hex string data. The PCK must be either 128-bit (16 bytes) or
        256-bit (32 bytes).

        :param file_path: Path to PCK file (text with hex string or binary file)
        :param search_paths: List of paths where to search for the file, defaults to None
        :param data: Direct hex string data (alternative to file_path)
        :param kwargs: Additional keyword arguments
        :raises SPSDKError: When PCK data cannot be parsed, file cannot be loaded, or neither
            file_path nor data is provided
        """
        super().__init__(**kwargs)

        if data:
            # Handle direct hex string data
            try:
                self.pck = bytes.fromhex(data)
            except ValueError as exc:
                raise SPSDKError(f"Cannot parse hex data: {str(exc)}") from exc
        elif file_path:
            try:
                # Try to load key with different expected sizes (256-bit first, then 128-bit)
                for expected_size in [32, 16]:  # 256-bit (32 bytes) and 128-bit (16 bytes)
                    try:
                        self.pck = load_hex_string(
                            source=file_path,
                            expected_size=expected_size,
                            search_paths=search_paths,
                            name="PCK",
                        )
                        break
                    except SPSDKError:
                        continue
                else:
                    raise SPSDKError(
                        "PCK key must be either 128-bit (16 bytes) or 256-bit (32 bytes)"
                    )
            except SPSDKError as exc:
                raise SPSDKError(f"Cannot load PCK from {file_path}: {str(exc)}") from exc
        else:
            raise SPSDKError("Either file_path or data must be provided")

        logger.info(f"SB3PCK: {self.pck.hex()}")

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using locally stored key.

        :param data: Input data for CMAC calculation.
        :return: Calculated CMAC value as bytes.
        """
        return cmac(key=self.pck, data=data)


class RemoteKeyDerivator(HTTPClientBase, SB31KeyDerivator):
    """Remote key derivator for SB31 operations using HTTP service.

    This class provides key derivation functionality by delegating operations
    to a remote HTTP service, enabling distributed key management and processing
    for secure boot file operations.

    :cvar identifier: Service identifier for proxy-based key derivation.
    :cvar api_version: API version supported by the remote service.
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

        This constructor sets up a connection to a remote key derivation service
        with configurable network parameters and timeout settings.

        :param host: Hostname of the remote service, defaults to "localhost".
        :param port: Port number of the remote service, defaults to 8000.
        :param url_prefix: URL prefix for API endpoints, defaults to "api".
        :param timeout: Request timeout in seconds, defaults to 60.
        :param kwargs: Additional configuration options passed to parent class.
        """
        super().__init__(
            host=host, port=int(port), url_prefix=url_prefix, timeout=timeout, **kwargs  # type: ignore[arg-type]
        )

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using the remote service.

        :param data: Input data for CMAC calculation.
        :return: Calculated CMAC value from the remote service.
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
    The kd_cfg parameter can be a file path, hex string key, or service configuration string.

    :param kd_cfg: Key derivator configuration (file path, hex string, or service config).
    :param local_file_key: Path to local key file.
    :param search_paths: Additional paths to search for configuration and key files.
    :param kwargs: Additional arguments passed to the key derivator constructor.
    :raises SPSDKError: When no configuration is provided or key derivator creation fails.
    :return: Configured key derivator instance.
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
            # Validate it's a hex string by trying to convert it
            bytes.fromhex(kd_cfg)
            # If successful, create LocalKeyDerivator with data parameter
            return LocalKeyDerivator(data=kd_cfg, search_paths=search_paths)
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

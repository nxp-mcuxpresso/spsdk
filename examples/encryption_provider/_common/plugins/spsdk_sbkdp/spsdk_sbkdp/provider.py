#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SB Key Derivation Provider implementation.

This module provides a custom key derivation provider for SPSDK's Secure Binary (SB) 3.1 format.
The provider implements remote key derivation functionality through HTTP requests to enable
secure key management in distributed environments.
"""

import requests

from spsdk.sbfile.utils.key_derivator import SB31KeyDerivator


class MySBKeyDerivatorProvider(SB31KeyDerivator):
    """SPSDK Secure Boot Key Derivation Provider for remote services.

    This provider implements secure boot key derivation operations by delegating
    CMAC calculations to a remote HTTP service. It extends the SB31KeyDerivator
    to provide network-based key derivation functionality for distributed
    secure boot implementations.

    :cvar identifier: Provider identifier used in YAML configuration files.
    """

    # identifier of this signature provider; used in yaml configuration file
    identifier = "mysbkdp"

    def __init__(self, key_id: int, url: str = "127.0.0.1:5010") -> None:
        """Initialize the MySBKeyDerivatorProvider.

        Creates a new instance of the SBKDP (Secure Boot Key Derivation Provider) with
        the specified key identifier and server URL for key derivation operations.

        :param key_id: Unique identifier for the key to be used in derivation operations.
        :param url: Server URL and port for the key derivation service, defaults to "127.0.0.1:5010".
        """
        super().__init__()
        self.url = url
        self.key_id = key_id

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using remote HTTP endpoint.

        Sends a GET request to the configured remote server to calculate CMAC
        for the provided data using the specified key ID.

        :param data: Input data for CMAC calculation
        :raises requests.exceptions.RequestException: HTTP request failed
        :raises requests.exceptions.HTTPError: HTTP response indicates an error
        :raises KeyError: Response JSON missing expected 'data' field
        :raises ValueError: Invalid hexadecimal data in response
        :return: Calculated CMAC value as bytes
        """
        endpoint = f"http://{self.url}/api/cmac/{self.key_id}"
        payload = {"data": data.hex()}
        response = requests.get(endpoint, json=payload, timeout=3000)
        response.raise_for_status()
        cmac_hex = response.json()["data"]
        return bytes.fromhex(cmac_hex)

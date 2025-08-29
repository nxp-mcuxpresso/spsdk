#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Main module for MySBKeyDerivatorProvider."""
import requests

from spsdk.sbfile.utils.key_derivator import SB31KeyDerivator


class MySBKeyDerivatorProvider(SB31KeyDerivator):
    """Signature Provider based on a remote signing service."""

    # identifier of this signature provider; used in yaml configuration file
    identifier = "mysbkdp"

    def __init__(self, key_id: int, url: str = "127.0.0.1:5010") -> None:
        """Initialize the MySBKeyDerivatorProvider."""
        super().__init__()
        self.url = url
        self.key_id = key_id

    def remote_cmac(self, data: bytes) -> bytes:
        """Calculate CMAC using the implementation-specific method.

        :param data: Input data for CMAC calculation
        :return: Calculated CMAC value
        """
        endpoint = f"http://{self.url}/api/cmac/{self.key_id}"
        payload = {"data": data.hex()}
        response = requests.get(endpoint, json=payload)
        response.raise_for_status()
        cmac_hex = response.json()["data"]
        return bytes.fromhex(cmac_hex)

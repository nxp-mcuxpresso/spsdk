#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Customer-specific Signature Provider."""

import base64

import requests  # type: ignore

from spsdk.crypto import SignatureProvider


class SuperAwesomeSP(SignatureProvider):
    """Signature Provider based on a remote signing service."""

    # identifier of this signature provider; used in yaml configuration file
    sp_type = "sasp"

    def __init__(self, key_number: int) -> None:
        """Initialize the Super Awesome SignatureProvider.

        :param key_number: index of the key to use (rot_id from yaml config)
        """
        self.url = f"http://127.0.0.1:5000/signer/{key_number}"

    def info(self) -> str:
        """Return basic info about the Signature provider."""
        msg = "Super Awesome Signature Provider\n"
        msg += f"Remote URL: {self.url}\n"
        return msg

    def sign(self, data: bytes) -> bytes:
        """Perform the signing.

        :param data: Data to sign
        :return: Signature
        """
        params = {"data": base64.b64encode(data)}
        response = requests.get(self.url, params=params)
        signature = response.json()["signature"]
        data = base64.b64decode(signature)
        return data.zfill(256)

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        return 256

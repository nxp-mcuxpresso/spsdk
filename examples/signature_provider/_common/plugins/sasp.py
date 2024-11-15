#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Customer-specific Signature Provider."""

import base64

import requests

from spsdk.crypto.keys import PublicKey
from spsdk.crypto.signature_provider import SignatureProvider


class SuperAwesomeSP(SignatureProvider):
    """Signature Provider based on a remote signing service."""

    # identifier of this signature provider; used in yaml configuration file
    identifier = "sasp"

    def __init__(self, key_number: int, key_type: str) -> None:
        """Initialize the Super Awesome SignatureProvider.

        :param key_number: index of the key to use (rot_id from yaml config)
        """
        self.url = "http://127.0.0.1:5000"
        self.key_number = key_number
        self.key_type = key_type

    def sign(self, data: bytes) -> bytes:
        """Perform the signing.

        :param data: Data to sign
        :return: Signature
        """
        endpoint = f"{self.url}/signer/{self.key_type}/{self.key_number}"
        params = {"data": base64.b64encode(data)}
        response = requests.get(endpoint, params=params, timeout=30)
        self.check_response(response)
        signature = response.json()["signature"]
        data = base64.b64decode(signature)
        return data

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key.

        :param public_key: Public key to verify
        :return: True if public_key is matching private_key, False otherwise
        """
        endpoint = f"{self.url}/verifier/{self.key_type}/{self.key_number}"
        params = {"public_key": base64.b64encode(public_key.export())}
        response = requests.get(endpoint, params=params, timeout=30)
        self.check_response(response)
        is_matching = response.json()["is_matching"]
        return is_matching

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        return {"rsa2048": 256, "secp256r1": 64, "secp384r1": 96, "secp521r1": 132}[self.key_type]

    @staticmethod
    def check_response(response: requests.Response) -> None:
        """Raise if response is not 2xx."""
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            if response.text:
                raise requests.HTTPError(
                    f"{str(e)}; Error Message: {response.text}",
                    request=e.request,
                    response=e.response,
                )
            raise e

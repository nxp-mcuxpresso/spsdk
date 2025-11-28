#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Super Awesome Signature Provider implementation.

This module provides a custom signature provider that integrates with external
signing services through HTTP requests, demonstrating how to implement remote
signature capabilities for SPSDK applications.
"""

import base64
from typing import Optional

import requests

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PublicKey
from spsdk.crypto.signature_provider import SignatureProvider


class SuperAwesomeSP(SignatureProvider):
    """Super Awesome Signature Provider for remote signing operations.

    This class implements a signature provider that connects to a remote signing service
    via HTTP API. It manages cryptographic signing operations by delegating them to
    an external service running on localhost, supporting various key types and hash
    algorithms for secure digital signatures.

    :cvar identifier: Provider identifier used in YAML configuration files.
    """

    # identifier of this signature provider; used in yaml configuration file
    identifier = "sasp"

    def __init__(
        self, key_number: int, key_type: str, hash_alg: Optional[EnumHashAlgorithm] = None, **kwargs
    ) -> None:
        """Initialize the Super Awesome SignatureProvider.

        Sets up the signature provider with specified key configuration and optional
        hash algorithm. The provider connects to a local service for signing operations.

        :param key_number: Index of the key to use (rot_id from yaml config).
        :param key_type: Type of the cryptographic key to be used.
        :param hash_alg: Hash algorithm to use for signing operations, optional.
        :param kwargs: Additional keyword arguments for signing configuration.
        """
        self.url = "http://127.0.0.1:5000"
        self.key_number = key_number
        self.key_type = key_type
        self.sign_kwargs = kwargs
        if hash_alg:
            self.sign_kwargs["algorithm"] = hash_alg.label

    def sign(self, data: bytes) -> bytes:
        """Sign data using the remote signature provider.

        The method sends a signing request to the configured SASP endpoint with the provided
        data and returns the generated signature. The data is hex-encoded for transmission
        and the signature is returned as base64-decoded bytes.

        :param data: Raw data bytes to be signed.
        :return: Digital signature as bytes.
        :raises SPSDKError: When the signing request fails or returns an error response.
        """
        endpoint = f"{self.url}/signer/{self.key_type}/{self.key_number}"
        params = {"data": data.hex(), **self.sign_kwargs}
        response = requests.get(endpoint, json=params, timeout=30)
        self.check_response(response)
        signature = response.json()["signature"]
        data = base64.b64decode(signature)
        return data

    def verify_public_key(self, public_key: PublicKey) -> bool:
        """Verify if given public key matches private key.

        Verify if given public key matches private key.
        Sends a verification request to the SASP server to check if the provided
        public key corresponds to the private key stored on the server.

        :param public_key: Public key to verify against the server's private key.
        :raises SPSDKError: If the server request fails or returns an error.
        :return: True if public_key matches the private key, False otherwise.
        """
        endpoint = f"{self.url}/verifier/{self.key_type}/{self.key_number}"
        params = {"public_key": public_key.export().hex()}
        response = requests.get(endpoint, json=params, timeout=30)
        self.check_response(response)
        is_matching = response.json()["is_matching"]
        return is_matching

    @property
    def signature_length(self) -> int:
        """Return length of the signature in bytes.

        The method returns the signature length based on the key type used by the provider.
        Supported key types: rsa2048 (256 bytes), secp256r1 (64 bytes), secp384r1 (96 bytes), secp521r1 (132 bytes).

        :raises KeyError: Unsupported key type.
        :return: Signature length in bytes.
        """
        return {"rsa2048": 256, "secp256r1": 64, "secp384r1": 96, "secp521r1": 132}[self.key_type]

    @staticmethod
    def check_response(response: requests.Response) -> None:
        """Check HTTP response status and raise detailed error if not successful.

        The method validates HTTP response status codes and enhances error messages
        with response text when available for better debugging.

        :param response: HTTP response object to validate.
        :raises requests.HTTPError: When response status is not 2xx, with enhanced
            error message if response text is available.
        """
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

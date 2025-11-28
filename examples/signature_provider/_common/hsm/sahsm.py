#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HSM simulation server for signature provider examples.

This module implements a Flask-based HTTP server that simulates a Hardware Security Module (HSM)
for testing and demonstration purposes in SPSDK signature provider examples. It provides REST API
endpoints for cryptographic operations including signing and verification without requiring actual
HSM hardware.
"""

import base64
import os
from http import HTTPStatus
from typing import Any, Optional

from flask import Flask, Response, jsonify, request
from markupsafe import escape

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKey, PublicKey, PublicKeyEcc, PublicKeyRsa, SPSDKInvalidKeyType

APP = Flask(__name__)
THIS_DIR = os.path.dirname(__file__)
SUPPORTED_KEY_TYPES = ["rsa2048", "secp384r1"]


@APP.route("/signer/<key_type>/<int:num>", methods=["GET"])
def signer(key_type: str, num: int) -> Response:
    """Route (API) that performing the signing.

    API route that performs cryptographic signing operations.
    This endpoint accepts signing requests via HTTP, validates the key type and index,
    loads the corresponding private key, and returns the signature encoded in base64.

    :param key_type: Type of cryptographic key (e.g., 'rsa2048' or 'secp384r1').
    :param num: Index of the key to use for signing (rotation ID).
    :return: HTTP Response containing JSON with base64-encoded signature or error message.
    """
    json_data = request.get_json() or {}
    key_type = escape(key_type)
    if key_type not in SUPPORTED_KEY_TYPES:
        return Response(
            response=f"Unsupported key_type {key_type}.",
            status=HTTPStatus.BAD_REQUEST,
        )
    private_key = _load_private_key(key_type, num)
    if not private_key:
        return Response(
            response=f"Key of a type {key_type} with index {num} not found",
            status=HTTPStatus.BAD_REQUEST,
        )
    data_to_sign = bytes.fromhex(json_data.pop("data", request.args.get("data", "")))

    signature = sign_data(private_key, data_to_sign, **json_data)
    data = base64.b64encode(signature)
    return jsonify({"signature": data.decode("utf-8")})


@APP.route("/verifier/<key_type>/<int:num>", methods=["GET"])
def verifier(key_type: str, num: int) -> Response:
    """Verify if a private key matches the provided public key.

    API route that performs verification by comparing a stored private key
    with a public key provided in the request. The public key can be either
    ECC or RSA format and is automatically detected.

    :param key_type: Type of key algorithm (rsa2048 or secp384r1)
    :param num: Index of the private key to use for verification (rot_id)
    :raises SPSDKInvalidKeyType: When public key format is not supported
    :return: JSON response containing verification result with 'is_matching' boolean field
    """
    json_data = request.get_json() or {}
    key_type = escape(key_type)
    if key_type not in SUPPORTED_KEY_TYPES:
        return Response(
            response=f"Unsupported key_type {key_type}.",
            status=HTTPStatus.BAD_REQUEST,
        )
    private_key = _load_private_key(key_type, num)
    if not private_key:
        return Response(
            response=f"Key {key_type} with index {num} not found", status=HTTPStatus.BAD_REQUEST
        )

    public_key_bytes = bytes.fromhex(
        json_data.pop("public_key", request.args.get("public_key", ""))
    )
    try:
        request_public_key: PublicKey = PublicKeyEcc.parse(public_key_bytes)
    except SPSDKInvalidKeyType:
        request_public_key = PublicKeyRsa.parse(public_key_bytes)
    is_matching = private_key.verify_public_key(request_public_key)
    return jsonify({"is_matching": is_matching})


def sign_data(private_key: PrivateKey, data: bytes, **kwargs: Any) -> bytes:
    """Sign given data with private key.

    The method supports optional algorithm specification through kwargs and delegates
    the actual signing operation to the private key's sign method.

    :param private_key: Private key to be used for signing operation.
    :param data: Raw data bytes to be signed.
    :param kwargs: Additional keyword arguments, may include 'algorithm' for hash algorithm specification.
    :return: Digital signature as bytes.
    """
    algorithm = (
        EnumHashAlgorithm.from_label(kwargs.pop("algorithm")) if "algorithm" in kwargs else None
    )
    return private_key.sign(data=data, algorithm=algorithm, **kwargs)


def _load_private_key(key_type: str, num: int) -> Optional[PrivateKey]:
    """Load a private key from file by type and index.

    The method loads a private key from a PEM file located in the current directory.
    The filename format is 'hsm_k{num}_{key_type}.pem'.

    :param key_type: Type of the key to load, must be in SUPPORTED_KEY_TYPES.
    :param num: Index of the key to use (rot_id).
    :return: Loaded private key instance or None if key type unsupported or file not found.
    """
    if key_type not in SUPPORTED_KEY_TYPES:
        return None
    private_key_file = os.path.join(THIS_DIR, f"hsm_k{num}_{key_type}.pem")
    if not os.path.isfile(private_key_file):
        return None
    private_key = PrivateKey.load(private_key_file)
    return private_key


if __name__ == "__main__":
    APP.run(debug=True)

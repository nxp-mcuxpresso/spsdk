#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module represent a customer-specific HSM system."""
import base64
import os
from http import HTTPStatus
from typing import Optional

from flask import Flask, Response, jsonify, request
from markupsafe import escape

from spsdk.crypto.keys import (
    PrivateKey,
    PublicKey,
    PublicKeyEcc,
    PublicKeyRsa,
    SPSDKInvalidKeyType,
)

APP = Flask(__name__)
THIS_DIR = os.path.dirname(__file__)
SUPPORTED_KEY_TYPES = ["rsa2048", "secp384r1"]


@APP.route("/signer/<key_type>/<int:num>", methods=["GET"])
def signer(key_type: str, num: int) -> Response:
    """Route (API) that performing the signing.

    :param key_type: Type of key, might be rsa2048 or secp384r1
    :param num: Index of the key to use (rot_id)
    :return: Signature wrapped in json, encoded in base64
    """
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

    data_to_sign = base64.b64decode(request.args["data"])

    signature = sign_data(private_key, data_to_sign)
    data = base64.b64encode(signature)
    return jsonify({"signature": data.decode("utf-8")})


@APP.route("/verifier/<key_type>/<int:num>", methods=["GET"])
def verifier(key_type: str, num: int) -> Response:
    """Route (API) that performing the verification.

    :param key_type: Type of key, might be rsa2048 or secp384r1
    :param num: Index of the key to use (rot_id)
    :return: Verification status(true/false) wrapped in json
    """
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

    public_key_bytes = base64.b64decode(request.args["public_key"])
    try:
        request_public_key: PublicKey = PublicKeyEcc.parse(public_key_bytes)
    except SPSDKInvalidKeyType:
        request_public_key = PublicKeyRsa.parse(public_key_bytes)
    is_matching = private_key.verify_public_key(request_public_key)
    return jsonify({"is_matching": is_matching})


def sign_data(private_key: PrivateKey, data: bytes) -> bytes:
    """Sign given data with private key.

    :param private_key: Private key to be used for signing
    :param data: Data to be signed
    :return: Signature as bytes
    """
    return private_key.sign(data=data)


def _load_private_key(key_type: str, num: int) -> Optional[PrivateKey]:
    """Create an instance of SPSDK_RSAKey by its index.

    :param num: Index of the key to use (rot_id)
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

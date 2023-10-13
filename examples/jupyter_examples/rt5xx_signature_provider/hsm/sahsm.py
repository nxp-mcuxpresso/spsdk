#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module represent a customer-specific HSM system."""
import base64
import os
from http import HTTPStatus
from typing import Optional

from flask import Flask, Response, jsonify, request

from spsdk.crypto.keys import PrivateKeyRsa, PublicKeyRsa

APP = Flask(__name__)
THIS_DIR = os.path.dirname(__file__)


@APP.route("/signer/<int:num>", methods=["GET"])
def signer(num: int) -> Response:
    """Route (API) that performing the signing.

    :param num: Index of the key to use (rot_id)
    :return: Signature wrapped in json, encoded in base64
    """
    private_key = _load_private_key(num)
    if not private_key:
        return Response(response=f"Key with index {num} not found", status=HTTPStatus.BAD_REQUEST)

    data_to_sign = base64.b64decode(request.args["data"])

    signature = sign_data(private_key, data_to_sign)
    data = base64.b64encode(signature)
    return jsonify({"signature": data.decode("utf-8")})


@APP.route("/verifier/<int:num>", methods=["GET"])
def verifier(num: int) -> Response:
    """Route (API) that performing the verification.

    :param num: Index of the key to use (rot_id)
    :return: Verification status(true/false) wrapped in json
    """

    private_key = _load_private_key(num)
    if not private_key:
        return Response(response=f"Key with index {num} not found", status=HTTPStatus.BAD_REQUEST)
    public_key = private_key.get_public_key()

    public_key_bytes = base64.b64decode(request.args["public_key"])
    request_public_key = PublicKeyRsa.parse(public_key_bytes)
    is_matching = private_key.verify_public_key(request_public_key)
    return jsonify({"is_matching": is_matching})


def sign_data(private_key: PrivateKeyRsa, data: bytes) -> bytes:
    """Sign given data with private key.

    :param private_key: Private key to be used for signing
    :param data: Data to be signed
    :return: Signature as bytes
    """
    return private_key.sign(data=data)


def _load_private_key(num: int) -> Optional[PrivateKeyRsa]:
    """Create an instance of SPSDK_RSAKey by its index.

    :param num: Index of the key to use (rot_id)
    """
    private_key_file = os.path.join(THIS_DIR, f"hsm_k{num}_cert0_2048.pem")
    if not os.path.isfile(private_key_file):
        return None
    private_key = PrivateKeyRsa.load(private_key_file)
    # in this example we assume RSA keys
    return private_key


if __name__ == "__main__":
    APP.run(debug=True)

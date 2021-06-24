#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module represent a customer-specific HSM system."""
import base64
import os

from flask import Flask, Response, jsonify, request

from spsdk import crypto

APP = Flask(__name__)
THIS_DIR = os.path.dirname(__file__)


@APP.route("/signer/<int:num>", methods=["GET"])
def signer(num: int) -> Response:
    """Route (API) that performing the signing.

    :param num: Index of the key to use (rot_id)
    :return: Signature wrapped in json, encoded in base64
    """
    private_key_file = os.path.join(THIS_DIR, f"k{num}_cert0_2048.pem")
    private_key = crypto.load_private_key(private_key_file)

    # in this example we assume RSA keys
    assert isinstance(private_key, crypto.RSAPrivateKey)

    data_to_sign = base64.b64decode(request.args["data"])
    signature = private_key.sign(
        data=data_to_sign,
        padding=crypto.padding.PKCS1v15(),
        algorithm=crypto.hashes.SHA256(),
    )
    data = base64.b64encode(signature)
    return jsonify({"signature": data.decode("utf-8")})


if __name__ == "__main__":
    APP.run(debug=True)

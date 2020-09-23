#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module represent a customer-specific HSM system."""
import base64
import os

from flask import Flask, jsonify, request

from spsdk import crypto

app = Flask(__name__)   #pylint: disable=invalid-name
THIS_DIR = os.path.dirname(__file__)


@app.route('/signer/<int:num>', methods=['GET'])
def signer(num: int) -> dict:
    """Route (API) that performing the signing.

    :param num: Index of the key to use (rot_id)
    :return: Signature wrapped in json, encoded in base64
    """
    private_key_file = os.path.join(THIS_DIR, f"k{num}_cert0_2048.pem")
    private_key = crypto.load_private_key(private_key_file)

    data_to_sign = base64.b64decode(request.args['data'])
    signature = private_key.sign(
        data=data_to_sign,
        padding=crypto.padding.PKCS1v15(),
        algorithm=crypto.hashes.SHA256()
    )
    data = base64.b64encode(signature)
    return jsonify({'signature': data.decode('utf-8')})

if __name__ == "__main__":
    app.run(debug=True)

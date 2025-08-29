#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from flask import Flask, jsonify, request

app = Flask(__name__)

THIS_DIR = Path(__file__).parent


def load_key(key_id: int) -> bytes:
    """Load a key from a file based on the key ID.

    :param key_id: Unique identifier for the key
    :return: Bytes representation of the key
    """
    key_path = THIS_DIR / f"pck_{key_id}.txt"
    if not key_path.exists():
        raise ValueError(f"Key with ID {key_id} not found")
    key_hex = key_path.read_text().strip()
    return bytes.fromhex(key_hex)


def calculate_cmac(data: bytes, key: bytes):
    """Calculate CMAC for the given hex data using the provided key."""
    # Create a CMAC object with the key
    cmac_obj = cmac.CMAC(algorithms.AES(key))
    # Update with the data and finalize
    cmac_obj.update(data)
    signature = cmac_obj.finalize()

    return signature.hex()


@app.route("/api/cmac/<int:key_id>", methods=["GET"])
def cmac_endpoint(key_id: int):
    """Endpoint to calculate CMAC for provided data."""
    # Get JSON payload
    payload = request.get_json()

    # Validate payload
    if not payload or "data" not in payload:
        return jsonify({"error": "Missing 'data' field in request payload"}), 400

    data_hex = payload["data"]

    # Validate data is a hex string
    try:
        data = bytes.fromhex(data_hex)
    except Exception:
        return jsonify({"error": "Invalid hex string in 'data' field"}), 400

    # Load the key
    try:
        key = load_key(key_id=key_id)
    except Exception as e:
        return jsonify({"error": f"Key {key_id} couldn't be loaded: {e}"}), 404

    # Calculate CMAC
    try:
        cmac_result = calculate_cmac(data, key)
        return jsonify({"data": cmac_result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5010)

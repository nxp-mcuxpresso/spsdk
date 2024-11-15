#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EL2GO mock-up."""

import base64
import os
import sys

from flask import Flask, Response, jsonify, request

from spsdk.crypto.certificate import (
    Certificate,
    SPSDKEncoding,
    generate_extensions,
    generate_name,
    x509,
)
from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.utils.misc import load_configuration, load_text

APP = Flask(__name__)


@APP.route("/api/v1/wpc/product-unit-certificate/<qi_id>/request-puc", methods=["POST"])
def request_product_unit_certificate(qi_id: str) -> tuple[Response, int]:
    """Request for product Unit certificate.

    :param qi_id: QI ID
    :return: TODO
    """
    man_dir = os.path.join(FILES_DIR, str(int(qi_id)))
    if not os.path.isdir(man_dir):
        return jsonify({"error": f"qi_id '{qi_id}' not found"}), 404

    token = request.headers.get("El2G-Api-Key")
    config = load_configuration(os.path.join(man_dir, "config.yaml"))
    if not token:
        return jsonify({"error": "no-key"}), 401
    if token not in config["tokens"]:
        return jsonify({"error": "wrong-key"}), 401
    if not request.json:
        return jsonify({"error": "Invalid request body, need JSON"}), 400

    try:
        csr_data = request.json["pucRequestType"]["requests"][0]["csr"]
        csr = x509.load_pem_x509_csr(base64.b64decode(csr_data))
        uuid = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert isinstance(uuid, str)
        # user last 9B of uuid as RSID
        rsid = bytes.fromhex(uuid)[-9:]
        rsid_hex = rsid.rjust(9, b"\x00").hex()
        common_name = f"{qi_id.zfill(6)}"
        extra_text = config["extra_text"]
        if extra_text:
            common_name += f"-{extra_text}"
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        man_prk = PrivateKeyEcc.load(os.path.join(man_dir, config["manufacturer_prk"]))
        man_cert = Certificate.load(os.path.join(man_dir, config["manufacturer_crt"]))

        leaf_cert = Certificate.generate_certificate(
            subject=generate_name({"COMMON_NAME": common_name}),
            issuer=man_cert.subject,
            subject_public_key=PublicKeyEcc(csr.public_key()),  # type: ignore[arg-type]
            issuer_private_key=man_prk,
            extensions=generate_extensions({"WPC_QIAUTH_RSID": {"value": rsid_hex}}),
        )

        return (
            jsonify(
                {
                    "pucType": {
                        "rootCaHash": load_text(
                            os.path.join(man_dir, config["wpc_root_hash"])
                        ).strip(),
                        "productManufacturingCertificate": man_cert.export(
                            SPSDKEncoding.PEM
                        ).decode("utf-8"),
                        "certificate": leaf_cert.export(SPSDKEncoding.PEM).decode("utf-8"),
                    }
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fl2go.py <path/to/service>")
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.isdir(path):
        print(f"Path {path} doesn't exist or isn't a directory")
        sys.exit(1)
    if not os.path.isfile(os.path.join(path, "wpc_root.crt")):
        print(f"Path {path} doesn't look like valid data directory for fl2go")
        sys.exit(1)
    FILES_DIR = path
    APP.run(host="localhost", port=5000, debug=True)  # nosec

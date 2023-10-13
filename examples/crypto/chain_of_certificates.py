#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Example provides the usage of x.509 certificates.

It creates a chain of certificates.
"""

import os
from os import path

from spsdk.crypto.certificate import Certificate, generate_name
from spsdk.crypto.keys import PrivateKeyRsa, PublicKeyRsa
from spsdk.crypto.types import SPSDKEncoding

#          Certificates' structure
#              CA Certificate
#              /      \
#             /        \
#           crt       chain_crt
#                        \
#                         \
#                       chain_crt2


# pylint: disable=too-many-locals
def main() -> None:
    """Main function."""
    # Set the folder for data (certificates, keys)
    data_dir = path.join(path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)
    # load private key from data folder
    private_key_2048_ca = PrivateKeyRsa.load(path.join(data_dir, "ca_privatekey_rsa2048.pem"))
    # load associated public key
    public_key_2048_ca = PublicKeyRsa.load(path.join(data_dir, "ca_publickey_rsa2048.pem"))
    subject = issuer = generate_name([{"COMMON_NAME": "first"}, {"COUNTRY_NAME": "CZ"}])
    # generate CA certificate (self-signed certificate)
    ca_cert = Certificate.generate_certificate(
        subject=subject,
        issuer=issuer,
        subject_public_key=public_key_2048_ca,
        issuer_private_key=private_key_2048_ca,
        serial_number=0x1,
        if_ca=True,
        duration=20 * 365,
        path_length=5,
    )
    # Save certificates in two formats (pem and der)
    ca_cert.save(path.join(data_dir, "ca_cert_pem.crt"))
    ca_cert.save(path.join(data_dir, "ca_cert_der.crt"), encoding_type=SPSDKEncoding.DER)
    print("The CA Certificate was created in der and pem format.")

    # Create first chain certificate signed by private key of the CA certificate
    subject_crt1 = generate_name([{"COMMON_NAME": "second"}, {"COUNTRY_NAME": "CZ"}])
    public_key_2048_subject = PublicKeyRsa.load(path.join(data_dir, "crt_publickey_rsa2048.pem"))
    crt1 = Certificate.generate_certificate(
        subject=subject_crt1,
        issuer=issuer,
        subject_public_key=public_key_2048_subject,
        issuer_private_key=private_key_2048_ca,
        serial_number=0x3CC30000BABADEDA,
        if_ca=False,
        duration=20 * 365,
    )
    # Save certificates in two formats (pem and der)
    crt1.save(path.join(data_dir, "crt_pem.crt"))
    crt1.save(path.join(data_dir, "crt_der.crt"), encoding_type=SPSDKEncoding.DER)
    print(
        "The first chain certificate (signed by CA certificate) was created in der and pem format."
    )

    # First chain certificate signed by private key of the CA certificate
    subject_crt2 = generate_name([{"COMMON_NAME": "third"}, {"COUNTRY_NAME": "CZ"}])
    private_key_2048_subject_1 = PrivateKeyRsa.load(
        path.join(data_dir, "chain_privatekey_rsa2048.pem")
    )
    public_key_2048_subject_1 = PublicKeyRsa.load(
        path.join(data_dir, "chain_publickey_rsa2048.pem")
    )
    crt2 = Certificate.generate_certificate(
        subject=subject_crt2,
        issuer=issuer,
        subject_public_key=public_key_2048_subject_1,
        issuer_private_key=private_key_2048_ca,
        serial_number=0x2,
        if_ca=True,
        duration=20 * 365,
        path_length=3,
    )
    # Save certificates in two formats (pem and der)
    crt2.save(path.join(data_dir, "chain_crt_pem.crt"))
    crt2.save(path.join(data_dir, "chain_crt_der.crt"), encoding_type=SPSDKEncoding.DER)
    print(
        "The first chain certificate (signed by CA certificate) was created in der and pem format."
    )

    # Create first chain certificate signed by private key of first certificate
    subject_crt3 = generate_name([{"COMMON_NAME": "fourth"}, {"COUNTRY_NAME": "CZ"}])
    issuer_crt3 = subject_crt2
    public_key_2048_subject_2 = PublicKeyRsa.load(
        path.join(data_dir, "chain_crt2_publickey_rsa2048.pem")
    )
    assert isinstance(public_key_2048_subject_2, PublicKeyRsa)
    crt3 = Certificate.generate_certificate(
        subject=subject_crt3,
        issuer=issuer_crt3,
        subject_public_key=public_key_2048_subject_2,
        issuer_private_key=private_key_2048_subject_1,
        serial_number=0x3CC30000BABADEDA,
        if_ca=False,
        duration=20 * 365,
    )
    # Save certificates in two formats (pem and der)
    crt3.save(path.join(data_dir, "chain_crt2_pem.crt"))
    crt3.save(path.join(data_dir, "chain_crt2_der.crt"), encoding_type=SPSDKEncoding.DER)
    print("The second certificate in a chain was created in der and pem format.")


if __name__ == "__main__":
    main()

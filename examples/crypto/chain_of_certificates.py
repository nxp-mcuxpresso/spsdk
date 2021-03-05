#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Example provides the usage of x.509 certificates.

It creates a chain of certificates.
"""

import os
from os import path

from spsdk.crypto import generate_certificate, save_crypto_item, \
    load_private_key, x509, Encoding, load_public_key, RSAPublicKey, RSAPrivateKey, generate_name_struct


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
    data_dir = path.join(path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    # load private key from data folder
    private_key_2048_ca = load_private_key(path.join(data_dir, "ca_privatekey_rsa2048.pem"))
    assert isinstance(private_key_2048_ca, RSAPrivateKey)
    # load associated public key
    public_key_2048_ca = load_public_key(path.join(data_dir, "ca_publickey_rsa2048.pem"))
    assert isinstance(public_key_2048_ca, RSAPublicKey)
    subject = issuer = generate_name_struct("first", "CZ")
    # generate CA certificate (self-signed certificate)
    ca_cert = generate_certificate(subject=subject, issuer=issuer, subject_public_key=public_key_2048_ca,
                                   issuer_private_key=private_key_2048_ca, serial_number=0x1,
                                   if_ca=True, duration=20 * 365, path_length=5)
    # Save certificates in two formats (pem and der)
    save_crypto_item(ca_cert, path.join(data_dir, "ca_cert_pem.crt"))
    save_crypto_item(ca_cert, path.join(data_dir, "ca_cert_der.crt"), encoding_type=Encoding.DER)
    print("The CA Certificate was created in der and pem format.")

    # Create first chain certificate signed by private key of the CA certificate
    subject_crt1 = generate_name_struct("second", "CZ")
    public_key_2048_subject = load_public_key(path.join(data_dir, "crt_publickey_rsa2048.pem"))
    assert isinstance(public_key_2048_subject, RSAPublicKey)
    crt1 = generate_certificate(subject=subject_crt1, issuer=issuer, subject_public_key=public_key_2048_subject,
                                issuer_private_key=private_key_2048_ca,
                                serial_number=0x3cc30000babadeda, if_ca=False, duration=20 * 365)
    # Save certificates in two formats (pem and der)
    save_crypto_item(crt1, path.join(data_dir, "crt_pem.crt"))
    save_crypto_item(crt1, path.join(data_dir, "crt_der.crt"), encoding_type=Encoding.DER)
    print("The first chain certificate (signed by CA certificate) was created in der and pem format.")

    # First chain certificate signed by private key of the CA certificate
    subject_crt2 = generate_name_struct("third", "CZ")
    private_key_2048_subject_1 = load_private_key(path.join(data_dir, "chain_privatekey_rsa2048.pem"))
    assert isinstance(private_key_2048_subject_1, RSAPrivateKey)
    public_key_2048_subject_1 = load_public_key(path.join(data_dir, "chain_publickey_rsa2048.pem"))
    assert isinstance(public_key_2048_subject_1, RSAPublicKey)
    crt1 = generate_certificate(subject=subject_crt2, issuer=issuer, subject_public_key=public_key_2048_subject_1,
                                issuer_private_key=private_key_2048_ca,
                                serial_number=0x2, if_ca=True, duration=20 * 365, path_length=3)
    # Save certificates in two formats (pem and der)
    save_crypto_item(crt1, path.join(data_dir, "chain_crt_pem.crt"))
    save_crypto_item(crt1, path.join(data_dir, "chain_crt_der.crt"), encoding_type=Encoding.DER)
    print("The first chain certificate (signed by CA certificate) was created in der and pem format.")

    # Create first chain certificate signed by private key of first certificate
    subject_crt3 = generate_name_struct("fourth", "CZ")
    issuer_crt3 = subject_crt2
    public_key_2048_subject_2 = load_public_key(path.join(data_dir, "chain_crt2_publickey_rsa2048.pem"))
    assert isinstance(public_key_2048_subject_2, RSAPublicKey)
    crt1 = generate_certificate(subject=subject_crt3, issuer=issuer_crt3, subject_public_key=public_key_2048_subject_2,
                                issuer_private_key=private_key_2048_subject_1,
                                serial_number=0x3cc30000babadeda, if_ca=False, duration=20 * 365)
    # Save certificates in two formats (pem and der)
    save_crypto_item(crt1, path.join(data_dir, "chain_crt2_pem.crt"))
    save_crypto_item(crt1, path.join(data_dir, "chain_crt2_der.crt"), encoding_type=Encoding.DER)
    print("The second certificate in a chain was created in der and pem format.")


if __name__ == "__main__":
    main()

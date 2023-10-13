#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Example provides the usage of certificates validation. It validates previously created chains."""

#          Certificates' structure
#              CA Certificate
#              /      \
#             /        \
#           crt       chain_crt
#                        \
#                         \
#                      chain_crt2
import os
from os import path

from spsdk.crypto.certificate import Certificate, validate_certificate_chain
from spsdk.crypto.keys import PublicKeyRsa
from spsdk.exceptions import SPSDKError


def main() -> None:
    """Main function."""
    # Set the folder for data (certificates, keys)
    data_dir = path.join(path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)
    # Load public key of CA certificate
    ca0_pubkey_rsa2048 = PublicKeyRsa.load(path.join(data_dir, "ca_publickey_rsa2048.pem"))
    # Load CA certificate
    ca0_cert = Certificate.load(path.join(data_dir, "ca_cert_pem.crt"))
    # Obtain public key from CA certificate
    pubkey_from_ca0_cert = ca0_cert.get_public_key()
    # Compare CA's public key from file and the one from certificate
    if ca0_pubkey_rsa2048 == pubkey_from_ca0_cert:
        raise SPSDKError("Keys are not the same (the one from disc and the one from cert)")
    # Load certificate, which is singed by CA
    crt = Certificate.load(path.join(data_dir, "crt_pem.crt"))
    if not ca0_cert.validate_subject(crt):
        raise SPSDKError("The certificate is not valid")
    print("The certificate was signed by the CA.")
    # Load chain of certificate
    chain = ["chain_crt2_pem.crt", "chain_crt_pem.crt", "ca_cert_pem.crt"]
    chain_cert = [Certificate.load(path.join(data_dir, cert_name)) for cert_name in chain]
    ch3_crt2 = Certificate.load(path.join(data_dir, "chain_crt2_pem.crt"))
    ch3_crt = Certificate.load(path.join(data_dir, "chain_crt_pem.crt"))
    ch3_ca = Certificate.load(path.join(data_dir, "ca_cert_pem.crt"))
    # Validate the chain (if corresponding items in chain are singed by one another)
    if not validate_certificate_chain(chain_cert):
        raise SPSDKError("The certificate chain is not valid")
    print("The chain of certificates is valid.")
    # Checks if CA flag is set correctly
    if ch3_crt2.ca:
        raise SPSDKError("CA flag is set")
    if not ch3_crt.ca:
        raise SPSDKError("CA flag is not set")
    if not ch3_ca.ca:
        raise SPSDKError("CA flag is not set")


if __name__ == "__main__":
    main()

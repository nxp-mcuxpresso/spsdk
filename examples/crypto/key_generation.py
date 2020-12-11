#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Key generation example provides the usage of RSA keys generation (private, public key).

This example has to be run as first before running the examples for certificates,
because it provides keys for certificate's generation.
"""

import os
from os import path
from spsdk.crypto.keys_management import (
    generate_rsa_private_key, generate_rsa_public_key, save_rsa_private_key, save_rsa_public_key, Encoding,
    generate_ecc_private_key, generate_ecc_public_key, save_ecc_private_key, save_ecc_public_key
)


def main() -> None:
    """Main function."""
    # Set the folder for data (certificates, keys)
    data_dir = path.join(path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)

    # Generate and save rsa keys (size 2048) - pem format (for usage of CA certificate)
    priv_key_2048 = generate_rsa_private_key(key_size=2048)
    pub_key_2048 = generate_rsa_public_key(priv_key_2048)
    save_rsa_private_key(priv_key_2048, path.join(data_dir, "ca_privatekey_rsa2048.pem"))
    save_rsa_public_key(pub_key_2048, path.join(data_dir, "ca_publickey_rsa2048.pem"))
    print("The pair of private (ca_privatekey_rsa2048.pem) and public (ca_publickey_rsa2048.pem) key was generated.")

    # Generate and save rsa keys (size 2048) - pem format (for usage of chain of certificate)
    priv_key_2048 = generate_rsa_private_key(key_size=2048)
    pub_key_2048 = generate_rsa_public_key(priv_key_2048)
    save_rsa_private_key(priv_key_2048, path.join(data_dir, "crt_privatekey_rsa2048.pem"))
    save_rsa_public_key(pub_key_2048, path.join(data_dir, "crt_publickey_rsa2048.pem"))
    print("The pair of private (crt_privatekey_rsa2048.pem) and public (crt_publickey_rsa2048.pem) key was generated.")

    # Generate and save rsa keys (size 2048) - pem format (for usage of chain of certificate)
    priv_key_2048 = generate_rsa_private_key(key_size=2048)
    pub_key_2048 = generate_rsa_public_key(priv_key_2048)
    save_rsa_private_key(priv_key_2048, path.join(data_dir, "chain_privatekey_rsa2048.pem"))
    save_rsa_public_key(pub_key_2048, path.join(data_dir, "chain_publickey_rsa2048.pem"))
    print("The pair of private (chain_privatekey_rsa2048.pem) and public (chain_publickey_rsa2048.pem) key was "
          "generated.")

    # Generate and save rsa keys (size 2048) - pem format (for usage of chain of certificate)
    priv_key_2048 = generate_rsa_private_key(key_size=2048)
    pub_key_2048 = generate_rsa_public_key(priv_key_2048)
    save_rsa_private_key(priv_key_2048, path.join(data_dir, "chain_crt2_privatekey_rsa2048.pem"))
    save_rsa_public_key(pub_key_2048, path.join(data_dir, "chain_crt2_publickey_rsa2048.pem"))
    print("The pair of private (chain_crt2_privatekey_rsa2048.pem) and public (chain_crt2_publickey_rsa2048.pem) key "
          "was generated.")

    # Generate and save rsa keys (size 3072) - pem format
    priv_key_3072 = generate_rsa_private_key(key_size=3072)
    pub_key_3072 = generate_rsa_public_key(priv_key_3072)
    save_rsa_private_key(priv_key_3072, path.join(data_dir, "private_rsa3072.pem"))
    save_rsa_public_key(pub_key_3072, path.join(data_dir, "public_rsa3072.pem"))
    print("The pair of private (private_rsa3072.pem) and public (public_rsa3072.pem) key was generated.")

    # Generate and save rsa keys (size 4096) - pem format
    priv_key_4096 = generate_rsa_private_key(key_size=4096)
    pub_key_4096 = generate_rsa_public_key(priv_key_4096)
    save_rsa_private_key(priv_key_4096, path.join(data_dir, "private_rsa4096.pem"))
    save_rsa_public_key(pub_key_4096, path.join(data_dir, "public_rsa4096.pem"))
    print("The pair of private (private_rsa4096.pem) and public (public_rsa4096.pem) key was generated.")

    # Generate and save rsa keys (size 2048) - der format
    priv_key_2048 = generate_rsa_private_key(key_size=2048)
    pub_key_2048 = generate_rsa_public_key(priv_key_2048)
    save_rsa_private_key(priv_key_2048, path.join(data_dir, "private_rsa2048.der"), encoding=Encoding.DER)
    save_rsa_public_key(pub_key_2048, path.join(data_dir, "public_rsa2048.der"), encoding=Encoding.DER)
    print("The pair of private (private_rsa2048.der) and public (public_rsa2048.der) key was generated.")

    # Generate and save rsa keys (size 3072) - der format
    priv_key_3072 = generate_rsa_private_key(key_size=3072)
    pub_key_3072 = generate_rsa_public_key(priv_key_3072)
    save_rsa_private_key(priv_key_3072, path.join(data_dir, "private_rsa3072.der"), encoding=Encoding.DER)
    save_rsa_public_key(pub_key_3072, path.join(data_dir, "public_rsa3072.der"), encoding=Encoding.DER)
    print("The pair of private (private_rsa3072.der) and public (public_rsa3072.der) key was generated.")

    # Generate and save rsa keys (size 4096) - der format
    priv_key_4096 = generate_rsa_private_key(key_size=4096)
    pub_key_4096 = generate_rsa_public_key(priv_key_4096)
    save_rsa_private_key(priv_key_4096, path.join(data_dir, "private_rsa4096.der"), encoding=Encoding.DER)
    save_rsa_public_key(pub_key_4096, path.join(data_dir, "public_rsa4096.der"), encoding=Encoding.DER)
    print("The pair of private (private_rsa4096.der) and public (public_rsa4096.der) key was generated.")

    # Generate and save ECC keys (curve P-256) - pem format
    priv_key_p256 = generate_ecc_private_key(curve_name='P-256')
    pub_key_p256 = generate_ecc_public_key(priv_key_p256)
    save_ecc_private_key(priv_key_p256, path.join(data_dir, "ecc_privatekey_p256.pem"))
    save_ecc_public_key(pub_key_p256, path.join(data_dir, "ecc_publickey_p256.pem"))
    print("The pair of private (ecc_privatekey_p256.pem) and public (ecc_publickey_p256.pem) key was generated.")


if __name__ == "__main__":
    main()

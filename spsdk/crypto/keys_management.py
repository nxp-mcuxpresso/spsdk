#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for key generation and saving keys to file."""

from spsdk.crypto import default_backend, RSAPublicKey, serialization, \
    rsa, RSAPrivateKeyWithSerialization, Encoding


def generate_rsa_private_key(key_size: int = 2048, exponent: int = 65537) -> RSAPrivateKeyWithSerialization:
    """Generate RSA private key.

    :param key_size: key size in bits; must be >= 512
    :param exponent: public exponent; must be >= 3 and odd
    :return: RSA private key with serialization
    """
    return rsa.generate_private_key(backend=default_backend(), public_exponent=exponent, key_size=key_size)


def generate_rsa_public_key(private_key: RSAPrivateKeyWithSerialization) -> RSAPublicKey:
    """Generate RSA public key.

    :param private_key: private key used for public key generation
    :return: RSA public key
    """
    return private_key.public_key()


def save_private_key(private_key: RSAPrivateKeyWithSerialization, file_path: str, password: bytes = None,
                     encoding: Encoding = Encoding.PEM) -> None:
    """Save the RSA private key to the given file.

    :param private_key: RSA private key to be saved
    :param file_path: path to the file, where the key will be stored
    :param password: password to private key; None to store without password
    :param encoding: encoding type, default is PEM
    """
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem_data = private_key.private_bytes(encoding, serialization.PrivateFormat.PKCS8, enc)
    with open(file_path, 'wb') as f:
        f.write(pem_data)


def save_public_key(public_key: RSAPublicKey, file_path: str, encoding: Encoding = Encoding.PEM) -> None:
    """Save the RSA public key to the file.

    :param public_key: public key to be saved
    :param file_path: path to the file, where the key will be stored
    :param encoding: encoding type, default is PEM
    """
    pem_data = public_key.public_bytes(encoding, serialization.PublicFormat.PKCS1)
    with open(file_path, 'wb') as f:
        f.write(pem_data)

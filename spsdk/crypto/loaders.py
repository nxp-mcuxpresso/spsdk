#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Loading methods for keys/certificates/CSR."""

from typing import Callable, Any, Union

from spsdk.crypto import (
    default_backend,
    RSAPrivateKeyWithSerialization,
    RSAPublicKey,
    Certificate,
    load_pem_x509_certificate,
    load_der_x509_certificate,
    load_pem_public_key,
    load_der_public_key,
    load_pem_private_key,
    load_der_private_key,
    Encoding,
    EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePublicKey,
)

PrivateKey = Union[RSAPrivateKeyWithSerialization, EllipticCurvePrivateKeyWithSerialization]
PublicKey = Union[RSAPublicKey, EllipticCurvePublicKey]


def load_private_key(
    file_path: str, password: bytes = None, encoding: Encoding = None
) -> PrivateKey:
    """Load private key from file.

    :param file_path: path to file, where private key is stored
    :param password: password for key
    :param encoding: encoding type of key
    :return: RSA private key
    """
    real_encoding = encoding or _get_encoding_type(file_path)

    def solve(key_data: bytes) -> PrivateKey:
        """Determine the type of data and perform loading based on data type.

        :param key_data: given private keys data
        :return: loaded private key
        """
        return {  # type: ignore
            Encoding.PEM: load_pem_private_key,
            Encoding.DER: load_der_private_key,
        }[real_encoding](key_data, password, default_backend())

    return generic_load(file_path, solve)


def load_public_key(file_path: str, encoding: Encoding = None) -> PublicKey:
    """Load the public key from file.

    :param file_path: path to file, where public key is stored
    :param encoding: encoding type of key
    :return: RSA public key
    """
    real_encoding = encoding or _get_encoding_type(file_path)

    def solve(key_data: bytes) -> PublicKey:
        """Determine the type of data and perform loading based on data type.

        :param key_data: given public keys data
        :return: loaded public key
        """
        return {  # type: ignore
            Encoding.PEM: load_pem_public_key,
            Encoding.DER: load_der_public_key,
        }[real_encoding](key_data, default_backend())

    return generic_load(file_path, solve)


def load_certificate(file_path: str, encoding: Encoding = None) -> Certificate:
    """Load the certificate from file.

    :param file_path: path to file, where certificate is stored
    :param encoding: type of encoding
    :return: Certificate
    """
    real_encoding = encoding or _get_encoding_type(file_path)

    def solve(certificate_data: bytes) -> Certificate:
        """Determine the type of data and perform loading based on data type.

        :param certificate_data: given certificate data
        :return: loaded certificate
        """
        return {  # type: ignore
            Encoding.PEM: load_pem_x509_certificate,
            Encoding.DER: load_der_x509_certificate,
        }[real_encoding](certificate_data, default_backend())

    return generic_load(file_path, solve)


def generic_load(file_path: str, inner_fun: Callable) -> Any:
    """General loading of item.

    :param file_path: path to file, where item is stored
    :param inner_fun: function, which distinguish what will be loaded
    :return: data, which are stored under file
    """
    with open(file_path, "rb") as f:
        data = f.read()
    try:
        return inner_fun(data)
    except ValueError:
        return None


def _get_encoding_type(file: str) -> Encoding:
    """Get the encoding type out of given item from the file.

    :param file: name of file, where item is stored
    :return: encoding type (Encoding.PEM, Encoding.DER)
    """
    try:
        with open(file, "r") as f:
            f.read()
    except UnicodeDecodeError:
        encoding = Encoding.DER
    else:
        encoding = Encoding.PEM
    return encoding

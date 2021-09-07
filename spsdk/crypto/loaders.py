#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Loading methods for keys/certificates/CSR."""

from typing import Any, Callable, Iterable, List, Optional

from cryptography.hazmat._types import _PRIVATE_KEY_TYPES as PrivateKey
from cryptography.hazmat._types import _PUBLIC_KEY_TYPES as PublicKey

from spsdk import SPSDKError
from spsdk.crypto import (
    Certificate,
    Encoding,
    default_backend,
    load_der_private_key,
    load_der_public_key,
    load_der_x509_certificate,
    load_pem_private_key,
    load_pem_public_key,
    load_pem_x509_certificate,
)


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
    :return: Certificate (from cryptography library)
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


def load_certificate_as_bytes(file_path: str) -> bytes:
    """Load certificate from file in PEM/DER format.

    Converts the certificate into DER format and serializes it into bytes.

    :param file_path: path to certificate file.
    :return: certificate in der format serialized into bytes.
    """
    return load_certificate(file_path).public_bytes(encoding=Encoding.DER)


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


def extract_public_key(file_path: str, password: Optional[str]) -> PublicKey:
    """Extract any kind of public key from a file that contains Certificate, Private Key or Public Key.

    :raises SPSDKError: Raised when file can not be loaded
    :return: private key of any type

    """
    cert_candidate = load_certificate(file_path)
    if cert_candidate:
        return cert_candidate.public_key()
    private_candidate = load_private_key(file_path, password.encode() if password else None)
    if private_candidate:
        return private_candidate.public_key()
    public_candidate = load_public_key(file_path)
    if public_candidate:
        return public_candidate
    raise SPSDKError(f"Unable to load secret file '{file_path}'.")


def extract_public_keys(secret_files: Iterable[str], password: Optional[str]) -> List[PublicKey]:
    """Extract any kind of public key from files that contain Certificate, Private Key or Public Key."""
    return [extract_public_key(file_path=source, password=password) for source in secret_files]

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Loading methods for keys/certificates/CSR."""

from typing import Iterable, List, Optional

from spsdk import SPSDKError
from spsdk.crypto import (
    Certificate,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    Encoding,
    PrivateKey,
    PublicKey,
    RSAPrivateKey,
    RSAPublicKey,
    _PublicKeyTuple,
    default_backend,
    load_der_private_key,
    load_der_public_key,
    load_der_x509_certificate,
    load_pem_private_key,
    load_pem_public_key,
    load_pem_x509_certificate,
)
from spsdk.utils.misc import load_binary


def load_private_key_from_data(
    data: bytes, password: Optional[bytes] = None, encoding: Optional[Encoding] = None
) -> PrivateKey:
    """Load private key from bytes.

    :param data: data of private key loaded from file
    :param password: password for key
    :param encoding: encoding type of key
    :return: RSA private key
    :raises SPSDKError: Unsupported private key to load
    """
    real_encoding = encoding or _get_encoding_type(data)

    try:
        private_key = {Encoding.PEM: load_pem_private_key, Encoding.DER: load_der_private_key,}[
            real_encoding
        ](data, password, default_backend())
        assert isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey))
        return private_key
    except ValueError as exc:
        raise SPSDKError(f"Cannot load private key: ({str(exc)})") from exc


def load_private_key(
    file_path: str, password: Optional[bytes] = None, encoding: Optional[Encoding] = None
) -> PrivateKey:
    """Load private key from file.

    :param file_path: path to file, where private key is stored
    :param password: password for key
    :param encoding: encoding type of key
    :return: RSA/ECC private key
    """
    data = load_binary(file_path)
    return load_private_key_from_data(data, password, encoding)


def load_public_key_from_data(data: bytes, encoding: Optional[Encoding] = None) -> PublicKey:
    """Load the public key from bytes.

    :param data: data of public key loaded from file
    :param encoding: encoding type of key
    :return: RSA public key
    :raises SPSDKError: Unsupported public key to load
    """
    real_encoding = encoding or _get_encoding_type(data)

    try:
        public_key = {Encoding.PEM: load_pem_public_key, Encoding.DER: load_der_public_key,}[
            real_encoding
        ](data, default_backend())
        assert isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey))
        return public_key
    except ValueError as exc:
        raise SPSDKError(f"Cannot load public key: ({str(exc)})") from exc


def load_public_key(file_path: str, encoding: Optional[Encoding] = None) -> PublicKey:
    """Load the public key from file.

    :param file_path: path to file, where public key is stored
    :param encoding: encoding type of key
    :return: RSA public key
    """
    data = load_binary(file_path)
    return load_public_key_from_data(data, encoding)


def load_certificate_from_data(data: bytes, encoding: Optional[Encoding] = None) -> Certificate:
    """Load the certificate from bytes.

    :param data: data with certificate loaded from file
    :param encoding: type of encoding
    :return: Certificate (from cryptography library)
    :raises SPSDKError: Unsupported certificate to load
    """
    real_encoding = encoding or _get_encoding_type(data)
    try:
        return {Encoding.PEM: load_pem_x509_certificate, Encoding.DER: load_der_x509_certificate,}[
            real_encoding
        ](data, default_backend())
    except ValueError as exc:
        raise SPSDKError(f"Cannot load certificate: ({str(exc)})") from exc


def load_certificate(file_path: str, encoding: Optional[Encoding] = None) -> Certificate:
    """Load the certificate from file.

    :param file_path: path to file, where certificate is stored
    :param encoding: type of encoding
    :return: Certificate (from cryptography library)
    """
    data = load_binary(file_path)
    return load_certificate_from_data(data, encoding)


def load_certificate_as_bytes(file_path: str) -> bytes:
    """Load certificate from file in PEM/DER format.

    Converts the certificate into DER format and serializes it into bytes.

    :param file_path: path to certificate file.
    :return: certificate in der format serialized into bytes.
    """
    return load_certificate(file_path).public_bytes(encoding=Encoding.DER)


def _get_encoding_type(data: bytes) -> Encoding:
    """Get the encoding type out of given item from the data.

    :param file: name of file, where item is stored
    :return: encoding type (Encoding.PEM, Encoding.DER)
    """
    encoding = Encoding.PEM
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        encoding = Encoding.DER
    else:
        if decoded.find("----") == -1:
            encoding = Encoding.DER
    return encoding


def extract_public_key_from_data(object_data: bytes, password: Optional[str] = None) -> PublicKey:
    """Extract any kind of public key from a data that contains Certificate, Private Key or Public Key.

    :raises SPSDKError: Raised when file can not be loaded
    :return: private key of any type
    """
    try:
        cert_candidate = load_certificate_from_data(object_data)
        public_key = cert_candidate.public_key()
        assert isinstance(public_key, _PublicKeyTuple)
        return public_key
    except SPSDKError:
        pass

    try:
        private_candidate = load_private_key_from_data(
            object_data, password.encode() if password else None
        )
        return private_candidate.public_key()
    except SPSDKError:
        pass

    try:
        public_candidate = load_public_key_from_data(object_data)
        return public_candidate
    except SPSDKError as exc:
        raise SPSDKError("Unable to load secret data.") from exc


def extract_public_key(
    file_path: str, password: Optional[str] = None, search_paths: Optional[List[str]] = None
) -> PublicKey:
    """Extract any kind of public key from a file that contains Certificate, Private Key or Public Key.

    :param file_path: File path to public key file.
    :param password: Optional password for encrypted Private file source.
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKError: Raised when file can not be loaded
    :return: Public key of any type
    """
    try:
        object_data = load_binary(file_path, search_paths=search_paths)
        return extract_public_key_from_data(object_data, password)
    except SPSDKError as exc:
        raise SPSDKError(f"Unable to load secret file '{file_path}'.") from exc


def extract_public_keys(
    secret_files: Iterable[str],
    password: Optional[str] = None,
    search_paths: Optional[List[str]] = None,
) -> List[PublicKey]:
    """Extract any kind of public key from files that contain Certificate, Private Key or Public Key.

    :param secret_files: List of file paths to public key files.
    :param password: Optional password for encrypted Private file source.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: List of public keys of any type
    """
    return [
        extract_public_key(file_path=source, password=password, search_paths=search_paths)
        for source in secret_files
    ]

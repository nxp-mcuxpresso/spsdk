#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for security backend."""

from typing import Any, Iterable, Optional

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKey, PublicKey
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import load_binary


def get_matching_key_id(public_keys: list[PublicKey], signature_provider: SignatureProvider) -> int:
    """Get index of public key that match to given private key.

    :param public_keys: List of public key used to find the match for the private key.
    :param signature_provider: Signature provider used to try to match public key index.
    :raises SPSDKValueError: No match found.
    :return: Index of public key.
    """
    for i, public_key in enumerate(public_keys):
        if signature_provider.verify_public_key(public_key):
            return i

    raise SPSDKValueError("There is no match of private key in given list.")


def get_matching_key_id_from_signature(
    public_keys: list[PublicKey],
    signed_data: bytes,
    signature: bytes,
    algorithm: Optional[EnumHashAlgorithm] = None,
    **kwargs: Any,
) -> int:
    """Get index of public key that match to given signed data and signature.

    :param public_keys: List of public key used to find the match for the private key
    :param signed_data: Signed data
    :param signature: Signature to signed data
    :param algorithm: Used algorithm, automatic detection - None
    :param kwargs: Keyword arguments for specific type of key
    :raises SPSDKValueError: No match found
    :return: Index of public key
    """
    for i, public_key in enumerate(public_keys):
        if public_key.verify_signature(signature, signed_data, algorithm, **kwargs):
            return i

    raise SPSDKValueError("There is no match of signature in given list.")


def extract_public_key_from_data(object_data: bytes, password: Optional[str] = None) -> PublicKey:
    """Extract any kind of public key from a data that contains Certificate, Private Key or Public Key.

    :raises SPSDKError: Raised when file can not be loaded
    :return: private key of any type
    """
    try:
        cert = Certificate.parse(object_data)
        key = cert.get_public_key()
        if cert.ca:
            # In case of CA certificate, return the public key with the 'ca' attribute set to True
            setattr(key, "ca", True)
        return key
    except SPSDKError:
        pass

    try:
        return PrivateKey.parse(
            object_data, password=password if password else None
        ).get_public_key()
    except SPSDKError:
        pass

    try:
        return PublicKey.parse(object_data)
    except SPSDKError as exc:
        raise SPSDKError("Unable to load secret data.") from exc


def extract_public_key(
    file_path: str, password: Optional[str] = None, search_paths: Optional[list[str]] = None
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
    search_paths: Optional[list[str]] = None,
) -> list[PublicKey]:
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


def get_hash_type_from_signature_size(signature_size: int) -> EnumHashAlgorithm:
    """Return hash type from ECC signature size."""
    if signature_size == 64:
        return EnumHashAlgorithm.SHA256
    if signature_size == 96:
        return EnumHashAlgorithm.SHA384
    if signature_size == 132:
        return EnumHashAlgorithm.SHA512
    raise SPSDKValueError("Unknown signature size")

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic utilities and helper functions.

This module provides essential cryptographic utility functions for key management,
certificate handling, and cryptographic operations across the SPSDK framework.
It includes functionality for key generation, public key extraction, signature
validation, and cryptographic type conversions.
"""

import logging
import os
from typing import Any, Callable, Iterable, Optional

from spsdk.crypto.certificate import Certificate, generate_extensions, generate_name
from spsdk.crypto.crypto_types import SPSDKEncoding, SPSDKName
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKey, PublicKey, get_supported_keys_generators
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


def get_matching_key_id(public_keys: list[PublicKey], signature_provider: SignatureProvider) -> int:
    """Get index of public key that matches the given private key.

    The method iterates through the list of public keys and uses the signature provider to verify
    which public key corresponds to the private key held by the signature provider.

    :param public_keys: List of public keys used to find the match for the private key.
    :param signature_provider: Signature provider used to try to match public key index.
    :raises SPSDKValueError: No match found between private key and any public key in the list.
    :return: Index of the matching public key in the provided list.
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
    """Get index of public key that matches given signed data and signature.

    The method iterates through the provided public keys and verifies which one
    can successfully validate the given signature against the signed data.

    :param public_keys: List of public keys to search for matching private key.
    :param signed_data: The data that was signed.
    :param signature: The signature to verify against the signed data.
    :param algorithm: Hash algorithm to use for verification, None for auto-detection.
    :param kwargs: Additional keyword arguments for specific key types.
    :raises SPSDKValueError: When no matching public key is found.
    :return: Index of the matching public key in the provided list.
    """
    for i, public_key in enumerate(public_keys):
        if public_key.verify_signature(signature, signed_data, algorithm, **kwargs):
            return i

    raise SPSDKValueError("There is no match of signature in given list.")


def extract_public_key_from_data(object_data: bytes, password: Optional[str] = None) -> PublicKey:
    """Extract any kind of public key from data containing Certificate, Private Key or Public Key.

    The method attempts to parse the input data as a certificate first, then as a private key,
    and finally as a public key. For CA certificates, the returned public key will have the
    'ca' attribute set to True.

    :param object_data: Raw data containing certificate, private key, or public key.
    :param password: Optional password for encrypted private keys.
    :raises SPSDKError: Raised when data cannot be parsed as any supported key format.
    :return: Extracted public key of any supported type.
    """
    try:
        cert = Certificate.parse(object_data)
        key = cert.get_public_key()
        if cert.ca:
            # In case of CA certificate, return the public key with the 'ca' attribute set to True
            setattr(key, "ca", True)

        return key
    except SPSDKError as exc:
        logger.debug(f"Failed to parse certificate: {exc}")

    try:
        return PrivateKey.parse(
            object_data, password=password if password else None
        ).get_public_key()
    except SPSDKError as exc:
        logger.debug(f"Failed to parse private key: {exc}")

    try:
        return PublicKey.parse(object_data)
    except SPSDKError as exc:
        logger.debug(f"Failed to parse public key: {exc}")
        raise SPSDKError("Unable to load secret data.") from exc


def extract_public_key(
    file_path: str, password: Optional[str] = None, search_paths: Optional[list[str]] = None
) -> PublicKey:
    """Extract any kind of public key from a file.

    The method supports files containing Certificate, Private Key or Public Key formats.
    It can search for the file in multiple directories and handle password-protected files.

    :param file_path: File path to public key file.
    :param password: Optional password for encrypted Private file source.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :raises SPSDKError: Raised when file cannot be loaded.
    :return: Public key of any type.
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
    """Extract public keys from multiple files containing certificates, private keys, or public keys.

    This method processes multiple input files and extracts the public key component from each,
    regardless of whether the source file contains a certificate, private key, or public key.

    :param secret_files: Iterable of file paths to process for public key extraction.
    :param password: Password for encrypted private key files, defaults to None.
    :param search_paths: Additional directories to search for files, defaults to None.
    :return: List of extracted public keys from all processed files.
    """
    return [
        extract_public_key(file_path=source, password=password, search_paths=search_paths)
        for source in secret_files
    ]


def get_hash_type_from_signature_size(signature_size: int) -> EnumHashAlgorithm:
    """Return hash type from ECC signature size.

    Determines the appropriate hash algorithm based on the size of an ECC signature.
    Supports standard ECC signature sizes for SHA256, SHA384, and SHA512.

    :param signature_size: Size of the ECC signature in bytes.
    :raises SPSDKValueError: Unknown or unsupported signature size.
    :return: Hash algorithm enum corresponding to the signature size.
    """
    if signature_size == 64:
        return EnumHashAlgorithm.SHA256
    if signature_size == 96:
        return EnumHashAlgorithm.SHA384
    if signature_size == 132:
        return EnumHashAlgorithm.SHA512
    raise SPSDKValueError("Unknown signature size")


def generate_key_pair(
    key_type: str,
    encoding: str,
    keys_path: str,
    key_prefix: str,
    idx: int,
    is_ca: bool,
    password: str,
    print_func: Callable[[str], None] = print,
    key_postfix: Optional[str] = None,
) -> tuple[PrivateKey, PublicKey, str, str]:
    """Generate key pair with the naming convention.

    The method creates a cryptographic key pair using specified parameters and saves both
    private and public keys to the filesystem with standardized naming convention.

    :param key_type: Key type from get_supported_keys_generators().
    :param encoding: Key encoding format (DER or PEM).
    :param keys_path: Path to the directory where keys will be stored.
    :param key_prefix: Prefix for the key filename (e.g., 'CA').
    :param idx: Index number to append to the key name.
    :param is_ca: True if the certificate with this key is certificate authority.
    :param password: Password to protect the private key.
    :param print_func: Custom function to print status messages, defaults to print.
    :param key_postfix: Optional postfix to append to the key name, defaults to None.
    :return: Tuple of private key, public key, key name and certificate name.
    """
    key_param = key_type.lower().strip()
    encoding_param = encoding.upper().strip()
    encoding_enum = SPSDKEncoding.all()[encoding_param]

    # Generate key
    ca_str = "_ca" if is_ca else ""
    postfix = f"_{key_postfix}" if key_postfix else ""
    key_name = f"{key_prefix}{idx}{postfix}_{key_param}{ca_str}_key"
    cert_name = f"{key_prefix}{idx}{postfix}_{key_param}{ca_str}_cert.{encoding_param.lower()}"
    private_key_path = os.path.join(keys_path, f"{key_name}.{encoding_param.lower()}")
    public_key_path = os.path.join(keys_path, f"{key_name}.pub")

    # Get generator according to the provided parameter
    generators = get_supported_keys_generators()
    func, params = generators[key_param]

    # generate public and private key
    private_key = func(**params)
    public_key = private_key.get_public_key()

    # save keys
    private_key.save(private_key_path, password if password else None, encoding=encoding_enum)
    public_key.save(public_key_path, encoding=encoding_enum)
    print_func(
        f"The {key_prefix}{idx} key pair has been created: {(public_key_path)}, {private_key_path}"
    )

    return private_key, public_key, key_name, cert_name


def generate_img_csf_key(
    key_type: str,
    encoding: str,
    keys_path: str,
    crts_path: str,
    ca_issuer: SPSDKName,
    srk_private_key: PrivateKey,
    duration: int,
    idx: int,
    password: str,
    serial: Optional[list[int]] = None,
    print_func: Callable[[str], None] = print,
    start_idx: int = 0,
    key_postfix: Optional[str] = None,
) -> None:
    """Generate IMG and CSF keys and certificates.

    This function creates both IMG (Image) and CSF (Command Sequence File) key pairs and their
    corresponding certificates signed by the provided SRK private key. The certificates are
    saved to the specified paths with the given encoding format.

    :param key_type: Type of cryptographic key to generate (e.g., 'rsa2048', 'ecc256').
    :param encoding: Encoding format for keys and certificates ('DER' or 'PEM').
    :param keys_path: Directory path where generated private keys will be stored.
    :param crts_path: Directory path where generated certificates will be stored.
    :param ca_issuer: Certificate authority issuer name for the generated certificates.
    :param srk_private_key: SRK (Super Root Key) private key used to sign the certificates.
    :param duration: Validity period of the certificates in years.
    :param idx: Index number used for naming the generated keys and certificates.
    :param password: Password used to protect the generated private keys.
    :param serial: List of serial numbers for certificates. Must have at least idx+1 items.
    :param print_func: Function used for output messages, defaults to built-in print.
    :param start_idx: Starting index offset for key numbering, defaults to 0.
    :param key_postfix: Optional suffix appended to key names, defaults to None.
    :raises SPSDKError: If serial list is provided but has insufficient items for the index.
    """
    encoding_enum = SPSDKEncoding.all()[encoding.upper().strip()]
    postfix = f"_{key_postfix}" if key_postfix else ""

    if serial and len(serial) <= idx:
        raise SPSDKError(
            f"Provided list of serial numbers has {len(serial)} items. Need (at least) {idx}"
        )

    _, csf_public_key, csf_key_name, csf_cert_name = generate_key_pair(
        key_type,
        encoding,
        keys_path,
        "CSF",
        idx + start_idx,
        False,
        password,
        key_postfix=key_postfix,
    )

    csf_cert_path = os.path.join(crts_path, csf_cert_name)
    subject = generate_name([{"COMMON_NAME": csf_key_name}])
    # generate CSF certificate signed by SRK certificate
    csf_cert = Certificate.generate_certificate(
        subject=subject,
        issuer=ca_issuer,
        subject_public_key=csf_public_key,
        issuer_private_key=srk_private_key,
        serial_number=serial[idx] if serial else None,
        duration=duration * 365,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": False}},
        ),
    )
    csf_cert.save(csf_cert_path, encoding_enum)
    print_func(f"The CSF{idx+start_idx}{postfix} certificate has been created: {csf_cert_path}")
    logger.info(csf_cert)

    # Create IMG certificate
    _, img_public_key, img_key_name, img_cert_name = generate_key_pair(
        key_type,
        encoding,
        keys_path,
        "IMG",
        idx + start_idx,
        False,
        password,
        key_postfix=key_postfix,
    )

    img_cert_path = os.path.join(crts_path, img_cert_name)
    subject = generate_name([{"COMMON_NAME": img_key_name}])
    # generate IMG certificate signed by SRK certificate
    img_cert = Certificate.generate_certificate(
        subject=subject,
        issuer=ca_issuer,
        subject_public_key=img_public_key,
        issuer_private_key=srk_private_key,
        serial_number=serial[idx] if serial else None,
        duration=duration * 365,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": False}},
        ),
    )
    img_cert.save(img_cert_path, encoding_enum)
    print_func(f"The IMG{idx}{postfix} certificate has been created: {img_cert_path}")
    logger.info(img_cert)


def generate_srk_keys(
    key_type: str,
    encoding: str,
    keys_path: str,
    crts_path: str,
    ca_issuer: SPSDKName,
    ca_private_key: PrivateKey,
    duration: int,
    srk_is_ca: bool,
    password: str,
    keys_number: int,
    serial: Optional[list[int]] = None,
    print_func: Callable[[str], None] = print,
    start_idx: int = 0,
    use_img_csf: bool = False,
) -> None:
    """Generate SRK keys and certificates.

    This function generates Super Root Key (SRK) pairs and their corresponding certificates
    signed by a CA. Optionally generates SGK certificates or IMG/CSF certificates based on
    configuration.

    :param key_type: Type of cryptographic key to generate (e.g., 'rsa2048', 'ecc256').
    :param encoding: Encoding format for keys and certificates ('DER' or 'PEM').
    :param keys_path: Directory path where generated private keys will be stored.
    :param crts_path: Directory path where generated certificates will be stored.
    :param ca_issuer: Certificate Authority issuer name for signing certificates.
    :param ca_private_key: CA private key used to sign the generated certificates.
    :param duration: Certificate validity duration in years.
    :param srk_is_ca: Whether the SRK should be marked as a Certificate Authority.
    :param password: Password for protecting the generated private keys.
    :param keys_number: Number of SRK key pairs to generate.
    :param serial: List of serial numbers for certificates, defaults to None.
    :param print_func: Function for output messages, defaults to print.
    :param start_idx: Starting index for key numbering, defaults to 0.
    :param use_img_csf: Whether to generate IMG and CSF certificates instead of SGK,
        defaults to False.
    :raises SPSDKError: If serial numbers list length doesn't match keys_number.
    """
    encoding_enum = SPSDKEncoding.all()[encoding.upper().strip()]

    if serial and len(serial) != keys_number:
        raise SPSDKError(
            f"Provided list of serial numbers has {len(serial)} items. Need {keys_number}"
        )

    for idx in range(keys_number):
        srk_private_key, srk_public_key, srk_key_name, srk_cert_name = generate_key_pair(
            key_type,
            encoding,
            keys_path,
            "SRK",
            idx + start_idx,
            srk_is_ca,
            password,
        )

        srk_cert_path = os.path.join(crts_path, srk_cert_name)
        subject = generate_name([{"COMMON_NAME": srk_key_name}])
        # generate SRK certificate signed by CA certificate
        srk_cert = Certificate.generate_certificate(
            subject=subject,
            issuer=ca_issuer,
            subject_public_key=srk_public_key,
            issuer_private_key=ca_private_key,
            serial_number=serial[idx] if serial else None,
            duration=duration * 365,
            extensions=generate_extensions(
                {"BASIC_CONSTRAINTS": {"ca": srk_is_ca}},
            ),
        )
        srk_cert.save(srk_cert_path, encoding_enum)
        print_func(f"The SRK{idx+start_idx} certificate has been created: {srk_cert_path}")
        logger.info(srk_cert)
        # In case the SRK is CA, create SGK certificates
        if srk_is_ca and not use_img_csf:
            _, sgk_public_key, sgk_key_name, sgk_cert_name = generate_key_pair(
                key_type, encoding, keys_path, "SGK", idx + start_idx, False, password
            )
            sgk_cert_path = os.path.join(crts_path, sgk_cert_name)
            subject = generate_name([{"COMMON_NAME": sgk_key_name}])
            # generate SGK certificate signed by SRK certificate
            sgk_cert = Certificate.generate_certificate(
                subject=subject,
                issuer=ca_issuer,
                subject_public_key=sgk_public_key,
                issuer_private_key=srk_private_key,
                serial_number=serial[idx] if serial else None,
                duration=duration * 365,
                extensions=generate_extensions(
                    {"BASIC_CONSTRAINTS": {"ca": False}},
                ),
            )
            sgk_cert.save(sgk_cert_path, encoding_enum)
            print_func(f"The SGK{idx} certificate has been created: {sgk_cert_path}")
            logger.info(sgk_cert)
        elif srk_is_ca and use_img_csf:
            generate_img_csf_key(
                key_type=key_type,
                encoding=encoding,
                keys_path=keys_path,
                crts_path=crts_path,
                ca_issuer=ca_issuer,
                srk_private_key=srk_private_key,
                duration=duration,
                idx=idx,
                password=password,
                serial=serial,
                print_func=print_func,
                start_idx=start_idx,
                key_postfix="0",
            )

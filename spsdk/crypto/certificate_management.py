#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for certificate management (generating certificate, validating certificate, chains)."""

from datetime import datetime, timedelta
from typing import Dict, List, Union

from spsdk import SPSDKError
from spsdk.crypto import (
    Certificate,
    CertificateSigningRequest,
    Encoding,
    ExtensionOID,
    InvalidSignature,
    PrivateKey,
    PublicKey,
    _PublicKeyTuple,
    default_backend,
    hashes,
    padding,
    rsa,
    x509,
)


def generate_certificate(
    subject: x509.Name,
    issuer: x509.Name,
    subject_public_key: PublicKey,
    issuer_private_key: PrivateKey,
    serial_number: int = None,
    if_ca: bool = True,
    duration: int = 3650,
    path_length: int = 2,
) -> Certificate:
    """Generate certificate.

    :param subject: subject name that the CA issues the certificate to
    :param issuer: issuer name that issued the certificate
    :param subject_public_key: RSA public key of subject
    :param issuer_private_key: RSA private key of issuer
    :param serial_number: certificate serial number, if not specified, random serial number will be set
    :param if_ca: true if the certificate can sign certificates, none otherwise
    :param duration: how long the certificate will be valid (in days)
    :param path_length: The maximum path length for certificates subordinate to this certificate.
    :return: certificate
    """
    crt = x509.CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=duration),
        public_key=subject_public_key,
        extensions=[],
        serial_number=serial_number or x509.random_serial_number(),
    )

    crt = crt.add_extension(
        x509.BasicConstraints(ca=if_ca, path_length=path_length if if_ca else None),
        critical=True,
    )
    return crt.sign(issuer_private_key, hashes.SHA256(), default_backend())


def save_crypto_item(
    item: Union[Certificate, CertificateSigningRequest],
    file_path: str,
    encoding_type: Encoding = Encoding.PEM,
) -> None:
    """Save the certificate/CSR into file.

    :param item: certificate or certificate signing request
    :param file_path: path to the file where item will be stored
    :param encoding_type: encoding type (PEM or DER)
    """
    with open(file_path, "wb") as f:
        f.write(item.public_bytes(encoding_type))


def validate_certificate_chain(chain_list: list) -> list:
    """Validate chain of certificates.

    :param chain_list: list of certificates in chain
    :return: list of boolean values, which corresponds to the certificate validation in chain
    :raises SPSDKError: When chain has less than two certificates
    """
    if len(chain_list) <= 1:
        raise SPSDKError("The chain must have at least two certificates")
    result = []
    for i in range(len(chain_list) - 1):
        result.append(validate_certificate(chain_list[i], chain_list[i + 1]))
    return result


def validate_certificate(subject_certificate: Certificate, issuer_certificate: Certificate) -> bool:
    """Validate certificate.

    :param subject_certificate: subject's certificate
    :param issuer_certificate: issuer's certificate
    :raises SPSDKError: Unsupported key type in Certificate
    :return: true/false whether certificate is valid or not
    """
    issuer_pub_key = get_public_key_from_certificate(issuer_certificate)
    cert_to_check = x509.load_pem_x509_certificate(
        convert_certificate_into_bytes(subject_certificate), default_backend()
    )

    try:
        if isinstance(issuer_pub_key, rsa.RSAPublicKey):
            assert cert_to_check.signature_hash_algorithm
            issuer_pub_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_check.signature_hash_algorithm,
            )
            return True
        raise SPSDKError(f"Certificate validation for {type(issuer_pub_key)} is not supported")
    except InvalidSignature:
        return False


def is_ca_flag_set(certificate: Certificate) -> bool:
    """Check if CA flag is set in certificate.

    :param certificate: Certificate to be checked
    :return: true/false depending whether ca flag is set or not
    """
    extension = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    return extension.value.ca  # type: ignore # mypy can not handle property definition in cryptography


def validate_ca_flag_in_cert_chain(chain_list: List[Certificate]) -> bool:
    """Validate CA flag in certification chain.

    :param chain_list: list of certificates in the chain
    :return: true/false depending whether ca flag is set or not
    """
    return is_ca_flag_set(chain_list[0])


def get_public_key_from_certificate(certificate: Certificate) -> PublicKey:
    """Get public keys from certificate.

    :param certificate: certificate item
    :return: RSA public key
    """
    public_key = certificate.public_key()
    assert isinstance(public_key, _PublicKeyTuple)
    return public_key


def convert_certificate_into_bytes(
    certificate: Certificate, encoding: Encoding = Encoding.PEM
) -> bytes:
    """Convert certificates into bytes.

    :param certificate: certificate item
    :param encoding: encoding type
    :return: certificate in bytes form
    """
    assert isinstance(certificate, Certificate), "The input is not a Certificate"
    return certificate.public_bytes(encoding)


X509NameConfig = Union[List[Dict[str, str]], Dict[str, Union[str, List[str]]]]


def generate_name(config: X509NameConfig) -> x509.Name:
    """Generate x509 Name.

    :param config: subject/issuer description
    :return: x509.Name
    """
    attributes: List[x509.NameAttribute] = []

    def _get_name_oid(name: str) -> x509.ObjectIdentifier:
        try:
            return getattr(x509.NameOID, name)
        except Exception as exc:
            raise SPSDKError(f"Invalid value of certificate attribute: {name}") from exc

    if isinstance(config, list):
        for item in config:
            for key, value in item.items():
                name_oid = _get_name_oid(key)
                attributes.append(x509.NameAttribute(name_oid, str(value)))

    if isinstance(config, dict):
        for key_second, value_second in config.items():
            name_oid = _get_name_oid(key_second)
            if isinstance(value_second, list):
                for value in value_second:
                    attributes.append(x509.NameAttribute(name_oid, str(value)))
            else:
                attributes.append(x509.NameAttribute(name_oid, str(value_second)))

    return x509.Name(attributes)

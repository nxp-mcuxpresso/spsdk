#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for key generation and saving keys to file (RSA and ECC)."""

from spsdk.crypto import (
    EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePublicKey,
    Encoding,
    RSAPrivateKeyWithSerialization,
    RSAPublicKey,
    default_backend,
    ec,
    rsa,
    serialization,
)
from spsdk.exceptions import SPSDKValueError


def get_ec_curve_object(name: str) -> ec.EllipticCurve:
    """Get the EC curve object by its name.

    :param name: Name of EC curve.
    :return: EC curve object.
    :raises SPSDKValueError: Invalid EC curve name.
    """
    # pylint: disable=protected-access
    for key_object in ec._CURVE_TYPES:  # type: ignore
        if key_object.lower() == name.lower():
            # pylint: disable=protected-access
            return ec._CURVE_TYPES[key_object]()  # type: ignore

    raise SPSDKValueError(f"The EC curve with name '{name}' is not supported.")


def generate_rsa_private_key(
    key_size: int = 2048, exponent: int = 65537
) -> RSAPrivateKeyWithSerialization:
    """Generate RSA private key.

    :param key_size: key size in bits; must be >= 512
    :param exponent: public exponent; must be >= 3 and odd
    :return: RSA private key with serialization
    """
    return rsa.generate_private_key(
        backend=default_backend(), public_exponent=exponent, key_size=key_size
    )


def generate_rsa_public_key(
    private_key: RSAPrivateKeyWithSerialization,
) -> RSAPublicKey:
    """Generate RSA public key.

    :param private_key: private key used for public key generation
    :return: RSA public key
    """
    return private_key.public_key()


def save_rsa_private_key(
    private_key: RSAPrivateKeyWithSerialization,
    file_path: str,
    password: str = None,
    encoding: Encoding = Encoding.PEM,
) -> None:
    """Save the RSA private key to the given file.

    :param private_key: RSA private key to be saved
    :param file_path: path to the file, where the key will be stored
    :param password: password to private key; None to store without password
    :param encoding: encoding type, default is PEM
    """
    if password:
        if isinstance(password, str):
            password_bytes = password.encode("utf-8")
        else:
            password_bytes = password
    enc = (
        serialization.BestAvailableEncryption(password=password_bytes)
        if password
        else serialization.NoEncryption()
    )
    pem_data = private_key.private_bytes(encoding, serialization.PrivateFormat.PKCS8, enc)
    with open(file_path, "wb") as f:
        f.write(pem_data)


def save_rsa_public_key(
    public_key: RSAPublicKey, file_path: str, encoding: Encoding = Encoding.PEM
) -> None:
    """Save the RSA public key to the file.

    :param public_key: public key to be saved
    :param file_path: path to the file, where the key will be stored
    :param encoding: encoding type, default is PEM
    """
    pem_data = public_key.public_bytes(encoding, serialization.PublicFormat.PKCS1)
    with open(file_path, "wb") as f:
        f.write(pem_data)


def generate_ecc_private_key(
    curve_name: str = "secp256r1",
) -> EllipticCurvePrivateKeyWithSerialization:
    """Generate ECC private key.

    :param curve_name: name of curve
    :return: ECC private key
    """
    curve_obj = get_ec_curve_object(curve_name)
    return ec.generate_private_key(curve_obj, default_backend())  # type: ignore


def generate_ecc_public_key(
    private_key: EllipticCurvePrivateKeyWithSerialization,
) -> EllipticCurvePublicKey:
    """Generate ECC private key.

    :param private_key:
    :return: ECC public key
    """
    return private_key.public_key()


def save_ecc_private_key(
    ec_private_key: EllipticCurvePrivateKeyWithSerialization,
    file_path: str,
    password: str = None,
    encoding: Encoding = Encoding.PEM,
) -> None:
    """Save the ECC private key to the given file.

    :param ec_private_key: ECC private key to be saved
    :param file_path: path to the file, where the key will be stored
    :param password: password to private key; None to store without password
    :param encoding: encoding type, default is PEM
    """
    serialized_private = ec_private_key.private_bytes(
        encoding=encoding,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption(),
    )
    with open(file_path, "wb") as f:
        f.write(serialized_private)


def save_ecc_public_key(
    ec_public_key: EllipticCurvePublicKey,
    file_path: str,
    encoding: Encoding = Encoding.PEM,
) -> None:
    """Save the ECC public key to the file.

    :param ec_public_key: public key to be saved
    :param file_path: path to the file, where the key will be stored
    :param encoding: encoding type, default is PEM
    """
    pem_data = ec_public_key.public_bytes(
        encoding=encoding, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(file_path, "wb") as f:
        f.write(pem_data)

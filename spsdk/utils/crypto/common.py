#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Common cryptographic functions."""
import math
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from spsdk import SPSDKError
from spsdk.crypto import EllipticCurvePublicKey, Encoding, PublicFormat, PublicKey
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.sbfile.misc import SecBootBlckSize

from ...exceptions import SPSDKValueError
from .abstract import BackendClass
from .backend_openssl import openssl_backend


def crypto_backend() -> BackendClass:
    """Return default crypto backend instance."""
    return openssl_backend


class Counter:
    """AES counter with specified counter byte ordering and customizable increment."""

    @property
    def value(self) -> bytes:
        """Initial vector for AES encryption."""
        return self._nonce + self._ctr.to_bytes(4, self._ctr_byteorder_encoding)  # type: ignore[arg-type]

    def __init__(
        self,
        nonce: bytes,
        ctr_value: Optional[int] = None,
        ctr_byteorder_encoding: str = "little",
    ):
        """Constructor.

        :param nonce: last four bytes are used as initial value for counter
        :param ctr_value: counter initial value; it is added to counter value retrieved from nonce
        :param ctr_byteorder_encoding: way how the counter is encoded into output value: either 'little' or 'big'
        :raises SPSDKError: When invalid byteorder is provided
        """
        assert isinstance(nonce, bytes) and len(nonce) == 16
        if ctr_byteorder_encoding not in ["little", "big"]:
            raise SPSDKError("Wrong byte order")
        self._nonce = nonce[:-4]
        self._ctr_byteorder_encoding = ctr_byteorder_encoding
        self._ctr = int.from_bytes(nonce[-4:], ctr_byteorder_encoding)  # type: ignore[arg-type]
        if ctr_value is not None:
            self._ctr += ctr_value

    def increment(self, value: int = 1) -> None:
        """Increment counter by specified value.

        :param value: to add to counter
        """
        self._ctr += value


def calc_cypher_block_count(size: int) -> int:
    """Calculate the amount if cypher blocks.

    :param size: Number of bytes for the cypher area
    :return: Number of blocks covering the cypher area
    """
    return SecBootBlckSize.to_num_blocks(size)


def matches_key_and_cert(priv_key: bytes, cert: Certificate) -> bool:
    """Verify that given private key matches the public certificate.

    :param priv_key: to be tested; decrypted binary data in PEM format
    :param cert: to be used for verification
    :return: True if yes; False otherwise
    """
    signature = crypto_backend().rsa_sign(priv_key, bytes())
    assert isinstance(cert, Certificate)
    cert_pub_key = cert.public_key()  # public key of last certificate
    assert isinstance(cert_pub_key, RSAPublicKey)
    return crypto_backend().rsa_verify(
        cert_pub_key.public_numbers().n,
        cert_pub_key.public_numbers().e,
        signature,
        bytes(),
    )


def serialize_ecc_signature(signature: bytes, coordinate_length: int) -> bytes:
    """Re-format ECC ANS.1 DER signature into the format used by ROM code."""
    r, s = utils.decode_dss_signature(signature)

    r_bytes = r.to_bytes(coordinate_length, "big")
    s_bytes = s.to_bytes(coordinate_length, "big")
    return r_bytes + s_bytes


def ecc_public_numbers_to_bytes(
    public_numbers: EllipticCurvePublicNumbers, length: Optional[int] = None
) -> bytes:
    """Converts public numbers from ECC key into bytes.

    :param public_numbers: instance of ecc public numbers
    :param length: length of bytes object to use
    :return: bytes representation
    """
    x: int = public_numbers.x
    y: int = public_numbers.y
    length = length or math.ceil(x.bit_length() / 8)
    x_bytes = x.to_bytes(length, "big")
    y_bytes = y.to_bytes(length, "big")
    return x_bytes + y_bytes


def get_matching_key_id(public_keys: List[PublicKey], signature_provider: SignatureProvider) -> int:
    """Get index of public key that match to given private key.

    :param public_keys: List of public key used to find the match for the private key.
    :param signature_provider: Signature provider used to try to match public key index.
    :raises SPSDKValueError: No match found.
    :return: Index of public key.
    """
    for i, public_key in enumerate(public_keys):
        if isinstance(public_key, RSAPublicKey):
            public_key_bytes = public_key.public_bytes(
                encoding=Encoding.DER, format=PublicFormat.PKCS1
            )
        if isinstance(public_key, EllipticCurvePublicKey):
            public_key_bytes = public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )

        if signature_provider.verify_public_key(public_key_bytes):
            return i

    raise SPSDKValueError("There is no match of private key in given list.")

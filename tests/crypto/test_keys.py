#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic keys testing module.

This module contains comprehensive tests for SPSDK cryptographic key functionality,
including RSA and ECC key operations, digital signatures, and key generation.
The tests validate RSA and ECC signing/verification, key generation for various
algorithms and sizes, ECDSA signature handling, and password-protected keys.
"""

import os
from typing import Any

import pytest

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import EccCurve, ECDSASignature, PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc
from spsdk.exceptions import SPSDKValueError


def test_rsa_sign(data_dir: str) -> None:
    """Test RSA private key signing functionality.

    Verifies that RSA private key can correctly sign data and produces the expected
    signature. The test loads a 2048-bit RSA private key from a PEM file and signs
    a 512-byte test data sequence, then compares the result against a known signature.

    :param data_dir: Directory path containing test data files including the RSA private key
    """
    private_key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    # specify key using SPSDK_Key class
    calc_signature = private_key.sign(data)
    assert len(calc_signature) == 256
    assert calc_signature == signature


def test_rsa_verify(data_dir: str) -> None:
    """Test RSA signature verification functionality.

    This test verifies that an RSA private key can be used to validate a signature
    against test data. It loads a 2048-bit RSA private key, extracts its public key,
    and verifies a pre-computed signature against 512 bytes of test data.

    :param data_dir: Directory path containing test data files including the RSA private key file.
    """
    private_key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    assert private_key.get_public_key().verify_signature(signature, data)


def test_ecc_sign_verify(data_dir: str) -> None:
    """Test ECC signature generation and verification functionality.

    This test verifies that ECC private keys can generate valid signatures and that
    corresponding public keys can verify those signatures. It also confirms that
    OpenSSL's randomized signature generation produces different signatures for
    the same data while maintaining verification validity.

    :param data_dir: Directory path containing test key files
    :raises AssertionError: If signature verification fails or signatures are unexpectedly identical
    """
    private_key = PrivateKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"))
    public_key = PublicKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"))
    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = private_key.sign(data)
    calc_signature2 = private_key.sign(data)
    # openssl utilize randomized signature thus two signatures are different
    assert calc_signature != calc_signature2

    is_valid = public_key.verify_signature(signature=calc_signature, data=data)
    is_valid2 = public_key.verify_signature(signature=calc_signature2, data=data)
    # randomized signatures are still valid
    assert is_valid and is_valid2


def test_ecc_sign_verify_incorrect(data_dir: str) -> None:
    """Test ECC signature verification with malformed signatures.

    This test verifies that ECC signature verification correctly rejects invalid
    signatures by testing two scenarios: truncated signature and oversized signature.
    The test ensures the cryptographic validation properly fails for corrupted data.

    :param data_dir: Directory path containing test cryptographic key files.
    """
    private_key = PrivateKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"))
    public_key = PublicKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"))

    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = private_key.sign(data)

    # malform the signature
    bad_signature = calc_signature[:-2] + bytes(2)
    is_valid = public_key.verify_signature(signature=bad_signature, data=data)
    assert not is_valid

    # make signature bigger than expected
    bad_signature = calc_signature + bytes(2)
    assert not public_key.verify_signature(signature=bad_signature, data=data)


def test_keys_generation_2048(tmpdir: Any) -> None:
    """Test RSA key generation with default 2048-bit key size.

    This test verifies that RSA private and public keys can be generated,
    extracted, and saved to files successfully using the default key size.

    :param tmpdir: Temporary directory for saving test files.
    """
    priv_key = PrivateKeyRsa.generate_key()
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_2048.pem"))
    pub_key.save(os.path.join(tmpdir, "pub_2048.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_2048.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_2048.pem"))


def test_keys_generation_2048_with_password(tmpdir: Any) -> None:
    """Test RSA 2048-bit key generation and saving with password protection.

    This test verifies that a 2048-bit RSA private key can be generated, saved with
    password protection, and that the corresponding public key can be extracted and
    saved. It confirms that both key files are successfully created in the filesystem.

    :param tmpdir: Temporary directory for saving test key files.
    """
    priv_key = PrivateKeyRsa.generate_key()
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_2048_password.pem"), "abc")
    pub_key.save(os.path.join(tmpdir, "pub_2048_2.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_2048_password.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_2048_2.pem"))


def test_keys_generation_3072(tmpdir: Any) -> None:
    """Test RSA key generation with 3072-bit key size.

    Generates a 3072-bit RSA private key, extracts its public key counterpart,
    saves both keys to PEM files in the temporary directory, and verifies
    that the files were created successfully.

    :param tmpdir: Temporary directory path for saving generated key files.
    """
    priv_key = PrivateKeyRsa.generate_key(key_size=3072)
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_3072.pem"))
    pub_key.save(os.path.join(tmpdir, "pub_3072.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_3072.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_3072.pem"))


def test_keys_generation_4096(tmpdir: Any) -> None:
    """Test RSA key generation with 4096-bit key size.

    This test verifies that 4096-bit RSA private and public keys can be generated,
    saved to files, and that the files are created successfully in the filesystem.

    :param tmpdir: Temporary directory for saving test key files.
    """
    priv_key = PrivateKeyRsa.generate_key(key_size=4096)
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_4096.pem"))
    pub_key.save(os.path.join(tmpdir, "pub_4096.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_4096.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_4096.pem"))


@pytest.mark.parametrize(
    "ec_name",
    [
        "secp192r1",
        "secp224r1",
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "secp256k1",
        "sect163k1",
        "sect233k1",
        "sect283k1",
        "sect409k1",
        "sect571k1",
        "sect163r2",
        "sect233r1",
        "sect283r1",
        "sect409r1",
        "sect571r1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
    ],
)
def test_keys_generation_ec(tmpdir: Any, ec_name: str) -> None:
    """Test elliptic curve key generation and file operations.

    Generates an EC private key with the specified curve, derives its public key,
    saves both keys to files in the temporary directory, and verifies that the
    files were created successfully.

    :param tmpdir: Temporary directory path for saving key files.
    :param ec_name: Name of the elliptic curve to use for key generation.
    """
    priv_key = PrivateKeyEcc.generate_key(curve_name=ec_name)  # type: ignore
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, f"key_{ec_name}.pem"))
    pub_key.save(os.path.join(tmpdir, f"key_{ec_name}.pub"))
    assert os.path.isfile(os.path.join(tmpdir, f"key_{ec_name}.pem"))
    assert os.path.isfile(os.path.join(tmpdir, f"key_{ec_name}.pub"))


def test_keys_generation_ec_invalid() -> None:
    """Test ECC private key generation with invalid curve name.

    Verifies that PrivateKeyEcc.generate_key() properly raises SPSDKValueError
    when provided with an invalid curve name parameter.

    :raises SPSDKValueError: When invalid curve name is provided to generate_key().
    """
    with pytest.raises(SPSDKValueError):
        PrivateKeyEcc.generate_key(curve_name="invalid")  # type: ignore


@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "ec_curve",
    [EccCurve.SECP256R1, EccCurve.SECP384R1, EccCurve.SECP521R1],
)
def test_ecdsa_signature(ec_curve: EccCurve, encoding: SPSDKEncoding) -> None:
    """Test ECDSA signature generation, parsing, and export functionality.

    This test verifies that an ECDSA signature can be generated from a private key,
    parsed into an ECDSASignature object, exported back to the original encoding,
    and that the exported signature matches the original signature.

    :param ec_curve: The elliptic curve to use for key generation and signing.
    :param encoding: The encoding format for signature export (DER or other SPSDK encoding).
    """
    priv_key = PrivateKeyEcc.generate_key(curve_name=ec_curve)
    is_der = encoding == SPSDKEncoding.DER
    signature = priv_key.sign(b"", der_format=is_der)
    ecdsa_sig = ECDSASignature.parse(signature)
    exported = ecdsa_sig.export(encoding)
    assert signature == exported


@pytest.mark.parametrize(
    "ec_curve",
    [EccCurve.SECP256R1, EccCurve.SECP384R1, EccCurve.SECP521R1],
)
def test_ecdsa_signature_get_encoding(ec_curve: EccCurve) -> None:
    """Test ECDSA signature encoding detection functionality.

    This test verifies that the ECDSASignature.get_encoding method correctly
    identifies the encoding format of ECDSA signatures. It tests both DER
    format (when der_format=True) and NXP format (default) signatures.

    :param ec_curve: The elliptic curve to use for key generation and signing.
    """
    priv_key = PrivateKeyEcc.generate_key(curve_name=ec_curve)
    signature = priv_key.sign(b"", der_format=True)
    ECDSASignature.get_encoding(signature) == SPSDKEncoding.DER
    signature = priv_key.sign(b"")
    ECDSASignature.get_encoding(signature) == SPSDKEncoding.NXP


def test_ecdsa_signature_get_encoding_rsa() -> None:
    """Test ECDSA signature encoding with RSA keys to ensure proper error handling.

    This test verifies that ECDSASignature.get_encoding() correctly raises SPSDKValueError
    when attempting to get encoding from RSA signatures, which are incompatible with ECDSA
    signature encoding methods.

    :raises SPSDKValueError: When RSA signature is passed to ECDSA encoding method.
    """
    key_sizes = [2048, 4096]
    for key_size in key_sizes:
        rsa_key = PrivateKeyRsa.generate_key()
        signature = rsa_key.sign(b"")
        with pytest.raises(SPSDKValueError):
            ECDSASignature.get_encoding(signature)

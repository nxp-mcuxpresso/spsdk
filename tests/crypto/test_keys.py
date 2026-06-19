#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic keys testing module.

This module contains comprehensive tests for SPSDK cryptographic key functionality,
including RSA and ECC key operations, digital signatures, and key generation.
The tests validate RSA and ECC signing/verification, key generation for various
algorithms and sizes, ECDSA signature handling, and password-protected keys.
"""

import os
from pathlib import Path
from typing import Any, Callable, Type

import pytest

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import (
    EccCurve,
    ECDSASignature,
    NonSupportingPrivateKey,
    NonSupportingPublicKey,
    PrivateKey,
    PrivateKeyDilithium,
    PrivateKeyEcc,
    PrivateKeyLMS,
    PrivateKeyMLDSA,
    PrivateKeyRsa,
    PrivateKeySM2,
    PublicKey,
    PublicKeyDilithium,
    PublicKeyEcc,
    PublicKeyLMS,
    PublicKeyMLDSA,
    PublicKeyRsa,
    PublicKeySM2,
    SPSDKInvalidKeyType,
    SPSDKKeyPassphraseMissing,
    SPSDKWrongKeyPassphrase,
    _crypto_load_private_key,
    get_ecc_curve,
    get_supported_keys_generators,
    load_key,
)
from spsdk.crypto.lms import IS_LMS_SUPPORTED
from spsdk.crypto.oscca import IS_OSCCA_SUPPORTED

if IS_LMS_SUPPORTED:
    from spsdk.crypto.lms import LMSParams

from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.utils.misc import write_file

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "_data", "keys")


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


@pytest.mark.parametrize(
    "secp_curve,brainpool_curve,key_length",
    [
        (EccCurve.SECP256R1, EccCurve.BRAINPOOLP256R1, 32),
        (EccCurve.SECP384R1, EccCurve.BRAINPOOLP384R1, 48),
    ],
)
def test_same_length_different_curves(
    secp_curve: EccCurve, brainpool_curve: EccCurve, key_length: int
) -> None:
    """Test that SECP and Brainpool curves with same length are different."""
    secp_key = PrivateKeyEcc.generate_key(curve_name=secp_curve)
    brainpool_key = PrivateKeyEcc.generate_key(curve_name=brainpool_curve)

    # Both should have same coordinate size
    assert secp_key.coordinate_size == key_length
    assert brainpool_key.coordinate_size == key_length

    # But different curves
    assert secp_key.curve != brainpool_key.curve
    assert secp_key.curve == secp_curve
    assert brainpool_key.curve == brainpool_curve


@pytest.mark.parametrize(
    "curve,coordinate_size",
    [
        (EccCurve.SECP256R1, 32),
        (EccCurve.BRAINPOOLP256R1, 32),
        (EccCurve.SECP384R1, 48),
        (EccCurve.BRAINPOOLP384R1, 48),
    ],
)
def test_recreate_from_data(curve: EccCurve, coordinate_size: int) -> None:
    """Test recreating public key from data with explicit curve specification."""
    # Generate a key
    private_key = PrivateKeyEcc.generate_key(curve_name=curve)
    public_key = private_key.get_public_key()

    # Export to NXP format (raw x,y coordinates)
    nxp_data = public_key.export(encoding=SPSDKEncoding.NXP)
    assert len(nxp_data) == coordinate_size * 2

    # Recreate with explicit curve - should work
    recreated_key = PublicKeyEcc.recreate_from_data(data=nxp_data)
    assert recreated_key.curve == curve
    assert recreated_key.x == public_key.x
    assert recreated_key.y == public_key.y


@pytest.mark.parametrize(
    "key_data,key_type",
    [
        pytest.param(
            lambda: PrivateKeyRsa.generate_key().export(encoding=SPSDKEncoding.DER),
            PrivateKeyRsa,
            id="rsa_private_der",
        ),
        pytest.param(
            lambda: PrivateKeyRsa.generate_key().export(encoding=SPSDKEncoding.PEM),
            PrivateKeyRsa,
            id="rsa_private_pem",
        ),
        pytest.param(
            lambda: PrivateKeyRsa.generate_key()
            .get_public_key()
            .export(encoding=SPSDKEncoding.PEM),
            PublicKeyRsa,
            id="rsa_public_pem",
        ),
        pytest.param(
            lambda: PrivateKeyRsa.generate_key()
            .get_public_key()
            .export(encoding=SPSDKEncoding.DER),
            PublicKeyRsa,
            id="rsa_public_der",
        ),
        pytest.param(
            lambda: PrivateKeyEcc.generate_key().export(encoding=SPSDKEncoding.PEM),
            PrivateKeyEcc,
            id="ecc_private_pem",
        ),
        pytest.param(
            lambda: PrivateKeyEcc.generate_key()
            .get_public_key()
            .export(encoding=SPSDKEncoding.DER),
            PublicKeyEcc,
            id="ecc_public_der",
        ),
        pytest.param(lambda: random_bytes(16), bytes, id="bytes"),
        pytest.param(lambda: random_bytes(16).hex(), bytes, id="hex_string"),
    ],
)
def test_load_key_formats(tmpdir: str, key_data: Callable, key_type: Type) -> None:
    """Test load_key function with different key types and formats.

    This test verifies that load_key can correctly load various key types from files:
    - RSA private/public keys in PEM, DER, and NXP formats
    - ECC private/public keys in PEM, DER, and NXP formats
    - Hex string format keys

    :param key_data: Callable that generates key data or raw key bytes.
    :param key_type: Expected type of the loaded key.
    """
    actual_key_data = key_data()
    is_bin = isinstance(actual_key_data, bytes)
    # Save the key in the specified format
    file_path = Path(tmpdir) / f"test_key.{'bin' if is_bin else 'hex'}"
    write_file(actual_key_data, str(file_path), mode="wb" if is_bin else "w")
    # Load the key using load_key
    loaded_key = load_key(str(file_path))
    # Verify the loaded key type
    assert isinstance(loaded_key, key_type), f"Expected {key_type}, got {type(loaded_key)}"


# ===========================================================================================
# RSA key tests
# ===========================================================================================


@pytest.fixture
def rsa2048_private_key() -> PrivateKeyRsa:
    """Load RSA-2048 private key for tests."""
    return PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pem"))


@pytest.fixture
def rsa2048_public_key(rsa2048_private_key: PrivateKeyRsa) -> PublicKeyRsa:
    """Get RSA-2048 public key for tests."""
    return rsa2048_private_key.get_public_key()


def test_rsa_public_key_repr(rsa2048_public_key: PublicKeyRsa) -> None:
    """Test RSA public key __repr__ method."""
    result = repr(rsa2048_public_key)
    assert "RSA2048" in result
    assert "Public Key" in result


def test_rsa_public_key_str(rsa2048_public_key: PublicKeyRsa) -> None:
    """Test RSA public key __str__ method."""
    result = str(rsa2048_public_key)
    assert "RSA2048" in result
    assert "Public key" in result
    assert "e(" in result
    assert "n(" in result


def test_rsa_public_key_eq_same(rsa2048_public_key: PublicKeyRsa) -> None:
    """Test RSA public key equality with identical key."""
    pub2 = PublicKeyRsa(rsa2048_public_key.key)
    assert rsa2048_public_key == pub2


def test_rsa_public_key_eq_different(
    rsa2048_public_key: PublicKeyRsa, rsa2048_private_key: PrivateKeyRsa
) -> None:
    """Test RSA public key inequality with different objects."""
    other_priv = PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "srk0_rsa2048.pem"))
    other_pub = other_priv.get_public_key()
    assert rsa2048_public_key != other_pub
    assert rsa2048_public_key != rsa2048_private_key
    assert rsa2048_public_key != "not a key"


def test_rsa_private_key_repr(rsa2048_private_key: PrivateKeyRsa) -> None:
    """Test RSA private key __repr__ method."""
    result = repr(rsa2048_private_key)
    assert "RSA2048" in result
    assert "Private Key" in result


def test_rsa_private_key_str(rsa2048_private_key: PrivateKeyRsa) -> None:
    """Test RSA private key __str__ method."""
    result = str(rsa2048_private_key)
    assert "RSA2048" in result
    assert "Private key" in result
    assert "d(" in result


def test_rsa_private_key_verify_public_key(
    rsa2048_private_key: PrivateKeyRsa, rsa2048_public_key: PublicKeyRsa
) -> None:
    """Test that verify_public_key correctly validates matching key pair."""
    assert rsa2048_private_key.verify_public_key(rsa2048_public_key) is True


def test_rsa_private_key_verify_public_key_mismatch(rsa2048_private_key: PrivateKeyRsa) -> None:
    """Test that verify_public_key returns False for mismatched public key."""
    other_priv = PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "srk0_rsa2048.pem"))
    other_pub = other_priv.get_public_key()
    assert rsa2048_private_key.verify_public_key(other_pub) is False


def test_rsa_public_key_key_hash(rsa2048_public_key: PublicKeyRsa) -> None:
    """Test RSA public key hash computation."""
    h = rsa2048_public_key.key_hash()
    assert len(h) == 32
    h384 = rsa2048_public_key.key_hash(EnumHashAlgorithm.SHA384)
    assert len(h384) == 48


def test_rsa_sign_pss_padding(
    rsa2048_private_key: PrivateKeyRsa, rsa2048_public_key: PublicKeyRsa
) -> None:
    """Test RSA signing with PSS padding."""
    data = b"test data for pss signing"
    signature = rsa2048_private_key.sign(data, pss_padding=True)
    assert len(signature) == 256
    valid = rsa2048_public_key.verify_signature(signature, data, pss_padding=True)
    assert valid is True


def test_rsa_sign_prehashed(
    rsa2048_private_key: PrivateKeyRsa, rsa2048_public_key: PublicKeyRsa
) -> None:
    """Test RSA signing with pre-hashed data."""
    data = b"test data to hash then sign"
    hashed = get_hash(data, EnumHashAlgorithm.SHA256)
    signature = rsa2048_private_key.sign(hashed, prehashed=True)
    assert len(signature) == 256
    valid = rsa2048_public_key.verify_signature(signature, hashed, prehashed=True)
    assert valid is True


def test_rsa_sign_pss_prehashed(
    rsa2048_private_key: PrivateKeyRsa, rsa2048_public_key: PublicKeyRsa
) -> None:
    """Test RSA signing with PSS padding and pre-hashed data."""
    data = b"test data"
    hashed = get_hash(data, EnumHashAlgorithm.SHA256)
    signature = rsa2048_private_key.sign(hashed, pss_padding=True, prehashed=True)
    assert len(signature) == 256
    valid = rsa2048_public_key.verify_signature(signature, hashed, pss_padding=True, prehashed=True)
    assert valid is True


def test_rsa_public_key_parse_invalid() -> None:
    """Test that parsing invalid data raises SPSDKError."""
    with pytest.raises(SPSDKError):
        PublicKeyRsa.parse(b"invalid rsa public key data")


def test_rsa_private_key_parse_invalid() -> None:
    """Test that parsing invalid private key data raises SPSDKError."""
    with pytest.raises(SPSDKError):
        PrivateKeyRsa.parse(b"invalid rsa private key data")


def test_rsa_private_key_parse_ecc_key() -> None:
    """Test that parsing ECC key as RSA private key raises SPSDKInvalidKeyType."""
    ecc_priv = PrivateKeyEcc.load(os.path.join(KEYS_DIR, "ecc256", "imgkey_ecc256.pem"))
    ecc_der = ecc_priv.export(encoding=SPSDKEncoding.DER)
    with pytest.raises(SPSDKInvalidKeyType):
        PrivateKeyRsa.parse(ecc_der)


def test_rsa_public_key_parse_ecc_key() -> None:
    """Test that parsing ECC public key as RSA raises SPSDKInvalidKeyType."""
    ecc_priv = PrivateKeyEcc.load(os.path.join(KEYS_DIR, "ecc256", "imgkey_ecc256.pem"))
    ecc_pub = ecc_priv.get_public_key()
    ecc_pub_der = ecc_pub.export(encoding=SPSDKEncoding.DER)
    with pytest.raises((SPSDKInvalidKeyType, SPSDKError)):
        PublicKeyRsa.parse(ecc_pub_der)


def test_rsa_public_key_recreate() -> None:
    """Test PublicKeyRsa.recreate from exponent and modulus."""
    priv = PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pem"))
    pub = priv.get_public_key()
    e = pub.public_numbers.e
    n = pub.public_numbers.n
    recreated = PublicKeyRsa.recreate(exponent=e, modulus=n)
    assert recreated == pub


# ===========================================================================================
# ECC key tests
# ===========================================================================================


@pytest.fixture
def ecc256_private_key() -> PrivateKeyEcc:
    """Load ECC P-256 private key for tests."""
    return PrivateKeyEcc.load(os.path.join(KEYS_DIR, "ecc256", "imgkey_ecc256.pem"))


@pytest.fixture
def ecc256_public_key(ecc256_private_key: PrivateKeyEcc) -> PublicKeyEcc:
    """Get ECC P-256 public key for tests."""
    return ecc256_private_key.get_public_key()


def test_ecc_private_key_repr(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECC private key __repr__ method."""
    result = repr(ecc256_private_key)
    assert "ECC" in result
    assert "Private Key" in result


def test_ecc_private_key_str(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECC private key __str__ method."""
    result = str(ecc256_private_key)
    assert "ECC" in result
    assert "Private key" in result
    assert "d(" in result


def test_ecc_public_key_repr(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC public key __repr__ method."""
    result = repr(ecc256_public_key)
    assert "ECC" in result
    assert "Public Key" in result


def test_ecc_public_key_str(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC public key __str__ method."""
    result = str(ecc256_public_key)
    assert "ECC" in result
    assert "Public key" in result
    assert "x(" in result
    assert "y(" in result


def test_ecc_public_key_eq_same(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC public key equality with identical key."""
    pub2 = PublicKeyEcc(ecc256_public_key.key)
    assert ecc256_public_key == pub2


def test_ecc_public_key_eq_different(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC public key inequality with different objects."""
    other_priv = PrivateKeyEcc.load(os.path.join(KEYS_DIR, "ecc256", "srk0_ecc256.pem"))
    other_pub = other_priv.get_public_key()
    assert ecc256_public_key != other_pub
    assert ecc256_public_key != "not a key"


def test_ecc_private_key_verify_public_key(
    ecc256_private_key: PrivateKeyEcc, ecc256_public_key: PublicKeyEcc
) -> None:
    """Test ECC verify_public_key with matching key pair."""
    assert ecc256_private_key.verify_public_key(ecc256_public_key) is True


def test_ecc_private_key_verify_public_key_mismatch(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECC verify_public_key with non-matching public key."""
    other_priv = PrivateKeyEcc.load(os.path.join(KEYS_DIR, "ecc256", "srk0_ecc256.pem"))
    other_pub = other_priv.get_public_key()
    assert ecc256_private_key.verify_public_key(other_pub) is False


def test_ecc_public_key_key_hash(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC public key hash computation."""
    h = ecc256_public_key.key_hash()
    assert len(h) == 32


def test_ecc_private_key_export_nxp(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECC private key export in NXP format."""
    exported = ecc256_private_key.export(encoding=SPSDKEncoding.NXP)
    assert len(exported) == 32  # P-256 = 32 bytes


def test_ecc_private_key_sign_der_format(
    ecc256_private_key: PrivateKeyEcc, ecc256_public_key: PublicKeyEcc
) -> None:
    """Test ECC sign returns DER-encoded signature."""
    data = b"test data for ecc sign"
    signature_der = ecc256_private_key.sign(data, der_format=True)
    assert signature_der[0] == 0x30  # DER sequence marker
    valid = ecc256_public_key.verify_signature(signature_der, data)
    assert valid is True


def test_ecc_private_key_sign_prehashed(
    ecc256_private_key: PrivateKeyEcc, ecc256_public_key: PublicKeyEcc
) -> None:
    """Test ECC sign with pre-hashed input."""
    data = b"test data to hash"
    hashed = get_hash(data, EnumHashAlgorithm.SHA256)
    signature = ecc256_private_key.sign(hashed, prehashed=True)
    valid = ecc256_public_key.verify_signature(signature, hashed, prehashed=True)
    assert valid is True


def test_ecc_private_key_parse_invalid() -> None:
    """Test that parsing invalid data as ECC private key raises SPSDKInvalidKeyType."""
    rsa_priv = PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pem"))
    rsa_der = rsa_priv.export(encoding=SPSDKEncoding.DER)
    with pytest.raises(SPSDKInvalidKeyType):
        PrivateKeyEcc.parse(rsa_der)


def test_ecc_public_key_recreate(ecc256_public_key: PublicKeyEcc) -> None:
    """Test PublicKeyEcc.recreate from coordinates."""
    recreated = PublicKeyEcc.recreate(
        coor_x=ecc256_public_key.x,
        coor_y=ecc256_public_key.y,
        curve=EccCurve.SECP256R1,
    )
    assert recreated == ecc256_public_key


def test_ecc_public_key_recreate_from_data(ecc256_public_key: PublicKeyEcc) -> None:
    """Test PublicKeyEcc.recreate_from_data from NXP-encoded bytes."""
    nxp_data = ecc256_public_key.export(encoding=SPSDKEncoding.NXP)
    recreated = PublicKeyEcc.recreate_from_data(nxp_data)
    assert recreated == ecc256_public_key


def test_ecc_verify_signature_invalid(ecc256_public_key: PublicKeyEcc) -> None:
    """Test ECC signature verification with bad signature."""
    data = b"some data"
    bad_sig = bytes(64)  # all zeros
    valid = ecc256_public_key.verify_signature(bad_sig, data)
    assert valid is False


def test_ecc_exchange_key(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECDH key exchange."""
    other_priv = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
    peer_pub = other_priv.get_public_key()
    shared = ecc256_private_key.exchange(peer_pub)
    assert len(shared) == 32


# ===========================================================================================
# ECDSASignature tests
# ===========================================================================================


def test_ecdsa_signature_parse_nxp(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECDSASignature parse from NXP format."""
    data = b"data to sign"
    sig_bytes = ecc256_private_key.sign(data)
    ecdsa = ECDSASignature.parse(sig_bytes)
    assert ecdsa.ecc_curve == EccCurve.SECP256R1
    assert ecdsa.r != 0
    assert ecdsa.s != 0


def test_ecdsa_signature_parse_der(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECDSASignature parse from DER format."""
    data = b"data to sign"
    sig_der = ecc256_private_key.sign(data, der_format=True)
    ecdsa = ECDSASignature.parse(sig_der)
    assert ecdsa.r != 0
    assert ecdsa.s != 0


def test_ecdsa_signature_export_nxp(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECDSASignature export in NXP format."""
    data = b"data to sign"
    sig_bytes = ecc256_private_key.sign(data)
    ecdsa = ECDSASignature.parse(sig_bytes)
    exported = ecdsa.export(SPSDKEncoding.NXP)
    assert len(exported) == 64


def test_ecdsa_signature_export_der(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECDSASignature export in DER format."""
    data = b"data to sign"
    sig_bytes = ecc256_private_key.sign(data)
    ecdsa = ECDSASignature.parse(sig_bytes)
    exported_der = ecdsa.export(SPSDKEncoding.DER)
    assert exported_der[0] == 0x30  # DER sequence marker


def test_ecdsa_signature_export_invalid_encoding() -> None:
    """Test ECDSASignature export raises error for invalid encoding."""
    ecdsa = ECDSASignature(1234, 5678, EccCurve.SECP256R1)
    with pytest.raises(SPSDKValueError):
        ecdsa.export(SPSDKEncoding.PEM)


def test_ecdsa_signature_get_encoding_invalid() -> None:
    """Test ECDSASignature.get_encoding raises error for unknown format."""
    with pytest.raises(SPSDKValueError):
        ECDSASignature.get_encoding(b"x" * 17)


# ===========================================================================================
# NonSupporting key tests
# ===========================================================================================


def test_non_supporting_public_key_raises() -> None:
    """Test that NonSupportingPublicKey cannot be instantiated (abstract)."""
    with pytest.raises((TypeError, SPSDKNotImplementedError)):
        NonSupportingPublicKey()  # type: ignore[abstract]


def test_non_supporting_private_key_raises() -> None:
    """Test that NonSupportingPrivateKey cannot be instantiated (abstract)."""
    with pytest.raises((TypeError, SPSDKNotImplementedError)):
        NonSupportingPrivateKey()  # type: ignore[abstract]


# ===========================================================================================
# Helper function tests
# ===========================================================================================


def test_get_ecc_curve_256() -> None:
    """Test get_ecc_curve for 32-byte key."""
    assert get_ecc_curve(32) == EccCurve.SECP256R1


def test_get_ecc_curve_384() -> None:
    """Test get_ecc_curve for 48-byte key."""
    assert get_ecc_curve(48) == EccCurve.SECP384R1


def test_get_ecc_curve_521() -> None:
    """Test get_ecc_curve for 66-byte key."""
    assert get_ecc_curve(66) == EccCurve.SECP521R1


def test_get_ecc_curve_64() -> None:
    """Test get_ecc_curve for 64-byte data (raw public X+Y for P-256)."""
    assert get_ecc_curve(64) == EccCurve.SECP256R1


def test_get_ecc_curve_invalid() -> None:
    """Test get_ecc_curve raises SPSDKError for unknown length."""
    with pytest.raises(SPSDKError):
        get_ecc_curve(1000)


def test_get_supported_keys_generators_basic() -> None:
    """Test get_supported_keys_generators with basic=True returns only RSA and ECC."""
    generators = get_supported_keys_generators(basic=True)
    assert "rsa2048" in generators
    assert "secp256r1" in generators
    # SM2, Dilithium, ML-DSA, LMS should not be in basic mode
    assert "sm2" not in generators
    assert "dil2" not in generators


def test_get_supported_keys_generators_full() -> None:
    """Test get_supported_keys_generators returns at least RSA and ECC keys."""
    generators = get_supported_keys_generators(basic=False)
    assert "rsa2048" in generators
    assert "rsa4096" in generators
    assert "secp256r1" in generators
    assert "secp384r1" in generators
    assert "secp521r1" in generators


def test_load_key_private(tmp_path: str) -> None:
    """Test load_key returns PrivateKey for private key file."""
    PrivateKeyRsa.load(os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pem"))
    key_path = os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pem")
    loaded = load_key(key_path)
    assert isinstance(loaded, PrivateKeyRsa)


def test_load_key_public() -> None:
    """Test load_key returns PublicKey for public key file."""
    key_path = os.path.join(KEYS_DIR, "rsa2048", "imgkey_rsa2048.pub")
    loaded = load_key(key_path)
    assert isinstance(loaded, PublicKeyRsa)


def test_load_key_invalid() -> None:
    """Test load_key raises SPSDKError for a non-existent file path."""
    with pytest.raises((SPSDKError, FileNotFoundError, Exception)):
        load_key("nonexistent_path_xyz.pem")


def test_ecc_public_key_sign_verify_prehashed(ecc256_private_key: PrivateKeyEcc) -> None:
    """Test ECC public key verify_signature with prehashed data."""
    data = b"test data"
    hashed = get_hash(data, EnumHashAlgorithm.SHA256)
    sig = ecc256_private_key.sign(hashed, prehashed=True)
    pub = ecc256_private_key.get_public_key()
    valid = pub.verify_signature(sig, hashed, prehashed=True)
    assert valid is True


def test_rsa_public_key_verify_signature_invalid(rsa2048_public_key: PublicKeyRsa) -> None:
    """Test RSA public key verify_signature with invalid signature."""
    data = b"some data"
    bad_sig = bytes(256)  # all zeros
    valid = rsa2048_public_key.verify_signature(bad_sig, data)
    assert valid is False


CRYPTO_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


# ===========================================================================================
# Branch coverage additions
# ===========================================================================================


def test_private_key_eq_different_keys_same_class() -> None:
    """Test PrivateKey.__eq__ returns False for two different keys of the same class.

    Covers the branch where isinstance(obj, self.__class__) is True but
    get_public_key() != obj.get_public_key() (line 452).
    """
    key1 = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
    key2 = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP256R1)
    assert key1 != key2


def test_crypto_load_private_key_unsupported_encoding() -> None:
    """Test _crypto_load_private_key raises SPSDKValueError for unsupported encoding (line 227)."""
    with pytest.raises(SPSDKValueError):
        _crypto_load_private_key(SPSDKEncoding.NXP, b"data", None)


def test_private_key_parse_wrong_password() -> None:
    """Test that loading a password-protected key with wrong password raises SPSDKWrongKeyPassphrase.

    Covers line 238 in _crypto_load_private_key.
    """
    key = PrivateKeyEcc.generate_key()
    pem_data = key.export(encoding=SPSDKEncoding.PEM, password="correct_pass")
    with pytest.raises(SPSDKWrongKeyPassphrase):
        _crypto_load_private_key(SPSDKEncoding.PEM, pem_data, b"wrong_pass")


def test_private_key_parse_missing_password() -> None:
    """Test that loading an encrypted key without password raises SPSDKKeyPassphraseMissing.

    Covers lines 240-242 in _crypto_load_private_key.
    """
    key = PrivateKeyEcc.generate_key()
    pem_data = key.export(encoding=SPSDKEncoding.PEM, password="secret")
    with pytest.raises(SPSDKKeyPassphraseMissing):
        _crypto_load_private_key(SPSDKEncoding.PEM, pem_data, None)


def test_private_key_create_invalid_type() -> None:
    """Test PrivateKey.create() raises SPSDKInvalidKeyType for unsupported type (line 569)."""
    with pytest.raises(SPSDKInvalidKeyType):
        PrivateKey.create("not_a_key")


def test_public_key_create_invalid_type() -> None:
    """Test PublicKey.create() raises SPSDKInvalidKeyType for unsupported type (line 776)."""
    with pytest.raises(SPSDKInvalidKeyType):
        PublicKey.create("not_a_key")


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="gmssl (SM2) not installed")
def test_sm2_private_key_parse() -> None:
    """Test loading SM2 private key via PrivateKey.parse() covers the SM2 branch (line 528)."""
    pem_data = open(os.path.join(CRYPTO_DATA_DIR, "openssl_sm2_private.pem"), "rb").read()
    key = PrivateKey.parse(data=pem_data)
    assert isinstance(key, PrivateKeySM2)


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="gmssl (SM2) not installed")
def test_sm2_public_key_parse() -> None:
    """Test loading SM2 public key via PublicKey.parse() covers SM2 public parse path."""
    pem_data = open(os.path.join(CRYPTO_DATA_DIR, "openssl_sm2_public.pem"), "rb").read()
    key = PublicKey.parse(data=pem_data)
    assert isinstance(key, PublicKeySM2)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_dilithium_private_key_parse() -> None:
    """Test loading Dilithium private key via PrivateKey.parse() covers line 529."""
    pem_data = open(os.path.join(KEYS_DIR, "dil3", "srk0_dil3.pem"), "rb").read()
    key = PrivateKey.parse(data=pem_data)
    assert isinstance(key, PrivateKeyDilithium)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_dilithium_public_key_parse() -> None:
    """Test loading Dilithium public key via PublicKey.parse() covers lines 694->704."""
    pub_data = open(os.path.join(KEYS_DIR, "dil3", "srk0_dil3.pub"), "rb").read()
    key = PublicKey.parse(data=pub_data)
    assert isinstance(key, PublicKeyDilithium)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_mldsa_private_key_parse() -> None:
    """Test loading ML-DSA private key via PrivateKey.parse() covers line 531."""
    pem_data = open(os.path.join(KEYS_DIR, "mldsa65", "srk0_mldsa65.pem"), "rb").read()
    key = PrivateKey.parse(data=pem_data)
    assert isinstance(key, PrivateKeyMLDSA)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_mldsa_public_key_parse() -> None:
    """Test loading ML-DSA public key via PublicKey.parse() covers lines 704->714."""
    pub_data = open(os.path.join(KEYS_DIR, "mldsa65", "srk0_mldsa65.pub"), "rb").read()
    key = PublicKey.parse(data=pub_data)
    assert isinstance(key, PublicKeyMLDSA)


@pytest.mark.skipif(not IS_LMS_SUPPORTED, reason="spsdk-pqc with LMS support not installed")
def test_lms_public_key_parse() -> None:
    """Test loading LMS public key via PublicKey.parse() covers lines 704->714 LMS branch."""
    lms_priv = PrivateKeyLMS.generate_key(LMSParams(hash_length=32, height=5, w=1))
    lms_pub = lms_priv.get_public_key()
    pub_data = lms_pub.export()
    key = PublicKey.parse(data=pub_data)
    assert isinstance(key, PublicKeyLMS)


def test_private_key_parse_invalid_data_raises() -> None:
    """Test PrivateKey.parse() with invalid DER data raises SPSDKError (lines 536-537)."""
    with pytest.raises(SPSDKError):
        PrivateKey.parse(data=b"\x00" * 32)


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="gmssl (SM2) not installed")
def test_sm2_private_key_create() -> None:
    """Test PrivateKey.create() dispatches to PrivateKeySM2 for SM2 key (lines 555->558)."""
    open(os.path.join(CRYPTO_DATA_DIR, "openssl_sm2_private.pem"), "rb").read()
    sm2_key = PrivateKeySM2.load(os.path.join(CRYPTO_DATA_DIR, "openssl_sm2_private.pem"))
    created = PrivateKey.create(sm2_key.key)
    assert isinstance(created, PrivateKeySM2)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_dilithium_private_key_create() -> None:
    """Test PrivateKey.create() dispatches for Dilithium key (lines 558->562)."""
    dil_key = PrivateKeyDilithium.load(os.path.join(KEYS_DIR, "dil3", "srk0_dil3.pem"))
    created = PrivateKey.create(dil_key.key)
    assert isinstance(created, PrivateKeyDilithium)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_mldsa_private_key_create() -> None:
    """Test PrivateKey.create() dispatches for ML-DSA key (lines 562->565)."""
    mldsa_key = PrivateKeyMLDSA.load(os.path.join(KEYS_DIR, "mldsa65", "srk0_mldsa65.pem"))
    created = PrivateKey.create(mldsa_key.key)
    assert isinstance(created, PrivateKeyMLDSA)


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="gmssl (SM2) not installed")
def test_sm2_public_key_create() -> None:
    """Test PublicKey.create() dispatches to PublicKeySM2 (lines 762->765)."""
    sm2_pub = PublicKeySM2.load(os.path.join(CRYPTO_DATA_DIR, "openssl_sm2_public.pem"))
    created = PublicKey.create(sm2_pub.key)
    assert isinstance(created, PublicKeySM2)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_dilithium_public_key_create() -> None:
    """Test PublicKey.create() dispatches for Dilithium public key (lines 765->769)."""
    dil_pub = PublicKeyDilithium.load(os.path.join(KEYS_DIR, "dil3", "srk0_dil3.pub"))
    created = PublicKey.create(dil_pub.key)
    assert isinstance(created, PublicKeyDilithium)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_mldsa_public_key_create() -> None:
    """Test PublicKey.create() dispatches for ML-DSA public key (lines 769->772)."""
    mldsa_pub = PublicKeyMLDSA.load(os.path.join(KEYS_DIR, "mldsa65", "srk0_mldsa65.pub"))
    created = PublicKey.create(mldsa_pub.key)
    assert isinstance(created, PublicKeyMLDSA)


@pytest.mark.skipif(not IS_LMS_SUPPORTED, reason="spsdk-pqc with LMS support not installed")
def test_lms_private_key_parse() -> None:
    """Test loading LMS private key via PrivateKey.parse() covers lines 533-534."""
    lms_priv = PrivateKeyLMS.generate_key(LMSParams(hash_length=32, height=5, w=1))
    priv_data = lms_priv.export()
    key = PrivateKey.parse(data=priv_data)
    assert isinstance(key, PrivateKeyLMS)


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_otps_format_public_key_parse() -> None:
    """Test PublicKey.parse() with OTPS-format MLDSA key covers line 718.

    Constructs an OTPS-format SubjectPublicKeyInfo where the subjectPublicKey BitString
    contains a SEQUENCE (non-standard wrapping used by NXP hardware). This data fails all
    standard parse paths and is handled by the OTPS extraction fallback.
    """
    from pyasn1.codec.der.encoder import encode as asn1_encode
    from pyasn1.type import univ as asn1_univ

    from spsdk.crypto._otps_puk import AlgorithmIdentifier, SubjectPublicKeyInfo

    priv = PrivateKeyMLDSA.load(os.path.join(KEYS_DIR, "mldsa65", "srk0_mldsa65.pem"))
    raw_key = priv.get_public_key().export()

    # Wrap the key in a SEQUENCE inside a BitString (the OTPS non-standard format)
    half = len(raw_key) // 2
    inner_seq = asn1_univ.Sequence()
    inner_seq.setComponentByPosition(0, asn1_univ.OctetString(raw_key[:half]))
    inner_seq.setComponentByPosition(1, asn1_univ.OctetString(raw_key[half:]))
    inner_seq_encoded = asn1_encode(inner_seq)

    mldsa_oid = asn1_univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 3, 18))
    alg_id = AlgorithmIdentifier()
    alg_id.setComponentByPosition(0, mldsa_oid)

    spki = SubjectPublicKeyInfo()
    spki.setComponentByPosition(0, alg_id)
    spki.setComponentByPosition(1, asn1_univ.BitString(hexValue=inner_seq_encoded.hex()))
    otps_data = asn1_encode(spki)

    key = PublicKey.parse(data=otps_data)
    assert isinstance(key, PublicKeyMLDSA)

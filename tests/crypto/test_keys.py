#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import EccCurve, ECDSASignature, PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc
from spsdk.exceptions import SPSDKValueError


def test_rsa_sign(data_dir):
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


def test_rsa_verify(data_dir):
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


def test_ecc_sign_verify(data_dir):
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
    assert is_valid == is_valid2 == True


def test_ecc_sign_verify_incorrect(data_dir):
    private_key = PrivateKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"))
    public_key = PublicKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"))

    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = private_key.sign(data)

    # malform the signature
    bad_signature = calc_signature[:-2] + bytes(2)
    is_valid = public_key.verify_signature(signature=bad_signature, data=data)
    assert is_valid == False

    # make signature bigger than expected
    bad_signature = calc_signature + bytes(2)
    assert not public_key.verify_signature(signature=bad_signature, data=data)


def test_keys_generation_2048(tmpdir):
    priv_key = PrivateKeyRsa.generate_key()
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_2048.pem"))
    pub_key.save(os.path.join(tmpdir, "pub_2048.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_2048.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_2048.pem"))


def test_keys_generation_2048_with_password(tmpdir):
    priv_key = PrivateKeyRsa.generate_key()
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_2048_password.pem"), "abc")
    pub_key.save(os.path.join(tmpdir, "pub_2048_2.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_2048_password.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_2048_2.pem"))


def test_keys_generation_3072(tmpdir):
    priv_key = PrivateKeyRsa.generate_key(key_size=3072)
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, "priv_3072.pem"))
    pub_key.save(os.path.join(tmpdir, "pub_3072.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "priv_3072.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "pub_3072.pem"))


def test_keys_generation_4096(tmpdir):
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
def test_keys_generation_ec(tmpdir, ec_name):
    priv_key = PrivateKeyEcc.generate_key(curve_name=ec_name)
    pub_key = priv_key.get_public_key()
    priv_key.save(os.path.join(tmpdir, f"key_{ec_name}.pem"))
    pub_key.save(os.path.join(tmpdir, f"key_{ec_name}.pub"))
    assert os.path.isfile(os.path.join(tmpdir, f"key_{ec_name}.pem"))
    assert os.path.isfile(os.path.join(tmpdir, f"key_{ec_name}.pub"))


def test_keys_generation_ec_invalid():
    with pytest.raises(SPSDKValueError):
        PrivateKeyEcc.generate_key(curve_name="invalid")


@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "ec_curve",
    [EccCurve.SECP256R1, EccCurve.SECP384R1, EccCurve.SECP521R1],
)
def test_ecdsa_signature(ec_curve, encoding):
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
def test_ecdsa_signature_get_encoding(ec_curve):
    priv_key = PrivateKeyEcc.generate_key(curve_name=ec_curve)
    signature = priv_key.sign(b"", der_format=True)
    ECDSASignature.get_encoding(signature) == SPSDKEncoding.DER
    signature = priv_key.sign(b"")
    ECDSASignature.get_encoding(signature) == SPSDKEncoding.NXP


def test_ecdsa_signature_get_encoding_rsa():
    key_sizes = [2048, 4096]
    for key_size in key_sizes:
        rsa_key = PrivateKeyRsa.generate_key()
        signature = rsa_key.sign(b"")
        with pytest.raises(SPSDKValueError):
            ECDSASignature.get_encoding(signature)

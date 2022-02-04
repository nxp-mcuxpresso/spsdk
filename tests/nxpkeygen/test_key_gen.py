#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for key management (generating public/private key)
"""
from os import path

import pytest

from spsdk import SPSDKValueError
from spsdk.crypto.keys_management import (
    generate_ecc_private_key,
    generate_ecc_public_key,
    generate_rsa_private_key,
    generate_rsa_public_key,
    save_ecc_private_key,
    save_ecc_public_key,
    save_rsa_private_key,
    save_rsa_public_key,
)


def test_keys_generation_2048(tmpdir):
    priv_key = generate_rsa_private_key()
    pub_key = generate_rsa_public_key(priv_key)
    save_rsa_private_key(priv_key, path.join(tmpdir, "priv_2048.pem"))
    save_rsa_public_key(pub_key, path.join(tmpdir, "pub_2048.pem"))
    assert path.isfile(path.join(tmpdir, "priv_2048.pem"))
    assert path.isfile(path.join(tmpdir, "pub_2048.pem"))


def test_keys_generation_2048_with_password(tmpdir):
    priv_key = generate_rsa_private_key()
    pub_key = generate_rsa_public_key(priv_key)
    save_rsa_private_key(priv_key, path.join(tmpdir, "priv_2048_password.pem"), "abc")
    save_rsa_public_key(pub_key, path.join(tmpdir, "pub_2048_2.pem"))
    assert path.isfile(path.join(tmpdir, "priv_2048_password.pem"))
    assert path.isfile(path.join(tmpdir, "pub_2048_2.pem"))


def test_keys_generation_3072(tmpdir):
    priv_key = generate_rsa_private_key(key_size=3072)
    pub_key = generate_rsa_public_key(priv_key)
    save_rsa_private_key(priv_key, path.join(tmpdir, "priv_3072.pem"))
    save_rsa_public_key(pub_key, path.join(tmpdir, "pub_3072.pem"))
    assert path.isfile(path.join(tmpdir, "priv_3072.pem"))
    assert path.isfile(path.join(tmpdir, "pub_3072.pem"))


def test_keys_generation_4096(tmpdir):
    priv_key = generate_rsa_private_key(key_size=4096)
    pub_key = generate_rsa_public_key(priv_key)
    save_rsa_private_key(priv_key, path.join(tmpdir, "priv_4096.pem"))
    save_rsa_public_key(pub_key, path.join(tmpdir, "pub_4096.pem"))
    assert path.isfile(path.join(tmpdir, "priv_4096.pem"))
    assert path.isfile(path.join(tmpdir, "pub_4096.pem"))


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
    priv_key = generate_ecc_private_key(curve_name=ec_name)
    pub_key = generate_ecc_public_key(priv_key)
    save_ecc_private_key(priv_key, path.join(tmpdir, f"key_{ec_name}.pem"))
    save_ecc_public_key(pub_key, path.join(tmpdir, f"key_{ec_name}.pub"))
    assert path.isfile(path.join(tmpdir, f"key_{ec_name}.pem"))
    assert path.isfile(path.join(tmpdir, f"key_{ec_name}.pub"))


def test_keys_generation_ec_invalid(tmpdir):
    with pytest.raises(SPSDKValueError):
        generate_ecc_private_key(curve_name="invalid")

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for Signature Provider interface."""
from os import path

import pytest

from spsdk.crypto.keys import IS_OSCCA_SUPPORTED, PrivateKeySM2, PublicKeySM2
from spsdk.crypto.signature_provider import SignatureProvider


def test_types():
    types = SignatureProvider.get_types()
    assert "file" in types

    class TestSP(SignatureProvider):
        sp_type = "test-typesp-test"

    types = SignatureProvider.get_types()
    assert "test-typesp-test" in types


def test_invalid_sp_type():
    provider = SignatureProvider.create("type=totally_legit_provider")
    assert provider is None


def test_plain_file(data_dir):
    my_key_path = path.join(data_dir, "priv.pem").replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider.sp_type == "file"
    assert my_key_path in provider.info()


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private.pem", "openssl_sm2_private.pem"),
    ],
)
def test_sm2_plain_file(data_dir, signing_key_file, verification_key_file):
    my_key_path = path.join(data_dir, signing_key_file).replace("\\", "/")
    verification_key_path = path.join(data_dir, verification_key_file).replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider.sp_type == "file"
    assert my_key_path in provider.info()

    message = b"message to sign"

    signature = provider.sign(data=message)
    verification_key = PrivateKeySM2.load(verification_key_path).get_public_key()
    verification_key.verify_signature(signature=signature, data=message)


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private_custom.der", "openssl_sm2_public.pem"),
    ],
)
def test_sm2_verify_public(data_dir, signing_key_file, verification_key_file):
    my_key_path = path.join(data_dir, signing_key_file).replace("\\", "/")
    verification_key_path = path.join(data_dir, verification_key_file).replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider.sp_type == "file"
    assert my_key_path in provider.info()

    verification_key = PublicKeySM2.load(verification_key_path)

    assert provider.verify_public_key(verification_key.export())

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for Signature Provider interface."""
import os
from os import path

import pytest

from spsdk.crypto.keys import (
    IS_OSCCA_SUPPORTED,
    ECDSASignature,
    PrivateKeyEcc,
    PrivateKeySM2,
    PublicKeySM2,
    get_supported_keys_generators,
)
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.types import SPSDKEncoding
from spsdk.exceptions import SPSDKKeyError
from spsdk.utils.misc import write_file


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


@pytest.mark.parametrize(
    "key_type",
    ["rsa2048", "secp256r1", "secp521r1"],
)
def test_get_signature(tmpdir, key_type):
    func, params = get_supported_keys_generators()[key_type]
    private_key = func(**params)
    private_key_path = os.path.join(tmpdir, f"{key_type}.der")
    write_file(private_key.export(), private_key_path, mode="wb")
    provider = SignatureProvider.create(f"type=file;file_path={private_key_path}")
    signature = provider.get_signature(b"")
    if isinstance(private_key, PrivateKeyEcc):
        assert ECDSASignature.get_encoding(signature) == SPSDKEncoding.NXP
    else:
        assert private_key.signature_size == len(signature)


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

    signature = provider.get_signature(data=message)
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


@pytest.mark.parametrize(
    "sp_cfg, sp_type, parsed_args, exception",
    [
        (
            "type=proxy;host=localhost;port=8000;url_prefix=server;key_type=IMG;key_index=0;data=ahoj",
            "proxy",
            {"key_type": "IMG", "key_index": "0"},
            False,
        ),
        (
            "type=proxy;host=localhost;port=8000;url_prefix=server;key_type=IMG;key_index=0;host=ahoj",
            "proxy",
            {},
            True,
        ),
    ],
)
def test_get_signature_provider(sp_cfg, sp_type, parsed_args, exception):
    if exception:
        with pytest.raises(SPSDKKeyError):
            sp = get_signature_provider(sp_cfg)
    else:
        sp = get_signature_provider(sp_cfg)
        assert sp.sp_type == sp_type
        assert sp.kwargs == parsed_args

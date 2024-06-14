#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for Signature Provider interface."""
import json
import os
from os import path
from unittest.mock import patch

import pytest

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import (
    IS_OSCCA_SUPPORTED,
    EccCurve,
    ECDSASignature,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PrivateKeySM2,
    PublicKeyEcc,
    PublicKeySM2,
    get_supported_keys_generators,
)
from spsdk.crypto.signature_provider import (
    HttpProxySP,
    SignatureProvider,
    get_signature_provider,
    requests,
)
from spsdk.exceptions import SPSDKError, SPSDKKeyError
from spsdk.utils.misc import write_file


def test_types():
    types = SignatureProvider.get_types()
    assert "file" in types

    class TestSP(SignatureProvider):
        identifier = "test-typesp-test"

    types = SignatureProvider.get_types()
    assert "test-typesp-test" in types


def test_invalid_sp_type():
    provider = SignatureProvider.create("type=totally_legit_provider")
    assert provider is None


def test_plain_file(data_dir):
    my_key_path = path.join(data_dir, "priv.pem").replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider.identifier == "file"
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

    assert provider.identifier == "file"
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

    assert provider.identifier == "file"
    assert my_key_path in provider.info()

    verification_key = PublicKeySM2.load(verification_key_path)

    assert provider.verify_public_key(verification_key)


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
        assert sp.identifier == sp_type
        assert sp.kwargs == parsed_args


PASSPHRASE = "test_pwd"


@pytest.fixture
def private_key(tmpdir) -> str:
    private_key = PrivateKeyRsa.generate_key(key_size=2048)
    private_key_path = os.path.join(tmpdir, f"private.der")
    write_file(private_key.export(password=PASSPHRASE), private_key_path, mode="wb")
    return private_key_path


def test_encrypted_key_no_password(private_key):
    config_string = f"type=file;file_path={private_key}"
    with pytest.raises(SPSDKError):
        SignatureProvider.create(config_string)


def test_encrypted_key_plain_password(private_key):
    config_string = f"type=file;file_path={private_key};password={PASSPHRASE}"
    SignatureProvider.create(config_string)


def test_encrypted_key_env_variable_value(private_key):
    os.environ["KEY_PASSPHRASE"] = PASSPHRASE
    config_string = f"type=file;file_path={private_key};password=${{KEY_PASSPHRASE}}"
    SignatureProvider.create(config_string)


def test_encrypted_key_path_to_file(tmpdir, private_key):
    pass_file = os.path.join(tmpdir, "passphrase.txt")
    write_file(PASSPHRASE, pass_file)
    config_string = f"type=file;file_path={private_key};password={pass_file}"
    SignatureProvider.create(config_string)


def test_encrypted_key_env_variable_with_path_to_file(tmpdir, private_key):
    pass_file = os.path.join(tmpdir, "passphrase.txt")
    write_file(PASSPHRASE, pass_file)
    os.environ["KEY_PASSPHRASE"] = pass_file
    config_string = f"type=file;file_path={private_key};password=${{KEY_PASSPHRASE}}"
    SignatureProvider.create(config_string)


@patch("spsdk.crypto.signature_provider.prompt_for_passphrase", lambda: PASSPHRASE)
def test_encrypted_key_no_password_interactive_sp(private_key):
    config_string = f"type=interactive_file;file_path={private_key}"
    SignatureProvider.create(config_string)


@patch("spsdk.crypto.keys.SPSDK_INTERACTIVE_DISABLED", True)
def test_encrypted_key_no_password_interactive_sp_non_interactive(private_key):
    config_string = f"type=interactive_file;file_path={private_key}"
    with pytest.raises(SPSDKError):
        SignatureProvider.create(config_string)


def test_proxy_sp_sign_metadata():
    sp = HttpProxySP(prehash="sha256")

    def my_thing(_, request: requests.PreparedRequest, **kwargs):
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers
        body = json.loads(request.body.decode("utf-8"))
        assert "prehashed" in body
        assert body["prehashed"] == "sha256"
        assert (
            bytes.fromhex(body["data"])
            == b"\xbf|\xbe\t\xd7\x1a\x1b\xcc7:\xb9\xa7d\x91\x7fs\nn\xd9Q\xff\xa1\xa79\x9bz\xbd\x8f\x8f\xd7<\xb4"
        )

    with pytest.raises(AttributeError):
        with patch("spsdk.crypto.signature_provider.requests.sessions.Session.send", my_thing):
            sp.sign(data=b"\x12\x34\x56")


def test_proxy_sp_verify_metadata():
    sp = HttpProxySP()
    prk = PrivateKeyEcc.generate_key()
    puk = prk.get_public_key()

    def my_thing(_, request: requests.PreparedRequest, **kwargs):
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers
        body = json.loads(request.body.decode("utf-8"))
        assert "encoding" in body
        assert body["encoding"] == "pem"
        puk2 = PublicKeyEcc.parse(body["data"].encode("utf-8"))
        assert puk == puk2

    with pytest.raises(AttributeError):
        with patch("spsdk.crypto.signature_provider.requests.sessions.Session.send", my_thing):
            sp.verify_public_key(public_key=puk)


def test_proxy_sp_signature_length_metadata():
    sp = HttpProxySP()

    def my_thing(_, request: requests.PreparedRequest, **kwargs):
        assert "spsdk-version" in request.headers
        assert "spsdk-api-version" in request.headers

    with pytest.raises(AttributeError):
        with patch("spsdk.crypto.signature_provider.requests.sessions.Session.send", my_thing):
            sp.signature_length

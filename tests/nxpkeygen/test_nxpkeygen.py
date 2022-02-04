#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpkeygen utility."""

import os

import pytest
from click.testing import CliRunner

from spsdk.apps.nxpkeygen import main
from spsdk.crypto import RSAPrivateKey, RSAPublicKey, load_private_key, load_public_key
from spsdk.utils.misc import use_working_directory


def test_command_line_interface():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0

    assert "Usage: main [OPTIONS] PATH" in result.output
    assert "NXP Key Generator Tool." in result.output
    assert (
        "PATH    - output file path, where the key pairs (private and public key) will be stored."
        in result.output
    )
    assert (
        "-k, --key-type KEY-TYPE  Set of the supported key types. Default is RSA2048."
        in result.output
    )


def test_generate_rsa_key(tmpdir) -> None:
    """Test generate rsa key pair."""

    cmd = f'{os.path.join(tmpdir, "key_rsa.pem")}'
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pub"))

    pub_key_from_file = load_public_key(os.path.join(tmpdir, "key_rsa.pub"))
    assert isinstance(pub_key_from_file, RSAPublicKey)
    assert pub_key_from_file.key_size == 2048

    priv_key_from_file = load_private_key(os.path.join(tmpdir, "key_rsa.pem"))
    assert isinstance(priv_key_from_file, RSAPrivateKey)
    assert priv_key_from_file.key_size == 2048


def test_generate_invalid_key(tmpdir) -> None:
    """Test generate invalid key pair."""

    cmd = f'genkey -k invalid-key-type {os.path.join(tmpdir, "key_invalid.pem")}'
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code != 0
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


def test_force_actual_dir(tmpdir):
    with use_working_directory(tmpdir):
        result = CliRunner().invoke(main, "-k rsa2048 key".split())
        assert result.exit_code == 0
        # attempt to rewrite the key should fail
        result = CliRunner().invoke(main, "-k rsa2048 key".split())
        assert result.exit_code == 1
        # attempt to rewrite should pass due to --forces
        result = CliRunner().invoke(main, "-k rsa2048 key --force".split())
        assert result.exit_code == 0


def test_force_subdir(tmpdir):
    with use_working_directory(tmpdir):
        result = CliRunner().invoke(main, "-k rsa2048 tmp/key".split())
        # should fail due to non-existing subfolder
        assert result.exit_code == 1
        result = CliRunner().invoke(main, "-k rsa2048 tmp/key --force".split())
        assert result.exit_code == 0
        assert os.path.isfile("tmp/key")


@pytest.mark.parametrize(
    "key, valid",
    [
        ("secp192r1", True),
        ("secp224r1", True),
        ("secp256r1", True),
        ("secp384r1", True),
        ("secp521r1", True),
        ("secp256k1", True),
        ("sect163k1", True),
        ("sect233k1", True),
        ("sect283k1", True),
        ("sect409k1", True),
        ("sect571k1", True),
        ("sect163r2", True),
        ("sect233r1", True),
        ("sect283r1", True),
        ("sect409r1", True),
        ("sect571r1", True),
        ("brainpoolP256r1", True),
        ("brainpoolP384r1", True),
        ("brainpoolP512r1", True),
        ("ras2048", False),
        ("secp100", False),
    ],
)
def test_key_types(tmpdir, key, valid):
    with use_working_directory(tmpdir):
        if valid:
            result = CliRunner().invoke(main, f"-k {key} my_key_{key}.pem")

            assert result.exit_code == 0
            assert os.path.isfile(f"my_key_{key}.pem")
            assert os.path.isfile(f"my_key_{key}.pub")
        else:
            result = CliRunner().invoke(main, f"-k {key} my_key_{key}.pem")
            assert result.exit_code != 0

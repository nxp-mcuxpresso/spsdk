#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpkeygen utility."""
import os

import pytest
from click.testing import CliRunner

from spsdk.apps.nxpkeygen import main, determine_protocol_version, determine_key_parameters
from spsdk.crypto import load_public_key, load_private_key, EllipticCurvePublicKey, RSAPrivateKey, \
    RSAPublicKey, EllipticCurvePrivateKey
from spsdk.utils.misc import use_working_directory


def test_command_line_interface():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0

    assert 'main [OPTIONS] COMMAND [ARGS]' in result.output
    assert 'NXP Key Generator Tool.' in result.output
    assert '-p, --protocol VERSION' in result.output
    assert 'genkey  Generate key pair for RoT or DCK.' in result.output
    assert 'gendc   Generate debug certificate (DC).' in result.output


def test_generate_rsa_key(tmpdir) -> None:
    """Test generate rsa key pair."""

    cmd = f'genkey {os.path.join(tmpdir, "key_rsa.pem")}'
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

@pytest.mark.parametrize(
    "protocol_version, curve_name",
    [
        ("2.0", 'secp256r1'),
        ("2.1",  'secp384r1'),
        ("2.2",  'secp521r1')
    ]
)
def test_generate_ecc_key(tmpdir, protocol_version, curve_name) -> None:
    """Test generate ecc key pair."""
    pem_path = os.path.join(tmpdir, f'{curve_name}_key_ecc.pem')
    pub_path = os.path.join(tmpdir, f'{curve_name}_key_ecc.pub')

    cmd = f'-p {protocol_version} genkey {pem_path}'
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(pem_path)
    assert os.path.isfile(pub_path)

    pub_key_from_file = load_public_key(pub_path)
    assert isinstance(pub_key_from_file, EllipticCurvePublicKey)
    assert pub_key_from_file.curve.name == curve_name

    priv_key_from_file = load_private_key(pem_path)
    assert isinstance(priv_key_from_file, EllipticCurvePrivateKey)
    assert pub_key_from_file.curve.name == curve_name



def test_generate_invalid_key(tmpdir) -> None:
    """Test generate invalid key pair."""

    cmd = f'-p 3.0 genkey {os.path.join(tmpdir, "key_invalid.pem")}'
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


@pytest.mark.parametrize(
    "protocol_version, expect_result, expected_key_params",
    [
        ("1.0", True, 2048),
        ("1.1", True, 4096),
        ("2.0", False, 'P-256'),
        ("2.1", False, 'P-384'),
        ("2.2", False, 'P-521')
    ]
)
def test_determine_protocol_version(protocol_version, expect_result, expected_key_params):
    """Test for checking all available protocol versions."""
    is_rsa, protocol_version = determine_protocol_version(protocol_version)
    key_param = determine_key_parameters(is_rsa, protocol_version)
    assert is_rsa is expect_result
    assert key_param == expected_key_params


def test_generate_rsa_dc_file(tmpdir, data_dir):
    """Test generate dc file with rsa 2048 protocol."""

    cmd = f'-p 1.0 gendc -c {os.path.join(data_dir, "new_dck_rsa2048.yml")} {os.path.join(tmpdir, "dc_2048.cert")}'
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(tmpdir, "dc_2048.cert"))


def test_generate_ecc_dc_file(tmpdir, data_dir):
    """Test generate dc file with ecc protocol."""

    cmd = f'-p 2.0 gendc -c {os.path.join(data_dir, "new_dck_secp256.yml")}' \
          f' {os.path.join(tmpdir, "dc_secp256r1.cert")}'
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(tmpdir, "dc_secp256r1.cert"))

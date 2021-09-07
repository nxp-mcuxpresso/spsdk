#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpkeygen utility."""
import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk import SPSDKValueError
from spsdk.apps.nxpkeygen import determine_key_parameters, determine_protocol_version, main
from spsdk.crypto import RSAPrivateKey, RSAPublicKey, load_private_key, load_public_key
from spsdk.utils.misc import use_working_directory


def test_command_line_interface():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0

    assert "main [OPTIONS] COMMAND [ARGS]" in result.output
    assert "NXP Key Generator Tool." in result.output
    assert "genkey            Generate key pair for RoT or DCK." in result.output
    assert "gendc             Generate debug certificate (DC)." in result.output
    assert "get-cfg-template  Generate the template of Debug Credentials YML..." in result.output


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


def test_generate_invalid_key(tmpdir) -> None:
    """Test generate invalid key pair."""

    cmd = f'genkey -k invalid-key-type {os.path.join(tmpdir, "key_invalid.pem")}'
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code != 0
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


@pytest.mark.parametrize(
    "protocol_version, expect_result, expected_key_params",
    [
        ("1.0", True, 2048),
        ("1.1", True, 4096),
        ("2.0", False, "secp256r1"),
        ("2.1", False, "secp384r1"),
        ("2.2", False, "secp521r1"),
    ],
)
def test_determine_protocol_version(protocol_version, expect_result, expected_key_params):
    """Test for checking all available protocol versions."""
    is_rsa, protocol_version = determine_protocol_version(protocol_version)
    key_param = determine_key_parameters(is_rsa, protocol_version)
    assert is_rsa is expect_result
    assert key_param == expected_key_params


def test_generate_rsa_dc_file(tmpdir, data_dir):
    """Test generate dc file with rsa 2048 protocol."""
    out_file = f"{tmpdir}/dc_2048.cert"
    cmd = f"gendc -c new_dck_rsa2048.yml -p 1.0 {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_ecc_dc_file(tmpdir, data_dir):
    """Test generate dc file with ecc protocol."""
    out_file = f"{tmpdir}/dc_secp256r1.cert"
    cmd = f"gendc -p 2.0 -c new_dck_secp256.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_dc_file_N4A_256(tmpdir, data_dir):
    """Test generate dc file with ecc protocol for N4A"""
    out_file = f"{tmpdir}/dc_secp256r1_N4A.cert"
    cmd = f"gendc -p 2.0 -c new_dck_secp256_N4A.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_dc_file_N4A_384(tmpdir, data_dir):
    """Test generate dc file with ecc protocol for N4A"""
    out_file = f"{tmpdir}/dc_secp384r1_N4A.cert"
    cmd = f"gendc -p 2.1 -c new_dck_secp384_N4A.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_rsa_with_elf2sb(tmpdir, data_dir):
    org_file = f"{tmpdir}/org.dc"
    new_file = f"{tmpdir}/new.dc"

    cmd1 = f"gendc -p 1.0 -c org_dck_rsa_2048.yml {org_file}"
    # keys were removed from yaml and suplied by elf2sb config
    cmd2 = f"gendc -p 1.0 -c no_key_dck_rsa_2048.yml -e elf2sb_config.json {new_file}"
    with use_working_directory(data_dir):
        result = CliRunner().invoke(main, cmd1.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(main, cmd2.split())
        assert result.exit_code == 0, result.output
    assert filecmp.cmp(org_file, new_file)


def test_force_actual_dir(tmpdir):
    with use_working_directory(tmpdir):
        result = CliRunner().invoke(main, "genkey -k rsa2048 key".split())
        assert result.exit_code == 0
        # attempt to rewrite the key should fail
        result = CliRunner().invoke(main, "genkey -k rsa2048 key".split())
        assert result.exit_code == 1
        # attempt to rewrite should pass due to --forces
        result = CliRunner().invoke(main, "genkey -k rsa2048 key --force".split())
        assert result.exit_code == 0


def test_force_subdir(tmpdir):
    with use_working_directory(tmpdir):
        result = CliRunner().invoke(main, "genkey -k rsa2048 tmp/key".split())
        # should fail due to non-existing subfolder
        assert result.exit_code == 1
        result = CliRunner().invoke(main, "genkey -k rsa2048 tmp/key --force".split())
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
            result = CliRunner().invoke(main, f"genkey -k {key} my_key_{key}.pem")

            assert result.exit_code == 0
            assert os.path.isfile(f"my_key_{key}.pem")
            assert os.path.isfile(f"my_key_{key}.pub")
        else:
            result = CliRunner().invoke(main, f"genkey -k {key} my_key_{key}.pem")
            assert result.exit_code != 0

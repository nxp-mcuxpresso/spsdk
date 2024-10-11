#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for 'pfr' application."""
import filecmp
import logging
import os

import pytest
from ruamel.yaml import YAML

from spsdk.apps import pfr as cli
from spsdk.pfr.pfr import CMPA
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner


def test_command_line_interface(cli_runner: CliRunner):
    """Test the CLI."""
    result = cli_runner.invoke(cli.main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "name,type",
    [
        ("lpc55s6x", "cmpa"),
        ("lpc55s6x", "cfpa"),
        ("lpc55s3x", "cmpa"),
        ("lpc55s3x", "cfpa"),
        ("mcxa1xx", "cmpa"),
        ("mcxa156", "cmpa"),
        ("mcxa155", "cmpa"),
        ("mcxa154", "cmpa"),
        ("mcxa144", "cmpa"),
        ("mcxa145", "cmpa"),
        ("mcxa146", "cmpa"),
        ("mcxa142", "cmpa"),
        ("mcxa143", "cmpa"),
        ("mcxa152", "cmpa"),
        ("mcxa153", "cmpa"),
        ("mcxn9xx", "cmpa"),
        ("mcxn9xx", "cfpa"),
        ("nhs52sxx", "cmpa"),
        ("nhs52sxx", "cfpa"),
    ],
)
def test_generate_all(cli_runner: CliRunner, data_dir, tmpdir, name, type):
    """Test PFR CLI - Generation CMPA binary for all interesting parts."""
    test_data_dir = os.path.join(data_dir, "yaml_bin")

    cmd = [
        "generate-binary",
        "--output",
        f"{tmpdir}/{name}_{type}.bin",
        "--config",
        f"{test_data_dir}/{name}_{type}.yaml",
        "--calc-inverse",
        "--ignore",  # Omit PFRC tests
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_data = load_binary(f"{tmpdir}/{name}_{type}.bin")
    expected = load_binary(f"{test_data_dir}/{name}_{type}.bin", "rb")
    assert new_data == expected


def test_generate_cmpa_validate_export(cli_runner: CliRunner, data_dir, tmpdir):
    out_file = os.path.join(tmpdir, "cmpa_mcxn9xx.bin")
    cmd_cmpa_config = [
        "generate-binary",
        "--output",
        out_file,
        "--config",
        os.path.join(data_dir, "cmpa_mcxn9xx.yaml"),
    ]
    cmd_cert_block_config = cmd_cmpa_config + [
        "--rot-config",
        os.path.join(data_dir, "cert_block_v21.yaml"),
    ]
    cmd_mbi_config = cmd_cmpa_config + [
        "--rot-config",
        os.path.join(data_dir, "mbi_config_mcxn9xx.yaml"),
    ]
    cmd_secret_file = cmd_cmpa_config + [
        f"--secret-file",
        os.path.join(data_dir, "keys", "ROT1_p384.pem"),
        f"--secret-file",
        os.path.join(data_dir, "keys", "ROT2_p384.pem"),
        f"--secret-file",
        os.path.join(data_dir, "keys", "ROT3_p384.pem"),
        f"--secret-file",
        os.path.join(data_dir, "keys", "ROT4_p384.pem"),
    ]

    reference_binary = b""
    for cmd in [cmd_cmpa_config, cmd_cert_block_config, cmd_mbi_config, cmd_secret_file]:
        cli_runner.invoke(cli.main, cmd)
        assert os.path.isfile(out_file)
        if not reference_binary:
            reference_binary = load_binary(out_file)
            continue
        assert reference_binary == load_binary(out_file)


def test_generate_cmpa(cli_runner: CliRunner, data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary."""
    cmd = [
        "generate-binary",
        "--output",
        f"{tmpdir}/pnd.bin",
        "--config",
        f"{data_dir}/cmpa_96mhz.json",
        "--calc-inverse",
        "--secret-file",
        f"{data_dir}/selfsign_privatekey_rsa2048.pem",
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_data = open(f"{tmpdir}/pnd.bin", "rb").read()
    expected = open(f"{data_dir}/CMPA_96MHz.bin", "rb").read()
    assert new_data == expected


def test_generate_cmpa_with_elf2sb(cli_runner: CliRunner, data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary with elf2sb."""
    org_file = f"{tmpdir}/org.bin"
    new_file = f"{tmpdir}/new.bin"
    big_file = f"{tmpdir}/big.bin"

    cmd = "generate-binary --config cmpa_96mhz.json --calc-inverse"
    # basic usage when keys are passed on command line
    cmd1 = cmd + f" -o {org_file} -sf rotk0_rsa_2048.pub -sf rotk1_rsa_2048.pub"
    # elf2sb config file contains previous two keys + one empty line + 4th entry is not present
    cmd2 = cmd + f" -o {new_file} -e elf2sb_config.json"
    # mbi config contains path to cert_block yaml
    cmd3 = (
        cmd
        + f" -o {big_file} -e big_elf2sb_config.json -sf rotk0_rsa_2048.pub -sf rotk1_rsa_2048.pub"
    )
    with use_working_directory(data_dir):
        cli_runner.invoke(cli.main, cmd1.split())
        cli_runner.invoke(cli.main, cmd2.split())
        cli_runner.invoke(cli.main, cmd3.split(), expected_code=-1)
    assert filecmp.cmp(org_file, new_file)


def test_generate_cmpa_with_elf2sb_lpc55s3x(data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary with elf2sb."""
    new = f"{tmpdir}/new.bin"
    org = "cmpa_lpc55s3x.bin"
    cmd = f"generate-binary --config cmpa_lpc55s3x.json -e mbi_config_lpc55s3x.yaml -o {new}"

    with use_working_directory(data_dir):
        result = CliRunner().invoke(cli.main, cmd.split())
        assert result.exit_code == 0, result.output
        assert filecmp.cmp(org, new)


def test_generate_cmpa_raw(cli_runner: CliRunner, data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary."""
    cmd = [
        "generate-binary",
        "--output",
        f"{tmpdir}/cmpa_raw.bin",
        "--config",
        f"{data_dir}/cmpa_mcxn9xx_raw.yaml",
    ]
    cli_runner.invoke(cli.main, cmd)
    new_data = open(f"{tmpdir}/cmpa_raw.bin", "rb").read()
    expected = open(f"{data_dir}/cmpa_mcxn9xx_raw.bin", "rb").read()
    assert new_data == expected


def test_parse(cli_runner: CliRunner, data_dir, tmpdir):
    """Test PFR CLI - Parsing CMPA binary to get config."""
    cmd = [
        "parse-binary",
        "--family",
        "lpc55s69",
        "--type",
        "cmpa",
        "--binary",
        f"{data_dir}/CMPA_96MHz.bin",
        "--show-diff",
        "--output",
        f"{tmpdir}/config.yml",
    ]

    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_cfg = load_configuration(f"{tmpdir}/config.yml")
    expected_cfg = load_configuration(f"{data_dir}/cmpa_96mhz_rotkh.yml")
    created = CMPA.load_from_config(new_cfg)
    expected = CMPA.load_from_config(expected_cfg)
    assert created == expected


@pytest.mark.parametrize(
    "family,type",
    [
        ("lpc5506", "cmpa"),
        ("lpc5506", "cfpa"),
        ("lpc5516", "cmpa"),
        ("lpc5516", "cfpa"),
        ("lpc5528", "cmpa"),
        ("lpc5528", "cfpa"),
        ("lpc5536", "cmpa"),
        ("lpc5536", "cfpa"),
        ("lpc55s06", "cmpa"),
        ("lpc55s06", "cfpa"),
        ("lpc55s16", "cmpa"),
        ("lpc55s16", "cfpa"),
        ("lpc55s26", "cmpa"),
        ("lpc55s26", "cfpa"),
        ("lpc55s36", "cmpa"),
        ("lpc55s36", "cfpa"),
        ("lpc55s69", "cmpa"),
        ("lpc55s69", "cfpa"),
        ("mcxn947", "cmpa"),
        ("mcxn947", "cfpa"),
        ("nhs52s04", "cmpa"),
        ("nhs52s04", "cfpa"),
        ("mcxa156", "cmpa"),
        ("mcxa155", "cmpa"),
        ("mcxa154", "cmpa"),
        ("mcxa144", "cmpa"),
        ("mcxa145", "cmpa"),
        ("mcxa146", "cmpa"),
        ("mcxa142", "cmpa"),
        ("mcxa143", "cmpa"),
        ("mcxa152", "cmpa"),
        ("mcxa153", "cmpa"),
    ],
)
def test_user_config(cli_runner: CliRunner, tmpdir, family, type):
    """Test PFR CLI - Generation CMPA user config."""
    cmd = [
        "get-template",
        "--family",
        family,
        "--type",
        type,
        "--output",
        f"{tmpdir}/pfr.yml",
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    pfr_config = load_configuration(f"{tmpdir}/pfr.yml")
    assert pfr_config
    assert pfr_config["type"] == type.upper()
    assert pfr_config["family"] == family


@pytest.mark.parametrize(
    "test_pass,dfl_niden,dfl_inverse,ignore",
    [
        (True, 0x0, 0xFFFF, False),  # OK
        (True, 0x0, 0xFFFE, False),  # breaking rule 1.4
        (True, 0x0, 0xFFFE, True),  # breaking rule 1.4
        (True, 0x1, 0xFFFE, True),  # breaking rule 1.7
        (False, 0x1, 0xFFFE, False),  # breaking rule 1.7
    ],
)
def test_pfrc_integration_1(
    cli_runner: CliRunner,
    tmp_path,
    data_dir,
    test_pass,
    dfl_niden,
    dfl_inverse,
    ignore,
):
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    config = load_configuration(cmpa_config_template)
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["NIDEN"] = dfl_niden
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["INVERSE_VALUE"] = dfl_inverse
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    output_bin = os.path.join(tmp_path, "pfr.bin")
    with open(cmpa_config_path, "w") as fp:
        yaml = YAML()
        yaml.dump(config, fp)

    cmd = f"generate-binary --config {cmpa_config_path} --output {output_bin}"
    if ignore:
        cmd += " --ignore"
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd.split(), expected_code=0 if test_pass else 1)


@pytest.mark.parametrize(
    "secret",
    [
        ("mbi_config_lpc55s3x.yaml"),
        ("mbi_config_lpc55s3x_bin_certblock.yaml"),
        ("cert_block_v21.yaml"),
        ("cert_block_v21.bin"),
    ],
)
def test_generate_cmpa_certblock_lpc55s3x(cli_runner: CliRunner, data_dir, tmpdir, secret):
    """Test PFR CLI - Generation CMPA binary with elf2sb."""
    new = f"{tmpdir}/new.bin"
    org = "cmpa_lpc55s3x.bin"
    cmd = f"generate-binary --config cmpa_lpc55s3x.json -e {secret} -o {new}"

    with use_working_directory(data_dir):
        logging.debug(cmd)
        cli_runner.invoke(cli.main, cmd.split())
        assert filecmp.cmp(org, new)

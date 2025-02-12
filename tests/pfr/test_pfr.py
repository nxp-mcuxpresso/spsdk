#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The test file for PFR API."""

import filecmp
import os

import pytest
from ruamel.yaml import YAML

from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.pfr.pfr import CFPA, CMPA, BaseConfigArea, SPSDKPfrRotkhIsNotPresent
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import load_configuration, load_file


def test_generate_cmpa(data_dir):
    """Test PFR tool - Generating CMPA binary."""
    binary = load_file(os.path.join(data_dir, "CMPA_96MHz.bin"), mode="rb")
    key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    pfr_cfg_json = load_configuration(os.path.join(data_dir, "cmpa_96mhz.json"))
    cmpa_json = CMPA.load_from_config(pfr_cfg_json)
    assert binary == cmpa_json.export(add_seal=False, keys=[key.get_public_key()])

    pfr_cfg_yml = load_configuration(os.path.join(data_dir, "cmpa_96mhz.yml"))
    cmpa_yml = CMPA.load_from_config(pfr_cfg_yml)
    assert binary == cmpa_yml.export(add_seal=False, keys=[key.get_public_key()])


def test_generate_cfpa(data_dir):
    """Test PFR tool - Generating CFPA binary."""
    binary = load_file(os.path.join(data_dir, "CFPA_test.bin"), mode="rb")

    pfr_cfg_json = load_configuration(os.path.join(data_dir, "cfpa_test.json"))
    cfpa_json = CFPA.load_from_config(pfr_cfg_json)
    assert cfpa_json.export(add_seal=True) == binary

    pfr_cfg_yml = load_configuration(os.path.join(data_dir, "cfpa_test.yml"))
    cfpa_yml = CFPA.load_from_config(pfr_cfg_yml)
    assert cfpa_yml.export(add_seal=True) == binary


def test_supported_devices():
    """Test PFR tool - Getting supported devices."""
    cfpa_devices = CFPA.get_supported_families()
    assert isinstance(cfpa_devices, list)
    assert cfpa_devices == DatabaseManager().quick_info.devices.get_devices_with_feature(
        "pfr", "cfpa"
    )

    cmpa_devices = CMPA.get_supported_families()
    assert isinstance(cmpa_devices, list)
    assert cmpa_devices == DatabaseManager().quick_info.devices.get_devices_with_feature(
        "pfr", "cmpa"
    )


def test_seal_cfpa():
    """Test PFR tool - Test CFPA seal."""
    cfpa = CFPA("lpc55s6x")

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1E0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1E0:] == CFPA.MARK * 8


def test_seal_cmpa_lpc55s3x():
    """Test PFR tool - Test CMPA seal on LPC55S3x."""
    cfpa = CFPA("lpc55s3x")

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1E0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1EC:0x1F0] == CFPA.MARK


def test_basic_cmpa():
    """Test PFR tool - Test CMPA basis."""
    CMPA("lpc55s6x")


def test_config_cfpa(data_dir):
    """Test PFR tool - Test CFPA configuration."""
    cfpa = CFPA("lpc55s6x")
    config = cfpa.generate_config()
    config2 = cfpa.generate_config()

    assert config == config2

    cfpa2 = CFPA("lpc55s6x")
    cfpa2.parse(bytes(512))  # Parse 512-bytes of empty CFPA page content
    cfpa2_pfr_cfg = load_configuration(
        data_dir + "/cfpa_after_reset.yml"
    )  # Apply known CFPA fields after reset values
    cfpa2.set_config(cfpa2_pfr_cfg["settings"])
    out = cfpa2.get_config()

    assert config == out


def test_config_cmpa():
    """Test PFR tool - Test CMPA configuration."""
    cmpa = CMPA("lpc55s3x")
    config = cmpa.get_config()
    config2 = cmpa.get_config()

    assert config == config2

    cmpa2 = CMPA.load_from_config(config2)
    cmpa2.parse(bytes(512))
    out = cmpa2.get_config()

    assert out == config2


def test_config_cmpa_yml(tmpdir):
    """Test PFR tool - Test CMPA configuration from YAML."""
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    cmpa = CMPA("lpc55s3x")
    config = cmpa.get_config()

    assert cmpa.get_config(True) == {
        "family": "lpc55s36",
        "revision": "a1",
        "type": "CMPA",
        "settings": {},
    }

    with open(os.path.join(tmpdir, "config.yml"), "w") as yml_file:
        yaml.dump(config, yml_file)

    cmpa2_pfr_cfg = load_configuration(os.path.join(tmpdir, "config.yml"))
    cmpa2 = CMPA.load_from_config(cmpa2_pfr_cfg)
    out_config = cmpa2.get_config(True)

    assert out_config == {
        "family": "lpc55s36",
        "revision": "a1",
        "type": "CMPA",
        "settings": {
            "DCFG_CC_SOCU_PIN": {"INVERSE_VALUE": "0xFFFF"},
            "DCFG_CC_SOCU_DFLT": {"INVERSE_VALUE": "0xFFFF"},
        },
    }


def test_set_config_rev_latest(data_dir):
    """Test invalid cases for set_config."""
    pfr_cfg = load_configuration(data_dir + "/latest_rev.yml")
    cmpa = CMPA.load_from_config(pfr_cfg)
    assert cmpa


def test_json_yml_configs(data_dir):
    """Test of JSON and YML configuration, it must be equal."""
    cmpa_json = CMPA.load_from_config(load_configuration(f"{data_dir}/cmpa_96mhz.json"))
    cmpa_yml = CMPA.load_from_config(load_configuration(f"{data_dir}/cmpa_96mhz.yml"))

    assert cmpa_yml.get_config(False) == cmpa_json.get_config(False)
    assert cmpa_yml.get_config(True) == cmpa_json.get_config(True)


def test_missing_rotkh():
    """Simple test to check right functionality of missing ROTKH."""
    cfpa = CFPA("lpc55s6x")
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.export(keys=["Invalid"])


def test_lpc55s3x_load_yml_without_change(data_dir):
    """Test silicon LPC55S3x mandatory computing of antipole values."""
    cfpa = CFPA.load_from_config(load_configuration(f"{data_dir}/cfpa_no_change.yml"))
    data = cfpa.export()

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CFPA_basic.bin", "rb") as binary:
        assert data == binary.read()


def test_lpc55s3x_binary_ec256(data_dir):
    """Test silicon LPC55S3x ECC256. Binary generation/ROTKH computation"""
    cmpa = CMPA("lpc55s3x")
    keys_path = [
        data_dir + "/ec_secp256r1_cert0.pem",
        data_dir + "/ec_secp256r1_cert1.pem",
        data_dir + "/ec_secp256r1_cert2.pem",
        data_dir + "/ec_secp256r1_cert3.pem",
    ]

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA.bin", "rb") as binary:
        assert data == binary.read()


def test_lpc55s3x_binary_ec384(data_dir):
    """Test silicon LPC55S3x ECC384. Binary generation/ROTKH computation"""
    cmpa = CMPA("lpc55s3x")
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA_384.bin", "rb") as binary:
        assert data == binary.read()


def test_invalid_key_size(data_dir):
    """Test Invalid Key size for ROTKH computation"""
    cfpa = CMPA("lpc55s6x")
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    with pytest.raises(SPSDKError):
        cfpa.export(keys=extract_public_keys(keys_path, password=None))


def test_base_config_area_invalid_device_revision():
    with pytest.raises(
        SPSDKError, match="Cannot load the device 'bb' - Doesn't exists in database."
    ):
        BaseConfigArea(family="bb")
    with pytest.raises(SPSDKError, match="Requested revision HH is not supported."):
        BaseConfigArea(family="lpc55s6x", revision="HH")

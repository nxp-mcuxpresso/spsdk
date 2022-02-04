#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The test file for PFR API."""

import filecmp
import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from ruamel.yaml import YAML

from spsdk import SPSDKError
from spsdk.crypto.loaders import extract_public_keys
from spsdk.pfr import (
    CFPA,
    CMPA,
    PfrConfiguration,
    SPSDKPfrConfigError,
    SPSDKPfrConfigReadError,
    SPSDKPfrError,
    SPSDKPfrRotkhIsNotPresent,
)
from spsdk.pfr.pfr import BaseConfigArea
from spsdk.utils.misc import load_file


def test_generate_cmpa(data_dir):
    """Test PFR tool - Generating CMPA binary."""
    binary = load_file(data_dir, "CMPA_96MHz.bin", mode="rb")
    key = load_pem_private_key(
        load_file(data_dir, "selfsign_privatekey_rsa2048.pem", mode="rb"),
        password=None,
        backend=default_backend(),
    )

    pfr_cfg_json = PfrConfiguration(os.path.join(data_dir, "cmpa_96mhz.json"))
    cmpa_json = CMPA("lpc55s6x", user_config=pfr_cfg_json)
    assert binary == cmpa_json.export(add_seal=False, keys=[key.public_key()])

    pfr_cfg_yml = PfrConfiguration(os.path.join(data_dir, "cmpa_96mhz.yml"))
    cmpa_yml = CMPA("lpc55s6x", user_config=pfr_cfg_yml)
    assert binary == cmpa_yml.export(add_seal=False, keys=[key.public_key()])


def test_generate_cfpa(data_dir):
    """Test PFR tool - Generating CFPA binary."""
    binary = load_file(data_dir, "CFPA_test.bin", mode="rb")

    pfr_cfg_json = PfrConfiguration(os.path.join(data_dir, "cfpa_test.json"))
    cfpa_json = CFPA("lpc55s6x", user_config=pfr_cfg_json)
    assert cfpa_json.export(add_seal=True) == binary

    pfr_cfg_yml = PfrConfiguration(os.path.join(data_dir, "cfpa_test.yml"))
    cfpa_yml = CFPA("lpc55s6x", user_config=pfr_cfg_yml)
    assert cfpa_yml.export(add_seal=True) == binary


def test_supported_devices():
    """Test PFR tool - Getting supported devices."""
    cfpa_devices = CFPA.devices()
    cmpa_devices = CMPA.devices()
    assert sorted(cmpa_devices) == sorted(cfpa_devices)


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
    config2 = cfpa.generate_config(exclude_computed=False)

    assert config != config2

    cfpa2 = CFPA("lpc55s6x", user_config=PfrConfiguration(config2))
    cfpa2.parse(bytes(512))  # Parse 512-bytes of empty CFPA page content
    cfpa2_pfr_cfg = PfrConfiguration(
        data_dir + "/cfpa_after_reset.yml"
    )  # Apply known CFPA fields after reset values
    cfpa2.set_config(cfpa2_pfr_cfg)
    out = cfpa2.get_yaml_config(exclude_computed=False)

    assert out == config2


def test_config_cmpa():
    """Test PFR tool - Test CMPA configuration."""
    cmpa = CMPA("lpc55s6x")
    config = cmpa.generate_config()
    config2 = cmpa.generate_config(exclude_computed=False)

    assert config != config2

    cmpa2 = CMPA("lpc55s6x", user_config=PfrConfiguration(config2))
    cmpa2.parse(bytes(512))
    out = cmpa2.get_yaml_config(exclude_computed=False)

    assert out == config2


def test_config_cmpa_yml(tmpdir):
    """Test PFR tool - Test CMPA configuration from YAML."""
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    cmpa = CMPA("lpc55s6x")
    config = cmpa.get_yaml_config(exclude_computed=True)
    with open(tmpdir + "/config.yml", "w") as yml_file:
        yaml.dump(config, yml_file)

    config2 = cmpa.get_yaml_config(exclude_computed=False)
    with open(tmpdir + "/config2.yml", "w") as yml_file:
        yaml.dump(config2, yml_file)

    assert not filecmp.cmp(tmpdir + "/config.yml", tmpdir + "/config2.yml")

    cmpa2 = CMPA("lpc55s6x")
    cmpa2_pfr_cfg = PfrConfiguration(tmpdir + "/config.yml")
    cmpa2.set_config(cmpa2_pfr_cfg)
    out_config = cmpa2.get_yaml_config(exclude_computed=True)
    with open(tmpdir + "/out_config.yml", "w") as yml_file:
        yaml.dump(out_config, yml_file)

    assert filecmp.cmp(tmpdir + "/config.yml", tmpdir + "/out_config.yml")

    cmpa2_pfr_cfg = PfrConfiguration(tmpdir + "/config2.yml")
    cmpa2.set_config(cmpa2_pfr_cfg, raw=True)
    out_config2 = cmpa2.get_yaml_config(exclude_computed=False)
    with open(tmpdir + "/out_config2.yml", "w") as yml_file:
        yaml.dump(out_config2, yml_file)

    assert filecmp.cmp(tmpdir + "/config2.yml", tmpdir + "/out_config2.yml")


def test_load_config():
    """Test just initialization of PFR config."""
    assert PfrConfiguration()


def test_load_config_initialized():
    """Test initialization of PFR config by another PFR config."""
    empty_cfg = PfrConfiguration()
    new_cfg = PfrConfiguration(empty_cfg)
    assert empty_cfg == new_cfg
    new_cfg.device = "Test Device"
    new_cfg.revision = "Test Revision"
    new_cfg.revision = "Test Type"
    new_cfg.settings = {"Reg": {"value": 0}}
    new_cfg1 = PfrConfiguration(new_cfg)
    assert new_cfg1 == new_cfg
    new_cfg2 = PfrConfiguration(config=new_cfg, device="Dev", revision="Rev", cfg_type="Typ")
    assert new_cfg2 != new_cfg
    assert new_cfg2.device == "Dev"
    assert new_cfg2.revision == "Rev"
    assert new_cfg2.type == "Typ"


def test_load_cfg_obsolete_data():
    """Test of loading of obsolete style of data."""
    cfg_dict = {"description": {"device": "dev", "revision": "rev", "type": "typ"}, "settings": {}}
    assert PfrConfiguration(cfg_dict)
    cfg_dict["settings"]["REG"] = "my_value"
    cfg_dict["settings"]["REG1"] = 0
    cfg = PfrConfiguration(cfg_dict)
    assert cfg
    assert cfg.settings["REG"]["value"] == "my_value"
    assert cfg.settings["REG1"]["value"] == 0


def test_load_cfg_obsolete_data1():
    """Test of loading of obsolete style of data."""
    cfg_dict = {"description": {"device": "dev", "revision": "rev", "type": "typ"}, "settings": {}}
    assert PfrConfiguration(cfg_dict)
    cfg_dict["settings"]["REG"] = 0
    cfg = PfrConfiguration(cfg_dict)
    assert cfg
    assert cfg.settings["REG"]["value"] == 0


def test_load_cfg_obsolete_data_bitfields():
    """Test of loading of obsolete style of data."""
    cfg_dict = {
        "description": {"device": "dev", "revision": "rev", "type": "typ"},
        "settings": {
            "REG": {
                "BITF1": "bitf_val1",
                "BITF2": "bitf_val2",
            }
        },
    }
    cfg = PfrConfiguration(cfg_dict)
    assert cfg
    assert cfg.settings["REG"]["bitfields"]["BITF1"] == "bitf_val1"


def test_load_cfg_obsolete_data_bitfields1():
    """Test of loading of obsolete style of data."""
    cfg_dict = {
        "description": {"device": "dev", "revision": "rev", "type": "typ"},
        "settings": {
            "REG": [],
            "REG1": {
                "BITF1": "bitf_val1",
                "BITF2": "bitf_val2",
            },
        },
    }
    cfg = PfrConfiguration(cfg_dict)
    assert cfg
    assert "REG" not in cfg.settings.keys()
    assert cfg.settings["REG1"]["bitfields"]["BITF1"] == "bitf_val1"


def test_load_cfg_none_obsolete():
    """Test of loading of none obsolete style of data."""
    cfg_dict = {
        "description": {"device": "dev", "revision": "rev", "type": "typ"},
        "settings": {
            "REG": {
                "bitfields": {
                    "BITF1": "bitf_val1",
                    "BITF2": "bitf_val2",
                }
            }
        },
    }
    cfg = PfrConfiguration(cfg_dict)
    assert cfg
    assert cfg.settings["REG"]["bitfields"]["BITF1"] == "bitf_val1"


def test_cfg_compare():
    """Test the comparision capability of PFR configuration."""
    assert PfrConfiguration() != 1
    assert PfrConfiguration(device="1") != PfrConfiguration(device="2")
    assert PfrConfiguration(revision="1") != PfrConfiguration(revision="2")
    assert PfrConfiguration(cfg_type="1") != PfrConfiguration(cfg_type="2")
    cfg_dict = {
        "description": {"device": "dev", "revision": "rev", "type": "typ"},
        "settings": {
            "REG": {
                "BITF1": "bitf_val1",
                "BITF2": "bitf_val2",
            }
        },
    }
    cfg_dict2 = {
        "description": {"device": "dev", "revision": "rev", "type": "typ"},
        "settings": {
            "REG": {
                "BITF1": "bitf_val1",
                "BITF2": "bitf_val2x",
            }
        },
    }
    assert PfrConfiguration(cfg_dict) != PfrConfiguration(cfg_dict2)


def test_load_config_invalid(data_dir):
    """Test PFR tool - PFR Configuration Invalid cases."""
    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/invalid_file")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/invalid_file.yml")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/invalid_file.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/empty_json.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/empty_json1.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/empty_yml.yml")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir + "/empty_file")


def test_set_config_invalid(data_dir):
    """Test invalid cases for set_config."""
    cmpa = CMPA(device="lpc55s6x")
    cfg = PfrConfiguration(data_dir + "/bad_dev.yml")
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)

    cfg = PfrConfiguration(data_dir + "/bad_rev.yml")
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)

    cfg = PfrConfiguration()
    cfg.device = cmpa.device
    cfg.revision = cmpa.revision
    cfg.type = "INV"
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)

    cfg = PfrConfiguration()
    cfg.device = cmpa.device
    cfg.revision = cmpa.revision
    cfg.type = "CMPA"
    cfg.settings = None
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)


def test_set_config_rev_latest(data_dir):
    """Test invalid cases for set_config."""
    pfr_cfg = PfrConfiguration(data_dir + "/latest_rev.yml")
    cmpa = CMPA(user_config=pfr_cfg)
    cmpa.set_config(pfr_cfg)
    assert cmpa


def test_invalid_computed_field_handler():
    """Test invalid case for computed filed handler."""
    cmpa = CMPA(device="lpc55s6x")
    fields = {"test_field": "invalid_handler"}

    with pytest.raises(SPSDKError):
        cmpa.reg_computed_fields_handler(b"\x00", fields)


def test_get_bitfields_ignore():
    """Test invalid case for computed filed handler."""
    cmpa = CMPA(device="lpc55s6x")
    cmpa.config.config.pop("ignored_fields", None)
    assert cmpa.generate_config()


def test_json_yml_configs(data_dir):
    """Test of JSON and YML configuration, it must be equal."""
    cmpa_json = CMPA("lpc55s6x", user_config=PfrConfiguration(f"{data_dir}/cmpa_96mhz.json"))
    cmpa_yml = CMPA("lpc55s6x", user_config=PfrConfiguration(f"{data_dir}/cmpa_96mhz.yml"))

    assert cmpa_yml.get_yaml_config(False) == cmpa_json.get_yaml_config(False)
    assert cmpa_yml.get_yaml_config(True) == cmpa_json.get_yaml_config(True)


def test_missing_rotkh():
    """Simple test to check right functionality of missing ROTKH."""
    cfpa = CFPA("lpc55s6x")
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.export(keys=["Invalid"])


def test_lpc55s3x_load_yml_without_change(data_dir):
    """Test silicon LPC55S3x mandatory computing of antipole values."""
    cfpa = CFPA(user_config=PfrConfiguration(f"{data_dir}/cfpa_no_change.yml"))
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
    cfpa = CMPA("lpc55s3x")
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    data = cfpa.export(keys=extract_public_keys(keys_path, password=None))

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

    with pytest.raises(SPSDKPfrError):
        cfpa.export(keys=extract_public_keys(keys_path, password=None))


@pytest.mark.parametrize(
    "dev,type,ret",
    [
        ("Valid", "Valid", None),
        (None, "Valid", "device"),
        ("Valid", None, "type"),
    ],
)
def test_config_is_invalid(dev, type, ret):
    """Simple test to check is_invalid functionality."""
    cfg = PfrConfiguration()
    cfg.device = dev
    cfg.type = type
    res = cfg.is_invalid()
    if ret:
        assert res
        assert ret in res
    else:
        assert not res


def test_config_various_revisions():
    """Simple test to check is_invalid functionality."""
    cfg = PfrConfiguration()
    cfg.device = "lpc55s6x"
    cfg.revision = None
    cfg.type = "CMPA"
    cfg.settings = {"BOOT_CFG": {"value": 0}}
    cmpa = CMPA(user_config=cfg)
    assert cmpa
    assert cmpa.revision
    cmpa.set_config(cfg)
    assert cmpa.revision
    cfg.revision = "latest"
    cmpa.set_config(cfg)
    assert cmpa.revision


def test_config_invalid_yaml_config():
    cfg = PfrConfiguration(device="lpc55s6x")
    cmpa = CMPA("lpc55s6x", user_config=cfg)
    cmpa.parse(bytes(512))
    cmpa.user_config.device = None
    with pytest.raises(SPSDKError, match="Device not found"):
        cmpa.get_yaml_config(exclude_computed=False)
    cfg = PfrConfiguration(device="lpc55s6x")
    cmpa = CMPA("lpc55s6x", user_config=cfg)
    cmpa.parse(bytes(512))
    cmpa.user_config.type = None
    with pytest.raises(SPSDKError, match="Type not found"):
        cmpa.get_yaml_config(exclude_computed=False)


def test_invalid_base_config_area():
    with pytest.raises(SPSDKError, match="No device provided"):
        BaseConfigArea()


def test_base_config_area_invalid_device_revision(data_dir):
    original_data_dir = BaseConfigArea.CONFIG_DIR
    BaseConfigArea.CONFIG_DIR = data_dir
    with pytest.raises(SPSDKError, match="Device 'bb' is not supported"):
        BaseConfigArea(device="bb")
    with pytest.raises(SPSDKError, match="Invalid revision 'HH'"):
        BaseConfigArea(device="lpc55s6x", revision="HH")
    BaseConfigArea.CONFIG_DIR = original_data_dir


def test_config_no_device_no_revision():
    cfg = PfrConfiguration(device="lpc55s6x")
    cfg.device = "lpc55s6x"
    cmpa = CMPA(user_config=cfg)
    cmpa.device = None
    with pytest.raises(SPSDKError, match="No device provided"):
        cmpa.set_config(cfg)
    cmpa.device = "lpc55s6x"
    cmpa.revision = None
    with pytest.raises(SPSDKError, match="No revision provided"):
        cmpa.set_config(cfg)

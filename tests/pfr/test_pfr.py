#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The test file for PFR API."""

import os
import filecmp
from spsdk.pfr.exceptions import SPSDKPfrRotkhIsNotPresent
import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from ruamel.yaml import YAML

from spsdk.exceptions import SPSDKError
from spsdk.pfr import (
    CFPA,
    CMPA,
    PfrConfiguration,
    SPSDKPfrConfigReadError,
    SPSDKPfrConfigError
)
from spsdk.utils.misc import load_file


def test_generate_cmpa(data_dir):
    """Test PFR tool - Generating CMPA binary."""
    binary = load_file(data_dir, 'CMPA_96MHz.bin', mode='rb')
    key = load_pem_private_key(
        load_file(data_dir, 'selfsign_privatekey_rsa2048.pem', mode='rb'),
        password=None, backend=default_backend())

    pfr_cfg_json = PfrConfiguration(os.path.join(data_dir, 'cmpa_96mhz.json'))
    cmpa_json = CMPA('lpc55s6x', user_config=pfr_cfg_json)
    assert binary == cmpa_json.export(add_seal=False, keys=[key.public_key()])

    pfr_cfg_yml = PfrConfiguration(os.path.join(data_dir, 'cmpa_96mhz.yml'))
    cmpa_yml = CMPA('lpc55s6x', user_config=pfr_cfg_yml)
    assert binary == cmpa_yml.export(add_seal=False, keys=[key.public_key()])


def test_generate_cfpa(data_dir):
    """Test PFR tool - Generating CFPA binary."""
    binary = load_file(data_dir, 'CFPA_test.bin', mode='rb')

    pfr_cfg_json = PfrConfiguration(os.path.join(data_dir, 'cfpa_test.json'))
    cfpa_json = CFPA('lpc55s6x', user_config=pfr_cfg_json)
    assert cfpa_json.export(add_seal=True) == binary

    pfr_cfg_yml = PfrConfiguration(os.path.join(data_dir, 'cfpa_test.yml'))
    cfpa_yml = CFPA('lpc55s6x', user_config=pfr_cfg_yml)
    assert cfpa_yml.export(add_seal=True) == binary


def test_supported_devices():
    """Test PFR tool - Getting supported devices."""
    cfpa_devices = CFPA.devices()
    cmpa_devices = CMPA.devices()
    assert sorted(cmpa_devices) == sorted(cfpa_devices)


def test_seal_cfpa():
    """Test PFR tool - Test CFPA seal."""
    cfpa = CFPA('lpc55s6x')

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1e0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1e0:] == CFPA.MARK * 8


def test_seal_cmpa_n4analog():
    """Test PFR tool - Test CMPA seal on Niobe 4Analog."""
    cfpa = CFPA('lpc55s3x')

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1e0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1ec:0x1f0] == CFPA.MARK


def test_basic_cmpa():
    """Test PFR tool - Test CMPA basis."""
    CMPA('lpc55s6x')


def test_config_cfpa():
    """Test PFR tool - Test CFPA configuration."""
    cfpa = CFPA('lpc55s6x')
    config = cfpa.generate_config()
    config2 = cfpa.generate_config(exclude_computed=False)

    assert config != config2

    cfpa2 = CFPA('lpc55s6x', user_config=PfrConfiguration(config2))
    cfpa2.parse(bytes(512), exclude_computed=False)
    out = cfpa2.get_yaml_config(exclude_computed=False)
    assert out == config2


def test_config_cmpa():
    """Test PFR tool - Test CMPA configuration."""
    cmpa = CMPA('lpc55s6x')
    config = cmpa.generate_config()
    config2 = cmpa.generate_config(exclude_computed=False)

    assert config != config2

    cmpa2 = CMPA('lpc55s6x', user_config=PfrConfiguration(config2))
    cmpa2.parse(bytes(512), exclude_computed=False)
    out = cmpa2.get_yaml_config(exclude_computed=False)

    assert out == config2

def test_config_cmpa_yml(tmpdir):
    """Test PFR tool - Test CMPA configuration from YAML."""
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    cmpa = CMPA('lpc55s6x')
    config = cmpa.get_yaml_config(exclude_computed=True)
    with open(tmpdir+"\\config.yml", 'w') as yml_file:
        yaml.dump(config, yml_file)

    config2 = cmpa.get_yaml_config(exclude_computed=False)
    with open(tmpdir+"\\config2.yml", 'w') as yml_file:
        yaml.dump(config2, yml_file)

    assert not filecmp.cmp(tmpdir+"\\config.yml", tmpdir+"\\config2.yml")

    cmpa2 = CMPA('lpc55s6x')
    cmpa2_pfr_cfg = PfrConfiguration(tmpdir+"\\config.yml")
    cmpa2.set_config(cmpa2_pfr_cfg)
    out_config = cmpa2.get_yaml_config(exclude_computed=True)
    with open(tmpdir+"\\out_config.yml", 'w') as yml_file:
        yaml.dump(out_config, yml_file)

    assert filecmp.cmp(tmpdir+"\\config.yml", tmpdir+"\\out_config.yml")

    cmpa2_pfr_cfg = PfrConfiguration(tmpdir+"\\config2.yml")
    cmpa2.set_config(cmpa2_pfr_cfg, raw=True)
    out_config2 = cmpa2.get_yaml_config(exclude_computed=False)
    with open(tmpdir+"\\out_config2.yml", 'w') as yml_file:
        yaml.dump(out_config2, yml_file)

    assert filecmp.cmp(tmpdir+"\\config2.yml", tmpdir+"\\out_config2.yml")

def test_load_config():
    """Test just initialization of PFR config."""
    assert PfrConfiguration()

def test_load_config_invalid(data_dir):
    """Test PFR tool - PFR Configuration Invalid cases."""
    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/invalid_file")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/invalid_file.yml")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/invalid_file.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/empty_json.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/empty_json1.json")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/empty_yml.yml")

    with pytest.raises(SPSDKPfrConfigReadError):
        PfrConfiguration(data_dir+"/empty_file")

def test_set_config_invalid(data_dir):
    """Test invalid cases for set_config."""
    cmpa = CMPA(device="lpc55s6x")
    cfg = PfrConfiguration(data_dir+"/bad_dev.yml")
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)

    cfg = PfrConfiguration(data_dir+"/bad_rev.yml")
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
    cfg.file_type = "INV"
    with pytest.raises(SPSDKPfrConfigError):
        cmpa.set_config(cfg)

def test_invalid_computed_field_handler():
    """Test invalid case for computed filed handler."""
    cmpa = CMPA(device="lpc55s6x")
    fields = {"test_field":"invalid_handler"}

    with pytest.raises(SPSDKError):
        cmpa.reg_computed_fields_handler(b'\x00', fields)

def test_get_bitfields_ignore():
    """Test invalid case for computed filed handler."""
    cmpa = CMPA(device="lpc55s6x")
    cmpa.config.config.pop('ignored_fields', None)
    assert cmpa.generate_config()

def test_json_yml_configs(data_dir):
    """Test of JSON and YML configuration, it must be equal."""
    cmpa_json = CMPA('lpc55s6x', user_config=PfrConfiguration(f"{data_dir}/cmpa_96mhz.json"))
    cmpa_yml = CMPA('lpc55s6x', user_config=PfrConfiguration(f"{data_dir}/cmpa_96mhz.yml"))

    assert cmpa_yml.get_yaml_config(False) == cmpa_json.get_yaml_config(False)
    assert cmpa_yml.get_json_config(False) == cmpa_json.get_json_config(False)

def test_without_ignored_bitfields(data_dir):
    """Test of CMPA configuration without ignored bitfields."""
    cmpa = CMPA('lpc55s6x', user_config=PfrConfiguration(f"{data_dir}/cmpa_96mhz.yml"))

    cmpa_with_ignored_bitfields_yml = cmpa.get_yaml_config(False)
    cmpa_with_ignored_bitfields_json = cmpa.get_json_config(False)
    cmpa.config.config.pop("ignored_fields")
    cmpa_without_ignored_bitfields_yml = cmpa.get_yaml_config(False)
    cmpa_without_ignored_bitfields_json = cmpa.get_json_config(False)
    assert cmpa_with_ignored_bitfields_yml != cmpa_without_ignored_bitfields_yml
    assert cmpa_with_ignored_bitfields_json != cmpa_without_ignored_bitfields_json

def test_missing_rotkh():
    """Simple test to check right functionality of missing ROTKH."""
    cfpa = CFPA('lpc55s6x')
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.export(keys=["Invalid"])

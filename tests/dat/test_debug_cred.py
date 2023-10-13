#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for debug credential."""


import pytest
import yaml

from spsdk.apps.nxpdebugmbox import DatProtocol
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.dat.debug_credential import DebugCredential
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import load_binary, use_working_directory, write_file


@pytest.mark.parametrize(
    "protocol_version, rsa_detected, invalid",
    [
        ("1.0", True, False),
        ("1.1", True, False),
        ("2.0", False, False),
        ("2.1", False, False),
        ("2.2", False, False),
        ("3.2", False, True),
        ("Invalid", False, True),
    ],
)
def test_determine_protocol_version(protocol_version, rsa_detected, invalid):
    """Test for checking all available protocol versions."""
    if invalid:
        with pytest.raises(SPSDKValueError):
            protocol = DatProtocol(protocol_version)
            protocol.validate()
    else:
        protocol = DatProtocol(protocol_version)
        assert protocol.is_rsa() is rsa_detected


def test_debugcredential_rsa_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_rsa2048.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredential.create_from_yaml_config(version="1.0", yaml_config=yaml_config)
            dc.sign()
            data = dc.export()
            data_loaded = load_binary("new_dck_rsa2048.cert")
            assert (
                data == data_loaded
            ), "The generated dc binary and the referenced one are not the same."


def test_verify_ecc_signature(data_dir):
    """Verifies the signature for ECC protocol."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version="2.0", yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["rotk"])
    data_without_signature = data[:-64]
    signature_bytes = data[-64:]
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
    )


def test_verify_ecc_signature_lpc55s3x_256(data_dir):
    """Verifies the signature for ECC256 protocol for LPC55S3x."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256_lpc55s3x.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version="2.0", yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["rotk"])
    data_without_signature = data[:-64]
    signature_bytes = data[-64:]
    assert len(signature_bytes) == 64
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
    )


def test_verify_ecc_signature_lpc55s3x_384(data_dir):
    """Verifies the signature for ECC384 protocol for LPC55S3x."""
    with use_working_directory(data_dir):
        with open("new_dck_secp384_lpc55s3x.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version="2.1", yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["rotk"])
    data_without_signature = data[:-96]
    signature_bytes = data[-96:]
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA384
    )


def test_debugcredential_ecc_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredential.create_from_yaml_config(version="2.0", yaml_config=yaml_config)
            dc.sign()
            data = dc.export()
            priv_key = PrivateKeyEcc.load(yaml_config["rotk"])
        data_without_signature = data[:-64]
        signature_bytes = data[-64:]
        with open("new_dck_secp256r1.cert", "rb") as f:
            data_loaded = f.read()
        ref_data_without_signature = data_loaded[:-64]
        ref_signature_bytes = data_loaded[-64:]
        assert (
            data_without_signature == ref_data_without_signature
        ), "The generated dc binary and the referenced one are not the same."
        pub_key = priv_key.get_public_key()
        assert pub_key.verify_signature(
            signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
        )
        assert pub_key.verify_signature(
            ref_signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
        )


@pytest.mark.parametrize(
    "yml_file_name, version",
    [
        ("new_dck_secp256_lpc55s3x.yml", "2.0"),
        ("new_dck_secp256_lpc55s3x_not_empty.yml", "2.0"),
        ("new_dck_secp384_lpc55s3x.yml", "2.1"),
        ("new_dck_secp384_lpc55s3x_not_empty.yml", "2.1"),
    ],
)
def test_lpc55s3x_export_parse(data_dir, yml_file_name, version):
    """Verifies the signature for lpc55s3x for different versions."""
    with use_working_directory(data_dir):
        with open(yml_file_name, "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        dc_parsed = dc.parse(data)
        assert dc == dc_parsed


def test_lpc55s3x_export_parse_invalid(data_dir):
    with use_working_directory(data_dir):
        with open("new_dck_secp256_lpc55s3x.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version="2.0", yaml_config=yaml_config)
        dc.sign()
        with pytest.raises(SPSDKError, match="Invalid flag"):
            dc.parse(bytes(232))


@pytest.mark.parametrize(
    "dc_file_name, class_name",
    [
        ("new_dck_rsa2048.cert", "DebugCredentialRSA2048"),
        ("new_dck_secp256r1.cert", "DebugCredentialECC256"),
        ("lpc55s3x_dck_secp384r1.cert", "DebugCredentialECC384"),
    ],
)
def test_parse(data_dir, dc_file_name, class_name):
    """Verifies the parse mechanisms on DC files."""
    with use_working_directory(data_dir):
        with open(dc_file_name, "rb") as f:
            dc_file = f.read()
        dc = DebugCredential.parse(dc_file)
        assert dc.__class__.__name__ == class_name


@pytest.mark.parametrize(
    "yml_file_name, version, required_values",
    [
        (
            "new_dck_secp256_lpc55s3x.yml",
            "2.0",
            ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678", "CRTK table not present"],
        ),
        (
            "new_dck_secp256_lpc55s3x_not_empty.yml",
            "2.0",
            [
                "E004090E6BDD2155BBCE9E0665805BE3",
                "4",
                "0x3ff",
                "0x5678",
                "CRTK table has 3 entries",
            ],
        ),
        (
            "new_dck_secp256.yml",
            "2.0",
            ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678"],
        ),
    ],
)
def test_debugcredential_info_lpc55s3x(data_dir, yml_file_name, version, required_values):
    """Verifies the info message for debug authentication."""
    with use_working_directory(data_dir):
        with open(yml_file_name, "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
    output = str(dc)
    req_strings = ["Version", "SOCC", "UUID", "UUID", "CC_SOCC", "CC_VU", "BEACON"]
    req_values = required_values
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
    for req_value in req_values:
        assert req_value in output, f"string {req_value} is not in the output: {output}"


def test_debugcredential_invalid(data_dir):
    """Evoke exceptions."""
    with use_working_directory(data_dir):
        with open("new_dck_rsa2048.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredential.create_from_yaml_config(version="1.0", yaml_config=yaml_config)
            with pytest.raises(SPSDKError, match="Debug Credential Signature is not set"):
                dc.export()
            with pytest.raises(SPSDKError, match="Debug Credential Signature provider is not set"):
                dc.signature_provider = None
                dc.sign()


def test_debugcredential_rot_meta_as_cert(data_dir):
    """Verifies the info message for debug authentication."""
    with use_working_directory(data_dir):
        with open("dck_rsa2048_rot_meta_cert.yml", "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version="1.0", yaml_config=yaml_config)
        dc.sign()
        assert dc.VERSION == "1.0"
        assert dc.cc_beacon == 0
        assert dc.cc_socu == 1023
        assert dc.cc_vu == 22136
        assert dc.socc == 1
        assert dc.uuid == b"\xe0\x04\t\x0ek\xdd!U\xbb\xce\x9e\x06e\x80[\xe3"


@pytest.mark.parametrize("dc_file_name", ["rt1180_256.dc"])
def test_debugcredential_parse_export(data_dir, dc_file_name):
    """Verifies parse/export functions."""
    with use_working_directory(data_dir):
        dc_binary = load_binary(dc_file_name)
        dc = DebugCredential.parse(dc_binary)
        assert dc_binary == dc.export()

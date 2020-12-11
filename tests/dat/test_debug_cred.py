#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for debug credential."""

import pytest
import yaml

from spsdk import crypto
from spsdk.crypto import hashes, ec, InvalidSignature
from spsdk.crypto.loaders import load_private_key
from spsdk.dat import utils
from spsdk.dat.debug_credential import DebugCredential
from spsdk.utils.misc import load_binary, use_working_directory


def test_debugcredential_rsa_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_rsa2048.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredential.create_from_yaml_config(version='1.0', yaml_config=yaml_config)
            dc.sign()
            data = dc.export()
            with open('sample.cert', 'wb') as f:
                f.write(data)
            with open('new_dck_rsa2048.cert', 'rb') as f:
                data_loaded = f.read()
            assert data == data_loaded, "The generated dc binary and the referenced one are not the same."


def test_reconstruct_signature(data_dir):
    """Reconstructs the signature."""
    signature_bytes = load_binary(data_dir, 'signature_bytes.bin')
    signature = load_binary(data_dir, 'signature.bin')
    reconstructed_signature = utils.reconstruct_signature(signature_bytes)
    assert signature == reconstructed_signature


def test_verify_ecc_signature(data_dir):
    """Verifies the signature for ECC protocol."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version='2.0', yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = load_private_key(yaml_config['rotk'])
    data_without_signature = data[:-132]
    signature_bytes = data[-132:]
    signature = utils.reconstruct_signature(signature_bytes)
    pub_key = priv_key.public_key()
    try:
        pub_key.verify(signature, data_without_signature, ec.ECDSA(hashes.SHA256()))
        assert True
    except InvalidSignature:
        assert False


def test_verify_ecc_signature_N4A_256(data_dir):
    """Verifies the signature for ECC protocol for Niobe4Analog 256."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256_N4A.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version='2.0', yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = load_private_key(yaml_config['rotk'])
    data_without_signature = data[:-64]
    signature_bytes = data[-64:]
    assert len(signature_bytes) == 64
    signature = utils.reconstruct_signature(signature_bytes=signature_bytes, size=32)
    pub_key = priv_key.public_key()
    try:
        pub_key.verify(signature, data_without_signature, ec.ECDSA(hashes.SHA256()))
        assert True
    except InvalidSignature:
        assert False


def test_verify_ecc_signature_N4A_384(data_dir):
    """Verifies the signature for ECC protocol for Niobe4Analog 384."""
    with use_working_directory(data_dir):
        with open("new_dck_secp384_N4A.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version='2.1', yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = load_private_key(yaml_config['rotk'])
    data_without_signature = data[:-96]
    signature_bytes = data[-96:]
    signature = utils.reconstruct_signature(signature_bytes=signature_bytes, size=48)
    pub_key = priv_key.public_key()
    try:
        pub_key.verify(signature, data_without_signature, ec.ECDSA(hashes.SHA384()))
        assert True
    except InvalidSignature:
        assert False



def test_debugcredential_ecc_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredential.create_from_yaml_config(version='2.0', yaml_config=yaml_config)
            dc.sign()
            data = dc.export()
            pub_key = load_private_key(yaml_config['rotk']).public_key()
        data_without_singature = data[:-132]
        signature_bytes = data[-132:]
        with open('new_dck_secp256r1.cert', 'rb') as f:
            data_loaded = f.read()
        ref_data_without_signature = data_loaded[:-132]
        ref_signature_bytes = data_loaded[-132:]
        assert data_without_singature == ref_data_without_signature, \
            "The generated dc binary and the referenced one are not the same."
        signature = utils.reconstruct_signature(signature_bytes)
        ref_signature = utils.reconstruct_signature(ref_signature_bytes)
        try:
            pub_key.verify(signature, data_without_singature, ec.ECDSA(hashes.SHA256()))
            pub_key.verify(ref_signature, data_without_singature, ec.ECDSA(hashes.SHA256()))
            assert True
        except InvalidSignature:
            assert False


@pytest.mark.parametrize(
    "yml_file_name, version",
    [
        ('new_dck_secp256_N4A.yml', '2.0'),
        ('new_dck_secp256_N4A_not_empty.yml', '2.0'),
        ('new_dck_secp384_N4A.yml', '2.1'),
        ('new_dck_secp384_N4A_not_empty.yml', '2.1')
    ]
)
def test_niobe4analog_export_parse(data_dir, yml_file_name, version):
    """Verifies the signature for N4A for different versions."""
    with use_working_directory(data_dir):
        with open(yml_file_name, 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
        data = dc.export()
        dc_parsed = dc.parse(data)
        assert dc == dc_parsed


@pytest.mark.parametrize(
    "yml_file_name, version, required_values",
    [
        ('new_dck_secp256_N4A.yml', '2.0',
         ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678", "CRTK table not present"]),
        ('new_dck_secp256_N4A_not_empty.yml', '2.0',
         ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678", "CRTK table has 3 entries"]),
        ('new_dck_secp256.yml', '2.0',
         ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678"]),
    ]
)
def test_debugcredential_info_N4A(data_dir, yml_file_name, version, required_values):
    """Verifies the info message for debug authentication."""
    with use_working_directory(data_dir):
        with open(yml_file_name, 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredential.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
    output = dc.info()
    req_strings = ["Version", "SOCC", "UUID", "UUID", "CC_SOCC", "CC_VU", "BEACON"]
    req_values = required_values
    for req_string in req_strings:
        assert req_string in output, f'string {req_string} is not in the output: {output}'
    for req_value in req_values:
        assert req_value in output, f'string {req_value} is not in the output: {output}'

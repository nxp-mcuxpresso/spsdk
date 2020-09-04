#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for debug credential."""

import yaml

from spsdk.crypto import hashes, ec, InvalidSignature
from spsdk.crypto.loaders import load_private_key
from spsdk.dat import utils
from spsdk.dat.debug_credential import DebugCredentialRSA, DebugCredentialECC
from spsdk.utils.misc import load_binary, use_working_directory


def test_debugcredential_rsa_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_rsa2048.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredentialRSA.from_yaml_config(version='1.0', yaml_config=yaml_config)
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
        dc = DebugCredentialECC.from_yaml_config(version='2.0', yaml_config=yaml_config)
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


def test_debugcredential_info(data_dir):
    """Verifies the info message for debug authentication."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredentialECC.from_yaml_config(version='2.0', yaml_config=yaml_config)
    output = dc.info()
    req_strings = ["Version", "SOCC", "UUID", "UUID", "CC_SOCC", "CC_VU", "BEACON"]
    for req_string in req_strings:
        assert req_string in output, f'string {req_string} is not in the output: {output}'


def test_debugcredential_ecc_compare_with_reference(data_dir):
    """Loads the yaml file, creates the debug credential, saves to a file and compares with reference."""
    with use_working_directory(data_dir):
        with open("new_dck_secp256.yml", 'r') as f:
            yaml_config = yaml.safe_load(f)
            dc = DebugCredentialECC.from_yaml_config(version='2.0', yaml_config=yaml_config)
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

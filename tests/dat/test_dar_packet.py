#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests with Debug Authentication Packet (DAR) Packet."""

import os
import pytest
import yaml

from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat import DebugAuthenticationChallenge as DAC
from spsdk.dat.debug_credential import DebugCredential as DC
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.mark.parametrize(
    "yml_file_name, dac_bin_file, version, dck_key_file, expected_length",
    [
        ('new_dck_rsa2048.yml', 'sample_dac.bin', '1.0', 'new_dck_2048.pem', 1200),
        ('new_dck_secp256.yml', 'sample_dac_ecc.bin', '2.0', 'new_dck_secp256r1.pem', 968)
    ]
)
def test_dar_packet_rsa(tmpdir, data_dir, yml_file_name, version, dck_key_file, expected_length, dac_bin_file):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, dac_bin_file))
        with open(os.path.join(data_dir, yml_file_name), 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DC.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
        assert dc.VERSION == DAC.parse(dac_bytes).version, "Version of DC and DAC are different."
        dar = DebugAuthenticateResponse.create(version=version, socc=dc.socc, dc=dc,
                                               auth_beacon=0, dac=DAC.parse(dac_bytes),
                                               dck=os.path.join(data_dir, dck_key_file))
        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert 'Authentication Beacon' in dar.info()


@pytest.mark.parametrize(
    "yml_file_name, version, file_key, expected_length",
    [
        ('new_dck_secp256_N4A.yml', '2.0', 'new_dck_secp256r1.pem', 316),
        ('new_dck_secp384_N4A.yml', '2.1', 'new_dck_secp384r1.pem', 444)
    ]
)
def test_dar_packet_4_analog_256(tmpdir, data_dir, yml_file_name, version, file_key, expected_length):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, 'sample_dac_analog.bin'))
        with open(os.path.join(data_dir, yml_file_name), 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DC.create_from_yaml_config(version=version, yaml_config=yaml_config)
        dc.sign()
        dar = DebugAuthenticateResponse.create(version=version, socc=dc.socc, dc=dc,
                                               auth_beacon=0, dac=DAC.parse(dac_bytes),
                                               dck=os.path.join(data_dir, file_key))
        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert 'Authentication Beacon' in dar.info()

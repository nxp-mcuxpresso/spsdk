#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests with Debug Authentication Packet (DAR) Packet."""

import os

import yaml

from spsdk.dat.dar_packet import DebugAuthenticateResponseRSA, \
    DebugAuthenticateResponseECC
from spsdk.dat.debug_credential import DebugCredentialRSA, DebugCredentialECC
from spsdk.utils.misc import load_binary, use_working_directory


def test_dar_packet_rsa(tmpdir, data_dir):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, 'sample_dac.bin'))
        with open(os.path.join(data_dir, "new_dck_rsa2048.yml"), 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredentialRSA.from_yaml_config(version='1.0', yaml_config=yaml_config)
        dar = DebugAuthenticateResponseRSA(debug_credential=dc,
                                           auth_beacon=0,
                                           dac=dac_bytes,
                                           path_dck_private=os.path.join(data_dir, 'new_dck_2048.pem'))
        dar_bytes = dar.export()
        assert len(dar_bytes) == 1200
        assert isinstance(dar_bytes, bytes)
        assert 'Authentication Beacon' in dar.info()


def test_dar_packet_ecc(tmpdir, data_dir):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, 'sample_dac.bin'))
        with open(os.path.join(data_dir, 'new_dck_secp256.yml'), 'r') as f:
            yaml_config = yaml.safe_load(f)
        dc = DebugCredentialECC.from_yaml_config(version='2.0', yaml_config=yaml_config)
        dar = DebugAuthenticateResponseECC(debug_credential=dc,
                                           auth_beacon=0,
                                           dac=dac_bytes,
                                           path_dck_private=os.path.join(data_dir, 'new_dck_secp256r1.pem'))
        dar_bytes = dar.export()
        assert len(dar_bytes) == 968
        assert isinstance(dar_bytes, bytes)
        assert 'Authentication Beacon' in dar.info()

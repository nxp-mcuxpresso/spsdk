#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests with Debug Authentication Packet (DAR) Packet."""

import os

import pytest
import yaml

from spsdk.crypto.signature_provider import get_signature_provider
from spsdk.dat.dac_packet import DebugAuthenticationChallenge as DAC
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import DebugCredentialCertificate as DC
from spsdk.dat.debug_credential import ProtocolVersion
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.mark.parametrize(
    "yml_file_name, dac_bin_file, version, dck_key_file, expected_length",
    [
        (
            "new_dck_rsa2048.yml",
            "sample_dac.bin",
            ProtocolVersion.from_version(1, 0),
            "../../_data/keys/rsa2048/dck_rsa2048.pem",
            1200,
        ),
        (
            "new_dck_secp256.yml",
            "sample_dac_ecc.bin",
            ProtocolVersion.from_version(2, 0),
            "../../_data/keys/ecc256/dck_ecc256.pem",
            316,
        ),
    ],
)
def test_dar_packet_rsa_ecc(
    data_dir, yml_file_name, version, dck_key_file, expected_length, dac_bin_file
):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, dac_bin_file))
        with open(os.path.join(data_dir, yml_file_name), "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DC.create_from_yaml_config(version=version, config=yaml_config)
        dc.sign()
        assert dc.version == DAC.parse(dac_bytes).version, "Version of DC and DAC are different."
        dar = DebugAuthenticateResponse.create(
            family=None,
            version=version,
            dc=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes),
            dck=os.path.join(data_dir, dck_key_file),
        )
        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert "Authentication Beacon" in str(dar)


@pytest.mark.parametrize(
    "yml_file_name, version, file_key, expected_length",
    [
        (
            "new_dck_secp256_lpc55s3x.yml",
            ProtocolVersion("2.0"),
            "../../_data/keys/ecc256/dck_ecc256.pem",
            316,
        ),
        (
            "new_dck_secp384_lpc55s3x.yml",
            ProtocolVersion("2.1"),
            "../../_data/keys/ecc384/dck_ecc384.pem",
            444,
        ),
    ],
)
def test_dar_packet_lpc55s3x_256(data_dir, yml_file_name, version, file_key, expected_length):
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, "sample_dac_lpc55s3x.bin"))
        with open(os.path.join(data_dir, yml_file_name), "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DC.create_from_yaml_config(version=version, config=yaml_config)
        dc.sign()

        dar = DebugAuthenticateResponse.create(
            family=None,
            version=version,
            dc=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes),
            dck=os.path.join(data_dir, file_key),
        )
        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert "Authentication Beacon" in str(dar)


def test_dar_packet_no_signature_provider(data_dir):
    with use_working_directory(data_dir):
        version = ProtocolVersion("1.0")
        dac_bin_file = "sample_dac.bin"
        yml_file_name = "new_dck_rsa2048.yml"
        dac_bytes = load_binary(os.path.join(data_dir, dac_bin_file))
        with open(os.path.join(data_dir, yml_file_name), "r") as f:
            yaml_config = yaml.safe_load(f)
        dc = DC.create_from_yaml_config(version=version, config=yaml_config)
        dc.sign()
        dar = DebugAuthenticateResponse(
            family="lpc55s6x",
            debug_credential=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes),
            sign_provider=get_signature_provider(
                local_file_key=os.path.join(data_dir, "../../_data/keys/rsa2048/dck_rsa2048.pem")
            ),
        )
        dar.sign_provider = None
        with pytest.raises(SPSDKError, match="Signature provider is not set"):
            dar.export()

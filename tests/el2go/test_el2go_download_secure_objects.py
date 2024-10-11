#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO download Secure Objects operation."""

import os
import shutil
import base64

import pytest
from unittest.mock import patch

from spsdk.el2go.api_utils import EL2GOTPClient, GenStatus, BAD_STATES, SPSDKError, NO_DATA_STATES
from spsdk.utils.misc import load_configuration, use_working_directory

from utils import mock_time_sleep


@pytest.mark.parametrize(
    "config, device_id, provisionings, gen_status",
    [
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
            GenStatus.GENERATION_COMPLETED.value[0],
        )
    ],
)
@mock_time_sleep
def test_00_019_download_secure_objects(
    tmpdir, data_dir, config, device_id, provisionings, gen_status
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [
            {
                "rtpProvisionings": [
                    {
                        "apdus": {"createApdu": {"apdu": provisionings}},
                        "state": "GENERATION_COMPLETED",
                    }
                ]
            }
        ]

    with patch(
        "spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status
    ):
        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings",
            return_value=download_prov_dict,
        ):
            data = client.download_secure_objects(device_id=device_id)
            assert data == expected_output


@pytest.mark.parametrize(
    "config, device_id, provisionings",
    [
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
        )
    ],
)
@mock_time_sleep
def test_00_020_download_secure_objects_gen_trig(
    tmpdir, data_dir, config, device_id, provisionings
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [
            {
                "rtpProvisionings": [
                    {
                        "apdus": {"createApdu": {"apdu": provisionings}},
                        "state": "GENERATION_COMPLETED",
                    }
                ]
            }
        ]

    with patch(
        "spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status",
        side_effect=[
            GenStatus.GENERATION_TRIGGERED.value[0],
            GenStatus.GENERATION_COMPLETED.value[0],
        ],
    ):
        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings",
            return_value=download_prov_dict,
        ):
            data = client.download_secure_objects(device_id=device_id)
            assert data == expected_output


@pytest.mark.parametrize(
    "config, device_id, provisionings, gen_status",
    [
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
            GenStatus.GENERATION_FAILED.value[0],
        ),
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
            GenStatus.PROVISIONING_COMPLETED.value[0],
        ),
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
            GenStatus.PROVISIONING_FAILED.value[0],
        ),
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
            GenStatus.GENERATION_ON_CONNECTION.value[0],
        ),
    ],
)
@mock_time_sleep
def test_00_021_download_secure_objects_diff_gen_status(
    tmpdir, data_dir, config, device_id, provisionings, gen_status
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [
            {
                "rtpProvisionings": [
                    {
                        "apdus": {"createApdu": {"apdu": provisionings}},
                        "provisioningState": gen_status,
                        "state": gen_status,
                        "provisioningId": 1234,
                    }
                ]
            }
        ]
        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status
        ):
            if gen_status in BAD_STATES:
                with pytest.raises(SPSDKError):
                    client.download_secure_objects(device_id=device_id)
            else:
                with patch(
                    "spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings",
                    return_value=download_prov_dict,
                ):
                    data = client.download_secure_objects(device_id=device_id)
                    if gen_status in NO_DATA_STATES:
                        assert data == b""


@pytest.mark.parametrize(
    "config, device_id, gen_status",
    [
        (
            "test_config.yml",
            "00112233445566778899AABBCCDDEEFF001122A",
            GenStatus.GENERATION_TRIGGERED.value[0],
        ),
    ],
)
@mock_time_sleep
def test_00_022_download_secure_objects_timeout_reached(
    tmpdir, data_dir, config, device_id, gen_status
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status
        ):
            # no need to wait :)
            client.download_timeout = 0.001
            with pytest.raises(SPSDKError, match="timed-out"):
                client.download_secure_objects(device_id=device_id)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python(tmpdir
# -*- coding: UTF-8 -*-
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

from spsdk.el2go.api_utils import EL2GOTPClient, GenStatus
from spsdk.utils.misc import load_configuration, use_working_directory


@pytest.mark.parametrize(
    "config, device_id, provisionings, gen_status",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
         GenStatus.GENERATION_COMPLETED)
    ]
)
def test_00_019_download_secure_objects(tmpdir, data_dir, config, device_id, provisionings, gen_status):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [{"rtpProvisionings": [{"apdus": {"createApdu": {"apdu": provisionings}}}]}]

    with patch("spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status):
        with patch("spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings", return_value=download_prov_dict):
            data = client.download_secure_objects(device_id=device_id)
            assert data == expected_output


@pytest.mark.parametrize(
    "config, device_id, provisionings",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=")

    ]
)
def test_00_020_download_secure_objects_gen_trig(tmpdir, data_dir, config, device_id, provisionings):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [{"rtpProvisionings": [{"apdus": {"createApdu": {"apdu": provisionings}}}]}]

    with patch("spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status",
               side_effect=[GenStatus.GENERATION_TRIGGERED, GenStatus.GENERATION_COMPLETED]):
        with patch("spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings", return_value=download_prov_dict):
            data = client.download_secure_objects(device_id=device_id)
            assert data == expected_output


@pytest.mark.parametrize(
    "config, device_id, provisionings, gen_status",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
         GenStatus.GENERATION_FAILED),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
         GenStatus.PROVISIONING_COMPLETED),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
         GenStatus.PROVISIONING_FAILED),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "S00oOyklMnVoN3EoMEYxXEVYQzAoViZ2aUA=",
         GenStatus.GENERATION_ON_CONNECTION)
    ]
)
def test_00_021_download_secure_objects_diff_gen_status(tmpdir, data_dir, config, device_id, provisionings, gen_status):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        download_prov_dict = [{"rtpProvisionings": [{"apdus": {"createApdu": {"apdu": provisionings}}}]}]

        with patch("spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status):
            with patch("spsdk.el2go.api_utils.EL2GOTPClient.download_provisionings", return_value=download_prov_dict):
                status_code = client.download_secure_objects(device_id=device_id)
                assert status_code == gen_status


@pytest.mark.parametrize(
    "config, device_id, gen_status",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", GenStatus.GENERATION_TRIGGERED),
    ]
)
def test_00_022_download_secure_objects_timeout_reached(tmpdir, data_dir, config, device_id, gen_status):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        with patch("spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status):
            status_code = client.download_secure_objects(device_id=device_id)
            assert status_code == gen_status

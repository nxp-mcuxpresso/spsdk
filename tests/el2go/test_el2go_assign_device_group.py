#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python(tmpdir
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO assign device to Device Group operation."""

import os
import shutil

import pytest
from unittest.mock import patch

from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.utils.misc import load_configuration, use_working_directory
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 202)
    ]
)
def test_00_001_whitelist_device(tmpdir, data_dir, config, device_id, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        generic_dict = {
            "mock": "el2go_test",
            "api": "response"
        }

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )
        mock_url = "mock_url"
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])
        with patch("spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group", return_value=[mock_el2go_response, mock_url]):
            client.assign_device_to_devicegroup(device_id=device_id)
            client.response_handling(mock_el2go_response.status_code, mock_url)


@pytest.mark.parametrize(
    "config, device_id, device_group_id, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "200", 422)
    ]
)
def test_00_002_device_reg_correct_group(tmpdir, data_dir, config, device_id, device_group_id, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)

        generic_dict = {
            "mock": "el2go_test",
            "api": "response"
        }

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )
        mock_url = "mock_url"
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        client.device_group_id = device_group_id
        with patch("spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
                   return_value=[mock_el2go_response, mock_url]):
            with patch("spsdk.el2go.api_utils.EL2GOTPClient._find_device_group_id", return_value=device_group_id):
                client.assign_device_to_devicegroup(device_id=device_id)


@pytest.mark.parametrize(
    "config, device_id, device_group_id, device_group_id_diff, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "200", "201", 422)
    ]
)
def test_00_003_device_reg_wrong_group(tmpdir, data_dir, config, device_id, device_group_id,
                                       device_group_id_diff, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)

        generic_dict = {
            "mock": "el2go_test",
            "api": "response"
        }

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )
        mock_url = "mock_url"
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        client.device_group_id = device_group_id

        with patch("spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
                   return_value=[mock_el2go_response, mock_url]):
            with patch("spsdk.el2go.api_utils.EL2GOTPClient._find_device_group_id", return_value=device_group_id_diff):
                with pytest.raises(SPSDKError):
                    client.assign_device_to_devicegroup(device_id=device_id)


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 500),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 415),
    ]
)
def test_00_004_005_assign_device_error(tmpdir, data_dir, config, device_id, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        generic_dict = {
            "mock": "el2go_test",
            "api": "response"
        }

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )
        mock_url = "mock_url"
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        with patch("spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
                   return_value=[mock_el2go_response, mock_url]):
            with pytest.raises(SPSDKError):
                client.assign_device_to_devicegroup(device_id=device_id)




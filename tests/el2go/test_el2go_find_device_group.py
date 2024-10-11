#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO find Device Group operation."""

import os
import shutil
from unittest.mock import patch

import pytest

from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_configuration, use_working_directory


@pytest.mark.parametrize(
    "config, device_id, device_group_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "301", 200)],
)
def test_00_006_009_extract_device_groups(
    tmpdir, data_dir, config, device_id, device_group_id, status_code
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        generic_dict = {"content": [{"id": device_group_id}]}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            response = client._find_device_group_id(device_id=device_id)
            assert response == device_group_id


@pytest.mark.parametrize(
    "config, device_id, status_code, device_group_id",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 409, "480"),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 405, "444"),
    ],
)
def test_00_007_008_extract_device_groups_fail(
    tmpdir, data_dir, config, device_id, status_code, device_group_id
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {"content": [{"id": device_group_id}]}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            with pytest.raises(SPSDKError):
                client._find_device_group_id(device_id=device_id)


@pytest.mark.parametrize(
    "config, device_id, device_group_id, status_code, status_code_not_found",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "300", 200, 404)],
)
def test_00_010_find_wrong_device_group(
    tmpdir, data_dir, config, device_id, device_group_id, status_code, status_code_not_found
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {
            "content": [{"id": device_group_id}, {"id": device_group_id}, {"id": device_group_id}]
        }

        mock_el2go_response_not_found = EL2GOApiResponse(
            status_code=status_code_not_found, json_body=generic_dict
        )

        mock_el2go_response_found = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            side_effect=[
                mock_el2go_response_found,
                mock_el2go_response_not_found,
                mock_el2go_response_not_found,
                mock_el2go_response_found,
            ],
        ):
            response = client._find_device_group_id(device_id=device_id)
            assert response == device_group_id


@pytest.mark.parametrize(
    "config, device_id, status_code, device_group_id, status_code_success",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 404, "300", 200),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 500, "300", 200),
    ],
)
def test_00_011_012_find_device_group_error(
    tmpdir, data_dir, config, device_id, status_code, device_group_id, status_code_success
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {"content": [{"id": device_group_id}]}

        mock_el2go_response_not_found = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )

        mock_el2go_response_found = EL2GOApiResponse(
            status_code=status_code_success, json_body=generic_dict
        )

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            side_effect=[mock_el2go_response_found, mock_el2go_response_not_found],
        ):
            with pytest.raises(SPSDKError):
                client._find_device_group_id(device_id=device_id)


@pytest.mark.parametrize(
    "config, device_id, device_group_id, status_code, status_code_not_found",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "300", 200, 404)],
)
def test_00_014_find_device_group_corner_case(
    tmpdir, data_dir, config, device_id, device_group_id, status_code, status_code_not_found
):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        generic_dict = {
            "content": [{"id": device_group_id}, {"id": device_group_id}, {"id": device_group_id}]
        }

        mock_el2go_response_not_found = EL2GOApiResponse(
            status_code=status_code_not_found, json_body=generic_dict
        )

        mock_el2go_response_found = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            side_effect=[
                mock_el2go_response_found,
                mock_el2go_response_not_found,
                mock_el2go_response_not_found,
                mock_el2go_response_not_found,
            ],
        ):
            with pytest.raises(SPSDKError):
                client._find_device_group_id(device_id=device_id)

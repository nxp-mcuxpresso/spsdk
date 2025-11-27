#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO device group assignment operation tests.

This module contains unit tests for the EL2GO (EdgeLock 2GO) functionality
related to assigning devices to device groups, including device whitelisting
and registration validation.
"""

import os
import shutil
from typing import Any
from unittest.mock import patch

import pytest

from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 202)],
)
def test_00_001_whitelist_device(
    tmpdir: Any, data_dir: str, config: str, device_id: str, status_code: int
) -> None:
    """Test device whitelisting functionality with mocked EL2GO API response.

    This test verifies that a device can be successfully assigned to a device group
    by mocking the EL2GO API response and testing the client's ability to handle
    the assignment operation and response processing.

    :param tmpdir: Temporary directory for test execution.
    :param data_dir: Path to the test data directory containing configuration files.
    :param config: Name of the configuration file to use for the test.
    :param device_id: Identifier of the device to be assigned to the group.
    :param status_code: HTTP status code to be returned by the mocked API response.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        generic_dict = {"mock": "el2go_test", "api": "response"}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)
        mock_url = "mock_url"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
        client.headers["EL2G-Correlation-ID"] = "some-uuid"
        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
            return_value=[mock_el2go_response, mock_url],
        ):
            client.assign_device_to_devicegroup(device_id=device_id)
            client.response_handling(mock_el2go_response, mock_url)


@pytest.mark.parametrize(
    "config, device_id, device_group_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "200", 422)],
)
def test_00_002_device_reg_correct_group(
    tmpdir: Any, data_dir: str, config: str, device_id: str, device_group_id: str, status_code: int
) -> None:
    """Test device registration with correct group assignment.

    This test verifies that device assignment to a device group works correctly
    by mocking the EL2GO API responses and testing the client's behavior when
    assigning a device to a specific device group.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name for EL2GO client setup.
    :param device_id: Identifier of the device to be assigned.
    :param device_group_id: Identifier of the target device group.
    :param status_code: HTTP status code for mocked API response.
    :raises SPSDKError: Expected exception during device assignment process.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)

        generic_dict = {"mock": "el2go_test", "api": "response", "code": "SOME_CODE"}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)
        mock_url = "mock_url"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
        client.headers["EL2G-Correlation-ID"] = "some-uuid"
        client.device_group_id = int(device_group_id)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
            return_value=[mock_el2go_response, mock_url],
        ):
            with patch(
                "spsdk.el2go.api_utils.EL2GOTPClient._find_device_group_id",
                return_value=device_group_id,
            ):
                with pytest.raises(SPSDKError):
                    client.assign_device_to_devicegroup(device_id=device_id)


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 500),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 415),
    ],
)
def test_00_004_005_assign_device_error(
    tmpdir: Any, data_dir: str, config: str, device_id: str, status_code: int
) -> None:
    """Test error handling when assigning device to device group fails.

    This test verifies that the EL2GO client properly raises SPSDKError when the
    API call to assign a device to a device group returns an error status code.
    It mocks the API response and validates the error handling behavior.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to assign to device group.
    :param status_code: HTTP status code to simulate in the mocked response.
    :raises SPSDKError: When device assignment fails due to API error.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        generic_dict = {"mock": "el2go_test", "api": "response"}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)
        mock_url = "mock_url"
        client = EL2GOTPClient.load_from_config(config_data=config_data)
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._assign_device_to_group",
            return_value=[mock_el2go_response, mock_url],
        ):
            with pytest.raises(SPSDKError):
                client.assign_device_to_devicegroup(device_id=device_id)

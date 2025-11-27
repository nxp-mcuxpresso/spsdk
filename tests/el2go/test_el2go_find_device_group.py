#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO device group finding operation tests.

This module contains unit tests for the EL2GO device group discovery and
extraction functionality, covering both successful operations and error
handling scenarios.
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
    "config, device_id, device_group_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", "301", 200)],
)
def test_00_006_009_extract_device_groups(
    tmpdir: Any, data_dir: str, config: str, device_id: str, device_group_id: str, status_code: int
) -> None:
    """Test device group extraction functionality with mocked EL2GO API response.

    This test verifies that the EL2GOTPClient can correctly find and extract device group IDs
    from mocked API responses. It sets up a temporary working directory with test configuration,
    creates a mock EL2GO API response, and validates that the client returns the expected
    device group ID.

    :param tmpdir: Temporary directory for test execution.
    :param data_dir: Path to test data directory containing configuration files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to search for device groups.
    :param device_group_id: Expected device group identifier to be returned.
    :param status_code: HTTP status code for the mocked API response.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

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
    tmpdir: Any, data_dir: str, config: str, device_id: str, status_code: int, device_group_id: str
) -> None:
    """Test device group extraction failure scenarios.

    This test verifies that the EL2GO client properly handles and raises SPSDKError
    when device group extraction fails due to various error conditions like invalid
    status codes or malformed responses.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to search for in device groups.
    :param status_code: HTTP status code to simulate in the mocked response.
    :param device_group_id: Device group identifier for the mock response.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)
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
    tmpdir: Any,
    data_dir: str,
    config: str,
    device_id: str,
    device_group_id: str,
    status_code: int,
    status_code_not_found: int,
) -> None:
    """Test finding device group with wrong/missing device group scenarios.

    This test verifies the behavior of the EL2GO client when searching for device groups
    that may not exist or return different status codes. It mocks multiple API responses
    to simulate various scenarios including found and not found cases.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to search for.
    :param device_group_id: Expected device group identifier.
    :param status_code: HTTP status code for successful responses.
    :param status_code_not_found: HTTP status code for not found responses.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)
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
    tmpdir: Any,
    data_dir: str,
    config: str,
    device_id: str,
    status_code: int,
    device_group_id: str,
    status_code_success: int,
) -> None:
    """Test error handling when finding device group fails after successful device lookup.

    This test verifies that the _find_device_group_id method properly raises an SPSDKError
    when the device is found but the subsequent device group lookup fails with an error status code.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Source directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to search for.
    :param status_code: HTTP status code for the failed device group request.
    :param device_group_id: Device group identifier returned in mock response.
    :param status_code_success: HTTP status code for the successful device request.
    :raises SPSDKError: When device group lookup fails after successful device lookup.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)
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
    tmpdir: Any,
    data_dir: str,
    config: str,
    device_id: str,
    device_group_id: str,
    status_code: int,
    status_code_not_found: int,
) -> None:
    """Test corner case for finding device group with multiple mock responses.

    This test verifies that the _find_device_group_id method properly handles
    a scenario where the first API call succeeds but subsequent calls fail,
    ensuring that an SPSDKError is raised when the device group cannot be
    consistently found.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier to search for.
    :param device_group_id: Device group identifier used in mock responses.
    :param status_code: HTTP status code for successful response.
    :param status_code_not_found: HTTP status code for not found response.
    :raises SPSDKError: When device group cannot be found consistently.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

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

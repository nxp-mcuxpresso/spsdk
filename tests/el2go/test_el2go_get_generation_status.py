#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO get generation status operation tests.

This module contains unit tests for the EL2GO (EdgeLock 2GO) service's
get generation status functionality, verifying both successful operations
and error handling scenarios.
"""

import os
import shutil
from typing import Any
from unittest.mock import patch

import pytest

from spsdk.el2go.api_utils import EL2GOTPClient, GenStatus
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "config, device_id, status_code, generation_status",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 200, "GENERATION_COMPLETED"),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 200, "GENERATION_TRIGGERED"),
    ],
)
def test_00_014_016_get_generation_status(
    tmpdir: Any,
    data_dir: str,
    config: str,
    device_id: str,
    status_code: int,
    generation_status: str,
) -> None:
    """Test EL2GO get generation status functionality.

    This test verifies that the EL2GOTPClient can successfully retrieve and parse
    device generation status from the EL2GO API, ensuring the returned status
    matches expected generation state values.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Path to test data directory containing configuration files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier for which to get generation status.
    :param status_code: Expected HTTP status code from the mocked API response.
    :param generation_status: Expected generation status string from API response.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

        generic_dict = {"content": [{"provisioningState": generation_status}]}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            status = client.get_generation_status(device_id=device_id)
            assert status in [
                GenStatus.GENERATION_COMPLETED.value[0],
                GenStatus.GENERATION_TRIGGERED.value[0],
            ]


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 404)],
)
def test_00_015_get_generation_status_error(
    tmpdir: Any, data_dir: str, config: str, device_id: str, status_code: int
) -> None:
    """Test error handling for get_generation_status method with various HTTP status codes.

    This test verifies that the EL2GOTPClient.get_generation_status method properly
    raises SPSDKError when the API returns non-success HTTP status codes. It sets up
    a mock environment with test configuration and simulates API error responses.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name for EL2GO client setup.
    :param device_id: Device identifier for generation status query.
    :param status_code: HTTP status code to simulate in mock response.
    :raises SPSDKError: When API returns error status code (expected behavior).
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {"content": [{"provisioningState": "GENERATION_COMPLETED"}]}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            with pytest.raises(SPSDKError):
                client.get_generation_status(device_id=device_id)

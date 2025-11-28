#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO secure objects download operation tests.

This module contains comprehensive test cases for the EL2GO (EdgeLock 2GO)
secure objects download functionality, covering various scenarios including
normal operation, generation triggers, status differences, and timeout handling.
"""

import base64
import os
import shutil
from typing import Any
from unittest.mock import patch

import pytest
from utils import mock_time_sleep

from spsdk.el2go.api_utils import BAD_STATES, NO_DATA_STATES, EL2GOTPClient, GenStatus, SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.misc import use_working_directory


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
    tmpdir: Any, data_dir: str, config: str, device_id: str, provisionings: str, gen_status: str
) -> None:
    """Test downloading secure objects from EL2GO service.

    This test verifies the complete workflow of downloading secure objects including
    setting up a temporary working directory, loading configuration, mocking API calls
    for generation status and provisioning download, and validating the returned data
    matches expected base64 decoded provisioning data.

    :param tmpdir: Temporary directory for test execution
    :param data_dir: Directory containing test data files
    :param config: Configuration file name for EL2GO client setup
    :param device_id: Unique identifier of the target device
    :param provisionings: Base64 encoded provisioning data for validation
    :param gen_status: Mock generation status to be returned by API
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

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
    tmpdir: Any, data_dir: str, config: str, device_id: str, provisionings: str
) -> None:
    """Test download secure objects with generation trigger scenario.

    This test verifies the download_secure_objects functionality when the generation
    process is initially triggered and then completes. It mocks the generation status
    to simulate a transition from GENERATION_TRIGGERED to GENERATION_COMPLETED state,
    and verifies that the downloaded provisioning data matches the expected output.

    :param tmpdir: Temporary directory for test execution.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name for EL2GO client setup.
    :param device_id: Device identifier for provisioning download.
    :param provisionings: Base64 encoded provisioning data for comparison.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        expected_output = base64.b64decode(provisionings)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

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
    tmpdir: Any, data_dir: str, config: str, device_id: str, provisionings: str, gen_status: str
) -> None:
    """Test downloading secure objects with different generation statuses.

    This test verifies the behavior of the EL2GO client when downloading secure objects
    for devices with various generation statuses. It mocks the generation status and
    provisioning data to test both successful downloads and error conditions.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name for EL2GO client setup.
    :param device_id: Device identifier for secure object download.
    :param provisionings: APDU provisioning data for mocked response.
    :param gen_status: Generation status to test (e.g., 'ready', 'failed', 'pending').
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

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
    tmpdir: Any, data_dir: str, config: str, device_id: str, gen_status: str
) -> None:
    """Test download secure objects operation when timeout is reached.

    This test verifies that the EL2GOTPClient properly handles timeout scenarios
    when downloading secure objects. It sets up a test environment, configures
    a very short timeout, and ensures that a timeout exception is raised when
    the operation cannot complete within the specified time limit.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name to use for the test.
    :param device_id: Device identifier for the secure object download.
    :param gen_status: Generation status to be mocked during the test.
    :raises SPSDKError: When the download operation times out.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient.get_generation_status", return_value=gen_status
        ):
            # no need to wait :)
            client.download_timeout = 0.001  # type: ignore
            with pytest.raises(SPSDKError, match="timed-out"):
                client.download_secure_objects(device_id=device_id)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO download provisionings operation tests.

This module contains unit tests for the EL2GO (EdgeLock 2GO) download
provisionings functionality, focusing on error handling scenarios and
validation of the provisioning download process.
"""

import os
import shutil
from typing import Any
from unittest.mock import patch

import pytest
from utils import mock_time_sleep

from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 422)],
)
@mock_time_sleep
def test_00_018_prov_download_error(
    tmpdir: Any, data_dir: str, config: str, device_id: str, status_code: int
) -> None:
    """Test provisioning download with error response.

    This test verifies that the EL2GO client properly handles error responses
    when downloading provisionings by mocking an API response with an error
    status code and ensuring an SPSDKError is raised.

    :param tmpdir: Temporary directory for test files.
    :param data_dir: Directory containing test data files.
    :param config: Configuration file name.
    :param device_id: Device identifier for provisioning download.
    :param status_code: HTTP status code to mock in the response.
    :raises SPSDKError: When the mocked API response contains an error status code.
    """
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = Config.create_from_file(config)
        client = EL2GOTPClient.load_from_config(config_data=config_data)
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {"mock": "el2go_test", "api": "response"}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            with pytest.raises(SPSDKError):
                client.download_provisionings(device_id=device_id)

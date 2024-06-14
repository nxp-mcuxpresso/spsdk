#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python(tmpdir
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO get generation status operation."""

import os
import shutil

import pytest
from unittest.mock import patch

from spsdk.el2go.api_utils import EL2GOTPClient, GenStatus
from spsdk.utils.misc import load_configuration, use_working_directory
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError


@pytest.mark.parametrize(
    "config, device_id, status_code, generation_status",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 200, "GENERATION_COMPLETED"),
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 200, "GENERATION_TRIGGERED")

    ]
)
def test_00_014_016_get_generation_status(tmpdir, data_dir, config, device_id, status_code, generation_status):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        generic_dict = {"content": [{"provisioningState": generation_status}]}

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )

        with patch("spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request", return_value=mock_el2go_response):
            status = client.get_generation_status(device_id=device_id)
            assert status == GenStatus.GENERATION_COMPLETED or status == GenStatus.GENERATION_TRIGGERED


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [
        ("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 404)
    ]
)
def test_00_015_get_generation_status_error(tmpdir, data_dir, config, device_id, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

        generic_dict = {"content": [{"provisioningState": "GENERATION_COMPLETED"}]}

        mock_el2go_response = EL2GOApiResponse(
            status_code=status_code, json_body=generic_dict
        )

        with patch("spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request", return_value=mock_el2go_response):
            with pytest.raises(SPSDKError):
                client.get_generation_status(device_id=device_id)


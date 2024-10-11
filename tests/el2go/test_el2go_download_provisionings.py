#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO download provisionings operation."""

import os
import shutil
from unittest.mock import patch

import pytest
from utils import mock_time_sleep

from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.client import EL2GOApiResponse
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_configuration, use_working_directory


@pytest.mark.parametrize(
    "config, device_id, status_code",
    [("test_config.yml", "00112233445566778899AABBCCDDEEFF001122A", 422)],
)
@mock_time_sleep
def test_00_018_prov_download_error(tmpdir, data_dir, config, device_id, status_code):
    work_dir = os.path.join(tmpdir)
    shutil.copytree(os.path.join(data_dir), work_dir, dirs_exist_ok=True)
    shutil.copy(os.path.join(data_dir, config), work_dir)
    with use_working_directory(work_dir):
        config_data = load_configuration(path=config)
        search_path = os.path.dirname(config)
        client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])
        client.headers["EL2G-Correlation-ID"] = "some-uuid"

        generic_dict = {"mock": "el2go_test", "api": "response"}

        mock_el2go_response = EL2GOApiResponse(status_code=status_code, json_body=generic_dict)

        with patch(
            "spsdk.el2go.api_utils.EL2GOTPClient._handle_el2go_request",
            return_value=mock_el2go_response,
        ):
            with pytest.raises(SPSDKError):
                client.download_provisionings(device_id=device_id)

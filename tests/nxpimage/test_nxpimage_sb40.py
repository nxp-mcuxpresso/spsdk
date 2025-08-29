#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test SecureBinary part of nxpimage app."""
import json
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.keys import IS_DILITHIUM_SUPPORTED
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration, use_working_directory
from tests.cli_runner import CliRunner

if not IS_DILITHIUM_SUPPORTED:
    pytest.skip(reason="PQC support is not installed", allow_module_level=True)


def process_config_file(config_path: str, destination: str):
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("containerOutputFile")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config

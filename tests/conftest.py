#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from os import path

import pytest

# Skip test collection of TP tests if smartcard package cannot be imported
try:
    import smartcard
except ImportError:
    collect_ignore_glob = ["tp*"]


@pytest.fixture(scope="module")
def data_dir(request):
    logging.debug(f"data_dir for module: {request.fspath}")
    data_path = path.join(path.dirname(request.fspath), "data")
    logging.debug(f"data_dir: {data_path}")
    return data_path


def pytest_addoption(parser):
    parser.addoption(
        "--target",
        action="store",
        default="VIRTUAL",
        help="Device: VIRTUAL, IMXRT, ... or 'VID:PID'",
    )

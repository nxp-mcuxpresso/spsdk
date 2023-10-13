#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
import os

import pytest


@pytest.fixture(scope="module")
def nxpimage_data_dir(request):
    logging.debug("data_dir is overloaded for module to nxpimage")
    logging.debug(f"request path {request.fspath}")
    path = os.path.dirname(request.fspath)
    path, _ = os.path.split(path)

    data_path = os.path.join(path, "nxpimage", "data")
    logging.debug(f"data_dir: {data_path}")
    return data_path

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from os import path
import pytest


@pytest.fixture(scope="module")
def data_dir(request):
    logging.debug(f"data_dir for module: {request.fspath}")
    data_path = path.join(path.dirname(request.fspath), 'data')
    logging.debug(f"data_dir: {data_path}")
    return data_path

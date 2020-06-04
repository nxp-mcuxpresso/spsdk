#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from os import path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="module")
def data_dir():
    return path.join(path.dirname(path.abspath(__file__)), 'data')


@pytest.fixture(scope="module")
def private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

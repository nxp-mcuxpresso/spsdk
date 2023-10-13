#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test CLI utilities."""
import os

import pytest

from spsdk.crypto.keys import PublicKey
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import use_working_directory


def test_extract_public_key(data_dir):
    """Test extraction of public key"""
    public_key = PublicKey.load(os.path.join(data_dir, "public.pem"))

    with use_working_directory(data_dir):
        assert extract_public_key("public.pem", password=None) == public_key
        assert extract_public_key("private.pem", password=None) == public_key
        assert extract_public_key("cert.pem", password=None) == public_key


def test_unsupported_secret_type(data_dir):
    """Test unsupported secret type."""
    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            extract_public_key("cfpa_test.json", password=None)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR CLI utilities testing module.

This module contains unit tests for PFR (Protected Flash Region) CLI utility functions,
focusing on cryptographic key operations and error handling scenarios.
"""

import os

import pytest

from spsdk.crypto.keys import PublicKey
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import use_working_directory


def test_extract_public_key(data_dir: str) -> None:
    """Test extraction of public key from various file formats.

    Verifies that the extract_public_key function can correctly extract public keys
    from public key files, private key files, and certificate files in PEM format.
    The test uses a temporary working directory and compares extracted keys against
    a reference public key.

    :param data_dir: Path to directory containing test key and certificate files
    :raises AssertionError: If extracted public key doesn't match expected key
    """
    public_key = PublicKey.load(os.path.join(data_dir, "public.pem"))

    with use_working_directory(data_dir):
        assert extract_public_key("public.pem", password=None) == public_key
        assert extract_public_key("private.pem", password=None) == public_key
        assert extract_public_key("cert.pem", password=None) == public_key


def test_unsupported_secret_type(data_dir: str) -> None:
    """Test unsupported secret type functionality.

    This test verifies that the extract_public_key function properly raises
    an SPSDKError when encountering an unsupported secret type in the
    configuration file.

    :param data_dir: Directory path containing test data files
    :raises SPSDKError: Expected exception when unsupported secret type is encountered
    """
    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            extract_public_key("cfpa_test.json", password=None)

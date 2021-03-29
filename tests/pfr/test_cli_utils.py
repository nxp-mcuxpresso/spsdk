#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test CLI utilities."""
from os import path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from spsdk.apps.pfr import _extract_public_key
from spsdk.utils.misc import use_working_directory

def read_file(data_dir, file_name, mode='r'):
    """Help function to load file."""
    with open(path.join(data_dir, file_name), mode) as f:
        return f.read()


def test_extract_public_key(data_dir):
    """Test extraction of public key"""
    public_key_data = read_file(data_dir, 'public.pem', 'rb')
    public_key = load_pem_public_key(public_key_data, default_backend())
    public_nums = public_key.public_numbers()

    with use_working_directory(data_dir):
        numbers = _extract_public_key('public.pem', password=None).public_numbers()
        assert public_nums == numbers
        numbers = _extract_public_key('private.pem', password=None).public_numbers()
        assert public_nums == numbers
        numbers = _extract_public_key('cert.pem', password=None).public_numbers()
        assert public_nums == numbers


def test_unsupported_secret_type(data_dir):
    """Test unsupported secret type."""
    with use_working_directory(data_dir):
        with pytest.raises(AssertionError):
            _extract_public_key('cfpa_test.json', password=None)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from os import path

import json
import jsonschema
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from spsdk.apps.pfr import _extract_public_key, _load_user_config
from spsdk.apps.pfr import _get_data_for_html, _generate_html
from spsdk.image import CMPA


def read_file(data_dir, file_name, mode='r'):
    with open(path.join(data_dir, file_name), mode) as f:
        return f.read()


def test_extract_public_key(data_dir):
    """Test extraction of public key"""
    public_key_data = read_file(data_dir, 'public.pem', 'rb')
    public_key = load_pem_public_key(public_key_data, default_backend())
    public_nums = public_key.public_numbers()
    
    private_key_data = read_file(data_dir, 'private.pem', 'rb')
    cert_data = read_file(data_dir, 'cert.pem', 'rb')

    numbers = _extract_public_key('pub-key', public_key_data, password=None).public_numbers()
    assert public_nums == numbers
    numbers = _extract_public_key('priv-key', private_key_data, password=None).public_numbers()
    assert public_nums == numbers
    numbers = _extract_public_key('cert', cert_data, password=None).public_numbers()
    assert public_nums == numbers


def test_unsupported_secret_type():
    with pytest.raises(AssertionError):
        _extract_public_key(secret_type='totally-legit', data=bytes(), password=None)


def test_no_user_config():
    assert _load_user_config(None) is None


def test_get_data_for_html(data_dir):
    data = _get_data_for_html(CMPA('lpc55xx'))
    schema = json.loads(read_file(data_dir, 'html_data.schema'))
    # in case of a failure, an exception is thrown
    jsonschema.validate(data, schema)
    assert True


def test_generate_html():
    data = _get_data_for_html(CMPA('lpc55xx'))
    html = _generate_html('CMPA', data)
    assert "<h1>CMPA</h1>" in html

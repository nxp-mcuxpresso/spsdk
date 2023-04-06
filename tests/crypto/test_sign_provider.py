#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for Signature Provider interface."""
from os import path

from spsdk.crypto.signature_provider import SignatureProvider


def test_types():
    types = SignatureProvider.get_types()
    assert types == ["file"]

    class TestSP(SignatureProvider):
        sp_type = "test-typesp-test"

    types = SignatureProvider.get_types()
    assert types == ["file", "test-typesp-test"]


def test_invalid_sp_type():
    provider = SignatureProvider.create("type=totally_legit_provider")
    assert provider is None


def test_plain_file(data_dir):
    my_key_path = path.join(data_dir, "priv.pem").replace("\\", "/")
    provider = SignatureProvider.create(f"type=file;file_path={my_key_path}")

    assert provider.sp_type == "file"
    assert my_key_path in provider.info()

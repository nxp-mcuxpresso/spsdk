#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from spsdk.crypto.miyaguchi_preneel import mp_compress, mp_padding


def test_mp_padding():
    data = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    exp_padding = bytes.fromhex("80000000000000000000000000000100")

    padding = mp_padding(data=data)

    assert len(padding) == len(exp_padding)
    assert padding == exp_padding


def test_mp_compress():
    data = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    exp_compress = bytes.fromhex("c7277a0dc1fb853b5f4d9cbd26be40c6")

    compress = mp_compress(data=data)

    assert len(compress) == len(exp_compress)
    assert compress == exp_compress

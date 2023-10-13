#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from binascii import unhexlify

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash


def test_hash():
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_sha256 = unhexlify("41116FE4EFB90A050AABB83419E19BF2196A0E76AB8E3034C8D674042EE23621")
    calc_sha256 = get_hash(plain_text, EnumHashAlgorithm.SHA256)
    assert calc_sha256 == text_sha256

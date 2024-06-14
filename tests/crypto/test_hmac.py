#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from binascii import unhexlify

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_hmac():
    key = b"12345678"
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_hmac_sha256 = unhexlify("d785d886a750c999aa86802697dd4a9934facac72614cbfa66bbf657b74eb1d5")
    calc_hmac_sha256 = hmac(key, plain_text, EnumHashAlgorithm.SHA256)
    assert calc_hmac_sha256 == text_hmac_sha256


def test_hmac_invalid():
    class TestEnumHashAlgorithm(SpsdkEnum):
        SHA256b = (0, "SHA256b", "SHA256b")

    with pytest.raises(SPSDKError):
        hmac(key=b"1", data=b"t", algorithm=TestEnumHashAlgorithm.SHA256b)

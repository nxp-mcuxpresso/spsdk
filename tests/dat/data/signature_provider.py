#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.crypto import SignatureProvider

class TestSignatureProvider(SignatureProvider):
    sp_type = 'test'

    def __init__(self, param: str) -> None:
        self.param = int(param)

    def info(self) -> str:
        msg = "Test Signature provider"
        msg += f'param: {param}'

    def sign(self, data: bytes) -> bytes:
        return b'x' * self.param

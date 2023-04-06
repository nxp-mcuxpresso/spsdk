#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.crypto.signature_provider import SignatureProvider


class TestSignatureProvider(SignatureProvider):
    sp_type = "test"

    def __init__(self, param: str) -> None:
        self.param = int(param)

    def sign(self, data: bytes) -> bytes:
        return b"x" * self.param

    @property
    def signature_length(self) -> int:
        return self.param

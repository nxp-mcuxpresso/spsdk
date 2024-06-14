#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

pytest.importorskip("spsdk_pqc")

from spsdk.crypto.keys import PrivateKeyDilithium, PublicKeyDilithium


@pytest.mark.parametrize("level", PrivateKeyDilithium.SUPPORTED_LEVELS)
def test_sign_verify(level: int):
    data = b"message to sign"

    prk = PrivateKeyDilithium.generate_key(level=level)
    puk = prk.get_public_key()
    signature = prk.sign(data=data)
    assert len(signature) == prk.signature_size

    assert puk.verify_signature(signature=signature, data=data)

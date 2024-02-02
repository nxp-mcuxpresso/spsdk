#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Test of common crypto utilities module."""
import os

import pytest

from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PrivateKeyRsa
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.crypto.symmetric import Counter
from spsdk.crypto.utils import get_matching_key_id
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import Endianness


def test_counter():
    """Test of Counter."""
    # simple counter with nonce only
    cntr = Counter(bytes([0] * 16))
    assert cntr.value == bytes([0] * 16)

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567, ctr_byteorder_encoding=Endianness.LITTLE)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as big endian
    cntr = Counter(bytes([0] * 16), ctr_value=1, ctr_byteorder_encoding=Endianness.BIG)
    assert cntr.value == bytes([0] * 15 + [1])

    # increment
    cntr.increment()
    assert cntr.value == bytes([0] * 15 + [2])
    cntr.increment(2)
    assert cntr.value == bytes([0] * 15 + [4])
    cntr.increment(256)
    assert cntr.value == bytes([0] * 14 + [1, 4])


@pytest.mark.parametrize("length", [(2048), (3072), (4096)])
def test_matching_keys_rsa(tmpdir, length):
    signature_providers = []
    pub_keys = []
    for i in range(4):
        prv_key = PrivateKeyRsa.generate_key(key_size=length)
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    for i in range(4):
        assert i == get_matching_key_id(
            public_keys=pub_keys, signature_provider=signature_providers[i]
        )


@pytest.mark.parametrize("curve", [(curve_name) for curve_name in EccCurve])
def test_matching_keys_ecc(tmpdir, curve):
    signature_providers = []
    pub_keys = []
    for i in range(4):
        prv_key = PrivateKeyEcc.generate_key(curve_name=curve)
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    for i in range(4):
        assert i == get_matching_key_id(
            public_keys=pub_keys, signature_provider=signature_providers[i]
        )


def test_matching_keys_unmatch(tmpdir):
    signature_providers = []
    pub_keys = []
    for i in range(4):
        prv_key = PrivateKeyRsa.generate_key()
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    prv_key = PrivateKeyRsa.generate_key()
    prv_key.save(os.path.join(tmpdir, "diff_key.pem"))
    with pytest.raises(SPSDKValueError):
        get_matching_key_id(
            public_keys=pub_keys,
            signature_provider=PlainFileSP(os.path.join(tmpdir, "diff_key.pem")),
        )

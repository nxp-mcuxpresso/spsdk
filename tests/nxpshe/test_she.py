#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest
from spsdk.exceptions import SPSDKError
from spsdk.she.she import SHEBootMac, SHEDeriveKey, SHEUpdate
from spsdk.utils.config import Config


def test_she_derive_enc():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    exp_enc = bytes.fromhex("118a46447a770d87828a69c222e2d17e")

    enc = SHEDeriveKey.derive_enc_key(key=key)

    assert enc == exp_enc


def test_she_key_update():
    auth_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    new_key = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    uid = 1
    new_key_id = 4
    auth_key_id = 1
    counter = 1

    exp_m1 = bytes.fromhex("00000000000000000000000000000141")
    exp_m2 = bytes.fromhex("2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3")
    exp_m3 = bytes.fromhex("b9d745e5ace7d41860bc63c2b9f5bb46")
    exp_m4 = bytes.fromhex("00000000000000000000000000000141b472e8d8727d70d57295e74849a27917")
    exp_m5 = bytes.fromhex("820d8d95dc11b4668878160cb2a4e23e")

    updater = SHEUpdate(
        new_key=new_key,
        new_key_id=new_key_id,
        uid=uid,
        auth_key_id=auth_key_id,
        auth_key=auth_key,
        counter=counter,
    )

    m1, m2, m3 = updater.get_messages()
    assert m1 == exp_m1
    assert m2 == exp_m2
    assert m3 == exp_m3

    updater.verify_messages(m4=exp_m4, m5=exp_m5)


def test_calc_boot_mac():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    data = bytes.fromhex("deadbeef")
    mac = SHEBootMac.calculate(key, data)
    assert mac.hex() == "48233ed841e8a70c41e972941f8f9644"


@pytest.mark.parametrize(
    "key_id, auth_key_id, passed",
    [
        ("USER_KEY_1", "USER_KEY_1", True),
        ("USER_KEY_1", "MASTER_ECU_KEY", True),
        ("USER_KEY_1", "BOOT_MAC_KEY", False),
        ("BOOT_MAC", "MASTER_ECU_KEY", True),
        ("BOOT_MAC", "BOOT_MAC_KEY", True),
        ("BOOT_MAC", "USER_KEY_1", False),
    ],
)
def test_auth_key_id(key_id: int, auth_key_id: int, passed: bool):
    cfg = Config(
        {
            "family": "mcxe247",
            "key": "2a71b6517a932c0dfd52f64652ddaea4",
            "key_id": key_id,
            "auth_key": "c311102df1237ce85658bb41818b3f12",
            "auth_key_id": auth_key_id,
        }
    )
    schemas = SHEUpdate.get_validation_schemas_from_cfg(cfg)
    if passed:
        cfg.check(schemas, check_unknown_props=True)
    else:
        with pytest.raises(SPSDKError):
            cfg.check(schemas, check_unknown_props=True)

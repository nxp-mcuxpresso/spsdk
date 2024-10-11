#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.el2go.secure_objects import ElementTag, SecureObject, SecureObjects, TLVElement
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary


def test_tlvelement_parse_length() -> None:
    assert TLVElement.parse_length(b"\x40\x01") == (1, 2)
    assert TLVElement.parse_length(b"\x40\x7F") == (0x7F, 2)
    assert TLVElement.parse_length(b"\x40\x81\xAB") == (0xAB, 3)
    assert TLVElement.parse_length(b"\x40\x82\x01\x00") == (0x100, 4)
    assert TLVElement.parse_length(b"\x40\x83\x01\x00\x00") == (0x10000, 5)


def test_tlvelement_encode_length() -> None:
    assert TLVElement.encode_length(0x7F) == b"\x7F"
    assert TLVElement.encode_length(0x80) == b"\x81\x80"
    assert TLVElement.encode_length(0x100) == b"\x82\x01\x00"
    assert TLVElement.encode_length(0x10000) == b"\x83\x01\x00\x00"


def test_parse_single_object(data_dir: str) -> None:
    data = load_binary(data_dir + "/full_data.bin")
    obj, _ = SecureObject.parse(data)
    assert len(obj) == 129
    assert obj[0].tag == ElementTag.MAGIC
    assert obj[-1].tag == ElementTag.SIGNATURE


def test_parse_whole(data_dir: str) -> None:
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    assert len(objs) == 3
    assert len(objs[0]) == 129


def test_validator_ok(data_dir: str) -> None:
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    validators = SecureObjects._make_validator("max_count=3")
    assert objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("none")
    assert objs._run_validators(validators=validators)


def test_validator_fail(data_dir: str) -> None:
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    validators = SecureObjects._make_validator("max_count=2")
    with pytest.raises(SPSDKError):
        objs._run_validators(validators=validators)


def test_validator_fail2() -> None:
    so = SecureObject()
    so.append(TLVElement(ElementTag.MAGIC, b"edgelock2go"))
    so.append(TLVElement(ElementTag.KEY_BLOB, bytes(1024)))
    so.append(TLVElement(ElementTag.SIGNATURE, bytes(1024)))

    objs = SecureObjects([so for _ in range(20)])

    validators = SecureObjects._make_validator("max_count=16")
    with pytest.raises(SPSDKError, match="Too many"):
        objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("max_so_size=1024;max_count=16")
    with pytest.raises(SPSDKError, match="too big"):
        objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("max_total_size=16384;max_so_size=1024;max_count=16")
    with pytest.raises(SPSDKError, match="Total size"):
        objs._run_validators(validators=validators)

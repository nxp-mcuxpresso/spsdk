#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import copy
import json
import os

import pytest

from spsdk.exceptions import SPSDKLengthError, SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_container import (
    AHABContainer,
    AHABImage,
    Blob,
    Certificate,
    ContainerSignature,
    ImageArrayEntry,
    SignatureBlock,
    SRKRecord,
    SRKTable,
)
from spsdk.utils.misc import use_working_directory


@pytest.fixture
def container_head() -> HeaderContainer:
    return HeaderContainer(tag=0x01, length=0x02, version=0x03)


@pytest.fixture(scope="function")
def srk_record():
    return SRKRecord(
        signing_algorithm="rsa",
        hash_type="sha256",
        key_size=0x05,
        srk_flags=0,
        crypto_param1=bytes.fromhex(5 * "5511"),
        crypto_param2=bytes.fromhex(10 * "aabb"),
    )


@pytest.fixture(scope="function")
def srk_table(request):
    srk_record = request.getfixturevalue("srk_record")
    srk_table = SRKTable(srk_records=[srk_record, srk_record, srk_record, srk_record])
    return srk_table


@pytest.fixture(scope="function")
def container_signature():
    return ContainerSignature(
        signature_data=bytes.fromhex(20 * "11223344"),
    )


@pytest.fixture(scope="function")
def certificate(request):
    srk_record = request.getfixturevalue("srk_record")
    return Certificate(permissions=0x00, uuid=bytes.fromhex(16 * "33"), public_key=srk_record)


@pytest.fixture(scope="function")
def blob():
    return Blob(
        flags=0x80,
        size=0x20,
        wrapped_key=bytes.fromhex(80 * "23"),
    )


@pytest.fixture(scope="function")
def signature_block(request):
    srk_table = request.getfixturevalue("srk_table")
    container_signature = request.getfixturevalue("container_signature")
    certificate = request.getfixturevalue("certificate")
    blob = request.getfixturevalue("blob")

    return SignatureBlock(
        srk_table=srk_table,
        container_signature=container_signature,
        certificate=certificate,
        blob=blob,
    )


@pytest.fixture(scope="function")
def image_entry():
    return ImageArrayEntry(
        image=bytes.fromhex(1024 * "22"),
        image_offset=0x000001F8,
        load_address=0x00000000_00000000,
        entry_point=0x00000000_00000000,
        flags=0x00000003,
        image_meta_data=0x00,
        image_hash=bytes.fromhex(32 * "11" + 32 * "00"),
        image_iv=bytes.fromhex(32 * "55"),
    )


@pytest.fixture(scope="function")
def image_array(request):
    image_entry = request.getfixturevalue("image_entry")

    image_array = []
    image_array.append(image_entry)
    return image_array


@pytest.fixture(scope="function")
def ahab_container(request):
    image_array = request.getfixturevalue("image_array")
    signature_block = request.getfixturevalue("signature_block")
    return AHABContainer(
        flags=0x00000000,
        fuse_version=0x00,
        sw_version=0x0001,
        image_array=image_array,
        signature_block=signature_block,
    )


@pytest.fixture(scope="function")
def ahab_image(request):
    return AHABImage(family="rt1180", ahab_containers=[request.getfixturevalue("ahab_container")])


def test_container_head_compare(container_head):
    """Test of HeaderContainer class compare function."""
    container_head2 = copy.copy(container_head)

    assert container_head2 == container_head
    container_head2.tag = 0
    assert container_head2 != container_head
    assert container_head != 1


def test_container_head_validate(container_head: HeaderContainer):
    """Test of HeaderContainer class validate function."""

    container_head.validate()

    container_head.tag = None
    with pytest.raises(SPSDKValueError):
        container_head.validate()
    container_head.tag = 0x01

    container_head.length = None
    with pytest.raises(SPSDKValueError):
        container_head.validate()
    container_head.length = 0x01

    container_head.version = None
    with pytest.raises(SPSDKValueError):
        container_head.validate()
    container_head.version = 0x01


def test_container_head_fixed_length(container_head: HeaderContainer):
    """Test of HeaderContainer class check input length function."""
    data = bytes(container_head.fixed_length())
    container_head._check_fixed_input_length(data)
    container_head.length += 1
    with pytest.raises(SPSDKLengthError):
        container_head._check_fixed_input_length(bytes(3))


def test_container_head_parse():
    """Test of HeaderContainer class check head parse function."""
    data = b"\x03\x78\x56\x01"
    tag, length, version = HeaderContainer.parse_head(data)
    assert tag == 0x01 and length == 0x5678 and version == 0x03

    with pytest.raises(SPSDKLengthError):
        HeaderContainer.parse_head(b"\x00")


def test_container_head_check_head():
    """Test of HeaderContainer class check head function."""

    class TestHeadContainer(HeaderContainer):
        TAG = 0x01
        VERSION = 0x03

    TestHeadContainer(tag=0x01, length=0x05, version=0x03)._check_container_head(
        b"\x03\x05\x00\x01\x99"
    )

    class TestHeadContainer2(HeaderContainer):
        TAG = [0x01, 0x06]
        VERSION = 0x03

    TestHeadContainer2(tag=0x01, length=0x05, version=0x03)._check_container_head(
        b"\x03\x05\x00\x01\x99"
    )

    head = TestHeadContainer(tag=0x01, length=0x05, version=0x03)

    with pytest.raises(SPSDKParsingError):
        head._check_container_head(b"\x03\x05\x00\x10\x99")

    with pytest.raises(SPSDKParsingError):
        head._check_container_head(b"\x04\x05\x00\x01\x99")

    with pytest.raises(SPSDKLengthError):
        head._check_container_head(b"\x04\x06\x00\x01\x99")

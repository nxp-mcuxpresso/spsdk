#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import copy

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.ele.ele_message import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKLengthError, SPSDKVerificationError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_container import AHABContainer
from spsdk.image.ahab.ahab_sign_block import SignatureBlock
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKTable
from spsdk.image.ahab.ahab_iae import ImageArrayEntry
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.ahab_certificate import AhabCertificate


@pytest.fixture
def container_head() -> HeaderContainer:
    class TestContainerHeader(HeaderContainer):
        TAG = 0x01
        VERSION = 0x03

        def __len__(self) -> int:
            return 2

    return TestContainerHeader(tag=0x01, length=0x02, version=0x03)


@pytest.fixture(scope="function")
def srk_record():
    return SRKRecord(
        signing_algorithm="rsa",
        hash_type=EnumHashAlgorithm.SHA256,
        key_size=0x05,
        srk_flags=0,
        crypto_params=bytes.fromhex(5 * "5511") + bytes.fromhex(10 * "aabb"),
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
    return AhabCertificate(permissions=0x00, uuid=bytes.fromhex(16 * "33"), public_key=srk_record)


@pytest.fixture(scope="function")
def blob():
    return AhabBlob(
        flags=0x80,
        size=0x20,
        dek_keyblob=bytes.fromhex(80 * "23"),
    )


@pytest.fixture(scope="function")
def signature_block(request):
    srk_table = request.getfixturevalue("srk_table")
    container_signature = request.getfixturevalue("container_signature")
    certificate = request.getfixturevalue("certificate")
    blob = request.getfixturevalue("blob")

    return SignatureBlock(
        srk_assets=srk_table,
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
    return AHABImage(
        family="mimxrt1189", ahab_containers=[request.getfixturevalue("ahab_container")]
    )


def test_container_head_compare(container_head):
    """Test of HeaderContainer class compare function."""
    container_head2 = copy.copy(container_head)

    assert container_head2 == container_head
    container_head2.tag = 0
    assert container_head2 != container_head
    assert container_head != 1


def test_container_head_validate(container_head: HeaderContainer):
    """Test of HeaderContainer class validate function."""

    container_head.verify_header().validate()

    container_head.tag = None
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.tag = 0x01

    container_head.length = None
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.length = 0x01

    container_head.version = None
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.version = 0x01


def test_container_head_fixed_length(container_head: HeaderContainer):
    """Test of HeaderContainer class check input length function."""
    data = bytes(container_head.fixed_length())
    container_head._check_fixed_input_length(data).validate()
    container_head.length += 1
    with pytest.raises(SPSDKVerificationError):
        container_head._check_fixed_input_length(bytes(3)).validate()


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

    TestHeadContainer(tag=0x01, length=0x05, version=0x03).check_container_head(
        b"\x03\x05\x00\x01\x99"
    ).validate()

    class TestHeadContainer2(HeaderContainer):
        TAG = [0x01, 0x06]
        VERSION = 0x03

    TestHeadContainer2(tag=0x01, length=0x05, version=0x03).check_container_head(
        b"\x03\x05\x00\x01\x99"
    ).validate()

    head = TestHeadContainer(tag=0x01, length=0x05, version=0x03)

    with pytest.raises(SPSDKVerificationError):
        head.check_container_head(b"\x03\x05\x00\x10\x99").validate()

    with pytest.raises(SPSDKVerificationError):
        head.check_container_head(b"\x04\x05\x00\x01\x99").validate()

    with pytest.raises(SPSDKVerificationError):
        head.check_container_head(b"\x03\x06\x00\x01\x99").validate()


def test_keyblob():
    keyblob = (
        b"\x00H\x00\x81\x01\x10\x03\x00\xfe\xda\x04v\xb3s\xcb\x8bE"
        + b"\xdc\x06(I\x8a\xd3\xe0\xf0\x86\xbf\xdc\xea\xeds-H\xb8"
        + b"\x94v\xe7\xc7\xae\x07\xca\xce;\x93Z\xcd\x0ff\x0c\xec{"
        + b'\xa6KMg\x97\x0e\xb3](]b"\xdd`\x16\xdb\xe5\x94*\x01\xea'
    )
    blob = AhabBlob().parse(keyblob)
    assert blob.algorithm == KeyBlobEncryptionAlgorithm.AES_CBC
    assert blob.mode == 0
    assert blob.flags == 1

    blob.export() == keyblob

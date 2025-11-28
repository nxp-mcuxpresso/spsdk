#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK AHAB container testing module.

This module provides comprehensive test cases for AHAB (Advanced High Assurance Boot)
container functionality, including validation, parsing, and error handling of AHAB
components used in secure boot processes.
"""

import copy
from typing import Any, List, cast

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.ele.ele_message import KeyBlobEncryptionAlgorithm
from spsdk.exceptions import SPSDKLengthError, SPSDKVerificationError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer
from spsdk.image.ahab.ahab_blob import AhabBlob
from spsdk.image.ahab.ahab_certificate import AhabCertificate
from spsdk.image.ahab.ahab_container import AHABContainer
from spsdk.image.ahab.ahab_data import (
    AhabChipContainerConfig,
    AHABSignAlgorithm,
    AHABSignHashAlgorithm,
    create_chip_config,
)
from spsdk.image.ahab.ahab_iae import ImageArrayEntry
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.ahab_sign_block import SignatureBlock
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKTable
from spsdk.utils.family import FamilyRevision


@pytest.fixture
def container_head() -> HeaderContainer:
    """Create test container header instance.

    Creates a test implementation of HeaderContainer with predefined TAG, VERSION,
    and length values for testing purposes.

    :return: Test container header instance with tag=0x01, length=0x02, version=0x03.
    """

    class TestContainerHeader(HeaderContainer):
        """Test container header for AHAB testing purposes.

        This class extends HeaderContainer to provide a concrete implementation
        used in AHAB (Advanced High Assurance Boot) unit tests with predefined
        TAG and VERSION values.

        :cvar TAG: Container tag identifier (0x01).
        :cvar VERSION: Container version identifier (0x03).
        """

        TAG = 0x01
        VERSION = 0x03

        def __len__(self) -> int:
            """Get the length of the object.

            Returns the fixed length value of 2 for this AHAB object.

            :return: The length value as integer (always 2).
            """
            return 2

    return TestContainerHeader(tag=0x01, length=0x02, version=0x03)


@pytest.fixture(scope="function")
def srk_record() -> SRKRecord:
    """Create a test SRK record with predefined values.

    This function creates an SRKRecord instance with fixed test parameters including
    RSA signing algorithm, SHA256 hash type, and predefined crypto parameters.

    :return: SRKRecord instance configured for testing purposes.
    """
    return SRKRecord(
        signing_algorithm=AHABSignAlgorithm.from_label("rsa"),
        hash_type=cast(AHABSignHashAlgorithm, EnumHashAlgorithm.SHA256),
        key_size=0x05,
        srk_flags=0,
        crypto_params=bytes.fromhex(5 * "5511") + bytes.fromhex(10 * "aabb"),
    )


@pytest.fixture(scope="function")
def srk_table(request: Any) -> SRKTable:
    """Create SRK table fixture for testing.

    Creates a test fixture that returns an SRKTable instance populated with four
    identical SRK records for use in AHAB testing scenarios.

    :param request: Pytest fixture request object used to access other fixtures.
    :return: SRKTable instance containing four SRK records.
    """
    srk_record = request.getfixturevalue("srk_record")
    srk_table = SRKTable(srk_records=[srk_record, srk_record, srk_record, srk_record])
    return srk_table


@pytest.fixture(scope="function")
def container_signature() -> ContainerSignature:
    """Create a test container signature instance.

    This function creates a ContainerSignature object with predefined test data
    for use in unit tests and testing scenarios.

    :return: ContainerSignature instance with test signature data.
    """
    return ContainerSignature(
        signature_data=bytes.fromhex(20 * "11223344"),
    )


@pytest.fixture(scope="function")
def certificate(request: Any) -> AhabCertificate:
    """Create AHAB certificate fixture for testing.

    This fixture creates an AhabCertificate instance with predefined test values
    including family revision, permissions, UUID, and SRK record for use in
    AHAB-related unit tests.

    :param request: Pytest request object providing access to test fixtures.
    :return: Configured AhabCertificate instance for testing.
    """
    srk_record = request.getfixturevalue("srk_record")
    return AhabCertificate(
        family=FamilyRevision("mimxrt1189"),
        permissions=0x00,
        uuid=bytes.fromhex(16 * "33"),
        public_key_0=srk_record,
    )


@pytest.fixture(scope="function")
def blob() -> AhabBlob:
    """Create test AHAB blob instance.

    Creates a test AhabBlob object with predefined test values for use in unit tests.
    The blob is configured with standard test flags, size, and a DEK keyblob filled
    with test data.

    :return: AhabBlob instance configured for testing.
    """
    return AhabBlob(
        flags=0x80,
        size=0x20,
        dek_keyblob=bytes.fromhex(80 * "23"),
    )


@pytest.fixture(scope="function")
def signature_block(request: Any) -> SignatureBlock:
    """Create a SignatureBlock fixture for AHAB testing.

    This fixture creates a SignatureBlock instance with all necessary components
    including SRK table, container signature, certificate, and blob for testing
    AHAB (Advanced High Assurance Boot) functionality.

    :param request: Pytest request object providing access to other fixtures.
    :return: Configured SignatureBlock instance for testing.
    """
    srk_table = request.getfixturevalue("srk_table")
    container_signature = request.getfixturevalue("container_signature")
    certificate = request.getfixturevalue("certificate")
    blob = request.getfixturevalue("blob")

    return SignatureBlock(
        chip_config=AhabChipContainerConfig(
            base=create_chip_config(family=FamilyRevision("mimxrt1189"))
        ),
        srk_assets=srk_table,
        container_signature=container_signature,
        certificate=certificate,
        blob=blob,
    )


@pytest.fixture(scope="function")
def image_entry() -> ImageArrayEntry:
    """Create test ImageArrayEntry instance for AHAB testing.

    This method creates a pre-configured ImageArrayEntry object with test data
    suitable for AHAB (Advanced High Assurance Boot) unit testing. The entry
    includes a chip configuration for mimxrt1189 family, dummy image data,
    and various security-related parameters.

    :return: Configured ImageArrayEntry instance with test data for AHAB testing.
    """
    return ImageArrayEntry(
        chip_config=AhabChipContainerConfig(
            base=create_chip_config(family=FamilyRevision("mimxrt1189"))
        ),
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
def image_array(request: Any) -> List[ImageArrayEntry]:
    """Get image array fixture for testing.

    Creates a list containing a single image entry fixture for use in AHAB tests.

    :param request: Pytest request object used to access other fixtures.
    :return: List containing one ImageArrayEntry object for testing purposes.
    """
    image_entry = request.getfixturevalue("image_entry")

    image_array = []
    image_array.append(image_entry)
    return image_array


@pytest.fixture(scope="function")
def ahab_container(request: Any) -> AHABContainer:
    """Create AHAB container fixture for testing.

    This fixture creates an AHABContainer instance with predefined configuration
    for MIMXRT1189 family, including image array and signature block from other fixtures.

    :param request: Pytest request object used to access other fixtures.
    :return: Configured AHABContainer instance for testing.
    """
    image_array = request.getfixturevalue("image_array")
    signature_block = request.getfixturevalue("signature_block")
    return AHABContainer(
        chip_config=create_chip_config(family=FamilyRevision("mimxrt1189")),
        flags=0x00000000,
        fuse_version=0x00,
        sw_version=0x0001,
        image_array=image_array,
        signature_block=signature_block,
    )


@pytest.fixture(scope="function")
def ahab_image(request: Any) -> AHABImage:
    """Create AHAB image fixture for testing.

    This fixture creates an AHABImage instance with a predefined family revision
    and container configuration for use in AHAB-related tests.

    :param request: Pytest request object used to access other fixtures.
    :return: Configured AHABImage instance for testing.
    """
    return AHABImage(
        family=FamilyRevision("mimxrt1189"),
        ahab_containers=[request.getfixturevalue("ahab_container")],
    )


def test_container_head_compare(container_head: HeaderContainer) -> None:
    """Test HeaderContainer class equality comparison functionality.

    Verifies that the HeaderContainer comparison operators work correctly by testing
    equality between identical containers and inequality when container properties
    are modified.

    :param container_head: HeaderContainer instance to test comparison operations on.
    """
    container_head2 = copy.copy(container_head)

    assert container_head2 == container_head
    container_head2.tag = 0
    assert container_head2 != container_head
    assert container_head != 1


def test_container_head_validate(container_head: HeaderContainer) -> None:
    """Test HeaderContainer class validate function.

    This test verifies that the HeaderContainer validation works correctly
    for valid headers and properly raises SPSDKVerificationError when
    header fields are invalid (None tag, zero length, None version).

    :param container_head: HeaderContainer instance to test validation on.
    :raises SPSDKVerificationError: When header validation fails due to invalid fields.
    """

    container_head.verify_header().validate()

    container_head.tag = None  # type: ignore
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.tag = 0x01

    container_head.length = 0
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.length = 0x01

    container_head.version = None  # type: ignore
    with pytest.raises(SPSDKVerificationError):
        container_head.verify_header().validate()
    container_head.version = 0x01


def test_container_head_fixed_length(container_head: HeaderContainer) -> None:
    """Test HeaderContainer fixed input length validation functionality.

    Validates that the HeaderContainer correctly checks input data length against
    its fixed length property. Tests both valid length scenarios and invalid
    length scenarios that should raise verification errors.

    :param container_head: HeaderContainer instance to test length validation on
    :raises SPSDKVerificationError: When input data length doesn't match expected fixed length
    """
    data = bytes(container_head.fixed_length())
    container_head._check_fixed_input_length(data).validate()
    container_head.length += 1
    with pytest.raises(SPSDKVerificationError):
        container_head._check_fixed_input_length(bytes(3)).validate()


def test_container_head_parse() -> None:
    """Test HeaderContainer class head parsing functionality.

    Verifies that the parse_head method correctly extracts tag, length, and version
    from binary data, and properly raises SPSDKLengthError for insufficient data.

    :raises SPSDKLengthError: When input data is too short to parse.
    """
    data = b"\x03\x78\x56\x01"
    tag, length, version = HeaderContainer.parse_head(data)
    assert tag == 0x01 and length == 0x5678 and version == 0x03

    with pytest.raises(SPSDKLengthError):
        HeaderContainer.parse_head(b"\x00")


def test_container_head_check_head() -> None:
    """Test HeaderContainer class check_container_head method functionality.

    This test verifies that the check_container_head method correctly validates
    container headers against expected tag, length, and version values. It tests
    both single tag and multiple tag scenarios, as well as validation failure
    cases for mismatched tag, version, and length values.

    :raises SPSDKVerificationError: When container head validation fails due to
        mismatched tag, version, or length values.
    """

    class TestHeadContainer(HeaderContainer):
        """Test implementation of AHAB Header Container.

        This class extends HeaderContainer to provide a concrete implementation
        for testing AHAB (Advanced High Assurance Boot) container functionality
        with predefined tag and version values.

        :cvar TAG: Container tag identifier for test instances.
        :cvar VERSION: Container version number for test instances.
        """

        TAG = 0x01
        VERSION = 0x03

    TestHeadContainer(tag=0x01, length=0x05, version=0x03).check_container_head(
        b"\x03\x05\x00\x01\x99"
    ).validate()

    class TestHeadContainer2(HeaderContainer):
        """Test header container for AHAB image testing.

        This class extends HeaderContainer to provide a specific test implementation
        with predefined TAG and VERSION values for AHAB (Advanced High Assurance Boot)
        image testing scenarios.

        :cvar TAG: Container tag identifier for test header container.
        :cvar VERSION: Version number for test header container format.
        """

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


def test_keyblob() -> None:
    """Test AHAB key blob parsing and export functionality.

    This test verifies that an AHAB blob can be correctly parsed from binary data
    and that the parsed blob maintains the expected properties (algorithm, mode, flags).
    It also validates that the blob can be exported back to its original binary format.

    :raises AssertionError: If parsed blob properties don't match expected values or export differs from original.
    """
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

    assert blob.export() == keyblob

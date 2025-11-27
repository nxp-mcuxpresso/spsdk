#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Certificate testing module.

This module contains comprehensive unit tests for the HAB (High Assurance Boot)
certificate functionality in SPSDK. It validates certificate initialization,
serialization, parsing, and data integrity operations.
"""

from typing import Any

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.image.hab.hab_certificate import HabCertificate
from spsdk.image.hab.hab_header import Header, SegmentTag


def test_hab_certificate_init(test_certificates: Any) -> None:
    """Test initialization of HabCertificate class.

    Verifies that HabCertificate objects are properly initialized with correct
    default values and custom parameters. Tests both default version (0x40)
    and custom version scenarios, ensuring header attributes are set correctly.

    :param test_certificates: List of test certificate data used for initialization.
    """
    hab_cert = HabCertificate(test_certificates[0])
    assert hab_cert._header.tag == SegmentTag.CRT.tag
    assert hab_cert._header.param == 0x40  # Default version is 0x40 (4.0)
    assert hab_cert.cert == test_certificates[0]

    # Test with custom version
    custom_version = 0x42
    hab_cert = HabCertificate(test_certificates[0], version=custom_version)
    assert hab_cert._header.param == custom_version
    assert hab_cert._header.version_major == 4
    assert hab_cert._header.version_minor == 2


def test_hab_certificate_size_and_len(test_certificates: Any) -> None:
    """Test size property and __len__ method of HabCertificate.

    Verifies that both the size property and __len__ method return the correct
    value, which should be the sum of the header size and the DER-encoded
    certificate size.

    :param test_certificates: List of test certificate objects used for testing.
    """
    hab_cert = HabCertificate(test_certificates[0])
    # Size should be header size + certificate DER size
    expected_size = Header.SIZE + len(test_certificates[0].export(SPSDKEncoding.DER))
    assert hab_cert.size == expected_size
    assert len(hab_cert) == expected_size


def test_hab_certificate_repr_and_str(test_certificates: Any) -> None:
    """Test string representation methods of HabCertificate class.

    Validates that both __repr__ and __str__ methods of HabCertificate produce
    the expected output format with correct version and size information.

    :param test_certificates: Test certificate data used to create HabCertificate instance
    :raises AssertionError: If the string representations don't match expected format
    """
    hab_cert = HabCertificate(test_certificates[0])
    repr_str = repr(hab_cert)
    str_output = str(hab_cert)

    # Check repr format
    assert "Certificate <Ver: 4.0, Size:" in repr_str

    # Check str format
    assert "Certificate (Ver: 4.0, Size:" in str_output
    assert "-" * 60 in str_output


def test_hab_certificate_export(test_certificates: Any) -> None:
    """Test HAB certificate export functionality.

    Validates that the HabCertificate export method correctly generates binary data
    with proper structure including header and certificate content.

    :param test_certificates: List of test certificates used for validation.
    """
    hab_cert = HabCertificate(test_certificates[0])
    exported_data = hab_cert.export()

    # Validate structure
    assert len(exported_data) == hab_cert.size

    # Check header is part of the exported data
    header_data = exported_data[: Header.SIZE]
    parsed_header = Header.parse(header_data, SegmentTag.CRT.tag)
    assert parsed_header.tag == SegmentTag.CRT.tag
    assert parsed_header.param == 0x40
    assert parsed_header.length == len(exported_data)

    # Check certificate data is included
    cert_data = exported_data[Header.SIZE :]
    assert cert_data == test_certificates[0].export(SPSDKEncoding.DER)


def test_hab_certificate_parse(test_certificates: Any) -> None:
    """Test HAB certificate parsing functionality.

    Validates that a HabCertificate can be exported to binary data and then
    parsed back to recreate an equivalent certificate object. Verifies that
    the parsed certificate maintains the same header properties, certificate
    data, and can be re-exported to identical binary data.

    :param test_certificates: List of test certificate objects used for validation.
    """
    # Create certificate and export it
    original_cert = HabCertificate(test_certificates[0])
    exported_data = original_cert.export()

    # Parse the exported data
    parsed_cert = HabCertificate.parse(exported_data)

    # Verify the parsed certificate matches the original
    assert parsed_cert._header.tag == original_cert._header.tag
    assert parsed_cert._header.param == original_cert._header.param
    assert parsed_cert._header.length == original_cert._header.length

    # Verify the certificate data is correctly parsed
    assert parsed_cert.cert.export(SPSDKEncoding.DER) == test_certificates[0].export(
        SPSDKEncoding.DER
    )

    # Verify the re-exported data matches the original
    assert parsed_cert.export() == exported_data


def test_hab_certificate_roundtrip(test_certificates: Any) -> None:
    """Test complete roundtrip: create â export â parse â export.

    Validates that a HAB certificate can be created, exported to binary data,
    parsed back from that data, and exported again with identical results.
    This ensures data integrity throughout the serialization/deserialization cycle.

    :param test_certificates: Test certificate data used for creating the initial HAB certificate.
    """
    original_cert = HabCertificate(test_certificates[0])
    exported_data = original_cert.export()
    parsed_cert = HabCertificate.parse(exported_data)
    re_exported_data = parsed_cert.export()

    assert re_exported_data == exported_data

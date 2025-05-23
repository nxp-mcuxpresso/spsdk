#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os

import pytest
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.image.hab.hab_certificate import HabCertificate
from spsdk.image.hab.hab_header import Header, SegmentTag


def test_hab_certificate_init(test_certificates):
    """Test initialization of HabCertificate."""
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


def test_hab_certificate_size_and_len(test_certificates):
    """Test size property and __len__ method."""
    hab_cert = HabCertificate(test_certificates[0])
    # Size should be header size + certificate DER size
    expected_size = Header.SIZE + len(test_certificates[0].export(SPSDKEncoding.DER))
    assert hab_cert.size == expected_size
    assert len(hab_cert) == expected_size


def test_hab_certificate_repr_and_str(test_certificates):
    """Test string representation methods."""
    hab_cert = HabCertificate(test_certificates[0])
    repr_str = repr(hab_cert)
    str_output = str(hab_cert)

    # Check repr format
    assert "Certificate <Ver: 4.0, Size:" in repr_str

    # Check str format
    assert "Certificate (Ver: 4.0, Size:" in str_output
    assert "-" * 60 in str_output


def test_hab_certificate_export(test_certificates):
    """Test export method."""
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


def test_hab_certificate_parse(test_certificates):
    """Test parse class method."""
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


def test_hab_certificate_roundtrip(test_certificates):
    """Test complete roundtrip: create → export → parse → export."""
    original_cert = HabCertificate(test_certificates[0])
    exported_data = original_cert.export()
    parsed_cert = HabCertificate.parse(exported_data)
    re_exported_data = parsed_cert.export()

    assert re_exported_data == exported_data

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate module unit tests.

This module contains comprehensive unit tests for the SPSDK Certificate class
and related certificate management functionality. Tests cover certificate loading,
parsing, validation, and basic certificate operations to ensure reliable
certificate handling across NXP MCU portfolio.
"""

import os
from datetime import datetime

from spsdk.crypto.certificate import Certificate, SPSDKName


def test_basics(data_dir: str) -> None:
    """Test basic functionality of the Certificate class.

    This test validates core Certificate class features including version detection,
    CA status, self-signed verification, serial number extraction, signature
    algorithm identification, public key hashing, and certificate export functionality.

    :param data_dir: Path to directory containing test certificate files.
    """
    cert = Certificate.load(os.path.join(data_dir, "selfsign_2048_v3.der.crt"))

    #
    assert cert.version.name == "v3"
    #
    assert not cert.ca
    #
    assert cert.self_signed
    #
    assert cert.serial_number == 0x3CC30000BABADEDA
    #
    assert cert.signature_hash_algorithm
    #
    assert cert.signature_hash_algorithm.name == "sha256"
    #
    expected_hash = (
        b"I\xad$\xeb=+\xddR\xa8\xef\x1b\xdf\xcaa-S\x10a\xfc\x13v\xff\xd4\xacVE~\xd0\x83\x80\xa6'"
    )
    assert cert.public_key_hash() == expected_hash
    #
    sign = cert.signature
    assert isinstance(sign, bytes) and len(sign) == 256
    #
    issuer = cert.issuer
    assert isinstance(issuer, SPSDKName) and len(issuer) == 5
    #
    no_before = cert.not_valid_before
    assert (
        isinstance(no_before, datetime)
        and no_before.year == 2019
        and no_before.month == 5
        and no_before.day == 6
    )
    no_after = cert.not_valid_after
    assert (
        isinstance(no_after, datetime)
        and no_after.year == 2039
        and no_after.month == 5
        and no_after.day == 1
    )
    #
    assert cert.raw_size == 1060
    #
    assert str(cert)
    #
    data = cert.export()
    assert isinstance(data, bytes) and len(data) == cert.raw_size

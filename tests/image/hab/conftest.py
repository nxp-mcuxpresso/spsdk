#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB image testing configuration and fixtures.

This module provides pytest configuration and fixtures for testing HAB (High Assurance Boot)
image functionality. It sets up test certificates and cryptographic materials needed
for HAB image testing scenarios.
"""

import os

import pytest

from spsdk.crypto.certificate import Certificate


@pytest.fixture(name="srk_pem")
def srk_pem_func(data_dir: str) -> list[bytes]:
    """Load SRK PEM certificate files for testing.

    Reads four Super Root Key (SRK) PEM certificate files from the specified
    data directory. The files are expected to follow the naming convention
    SRK{1-4}_sha256_4096_65537_v3_ca_crt.pem.

    :param data_dir: Directory path containing the SRK PEM certificate files.
    :raises FileNotFoundError: If any of the required SRK PEM files are not found.
    :raises IOError: If there's an error reading the certificate files.
    :return: List of certificate file contents as bytes, ordered from SRK1 to SRK4.
    """
    srk_pem = []
    for i in range(4):
        srk_pem_file = "SRK{}_sha256_4096_65537_v3_ca_crt.pem".format(i + 1)
        with open(os.path.join(data_dir, srk_pem_file), "rb") as f:
            srk_pem.append(f.read())
    return srk_pem


@pytest.fixture(name="test_certificates")
def test_certificates_fixture(srk_pem: list[bytes]) -> list[Certificate]:
    """Parse PEM certificates into Certificate objects for testing.

    This fixture converts a list of PEM-encoded certificate bytes into
    Certificate objects that can be used in HAB-related tests.

    :param srk_pem: List of PEM-encoded certificate data as bytes.
    :return: List of parsed Certificate objects.
    """
    return [Certificate.parse(cert) for cert in srk_pem]

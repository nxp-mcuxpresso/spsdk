#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK RKHT (Root Key Hash Table) unit tests.

This module contains comprehensive unit tests for RKHT functionality in SPSDK,
covering both RKHTv1 and RKHTv21 implementations used in secure boot processes.
Tests verify RKHT creation from certificates and parsing capabilities.
"""

import os

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.image.cert_block.rkht import RKHTv1, RKHTv21


@pytest.fixture(scope="module")
def certs_and_keys_dir(data_dir: str) -> str:
    """Get path to certificates and keys directory.

    Constructs the absolute path to the certificates and keys subdirectory
    within the provided data directory.

    :param data_dir: Base data directory path.
    :return: Absolute path to the certificates and keys directory.
    """
    return os.path.join(data_dir, "certs_and_keys")


@pytest.mark.parametrize(
    "certificates, hash_table, rotkh",
    [
        (
            [
                "root_k0_signed_cert0_noca.der.cert",
                "root_k1_signed_cert0_noca.der.cert",
                "root_k2_signed_cert0_noca.der.cert",
                "root_k0_signed_cert0_noca.der.cert",
            ],
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627b19fc27184372a3a590548f2d8392089afa413776567ccda213d6c5d27fe378955e7a33bc27454ec5e15b9660938a7b431aa35ae22cfe6857093274f1164d02449ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627",  # pylint: disable=line-too-long
            "46375246bab50ecdd35014b6782f1e81fc4f8a047705f11274031f7297a6ae86",
        ),
        (
            [
                "root_k0_signed_cert0_noca.der.cert",
                "root_k1_signed_cert0_noca.der.cert",
            ],
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627b19fc27184372a3a590548f2d8392089afa413776567ccda213d6c5d27fe378900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # pylint: disable=line-too-long
            "5905022784a39901b0dc0860c9455cd1b83c5336a2e973825759961554664c89",
        ),
        (
            [
                "root_k0_signed_cert0_noca.der.cert",
            ],
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # pylint: disable=line-too-long
            "db31d46c717711a8231cbc38b1de8a6e8657e1f733e04c2ee4b62fcea59149fa",
        ),
    ],
)
def test_rkhtv1_from_keys_cert(
    certs_and_keys_dir: str,  # pylint: disable=redefined-outer-name
    certificates: list[str],
    hash_table: str,
    rotkh: str,
) -> None:
    """Test RKHTv1 creation from certificate files and validate hash table and ROTKH.

    This test loads certificates from files, creates an RKHTv1 instance from them,
    and verifies that the generated hash table and Root of Trust Key Hash (ROTKH)
    match the expected values.

    :param certs_and_keys_dir: Directory path containing certificate files.
    :param certificates: List of certificate filenames to load.
    :param hash_table: Expected hash table as hexadecimal string.
    :param rotkh: Expected Root of Trust Key Hash as hexadecimal string.
    """
    certs = []
    for cert in certificates:
        certificate = Certificate.load(os.path.join(certs_and_keys_dir, cert))
        certs.append(certificate)
    rkht = RKHTv1.from_keys(certs)
    assert rkht.hash_algorithm == EnumHashAlgorithm.SHA256
    assert rkht.export().hex() == hash_table
    assert rkht.rkth().hex() == rotkh


@pytest.mark.parametrize(
    "key_names, hash_table, rotkh, hash_algorithm",
    [
        (
            [
                "ecc_256_r1_0.pub",
                "ecc_256_r1_1.pub",
                "ecc_256_r1_2.pub",
                "ecc_256_r1_3.pub",
            ],
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d389280134e7f483ee31ad1a5a983be80452cb6d64ae1656474f4f81521da2a7628552fc61e8ea7d446d8fec7834aba40a6ddc5cfe834426da751bcf7085853076f",  # pylint: disable=line-too-long
            "e1d7904f1e83517f7055a33bfe63cadfbb575976cde671678ba4c991bbc4005c",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_256_r1_0.pem",
                "ecc_256_r1_1.pem",
                "ecc_256_r1_2.pem",
                "ecc_256_r1_3.pem",
            ],
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d389280134e7f483ee31ad1a5a983be80452cb6d64ae1656474f4f81521da2a7628552fc61e8ea7d446d8fec7834aba40a6ddc5cfe834426da751bcf7085853076f",  # pylint: disable=line-too-long
            "e1d7904f1e83517f7055a33bfe63cadfbb575976cde671678ba4c991bbc4005c",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_256_r1_0.pub",
                "ecc_256_r1_1.pub",
            ],
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d38",  # pylint: disable=line-too-long
            "4ef1933909dac83e1c61b83a82ba8e6a349e2472c10eae30ce750a88a2e6a2c2",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_256_r1_0.pem",
                "ecc_256_r1_1.pem",
            ],
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d38",  # pylint: disable=line-too-long
            "4ef1933909dac83e1c61b83a82ba8e6a349e2472c10eae30ce750a88a2e6a2c2",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_256_r1_0.pub",
            ],
            "",
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a956",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_256_r1_0.pem",
            ],
            "",
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a956",
            EnumHashAlgorithm.SHA256,
        ),
        (
            [
                "ecc_384_r1_0.pub",
                "ecc_384_r1_1.pub",
                "ecc_384_r1_2.pub",
                "ecc_384_r1_3.pub",
            ],
            "632898678aacaaeca777eaf6db3fd6fd1e70442cc1346c2093b10afd7b1a9eb8c3e05bab08131776192077138c46ea5a3bfa3cf0d6b921d3f0bb53b201d78043017fdca2aca6c7336a968604c78bd713da2816d3eb3275e8bc2e084601ed384e6ea6e12b7733d368b7f40f8632d60a587e3742b807a0eb8bef9a99c80a933814df5005ad9682d4a514f9111228abcbce3d8d78eeace3b7c6ab278b7025040b92ccf471fe65ec8c09e6b1ba6ccbeed4f9d8c78c57172c3f0dc276b5a7257a6bc6",  # pylint: disable=line-too-long
            "d2cd7c4ce827fef9365e8b3ecc0da14d29fef0b6f971e2123fe9336e6c212d54c37b643d3d3bef9c15d66107854b5bac",
            EnumHashAlgorithm.SHA384,
        ),
        (
            [
                "ecc_384_r1_0.pub",
                "ecc_384_r1_1.pub",
            ],
            "632898678aacaaeca777eaf6db3fd6fd1e70442cc1346c2093b10afd7b1a9eb8c3e05bab08131776192077138c46ea5a3bfa3cf0d6b921d3f0bb53b201d78043017fdca2aca6c7336a968604c78bd713da2816d3eb3275e8bc2e084601ed384e",  # pylint: disable=line-too-long
            "6070afef25e2b3f7882e0021bf6013c2e5299dbcb78e8bd1bf1d5a7030712e90a58b4b321cc83f47b9542a7467cf9314",
            EnumHashAlgorithm.SHA384,
        ),
        (
            [
                "ecc_384_r1_0.pub",
            ],
            "",
            "632898678aacaaeca777eaf6db3fd6fd1e70442cc1346c2093b10afd7b1a9eb8c3e05bab08131776192077138c46ea5a",
            EnumHashAlgorithm.SHA384,
        ),
    ],
)
def test_rkhtv21_from_keys_cert(
    certs_and_keys_dir: str,  # pylint: disable=redefined-outer-name
    key_names: list[str],
    hash_table: str,
    rotkh: str,
    hash_algorithm: EnumHashAlgorithm,
) -> None:
    """Test RKHTv21 creation from certificate keys.

    Validates that RKHTv21 can be properly created from a list of certificate keys
    and verifies the resulting hash algorithm, exported hash table, and root key
    table hash match expected values.

    :param certs_and_keys_dir: Directory path containing certificate and key files.
    :param key_names: List of key file names to be used for RKHT creation.
    :param hash_table: Expected hexadecimal string representation of the hash table.
    :param rotkh: Expected hexadecimal string representation of the root key table hash.
    :param hash_algorithm: Expected hash algorithm used in the RKHT.
    """
    keys = [os.path.join(certs_and_keys_dir, key_name) for key_name in key_names]
    rkht = RKHTv21.from_keys(keys)
    assert rkht.hash_algorithm == hash_algorithm
    assert rkht.export().hex() == hash_table
    assert rkht.rkth().hex() == rotkh


@pytest.mark.parametrize(
    "hash_table, rotkh",
    [
        (
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627b19fc27184372a3a590548f2d8392089afa413776567ccda213d6c5d27fe378955e7a33bc27454ec5e15b9660938a7b431aa35ae22cfe6857093274f1164d02449ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627",  # pylint: disable=line-too-long
            "46375246bab50ecdd35014b6782f1e81fc4f8a047705f11274031f7297a6ae86",
        ),
        (
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627b19fc27184372a3a590548f2d8392089afa413776567ccda213d6c5d27fe378900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # pylint: disable=line-too-long
            "5905022784a39901b0dc0860c9455cd1b83c5336a2e973825759961554664c89",
        ),
        (
            "49ad24eb3d2bdd52a8ef1bdfca612d531061fc1376ffd4ac56457ed08380a627000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # pylint: disable=line-too-long
            "db31d46c717711a8231cbc38b1de8a6e8657e1f733e04c2ee4b62fcea59149fa",
        ),
    ],
)
def test_rkhtv1_parse_cert(hash_table: str, rotkh: str) -> None:
    """Test parsing of RKHTv1 from hexadecimal hash table data.

    Verifies that RKHTv1 can correctly parse a hash table from hex bytes
    and validates the hash algorithm and root key table hash output.

    :param hash_table: Hexadecimal string representation of the hash table data.
    :param rotkh: Expected hexadecimal string of the root key table hash.
    """
    rkht = RKHTv1.parse(bytes.fromhex(hash_table))
    assert rkht.hash_algorithm == EnumHashAlgorithm.SHA256
    assert rkht.rkth().hex() == rotkh


@pytest.mark.parametrize(
    "hash_table, rotkh, hash_alg",
    [
        (
            "632898678aacaaeca777eaf6db3fd6fd1e70442cc1346c2093b10afd7b1a9eb8c3e05bab08131776192077138c46ea5a3bfa3cf0d6b921d3f0bb53b201d78043017fdca2aca6c7336a968604c78bd713da2816d3eb3275e8bc2e084601ed384e6ea6e12b7733d368b7f40f8632d60a587e3742b807a0eb8bef9a99c80a933814df5005ad9682d4a514f9111228abcbce3d8d78eeace3b7c6ab278b7025040b92ccf471fe65ec8c09e6b1ba6ccbeed4f9d8c78c57172c3f0dc276b5a7257a6bc6",  # pylint: disable=line-too-long
            "d2cd7c4ce827fef9365e8b3ecc0da14d29fef0b6f971e2123fe9336e6c212d54c37b643d3d3bef9c15d66107854b5bac",
            EnumHashAlgorithm.SHA384,
        ),
        (
            "632898678aacaaeca777eaf6db3fd6fd1e70442cc1346c2093b10afd7b1a9eb8c3e05bab08131776192077138c46ea5a3bfa3cf0d6b921d3f0bb53b201d78043017fdca2aca6c7336a968604c78bd713da2816d3eb3275e8bc2e084601ed384e",  # pylint: disable=line-too-long
            "6070afef25e2b3f7882e0021bf6013c2e5299dbcb78e8bd1bf1d5a7030712e90a58b4b321cc83f47b9542a7467cf9314",
            EnumHashAlgorithm.SHA384,
        ),
        (
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d38",  # pylint: disable=line-too-long
            "4ef1933909dac83e1c61b83a82ba8e6a349e2472c10eae30ce750a88a2e6a2c2",
            EnumHashAlgorithm.SHA256,
        ),
        (
            "dba61f744e0656a51c321f121ef7a8c66c45582d264bc462727a8871cbd0a9568babe39e87c7a2307c75538bbe1481316af18429e9ca6ad277eb161725020d389280134e7f483ee31ad1a5a983be80452cb6d64ae1656474f4f81521da2a7628552fc61e8ea7d446d8fec7834aba40a6ddc5cfe834426da751bcf7085853076f",  # pylint: disable=line-too-long
            "e1d7904f1e83517f7055a33bfe63cadfbb575976cde671678ba4c991bbc4005c",
            EnumHashAlgorithm.SHA256,
        ),
    ],
)
def test_rkhtv21_parse_cert(hash_table: str, rotkh: str, hash_alg: EnumHashAlgorithm) -> None:
    """Test parsing of RKHTv21 hash table with specified hash algorithm.

    Verifies that the parsed RKHTv21 object correctly stores the hash algorithm
    and generates the expected root key table hash (RKTH).

    :param hash_table: Hexadecimal string representation of the hash table data.
    :param rotkh: Expected hexadecimal string of the root key table hash.
    :param hash_alg: Hash algorithm enumeration to use for parsing.
    """
    rkht = RKHTv21.parse(bytes.fromhex(hash_table), hash_alg)
    assert rkht.hash_algorithm == hash_alg
    assert rkht.rkth().hex() == rotkh

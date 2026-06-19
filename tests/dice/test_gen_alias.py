#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk/dice/gen_alias.py coverage."""

from pathlib import Path

import pytest

from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
from spsdk.dice.gen_alias import (
    generate_fmc,
    get_mode,
    get_printable_string,
    make_container,
    to_be_bytes,
)
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.config import Config

# ---------------------------------------------------------------------------
# to_be_bytes
# ---------------------------------------------------------------------------


def test_to_be_bytes_auto_length_single_byte() -> None:
    result = to_be_bytes(0xFF)
    assert result == b"\xff"


def test_to_be_bytes_auto_length_two_bytes() -> None:
    result = to_be_bytes(0x0100)
    assert result == b"\x01\x00"


def test_to_be_bytes_explicit_length_pads() -> None:
    result = to_be_bytes(1, length=4)
    assert result == b"\x00\x00\x00\x01"


def test_to_be_bytes_explicit_length_exact() -> None:
    result = to_be_bytes(0xDEADBEEF, length=4)
    assert result == b"\xde\xad\xbe\xef"


def test_to_be_bytes_large_value() -> None:
    result = to_be_bytes(0x01AABBCCDD)
    assert result == b"\x01\xaa\xbb\xcc\xdd"


def test_to_be_bytes_explicit_length_five() -> None:
    result = to_be_bytes(0x0111223344, length=5)
    assert result == b"\x01\x11\x22\x33\x44"


# ---------------------------------------------------------------------------
# get_mode
# ---------------------------------------------------------------------------


def test_get_mode_ecdsa_explicit() -> None:
    config = Config({"mode": "ecdsa"})
    assert get_mode(config) == "ecdsa"


def test_get_mode_mldsa_explicit() -> None:
    config = Config({"mode": "mldsa"})
    assert get_mode(config) == "mldsa"


def test_get_mode_default_is_ecdsa() -> None:
    config = Config({})
    assert get_mode(config) == "ecdsa"


def test_get_mode_invalid_raises() -> None:
    config = Config({"mode": "rsa"})
    with pytest.raises(SPSDKValueError):
        get_mode(config)


def test_get_mode_invalid_empty_string() -> None:
    config = Config({"mode": ""})
    with pytest.raises(SPSDKValueError):
        get_mode(config)


# ---------------------------------------------------------------------------
# get_printable_string
# ---------------------------------------------------------------------------


def test_get_printable_string_tag_is_0x13() -> None:
    result = get_printable_string(b"\x01\x02\x03")
    assert result[0] == 0x13


def test_get_printable_string_length_is_hex_len() -> None:
    data = b"\xab\xcd"
    result = get_printable_string(data)
    expected_hex = data.hex()  # "abcd"
    assert result[1] == len(expected_hex)


def test_get_printable_string_content_is_hex() -> None:
    data = b"\xde\xad"
    result = get_printable_string(data)
    assert result[2:] == data.hex().encode("utf-8")


def test_get_printable_string_empty() -> None:
    result = get_printable_string(b"")
    assert result == bytes([0x13, 0])


def test_get_printable_string_roundtrip() -> None:
    data = b"\x11\x22\x33\x44"
    result = get_printable_string(data)
    # tag + length + hex
    assert len(result) == 2 + len(data) * 2


# ---------------------------------------------------------------------------
# generate_fmc – ECDSA modes
# ---------------------------------------------------------------------------


def test_generate_fmc_basic_ecdsa_no_key(tmp_path: Path) -> None:
    """generate_fmc generates its own key when template_key is absent."""
    config = Config(
        {
            "issuer_name": "TestIssuer",
            "subject_name": "TestSubject",
            "container_output": str(tmp_path / "out.bin"),
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()
    assert (tmp_path / "out.bin").stat().st_size > 0


def test_generate_fmc_with_template_key_and_outputs(tmp_path: Path) -> None:
    key = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP384R1)
    key_path = tmp_path / "key.pem"
    key.save(str(key_path))

    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "template_key": str(key_path),
            "template_output": str(tmp_path / "cert.der"),
            "descriptor_output": str(tmp_path / "desc.bin"),
        }
    )
    generate_fmc(config)

    assert (tmp_path / "out.bin").exists()
    assert (tmp_path / "cert.der").exists()
    assert (tmp_path / "desc.bin").exists()


def test_generate_fmc_include_cust_table(tmp_path: Path) -> None:
    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "include_cust_table": True,
            "cust_svn": 0x01234567,
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()


def test_generate_fmc_include_nxp_table(tmp_path: Path) -> None:
    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "include_nxp_table": True,
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()


def test_generate_fmc_include_both_tables(tmp_path: Path) -> None:
    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "include_cust_table": True,
            "cust_svn": 0x01234567,
            "include_nxp_table": True,
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_generate_fmc_mldsa(tmp_path: Path) -> None:
    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "mode": "mldsa",
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="spsdk-pqc not installed")
def test_generate_fmc_mldsa_with_outputs(tmp_path: Path) -> None:
    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "out.bin"),
            "mode": "mldsa",
            "template_output": str(tmp_path / "cert.der"),
            "descriptor_output": str(tmp_path / "desc.bin"),
        }
    )
    generate_fmc(config)
    assert (tmp_path / "out.bin").exists()
    assert (tmp_path / "cert.der").exists()
    assert (tmp_path / "desc.bin").exists()


# ---------------------------------------------------------------------------
# make_container
# ---------------------------------------------------------------------------


def _create_template_and_descriptor(tmp_path: Path, mode: str = "ecdsa") -> None:
    """Helper: run generate_fmc to produce template + descriptor files."""
    key = PrivateKeyEcc.generate_key(curve_name=EccCurve.SECP384R1)
    key_path = tmp_path / "key.pem"
    key.save(str(key_path))

    config = Config(
        {
            "issuer_name": "Issuer",
            "subject_name": "Subject",
            "container_output": str(tmp_path / "gen_out.bin"),
            "template_key": str(key_path),
            "template_output": str(tmp_path / "cert.der"),
            "descriptor_output": str(tmp_path / "desc.bin"),
            "mode": mode,
        }
    )
    generate_fmc(config)


def test_make_container_ecdsa(tmp_path: Path) -> None:
    _create_template_and_descriptor(tmp_path, "ecdsa")

    config = Config(
        {
            "template_output": str(tmp_path / "cert.der"),
            "descriptor_output": str(tmp_path / "desc.bin"),
            "container_output": str(tmp_path / "container.bin"),
            "mode": "ecdsa",
        }
    )
    make_container(config)
    assert (tmp_path / "container.bin").exists()
    assert (tmp_path / "container.bin").stat().st_size > 0


def test_make_container_mldsa(tmp_path: Path) -> None:
    # For mldsa make_container we still use ecdsa for generating the template
    # (the tag differs, but the binary data structure is the same for the test)
    _create_template_and_descriptor(tmp_path, "ecdsa")

    config = Config(
        {
            "template_output": str(tmp_path / "cert.der"),
            "descriptor_output": str(tmp_path / "desc.bin"),
            "container_output": str(tmp_path / "container.bin"),
            "mode": "mldsa",
        }
    )
    make_container(config)
    assert (tmp_path / "container.bin").exists()

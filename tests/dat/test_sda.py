#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SDA (Secure Debug Access) Authentication module."""

import pytest

from spsdk.dat.sda import SdaAuthentication
from spsdk.exceptions import SPSDKError
from spsdk.utils.family import FamilyRevision
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


@pytest.fixture
def family() -> FamilyRevision:
    """Get family for testing.

    :return: FamilyRevision instance for MCXE31B device.
    """
    return FamilyRevision("mcxe31b")


@pytest.fixture
def debug_probe(sda_ap_registers: dict) -> DebugProbeVirtual:
    """Create virtual debug probe for testing.

    :return: Configured DebugProbeVirtual instance.
    """
    probe = DebugProbeVirtual(DebugProbeVirtual.UNIQUE_SERIAL, options={})
    probe.open()
    probe.connect()
    probe.coresight_ap.update(sda_ap_registers)
    return probe


@pytest.fixture
def sda_ap_registers() -> dict:
    """Setup SDA AP register values for virtual probe.

    :return: Dictionary mapping register addresses to expected values.
    """
    return {
        # IDR register - SDA AP identification
        0x070000FC: 0x001C0040,
        # Challenge registers (KEYCHALn 0x10-0x2C) - 8 x 32-bit words
        0x07000010: 0x0A1264CE,
        0x07000014: 0x372048B9,
        0x07000018: 0xE53CF579,
        0x0700001C: 0xAD1E2B34,
        0x07000020: 0xB51AD9A0,
        0x07000024: 0x9909A877,
        0x07000028: 0x88DB662D,
        0x0700002C: 0xA8C1F94A,
        # UID registers (UID0/UID1 0x70/0x74)
        0x07000070: 0x12345678,  # UID0 (low 32 bits)
        0x07000074: 0x9ABCDEF0,  # UID1 (high 32 bits)
        # Authentication status register (AUTHSTTS 0x00)
        # Bits 30-29 set = APPDBGEN | SYSDBGEN (authentication successful)
        0x07000000: 0x60000000,
    }


@pytest.fixture
def sda_ap_registers_failure() -> dict:
    """Setup SDA AP register values for failed authentication.

    :return: Dictionary mapping register addresses to expected values.
    """
    return {
        # IDR register - SDA AP identification
        0x070000FC: 0x001C0040,
        # Authentication status register (AUTHSTTS 0x00)
        # Bits 30-29 NOT set = authentication failed
        0x07000000: 0x00000000,
    }


def test_sda_verify_ap_success(family: FamilyRevision, debug_probe: DebugProbeVirtual) -> None:
    """Test successful SDA AP verification.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)
    assert sda.verify_sda_ap() is True


def test_sda_verify_ap_failure(family: FamilyRevision, debug_probe: DebugProbeVirtual) -> None:
    """Test SDA AP verification failure with wrong IDR.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    # Setup virtual probe with incorrect IDR
    debug_probe.coresight_ap[0x070000FC] = 0xDEADBEEF

    with pytest.raises(SPSDKError, match="SDA AP verification failed"):
        SdaAuthentication(family=family, debug_probe=debug_probe)


def test_sda_get_challenge(family: FamilyRevision, debug_probe: DebugProbeVirtual) -> None:
    """Test reading authentication challenge from device.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)
    challenge = sda.get_challenge()

    # Verify challenge is 32 bytes (256 bits)
    assert len(challenge) == 32

    # Verify challenge matches expected value (little-endian packed)
    expected = bytes.fromhex("ce64120ab948203779f53ce5342b1eada0d91ab577a809992d66db884af9c1a8")
    assert challenge == expected


def test_sda_get_uid(family: FamilyRevision, debug_probe: DebugProbeVirtual) -> None:
    """Test reading device UID from registers.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)
    uid = sda.get_uid()

    # Verify UID is 8 bytes (64 bits)
    assert len(uid) == 8

    # Verify UID matches expected value
    # UID = (UID1 << 32) | UID0 = (0x9ABCDEF0 << 32) | 0x12345678
    expected = bytes.fromhex("9abcdef012345678")
    assert uid == expected


def test_derive_adkp_invalid_master_key(debug_probe: DebugProbeVirtual) -> None:
    """Test ADKP derivation with invalid master key length.

    Verifies that SPSDKError is raised when master ADKP is not 16 bytes.
    """

    family = FamilyRevision("mcxe31b")
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Invalid master ADKP (wrong length)
    invalid_master_adkp = bytes.fromhex("0102030405060708")  # Only 8 bytes
    uid = bytes.fromhex("9abcdef012345678")

    with pytest.raises(SPSDKError, match="Master ADKP must be 16 bytes"):
        sda.derive_adkp_from_uid(invalid_master_adkp, uid)


def test_derive_adkp_invalid_uid(debug_probe: DebugProbeVirtual) -> None:
    """Test ADKP derivation with invalid UID length.

    Verifies that SPSDKError is raised when UID is not 8 bytes.
    """

    family = FamilyRevision("mcxe31b")
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    master_adkp = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    invalid_uid = bytes.fromhex("12345678")  # Only 4 bytes

    with pytest.raises(SPSDKError, match="UID must be 8 bytes"):
        sda.derive_adkp_from_uid(master_adkp, invalid_uid)


def test_compute_response_aes_ecb(debug_probe: DebugProbeVirtual) -> None:
    """Test AES-ECB response computation."""
    adkp = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    challenge = bytes.fromhex("ce64120ab948203779f53ce5342b1eada0d91ab577a809992d66db884af9c1a8")

    family = FamilyRevision("mcxe31b")
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    result = sda.compute_response_aes_ecb(challenge, adkp)

    # Verify response is 32 bytes (256 bits)
    assert len(result) == 32

    # Expected value from test vector
    expected = bytes.fromhex("c398a01a7cfc03e124cdc48ff64b75ef04e4b00ec31afd38439331035670f40d")
    assert result == expected


def test_compute_response_invalid_challenge(debug_probe: DebugProbeVirtual) -> None:
    """Test response computation with invalid challenge length."""
    family = FamilyRevision("mcxe31b")
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    adkp = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    invalid_challenge = bytes.fromhex("a8858bf694aa0f22")  # Only 8 bytes

    with pytest.raises(SPSDKError, match="Challenge must be 32 bytes"):
        sda.compute_response_aes_ecb(invalid_challenge, adkp)


def test_compute_response_invalid_adkp(debug_probe: DebugProbeVirtual) -> None:
    """Test response computation with invalid ADKP length."""
    family = FamilyRevision("mcxe31b")
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    invalid_adkp = bytes.fromhex("00010203040506070809")  # Only 10 bytes
    challenge = bytes.fromhex("a8858bf694aa0f229f75a493b5db1a8d671bf2327177c05c6a8ee22a5ef57fbe")

    with pytest.raises(SPSDKError, match="ADKP key must be 16 bytes"):
        sda.compute_response_aes_ecb(challenge, invalid_adkp)


def test_write_response_and_authenticate_success(
    family: FamilyRevision, debug_probe: DebugProbeVirtual
) -> None:
    """Test successful response write and authentication.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """

    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Test response (32 bytes)
    response = bytes.fromhex("2caa64e76e07e71a83d1a32f7b8abb98ad81a06d37aa7c134e01b4cf32a4e8a3")

    # Should succeed with authentication status showing success
    sda._write_keyresp_registers(response)
    sda._trigger_authentication_and_verify()

    # Verify AUTHCTL was written
    assert 0x07000004 in debug_probe.coresight_ap
    assert debug_probe.coresight_ap[0x07000004] == 0x00000001  # HSEAUTHREQ bit

    # Verify DBGENCTRL was written
    assert 0x07000080 in debug_probe.coresight_ap
    assert debug_probe.coresight_ap[0x07000080] == 0x10000010  # GDBGEN | CDBGEN


def test_write_response_and_authenticate_failure(
    family: FamilyRevision, debug_probe: DebugProbeVirtual
) -> None:
    """Test authentication failure with incorrect response.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """

    # Set authentication status to failure (bits 30-29 not set)
    debug_probe.coresight_ap[0x07000000] = 0x00000000

    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Test response (32 bytes)
    response = bytes.fromhex("2caa64e76e07e71a83d1a32f7b8abb98ad81a06d37aa7c134e01b4cf32a4e8a3")
    sda._write_keyresp_registers(response)
    # Should fail with authentication error
    with pytest.raises(SPSDKError, match="Checking Assertion of SDA AP AUTHSTTS.APPDBGEN"):
        sda._trigger_authentication_and_verify()


def test_write_response_invalid_length(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
) -> None:
    """Test response write with invalid response length.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Invalid response (wrong length)
    invalid_response = bytes.fromhex("2caa64e76e07e71a")  # Only 8 bytes

    with pytest.raises(SPSDKError, match="Data must be 32 bytes for 8 registers, got 8"):
        sda._write_keyresp_registers(invalid_response)


def test_authenticate_without_diversification(
    family: FamilyRevision, debug_probe: DebugProbeVirtual
) -> None:
    """Test full authentication flow without ADKP diversification.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """

    sda = SdaAuthentication(family=family, debug_probe=debug_probe)
    adkp = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    sda.authenticate_challenge(adkp_key=adkp, use_diversification=False)


def test_authenticate_with_diversification(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
) -> None:
    """Test full authentication flow with ADKP diversification.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)
    master_adkp = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    sda.authenticate_challenge(adkp_key=master_adkp, use_diversification=True)


def test_sda_register_read_write(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
) -> None:
    """Test SDA AP register read/write operations.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    """

    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Test write
    test_value = 0xDEADBEEF
    sda._write_reg(0x04, test_value)  # Write to AUTHCTL

    # Test read
    read_value = sda._read_reg(0x04)
    assert read_value == test_value


def test_authenticate_password_success(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
) -> None:
    """Test successful password-based authentication.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    :param sda_ap_registers_success: SDA AP register values for success.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Test password (16 bytes / 128 bits) - from PE Micro example
    password = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

    # Should succeed without raising exception
    sda.authenticate_password(password)

    # Verify password was written to first 4 KEYRESP registers (0x40-0x4C)
    assert 0x07000040 in debug_probe.coresight_ap  # KEYRESP0
    assert 0x07000044 in debug_probe.coresight_ap  # KEYRESP1
    assert 0x07000048 in debug_probe.coresight_ap  # KEYRESP2
    assert 0x0700004C in debug_probe.coresight_ap  # KEYRESP3

    # Verify AUTHCTL.HSEAUTHREQ was set
    assert 0x07000004 in debug_probe.coresight_ap
    assert debug_probe.coresight_ap[0x07000004] == 0x00000001

    # Verify DBGENCTRL.GDBGEN and DBGENCTRL.CDBGEN were set
    assert 0x07000080 in debug_probe.coresight_ap
    assert debug_probe.coresight_ap[0x07000080] == 0x10000010


def test_authenticate_password_failure_wrong_password(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
    sda_ap_registers_failure: dict,
) -> None:
    """Test password authentication failure with wrong password.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    :param sda_ap_registers_failure: SDA AP register values for failure.
    """
    debug_probe.coresight_ap.update(sda_ap_registers_failure)

    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Wrong password
    password = bytes.fromhex("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")

    # Should fail with authentication error
    with pytest.raises(
        SPSDKError,
        match="Checking Assertion of SDA AP AUTHSTTS.APPDBGEN and AUTHSTTS.SYSDBGEN failed",
    ):
        sda.authenticate_password(password)


def test_authenticate_password_invalid_length_too_short(
    family: FamilyRevision,
    debug_probe: DebugProbeVirtual,
) -> None:
    """Test password authentication with password that is too short.

    :param family: Device family fixture.
    :param debug_probe: Virtual debug probe fixture.
    :param sda_ap_registers_success: SDA AP register values for success.
    """
    sda = SdaAuthentication(family=family, debug_probe=debug_probe)

    # Password too short (8 bytes instead of 16)
    invalid_password = bytes.fromhex("0123456789ABCDEF")

    with pytest.raises(SPSDKError, match="Password must be 16 bytes"):
        sda.authenticate_password(invalid_password)

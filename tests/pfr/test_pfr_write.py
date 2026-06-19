#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for PFR write methods and error paths."""

from unittest.mock import MagicMock

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrError, SPSDKPfrRotkhIsNotPresent
from spsdk.pfr.pfr import CFPA, CMPA, UPDATE_CFPA, UPDATE_CFPA_CMPA
from spsdk.utils.family import FamilyRevision

# Families used across tests
LPC55S6X = FamilyRevision("lpc55s6x")
LPC55S3X = FamilyRevision("lpc55s3x")
MCXA286 = FamilyRevision("mcxa286")


# ---------------------------------------------------------------------------
# compute_rotkh tests
# ---------------------------------------------------------------------------


def test_compute_rotkh_with_precomputed_bytes() -> None:
    """compute_rotkh with pre-computed rotkh bytes should set the register."""
    cmpa = CMPA(LPC55S6X)
    rotkh_bytes = b"\xab" * 32  # 256 bits = 32 bytes
    cmpa.compute_rotkh(rotkh=rotkh_bytes)
    reg = cmpa.registers.find_reg(cmpa.ROTKH_REGISTER)
    assert reg.get_bytes_value() == rotkh_bytes


def test_compute_rotkh_no_input_raises() -> None:
    """compute_rotkh with neither keys nor rotkh should raise SPSDKError."""
    cmpa = CMPA(LPC55S6X)
    with pytest.raises(SPSDKError):
        cmpa.compute_rotkh()


def test_compute_rotkh_register_not_present_raises() -> None:
    """compute_rotkh on a device without ROTKH register should raise SPSDKPfrRotkhIsNotPresent."""
    # CFPA for lpc55s6x has no ROTKH register
    cfpa = CFPA(LPC55S6X)
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.compute_rotkh(rotkh=b"\xab" * 32)


# ---------------------------------------------------------------------------
# get_supported_families tests
# ---------------------------------------------------------------------------


def test_cmpa_get_supported_families_returns_list() -> None:
    """get_supported_families should return a non-empty list of FamilyRevision objects."""
    families = CMPA.get_supported_families()
    assert isinstance(families, list)
    assert len(families) > 0
    assert all(isinstance(f, FamilyRevision) for f in families)


def test_cfpa_get_supported_families_returns_list() -> None:
    """get_supported_families should return list for CFPA class."""
    families = CFPA.get_supported_families()
    assert isinstance(families, list)
    assert len(families) > 0


def test_update_cfpa_cmpa_get_supported_families() -> None:
    """UPDATE_CFPA_CMPA.get_supported_families should include mcxa286."""
    families = UPDATE_CFPA_CMPA.get_supported_families()
    family_names = [f.name for f in families]
    assert "mcxa286" in family_names


# ---------------------------------------------------------------------------
# BaseConfigArea.write_to_device (single region) tests
# ---------------------------------------------------------------------------


def test_write_to_device_single_region_success() -> None:
    """write_to_device should call write_method with correct address and return True on success."""
    cmpa = CMPA(LPC55S6X)
    write_mock = MagicMock(return_value=True)
    result = cmpa.write_to_device(write_mock)
    assert result is True
    write_mock.assert_called_once()
    call_addr, call_data = write_mock.call_args[0]
    assert call_addr == cmpa.write_address
    assert len(call_data) == cmpa.binary_size


def test_write_to_device_single_region_failure() -> None:
    """write_to_device should return False when write_method returns False."""
    cmpa = CMPA(LPC55S6X)
    write_fail = MagicMock(return_value=False)
    result = cmpa.write_to_device(write_fail)
    assert result is False


def test_write_to_device_single_region_cfpa_success() -> None:
    """write_to_device should succeed for CFPA single region."""
    cfpa = CFPA(LPC55S6X)
    write_mock = MagicMock(return_value=True)
    result = cfpa.write_to_device(write_mock)
    assert result is True
    call_addr, call_data = write_mock.call_args[0]
    assert call_addr == cfpa.write_address
    assert len(call_data) == cfpa.binary_size


# ---------------------------------------------------------------------------
# erase_scratch_if_needed tests
# ---------------------------------------------------------------------------


def test_erase_scratch_if_needed_not_required() -> None:
    """erase_scratch_if_needed should not call erase when not required by db."""
    cmpa = CMPA(LPC55S6X)
    erase_mock = MagicMock(return_value=True)
    # lpc55s6x doesn't require scratch erase
    cmpa.erase_scratch_if_needed(erase_mock)
    erase_mock.assert_not_called()


def test_erase_scratch_if_needed_required_success() -> None:
    """erase_scratch_if_needed should call erase_method when required and succeed."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    erase_mock = MagicMock(return_value=True)
    # mcxa286 requires scratch erase
    obj.erase_scratch_if_needed(erase_mock)
    erase_mock.assert_called_once()
    call_addr, call_size = erase_mock.call_args[0]
    assert call_addr == obj.db.get_int(obj.FEATURE, "scratch_page_address")
    assert call_size == obj.db.get_int(obj.FEATURE, "scratch_page_size")


def test_erase_scratch_if_needed_required_failure_raises() -> None:
    """erase_scratch_if_needed should raise SPSDKPfrError when erase_method fails."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    erase_fail = MagicMock(return_value=False)
    with pytest.raises(SPSDKPfrError, match="Failed to erase scratch page"):
        obj.erase_scratch_if_needed(erase_fail)


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea write_to_device (CFPA_CMPA_SPLIT) tests
# ---------------------------------------------------------------------------


def test_write_to_device_cfpa_cmpa_split_success() -> None:
    """write_to_device in CFPA_CMPA_SPLIT mode should write CFPA + CMPA + UPDATE regions."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    assert obj.additional_data_config.type == "CFPA_CMPA_SPLIT"
    write_mock = MagicMock(return_value=True)
    result = obj.write_to_device(write_mock)
    assert result is True
    # Should write at least CFPA and CMPA (and UPDATE if present)
    assert write_mock.call_count >= 2


def test_write_to_device_cfpa_cmpa_split_cfpa_write_fails() -> None:
    """CFPA_CMPA_SPLIT write should return False if CFPA write fails."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cfpa = obj.get_region("CFPA")
    write_mock = MagicMock(side_effect=lambda addr, data: addr != cfpa.write_address)
    result = obj.write_to_device(write_mock)
    assert result is False


def test_write_to_device_cfpa_cmpa_split_cmpa_write_fails() -> None:
    """CFPA_CMPA_SPLIT write should return False if CMPA write fails."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cmpa = obj.get_region("CMPA")
    write_mock = MagicMock(side_effect=lambda addr, data: addr != cmpa.write_address)
    result = obj.write_to_device(write_mock)
    assert result is False


def test_write_to_device_cfpa_cmpa_split_with_additional_data() -> None:
    """CFPA_CMPA_SPLIT write with additional data should write extra AD block."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cfpa = obj.get_region("CFPA")
    cmpa = obj.get_region("CMPA")

    # Set split offset to a non-zero value (e.g. 2 = 64 bytes)
    reg = cmpa.registers.find_reg("BOOT_CFG1")
    bf = reg.find_bitfield("EXT_CMPA_32B_SIZE")
    bf.set_value(2)  # 2 * 32 = 64 bytes

    # Set CFPA additional data
    cfpa.additional_data = b"\xaa" * 16

    write_mock = MagicMock(return_value=True)
    result = obj.write_to_device(write_mock)
    assert result is True
    # Should have written CFPA, CMPA, AD block, UPDATE = 4 calls
    assert write_mock.call_count >= 3


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea write_to_device (CFPA_ONLY) tests
# ---------------------------------------------------------------------------


def test_write_to_device_cfpa_only_no_read_method_raises() -> None:
    """CFPA_ONLY write without read_method should raise SPSDKPfrError."""
    obj = UPDATE_CFPA(MCXA286)
    assert obj.additional_data_config.type == "CFPA_ONLY"
    write_mock = MagicMock(return_value=True)
    with pytest.raises(SPSDKPfrError):
        obj.write_to_device(write_mock, read_method=None)


def test_write_to_device_cfpa_only_success_no_additional_data() -> None:
    """CFPA_ONLY write without additional data should succeed with read_method provided."""
    obj = UPDATE_CFPA(MCXA286)
    write_mock = MagicMock(return_value=True)
    read_mock = MagicMock(return_value=b"\x00" * 512)
    result = obj.write_to_device(write_mock, read_method=read_mock)
    assert result is True
    # Should write CFPA and UPDATE
    assert write_mock.call_count >= 1


def test_write_to_device_cfpa_only_cfpa_write_fails() -> None:
    """CFPA_ONLY write should return False if CFPA write fails."""
    obj = UPDATE_CFPA(MCXA286)
    write_mock = MagicMock(return_value=False)
    read_mock = MagicMock(return_value=b"\x00" * 512)
    result = obj.write_to_device(write_mock, read_method=read_mock)
    assert result is False


# ---------------------------------------------------------------------------
# _build_additional_data_block tests
# ---------------------------------------------------------------------------


def test_build_additional_data_block_cmpa_exceeds_split_offset_raises() -> None:
    """_build_additional_data_block raises SPSDKError if cmpa_ad > split_offset."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cmpa_ad = b"\xaa" * 100  # 100 bytes
    cfpa_ad = b"\xbb" * 16
    split_offset = 64  # only 64 bytes available before CFPA

    with pytest.raises(SPSDKError, match="exceeds"):
        obj._build_additional_data_block(cmpa_ad, cfpa_ad, split_offset)


def test_build_additional_data_block_valid() -> None:
    """_build_additional_data_block returns correctly structured block."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cmpa_ad = b"\xaa" * 32
    cfpa_ad = b"\xbb" * 16
    split_offset = 64

    result = obj._build_additional_data_block(cmpa_ad, cfpa_ad, split_offset)

    assert result[:32] == cmpa_ad
    # Padding between cmpa_ad end and split_offset should be 0xFF
    assert result[32:64] == b"\xff" * 32
    assert result[split_offset : split_offset + 16] == cfpa_ad


# ---------------------------------------------------------------------------
# _extract_split_offset_from_cmpa tests
# ---------------------------------------------------------------------------


def test_extract_split_offset_no_offset_configured_raises() -> None:
    """_extract_split_offset_from_cmpa raises SPSDKError when offset is not configured."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    # Override offset to None to simulate unconfigured state
    obj.additional_data_config.offset = None
    cmpa = obj.get_region("CMPA")

    with pytest.raises(SPSDKError, match="Split offset path not configured"):
        obj._extract_split_offset_from_cmpa(cmpa)


def test_extract_split_offset_valid() -> None:
    """_extract_split_offset_from_cmpa returns correct offset for configured bitfield."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cmpa = obj.get_region("CMPA")

    # Set the bitfield to 3 (= 96 bytes)
    reg = cmpa.registers.find_reg("BOOT_CFG1")
    bf = reg.find_bitfield("EXT_CMPA_32B_SIZE")
    bf.set_value(3)

    offset = obj._extract_split_offset_from_cmpa(cmpa)
    assert offset == 3 * 32  # 96 bytes


# ---------------------------------------------------------------------------
# additional_data setter error path
# ---------------------------------------------------------------------------


def test_additional_data_setter_not_supported_raises() -> None:
    """Setting additional_data on a region that doesn't support it should raise SPSDKPfrError."""
    # lpc55s6x CMPA does not support additional data
    cmpa = CMPA(LPC55S6X)
    assert not cmpa.support_additional_data
    with pytest.raises(SPSDKPfrError, match="not supported"):
        cmpa.additional_data = b"\xaa" * 16


# ---------------------------------------------------------------------------
# MultiRegionBaseConfigArea compute_rotkh tests
# ---------------------------------------------------------------------------


def test_multi_region_compute_rotkh_with_precomputed_bytes() -> None:
    """compute_rotkh on UPDATE_CFPA_CMPA should set rotkh in the CMPA region."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cmpa = obj.get_region("CMPA")
    rotkh_bytes = b"\xcd" * 32
    obj.compute_rotkh(rotkh=rotkh_bytes)
    reg = cmpa.registers.find_reg(cmpa.ROTKH_REGISTER)
    assert reg.get_bytes_value() == rotkh_bytes


def test_multi_region_compute_rotkh_no_rotkh_region_raises() -> None:
    """compute_rotkh on multi-region where no region has ROTKH should raise SPSDKPfrRotkhIsNotPresent."""
    obj = UPDATE_CFPA(MCXA286)
    # UPDATE_CFPA regions are UPDATE + CFPA; neither has ROTKH in mcxa286
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        obj.compute_rotkh(rotkh=b"\xab" * 32)


# ---------------------------------------------------------------------------
# _write_simple failure tests
# ---------------------------------------------------------------------------


def test_write_simple_non_update_region_failure() -> None:
    """_write_simple should return False when a non-UPDATE region write fails."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    cfpa = obj.get_region("CFPA")

    def fail_if_cfpa(addr: int, data: bytes) -> bool:
        return addr != cfpa.write_address

    result = obj._write_simple(MagicMock(side_effect=fail_if_cfpa))
    assert result is False


def test_write_simple_update_region_failure() -> None:
    """_write_simple should return False when the UPDATE region write fails."""
    obj = UPDATE_CFPA_CMPA(MCXA286)
    update = obj.get_region("UPDATE")

    def fail_if_update(addr: int, data: bytes) -> bool:
        return addr != update.write_address

    result = obj._write_simple(MagicMock(side_effect=fail_if_update))
    assert result is False


# ---------------------------------------------------------------------------
# read_from_device tests
# ---------------------------------------------------------------------------


def test_read_from_device_single_region_success() -> None:
    """read_from_device should call read_method with correct address and update registers."""
    cmpa = CMPA(LPC55S6X)
    dummy_data = b"\x00" * cmpa.registers_size
    read_mock = MagicMock(return_value=dummy_data)
    cmpa.read_from_device(read_mock)
    read_mock.assert_called_once_with(cmpa.read_address, cmpa.registers_size)


def test_read_from_device_returns_empty_raises() -> None:
    """read_from_device should raise SPSDKPfrError when read_method returns empty bytes."""
    cmpa = CMPA(LPC55S6X)
    read_empty = MagicMock(return_value=b"")
    with pytest.raises(SPSDKPfrError):
        cmpa.read_from_device(read_empty)


# ---------------------------------------------------------------------------
# parse error path tests
# ---------------------------------------------------------------------------


def test_cmpa_parse_without_family_raises() -> None:
    """CMPA.parse without family parameter should raise SPSDKPfrError."""
    with pytest.raises(SPSDKPfrError, match="family parameter is mandatory"):
        CMPA.parse(b"\x00" * 512, family=None)


def test_multi_region_parse_without_family_raises() -> None:
    """UPDATE_CFPA_CMPA.parse without family parameter should raise SPSDKPfrError."""
    with pytest.raises(SPSDKPfrError, match="family parameter is mandatory"):
        UPDATE_CFPA_CMPA.parse(b"\x00" * 1024, family=None)

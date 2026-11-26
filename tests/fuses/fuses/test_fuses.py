#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Fuses module unit tests.

This module contains comprehensive unit tests for the SPSDK fuses functionality,
covering fuse operations, configuration management, family support validation,
and error handling scenarios.
"""

import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from yaml import safe_load

from spsdk.ele.ele_comm import EleMessageHandler, SPSDKEleMessageError
from spsdk.exceptions import SPSDKAttributeError, SPSDKConnectionError, SPSDKError, SPSDKKeyError
from spsdk.fuses.fuse_registers import FuseRegister
from spsdk.fuses.fuses import (
    BlhostFuseOperator,
    BlhostFuseOperatorLegacy,
    FuseCompareResult,
    FuseCompareStatus,
    FuseOperator,
    Fuses,
    FuseVerifyResult,
    FuseVerifyStatus,
    NxpeleFuseOperator,
    SPSDKFuseOperationFailure,
)
from spsdk.mboot.error_codes import StatusCode
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration
from tests.fuses.fuses.fuses_test_operator import TestFuseOperator
from tests.fuses.fuses.test_fuse_registers import get_reg_from_cfg


def test_get_operator_type() -> None:
    """Test getting operator type from string identifier.

    Verifies that FuseOperator.get_operator_type() correctly returns the appropriate
    operator class for valid identifiers and raises SPSDKKeyError for unknown ones.

    :raises SPSDKKeyError: When an unknown operator type identifier is provided.
    """
    assert FuseOperator.get_operator_type("blhost") == BlhostFuseOperator
    assert FuseOperator.get_operator_type("nxpele") == NxpeleFuseOperator
    with pytest.raises(SPSDKKeyError):
        FuseOperator.get_operator_type("unknown")


def test_get_fuse_script(data_dir: str) -> None:
    """Test fuse script generation for different operators.

    This test verifies that both BlhostFuseOperator and NxpeleFuseOperator
    can generate proper fuse programming scripts with correct commands
    and formatting for a given family revision and fuse configuration.

    :param data_dir: Directory path containing test data files including fuses.json configuration
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, "BOOT_CFG", "SDHC_CFGF1")
    fuse = FuseRegister.create_from_spec(fuse_cfg)
    fuse.set_value(0xA)
    script = BlhostFuseOperator.get_fuse_script(FamilyRevision("mimxrt798s"), fuses=[fuse])
    assert "BLHOST fuses programming script" in script
    assert "efuse-program-once 159 0xA --no-verify" in script
    script = NxpeleFuseOperator.get_fuse_script(FamilyRevision("mimxrt798s"), fuses=[fuse])
    assert "NXPELE fuses programming script" in script
    assert "write-fuse --index 159 --data 0xA" in script


def test_get_supported_families(mock_test_database: Any, data_dir: str) -> None:
    """Test that Fuses.get_supported_families() returns expected family revisions.

    Verifies that the method returns exactly 3 families with correct FamilyRevision
    objects including dev2 family with rev1, rev_test_invalid_computed, and
    rev_test_invalid_flush_func revisions.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    families = Fuses.get_supported_families()
    assert len(families) == 3
    assert families[0] == FamilyRevision("dev2", "rev1")
    assert families[1] == FamilyRevision("dev2", "rev_test_invalid_computed")
    assert families[2] == FamilyRevision("dev2", "rev_test_invalid_flush_func")


def test_initialize_unsupported_family(mock_test_database: Any, data_dir: str) -> None:
    """Test that Fuses initialization raises SPSDKError for unsupported family.

    This test verifies that attempting to initialize the Fuses class with an
    unsupported family revision properly raises an SPSDKError exception.

    :param mock_test_database: Mocked test database fixture.
    :param data_dir: Directory path containing test data files.
    """
    with pytest.raises(SPSDKError):
        Fuses(family=FamilyRevision("dev1"))


def test_fuses_operator(mock_test_database: Any, data_dir: str) -> None:
    """Test fuses operator functionality and validation.

    Tests the fuses operator property getter/setter behavior, including error handling
    for missing operators, validation of operator types, and verification that the
    correct operator type is returned for a given family revision.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKError: When fuse operator is not set or invalid operator is assigned.
    """
    fuses = Fuses(family=FamilyRevision("dev2"))
    with pytest.raises(SPSDKError):
        _ = fuses.fuse_operator
    with pytest.raises(SPSDKError):
        from spsdk.mboot.mcuboot import McuBoot

        mock_mcuboot = McuBoot(interface=None)  # type: ignore
        fuses.fuse_operator = BlhostFuseOperator(mock_mcuboot)
    fuses.fuse_operator = TestFuseOperator()
    assert fuses.fuse_operator_type == TestFuseOperator
    assert Fuses.get_fuse_operator_type(FamilyRevision("dev2")) == TestFuseOperator


def test_fuses_try_read_write_only_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a write-only fuse raises appropriate exception.

    This test verifies that attempting to read a write-only fuse field
    raises SPSDKFuseOperationFailure and that no actions are recorded
    in the operator when the operation fails.

    :param mock_test_database: Mocked test database fixture.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to read write-only fuse.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field200")
    assert operator.actions == []


def test_fuses_try_write_read_only_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test writing to a read-only fuse field.

    Verifies that attempting to write to a read-only fuse field raises the appropriate
    exception and that no actions are performed on the fuse operator.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to write to read-only fuse field.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field204")
    assert operator.actions == []


def test_fuses_read_single(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a single fuse value and verifying register update.

    This test verifies that reading a single fuse field correctly retrieves the value
    from the fuse operator and updates the corresponding register's cached value.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x14: 3})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.registers.get_reg("field204")
    assert register.get_value() == 0
    assert fuses.read_single("field204") == 3
    assert register.get_value() == 3


def test_fuses_read_single_grouped(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a single grouped fuse register.

    This test verifies that reading a single fuse register that spans multiple
    physical fuse addresses works correctly. It sets up a mock fuse operator
    with specific return values and tests that the grouped register value is
    properly assembled from individual fuse reads.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x3: 1, 0x4: 1})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.registers.find_reg("REG_BIG")
    assert register.get_value() == 0
    assert fuses.read_single("REG_BIG") == 0x100000001


def test_fuses_read_all(mock_test_database: Any, data_dir: str) -> None:
    """Test reading all fuses from a mock database.

    This test verifies that the Fuses.read_all() method correctly reads fuse values
    from the operator and populates the fuse registers. It also ensures that fuses
    without proper permissions are not included in the fuse context.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x14: 0x30, 0x400: 3})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    fuses.read_all()
    assert fuses.registers.find_reg("lock0").get_value() == 3
    assert fuses.registers.find_reg("READ_ONLY_REG").get_value() == 0x30


def test_fuses_try_read_locked_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a locked fuse register and verify proper exception handling.

    This test verifies that attempting to read a locked fuse register raises the appropriate
    exception, while also testing the lock register properties and write operations.
    The test uses a mock fuse operator to simulate hardware behavior.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to read a locked fuse register.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 2})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator, cache=False)
    register = fuses.registers.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")
    register.set_value(10)
    fuses.write_single("field208")
    assert len(operator.actions) == 3
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "read"
    assert operator.actions[2].action_type == "write"
    assert operator.actions[2].fuse_index == 0x15
    assert operator.actions[2].value == 10


def test_fuses_try_read_locked_fuse_cache(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a locked fuse register and verify proper exception handling.

    This test verifies that attempting to read a locked fuse register raises the appropriate
    exception, while also testing the lock register properties and write operations.
    The test uses a mock fuse operator to simulate hardware behavior.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to read a locked fuse register.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 2})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.registers.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")
    register.set_value(10)
    fuses.write_single("field208")
    assert len(operator.actions) == 2
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "write"
    assert operator.actions[1].fuse_index == 0x15
    assert operator.actions[1].value == 10


def test_fuses_try_write_locked_fuse_cache(mock_test_database: Any, data_dir: str) -> None:
    """Test writing to a locked fuse register and verify proper exception handling.

    This test verifies that the fuse system correctly prevents write operations
    to locked fuse registers and raises appropriate exceptions. It also tests
    that read operations are handled correctly based on lock status.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to write to locked fuse or read locked fuse.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 1})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.registers.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    fuses.read_single("field208")
    assert len(operator.actions) == 2  # due to reading the lock register
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "read"
    assert operator.actions[1].fuse_index == 0x15
    fuses.clear_cache()
    operator.return_values[0x400] = 3  # lock the read and write
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")


def test_fuses_try_write_locked_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test writing to a locked fuse register and verify proper exception handling.

    This test verifies that the fuse system correctly prevents write operations
    to locked fuse registers and raises appropriate exceptions. It also tests
    that read operations are handled correctly based on lock status.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to write to locked fuse or read locked fuse.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 1})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator, cache=False)
    register = fuses.registers.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    fuses.read_single("field208")
    assert len(operator.actions) == 3  # due to reading the lock register
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "read"
    assert operator.actions[2].action_type == "read"
    assert operator.actions[2].fuse_index == 0x15
    operator.return_values[0x400] = 3  # lock the read and write
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")


def test_fuses_template(mock_test_database: Any, data_dir: str) -> None:
    """Test fuses configuration template generation functionality.

    This test verifies that the Fuses class can generate a proper configuration
    template for a given family revision and that the template contains the
    expected structure and values.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    fuses = Fuses(family=FamilyRevision("dev2"))
    template = fuses.get_config_template(FamilyRevision("dev2"))
    template_dict = safe_load(template)
    assert template_dict["family"] == "dev2"
    assert template_dict["revision"] == "latest"
    assert template_dict["registers"]


def test_fuses_load_config(mock_test_database: Any, data_dir: str) -> None:
    """Test loading fuses configuration from YAML file.

    Validates that fuses can be properly loaded from a configuration file and that
    the loaded fuse registers contain the expected values. Tests the complete flow
    of configuration loading and fuse register initialization.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test configuration files.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    assert isinstance(fuses, Fuses)
    reg = fuses.registers.find_reg("REG1")
    assert reg.get_value() == 0x300
    reg = fuses.registers.find_reg("REG2")
    assert reg.get_value() == 0x85
    reg = fuses.registers.find_reg("LOCK0")
    assert reg.get_value() == 0x1
    assert len([f for f in fuses if f.loaded_from_config]) == 3


def test_blhost_get_fuse_write_cmd_variants() -> None:
    """Test BlhostFuseOperator.get_fuse_write_cmd renders verify and lock options."""
    assert (
        BlhostFuseOperator.get_fuse_write_cmd(10, 0x20, lock=False, verify=False)
        == "efuse-program-once 10 0x20 --no-verify"
    )
    assert (
        BlhostFuseOperator.get_fuse_write_cmd(10, 0x20, lock=True, verify=True)
        == "efuse-program-once 10 0x20 --verify lock"
    )


def test_get_fuse_script_missing_otp_index_raises(data_dir: str) -> None:
    """Test get_fuse_script raises when a fuse has no OTP index.

    :param data_dir: Directory path containing test data files.
    :raises SPSDKAttributeError: When the OTP index is not defined for a fuse.
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, "BOOT_CFG", "SDHC_CFGF1")
    fuse = FuseRegister.create_from_spec(fuse_cfg)
    fuse.otp_index = None
    for operator in (BlhostFuseOperator, BlhostFuseOperatorLegacy):
        with pytest.raises(SPSDKAttributeError):
            operator.get_fuse_script(FamilyRevision("mimxrt798s"), fuses=[fuse])


def test_blhost_read_fuse_success_and_failure() -> None:
    """Test BlhostFuseOperator.read_fuse returns a value or raises on failure.

    :raises SPSDKFuseOperationFailure: When the underlying read returns None.
    """
    mboot = MagicMock()
    mboot.is_opened = False
    mboot.efuse_read_once.return_value = 0x1234
    operator = BlhostFuseOperator(mboot)
    assert operator.read_fuse(5, 32) == 0x1234
    mboot.open.assert_called_once()
    mboot.close.assert_called_once()

    mboot.efuse_read_once.return_value = None
    mboot.status_code = StatusCode.OCOTP_READ_FAILURE.tag
    with pytest.raises(SPSDKFuseOperationFailure):
        operator.read_fuse(5, 32)

    # No response from the device is a communication error
    mboot.status_code = StatusCode.NO_RESPONSE.tag
    with pytest.raises(SPSDKConnectionError):
        operator.read_fuse(5, 32)


def test_blhost_legacy_read_fuse_no_response() -> None:
    """Test BlhostFuseOperatorLegacy.read_fuse maps no response to a connection error."""
    mboot = MagicMock()
    mboot.is_opened = True
    mboot.fuse_read.return_value = None
    mboot.status_code = StatusCode.NO_RESPONSE.tag
    operator = BlhostFuseOperatorLegacy(mboot)
    with pytest.raises(SPSDKConnectionError):
        operator.read_fuse(5, 32)

    mboot.status_code = StatusCode.FAIL.tag
    with pytest.raises(SPSDKFuseOperationFailure):
        operator.read_fuse(5, 32)


def test_nxpele_read_fuse_errors() -> None:
    """Test NxpeleFuseOperator.read_fuse error mapping."""
    handler = MagicMock(spec=EleMessageHandler)
    operator = NxpeleFuseOperator(handler)

    handler.send_message.side_effect = SPSDKError("ELE Communication failed with mBoot: x")
    with pytest.raises(SPSDKConnectionError):
        operator.read_fuse(5, 32)

    handler.send_message.side_effect = SPSDKEleMessageError(
        "ELE Message failed", status=0xFF, indication=0x10
    )
    with pytest.raises(SPSDKEleMessageError):
        operator.read_fuse(5, 32)


def test_blhost_write_fuse_success_failure_and_lock() -> None:
    """Test BlhostFuseOperator.write_fuse handles lock, success and failure paths.

    :raises SPSDKFuseOperationFailure: When the underlying program returns a falsy value.
    """
    mboot = MagicMock()
    mboot.is_opened = True
    mboot.efuse_program_once.return_value = True
    operator = BlhostFuseOperator(mboot)
    operator.write_fuse(7, 0x55, 32, lock=True)
    # Lock sets bit 24 in the index.
    mboot.efuse_program_once.assert_called_once_with(7 | (1 << 24), 0x55)

    mboot.efuse_program_once.return_value = False
    with pytest.raises(SPSDKFuseOperationFailure):
        operator.write_fuse(7, 0x55, 32)


@pytest.mark.parametrize(
    "fuse_name,bitfields",
    [
        ("BOOT_CFG4", {"XSPI_NAND_FREQ": (0, 3), "XSPI_PAGES_PER_BLOCK": (4, 2)}),
        ("BOOT_CFG5", {"USDHC0_RST_POLARITY": (3, 1), "MMC_FAST_BOOT_ACK_EN": (15, 1)}),
        ("BOOT_CFG6", {"DLL_DELAY_CALIB_START": (0, 7), "DLL_DELAY_CALIB_STEP": (12, 2)}),
        ("BOOT_CFG7", {"LLC_CACHE_EN": (7, 1)}),
        (
            "BOOT_CFG8",
            {
                "2ND_IMG_OFFSET": (0, 6),
                "WDOG_TIMEOUT_SEL": (8, 3),
                "XMC_CRC32_CHECK_EN": (12, 1),
                "XMC_DISABLE": (13, 1),
                "WDOG_EN": (15, 1),
            },
        ),
    ],
)
def test_rt2662_boot_cfg_bitfields(fuse_name: str, bitfields: dict[str, tuple[int, int]]) -> None:
    """Test that RT2660 BOOT_CFG fuse words expose the bitfields from the reference manual.

    :param fuse_name: Name of the fuse word.
    :param bitfields: Expected bitfield names mapped to (offset, width).
    """
    fuses = Fuses(family=FamilyRevision("mimxrt2662"))
    reg = fuses.registers.find_reg(fuse_name)
    assert reg.width == 16
    for name, (offset, width) in bitfields.items():
        bitfield = reg.find_bitfield(name)
        assert (bitfield.offset, bitfield.width) == (offset, width)


def test_rt2662_boot_cfg8_xmc_crc32_check_en() -> None:
    """Test that XMC_CRC32_CHECK_EN maps to BOOT_CFG8 bit 12 on RT2660."""
    fuses = Fuses(family=FamilyRevision("mimxrt2662"))
    reg = fuses.registers.find_reg("BOOT_CFG8")
    reg.find_bitfield("XMC_CRC32_CHECK_EN").set_enum_value("ENABLED")
    assert reg.get_value() == 1 << 12


def test_verify_loaded_all_match(mock_test_database: Any, data_dir: str) -> None:
    """Test Fuses.verify_loaded() reports PASS when all values match.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    # LOCK0 otp_index=0x400, REG1 otp_index=0x0, REG2 otp_index=0x1,
    # REG_INVERTED_AP (antipole of REG1) otp_index=0x2
    operator = TestFuseOperator(return_values={0x400: 0x1, 0x0: 0x300, 0x1: 0x85, 0x2: 0xFFFFFCFF})
    fuses.fuse_operator = operator

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.PASS
    assert len(report.records) == 4
    names = {record.name for record in report.records}
    assert names == {"LOCK0", "REG1", "REG2", "REG_INVERTED_AP"}
    for record in report.records:
        assert record.result == FuseVerifyResult.MATCH
        assert record.actual == record.expected
        assert record.reason is None


def test_verify_loaded_ignores_unconfigured_bitfields(mock_test_database: Any) -> None:
    """Test that bits not defined in the configuration do not cause a MISMATCH.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    cfg = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"REG2": {"BITFIELD 1": "0x5", "BITFIELD 4": "RUN"}},
        }
    )
    fuses = Fuses.load_from_config(cfg)
    # Configured bits match (0x85), unconfigured BITFIELD 5 (bit 8) is set on device.
    fuses.fuse_operator = TestFuseOperator(return_values={0x1: 0x185})

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.PASS
    record = report.records[0]
    assert record.result == FuseVerifyResult.MATCH
    assert record.mask == "0x008F"
    assert record.actual == "0x0185"
    assert "mask: '0x008F'" in report.get_report_yaml()

    # A difference in a configured bitfield is still reported.
    fuses = Fuses.load_from_config(cfg)
    fuses.fuse_operator = TestFuseOperator(return_values={0x1: 0x105})
    report = fuses.verify_loaded()
    assert report.status == FuseVerifyStatus.FAIL
    assert report.records[0].result == FuseVerifyResult.MISMATCH
    assert "0x008F" in str(report.records[0].reason)


def test_verify_loaded_whole_register_value(mock_test_database: Any) -> None:
    """Test that a register defined by a whole value is compared completely.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    cfg = Config({"family": "dev2", "revision": "latest", "registers": {"REG2": "0x85"}})
    fuses = Fuses.load_from_config(cfg)
    fuses.fuse_operator = TestFuseOperator(return_values={0x1: 0x185})

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.FAIL
    assert report.records[0].mask is None
    assert "mask" not in report.get_config()["fuses"]["REG2"]


def test_verify_loaded_antipole_mismatch(mock_test_database: Any, data_dir: str) -> None:
    """Test that a wrong antipole register value is detected.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    fuses.fuse_operator = TestFuseOperator(return_values={0x400: 0x1, 0x0: 0x300, 0x1: 0x85})

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.FAIL
    record = next(record for record in report.records if record.name == "REG_INVERTED_AP")
    assert record.result == FuseVerifyResult.MISMATCH
    assert record.expected == "0xFFFFFCFF"
    assert record.actual == "0x00000000"


def test_verify_loaded_expected_values_captured_before_read(mock_test_database: Any) -> None:
    """Test that expected values are not overwritten by reading other fuses.

    Reading a fuse first reads its lock fuse, which overwrites the local lock fuse
    value. The expected lock value must be captured before any read happens.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    cfg = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"REG2": "0x85", "LOCK0": "0x00000001"},
        }
    )
    fuses = Fuses.load_from_config(cfg)
    # Device has LOCK0 = 0, so LOCK0 must be reported as MISMATCH
    fuses.fuse_operator = TestFuseOperator(return_values={0x1: 0x85, 0x400: 0x0})

    report = fuses.verify_loaded()

    lock_record = next(record for record in report.records if record.name == "LOCK0")
    assert lock_record.expected == "0x00000001"
    assert lock_record.actual == "0x00000000"
    assert lock_record.result == FuseVerifyResult.MISMATCH


def test_verify_loaded_mismatch(mock_test_database: Any, data_dir: str) -> None:
    """Test Fuses.verify_loaded() reports FAIL when at least one value mismatches.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    # REG1 expected value is 0x300, simulate a device value of 0x301 (mismatch).
    operator = TestFuseOperator(return_values={0x400: 0x1, 0x0: 0x301, 0x1: 0x85, 0x2: 0xFFFFFCFF})
    fuses.fuse_operator = operator

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.FAIL
    reg1_record = next(record for record in report.records if record.name == "REG1")
    assert reg1_record.result == FuseVerifyResult.MISMATCH
    assert reg1_record.expected == "0x00000300"
    assert reg1_record.actual == "0x00000301"
    assert reg1_record.reason is not None
    # Other fuses still match.
    for record in report.records:
        if record.name != "REG1":
            assert record.result == FuseVerifyResult.MATCH


def test_verify_loaded_not_verifiable(mock_test_database: Any, data_dir: str) -> None:
    """Test Fuses.verify_loaded() reports PARTIAL for unreadable fuses.

    A write-only fuse cannot be read back from the device, so it must be
    reported as NOT_VERIFIABLE with a non-empty reason, and the overall
    status must be PARTIAL (since there is no MISMATCH).

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    write_only_reg = fuses.registers.find_reg("WRITE_ONLY_REG")
    write_only_reg.set_value(0x1234)
    write_only_reg.loaded_from_config = True

    report = fuses.verify_loaded()

    assert report.status == FuseVerifyStatus.PARTIAL
    assert len(report.records) == 1
    record = report.records[0]
    assert record.name == "WRITE_ONLY_REG"
    assert record.result == FuseVerifyResult.NOT_VERIFIABLE
    assert record.actual is None
    assert record.reason

    # The unreadable fuse has no actual value, so the key is omitted from the report
    # (no artificial "null" string), while the reason is present.
    record_cfg = report.get_config()["fuses"]["WRITE_ONLY_REG"]
    assert "actual" not in record_cfg
    assert record_cfg["reason"]
    report_yaml = report.get_report_yaml()
    assert "null" not in report_yaml


def test_verify_loaded_force_reads_not_verifiable_fuse(
    mock_test_database: Any, data_dir: str
) -> None:
    """Test Fuses.verify_loaded(force=True) reads otherwise unreadable fuses.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x13: 0x1234})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    write_only_reg = fuses.registers.find_reg("WRITE_ONLY_REG")
    write_only_reg.set_value(0x1234)
    write_only_reg.loaded_from_config = True

    report = fuses.verify_loaded(force=True)

    record = report.records[0]
    # Reading was forced, so the value is actually read from the device
    # (otp_index 0x13), and it matches the configured expected value.
    assert record.result == FuseVerifyResult.MATCH
    assert record.actual == "0x00001234"


def test_verify_loaded_no_loaded_registers(mock_test_database: Any, data_dir: str) -> None:
    """Test Fuses.verify_loaded() returns an empty PASS report when nothing was loaded.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)

    report = fuses.verify_loaded()

    assert report.records == []
    assert report.status == FuseVerifyStatus.PASS


def test_compare_configs_semantically_identical(mock_test_database: Any) -> None:
    """Test semantic comparison ignores ordering and value formatting.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    old_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {
                "REG1": {
                    "BITFIELD1": "ENABLED",
                    "BITFIELD2": "DISABLED",
                }
            },
        }
    )
    new_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {
                "REG1": {
                    "BITFIELD2": 0,
                    "BITFIELD1": 1,
                }
            },
        }
    )

    report = Fuses.compare_configs(old_config, new_config)

    assert report.status == FuseCompareStatus.IDENTICAL
    assert report.records == []


def test_compare_configs_field_difference(mock_test_database: Any) -> None:
    """Test semantic comparison reports only a differing bitfield.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    old_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"REG1": {"BITFIELD1": "DISABLED", "BITFIELD2": "DISABLED"}},
        }
    )
    new_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"REG1": {"BITFIELD1": "DISABLED", "BITFIELD2": "ENABLED"}},
        }
    )

    report = Fuses.compare_configs(old_config, new_config)

    assert report.status == FuseCompareStatus.DIFFERENT
    assert len(report.records) == 1
    record = report.records[0]
    assert record.name == "REG1.BITFIELD2"
    assert record.old == "DISABLED"
    assert record.new == "ENABLED"
    assert record.result == FuseCompareResult.DIFFERENT
    assert "REG1.BITFIELD1" not in report.get_report_yaml()


def test_compare_configs_not_verifiable(mock_test_database: Any) -> None:
    """Test write-only fields are classified as NOT_VERIFIABLE.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    old_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"WRITE_ONLY_REG": "0x1234"},
        }
    )
    new_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"WRITE_ONLY_REG": "0x5678"},
        }
    )

    report = Fuses.compare_configs(old_config, new_config)

    assert report.status == FuseCompareStatus.PARTIAL
    assert len(report.records) == 1
    assert report.records[0].result == FuseCompareResult.NOT_VERIFIABLE
    assert report.records[0].old == "0x00001234"
    assert report.records[0].new == "0x00005678"


def test_compare_configs_ignores_configured_read_lock(mock_test_database: Any) -> None:
    """Test that read locks derived from configured lock fuses do not affect comparison.

    LOCK0 value 0x2 sets the read lock of REGISTER_LOCKED. The register is still
    readable by its static access rights, so values are compared normally.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    old_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"LOCK0": "0x2", "REGISTER_LOCKED": "0x1"},
        }
    )
    new_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"LOCK0": "0x2", "REGISTER_LOCKED": "0x2"},
        }
    )

    report = Fuses.compare_configs(old_config, new_config)

    assert report.status == FuseCompareStatus.DIFFERENT
    assert len(report.records) == 1
    assert report.records[0].name == "REGISTER_LOCKED"
    assert report.records[0].result == FuseCompareResult.DIFFERENT


def test_compare_configs_missing_field(mock_test_database: Any) -> None:
    """Test a field present in only one configuration is reported as different.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    old_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {"REG1": {"BITFIELD1": "ENABLED"}},
        }
    )
    new_config = Config(
        {
            "family": "dev2",
            "revision": "latest",
            "registers": {},
        }
    )

    report = Fuses.compare_configs(old_config, new_config)

    assert report.status == FuseCompareStatus.DIFFERENT
    assert len(report.records) == 1
    assert report.records[0].name == "REG1.BITFIELD1"
    assert report.records[0].old == "ENABLED"
    assert report.records[0].new is None
    record_cfg = report.get_config()["fields"]["REG1.BITFIELD1"]
    assert "new" not in record_cfg
    assert "null" not in report.get_report_yaml()

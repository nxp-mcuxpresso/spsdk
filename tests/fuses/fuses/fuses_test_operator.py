#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Fuse testing utilities and operators.

This module provides test implementations and utilities for fuse operations
in SPSDK testing context. It includes mock operators and action tracking
for validating fuse programming and reading functionality.
"""

from dataclasses import dataclass
from typing import Optional

from spsdk.fuses.fuse_registers import FuseRegister, FuseRegisters
from spsdk.fuses.fuses import FuseOperator
from spsdk.utils.family import FamilyRevision


@dataclass
class FuseAction:
    """SPSDK Fuse Action Representation.

    This class represents a single fuse operation action that can be performed
    on NXP MCU fuses, encapsulating the action type, target fuse index, and
    optional value for write operations.
    """

    action_type: str
    fuse_index: int
    value: Optional[int] = None


class TestFuseOperator(FuseOperator):
    """Test fuse operator for SPSDK fuse operations.

    This class provides a mock implementation of FuseOperator for testing purposes,
    allowing simulation of fuse read and write operations without actual hardware
    interaction. It records all operations for verification and supports predefined
    return values for controlled testing scenarios.

    :cvar NAME: Identifier name for the test operator.
    """

    __test__ = False

    NAME = "test_operator"

    def __init__(self, return_values: Optional[dict] = None):
        """Initialize the test operator for fuse operations.

        Creates a new instance of the fuse test operator with an empty list of actions
        and optional return values for mocking purposes.

        :param return_values: Optional dictionary containing predefined return values for test scenarios.
        """
        self.actions: list[FuseAction] = []
        self.return_values = return_values or {}

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the test operator.

        Records the read action and returns the corresponding value from the return_values dictionary.

        :param index: Index of the fuse to read.
        :param length: Length of the fuse in bits.
        :return: Fuse value if found in return_values, otherwise 0.
        """
        self.actions.append(FuseAction(action_type="read", fuse_index=index))
        return self.return_values.get(index, 0)

    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a fuse value and record the operation.

        This method simulates writing a value to a fuse at the specified index and records
        the action for testing purposes. The written value is stored in return_values
        and the operation is logged in the actions list.

        :param index: The fuse index to write to.
        :param value: The value to write to the fuse.
        :param length: The length of the fuse data in bits.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        """
        self.return_values[index] = value
        self.actions.append(FuseAction(action_type="write", fuse_index=index, value=value))

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Generate fuse programming script for given family and fuse registers.

        Creates a script containing fuse write commands for all fuse registers that have
        a valid OTP index. Fuse registers without an OTP index are skipped.

        :param family: Target MCU family and revision information.
        :param fuses: List of fuse register objects to include in the script.
        :return: Generated fuse programming script as a string.
        """
        ret = ""
        for fuse in fuses:
            otp_index = fuse.otp_index
            if otp_index is not None:
                ret += cls.get_fuse_write_cmd(otp_index, fuse.get_value())
        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Generate fuse write command string.

        Creates a command string for writing a value to a specific fuse index.

        :param index: Fuse index to write to.
        :param value: Value to write to the fuse.
        :param lock: Whether to lock the fuse after writing.
        :param verify: Whether to verify the write operation.
        :return: Formatted fuse write command string.
        """
        return f"write {index} {value}"


class TestBlhostFuseOperator(FuseOperator):
    """Test implementation of FuseOperator for unit testing and validation.

    This class provides a mock implementation of the FuseOperator interface that records
    all fuse operations in memory for test verification. It simulates fuse read/write
    operations without actual hardware interaction, making it suitable for automated
    testing of fuse-related functionality.

    :cvar NAME: Operator identifier set to "blhost".
    :cvar ACTIONS: List of recorded fuse actions for test verification.
    :cvar RETURN_VALUES: Dictionary storing simulated fuse values by index.
    """

    __test__ = False

    NAME = "blhost"
    ACTIONS: list[FuseAction] = []
    RETURN_VALUES: dict = {}

    def __init__(self, family: FamilyRevision):
        """Initialize the fuses test operator.

        Creates a new fuses test operator instance for the specified MCU family
        and initializes the fuse registers for that family.

        :param family: The MCU family and revision to operate on.
        """
        self.family = family
        self.registers = FuseRegisters(self.family)

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value from the test operator.

        The method records the read action and returns either a predefined return value
        or the reset value from the corresponding register.

        :param index: Index of the fuse to read.
        :param length: Length of fuse in bits.
        :return: Fuse value as integer.
        """
        self.ACTIONS.append(FuseAction(action_type="read", fuse_index=index))
        return (
            self.RETURN_VALUES.get(index)
            or self.registers.get_by_otp_index(index).get_reset_value()
        )

    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        """Write a fuse value to the test operator's memory.

        This method simulates writing a fuse value by storing it in the RETURN_VALUES
        dictionary and recording the action in the ACTIONS list for test verification.

        :param index: The fuse index to write to.
        :param value: The value to write to the fuse.
        :param length: The length of the fuse data in bits.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        """
        self.RETURN_VALUES[index] = value
        self.ACTIONS.append(FuseAction(action_type="write", fuse_index=index, value=value))

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Generate fuse programming script for given family and fuse registers.

        This method creates a script containing fuse write commands for all fuse registers
        that have a valid OTP index. Only fuses with non-None OTP index values are included
        in the generated script.

        :param family: Target MCU family and revision information.
        :param fuses: List of fuse register objects to include in the script.
        :return: Generated fuse programming script as a string.
        """
        ret = ""
        for fuse in fuses:
            otp_index = fuse.otp_index
            if otp_index is not None:
                ret += cls.get_fuse_write_cmd(otp_index, fuse.get_value())
        return ret

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        """Generate fuse write command string.

        Creates a command string for writing a value to a specific fuse index.

        :param index: The fuse index to write to.
        :param value: The value to write to the fuse.
        :param lock: Whether to lock the fuse after writing, defaults to False.
        :param verify: Whether to verify the write operation, defaults to False.
        :return: Command string in format "write {index} {value}".
        """
        return f"write {index} {value}"

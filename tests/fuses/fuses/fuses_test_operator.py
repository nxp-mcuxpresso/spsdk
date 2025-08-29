#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from dataclasses import dataclass
from typing import Optional
from spsdk.fuses.fuse_registers import FuseRegister, FuseRegisters
from spsdk.fuses.fuses import FuseOperator
from spsdk.utils.family import FamilyRevision


@dataclass
class FuseAction:
    action_type: str
    fuse_index: int
    value: int = None


class TestFuseOperator(FuseOperator):
    """Test fuse operator."""

    __test__ = False

    NAME = "test_operator"

    def __init__(self, return_values: Optional[dict] = None):
        self.actions: list[FuseAction] = []
        self.return_values = return_values or {}

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value.

        :param index: Index of a fuse
        :param length: Length of fuse in bits
        :return: Fuse value
        """
        self.actions.append(FuseAction(action_type="read", fuse_index=index))
        return self.return_values.get(index, 0)

    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        self.return_values[index] = value
        self.actions.append(FuseAction(action_type="write", fuse_index=index, value=value))

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Get fuses script."""
        ret = ""
        for fuse in fuses:
            ret += cls.get_fuse_write_cmd(fuse.otp_index, fuse.get_value())

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        return f"write {index} {value}"


class TestBlhostFuseOperator(FuseOperator):
    """Test blhost fuse operator using class attributes."""

    __test__ = False

    NAME = "blhost"
    ACTIONS: list[FuseAction] = []
    RETURN_VALUES: dict = {}

    def __init__(self, family: FamilyRevision):
        self.family = family
        self.registers = FuseRegisters(self.family)

    def read_fuse(self, index: int, length: int) -> int:
        """Read a single fuse value.

        :param index: Index of a fuse
        :param length: Length of fuse in bits
        :return: Fuse value
        """
        self.ACTIONS.append(FuseAction(action_type="read", fuse_index=index))
        return (
            self.RETURN_VALUES.get(index)
            or self.registers.get_by_otp_index(index).get_reset_value()
        )

    def write_fuse(self, index: int, value: int, length: int, lock: bool = False) -> None:
        self.RETURN_VALUES[index] = value
        self.ACTIONS.append(FuseAction(action_type="write", fuse_index=index, value=value))

    @classmethod
    def get_fuse_script(cls, family: FamilyRevision, fuses: list[FuseRegister]) -> str:
        """Get fuses script."""
        ret = ""
        for fuse in fuses:
            ret += cls.get_fuse_write_cmd(fuse.otp_index, fuse.get_value())

    @classmethod
    def get_fuse_write_cmd(
        cls, index: int, value: int, lock: bool = False, verify: bool = False
    ) -> str:
        return f"write {index} {value}"

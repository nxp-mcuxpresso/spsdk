#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK shadow registers management for Debug Authentication Tool (DAT).

This module provides functionality for controlling and managing shadow registers
that enable debug access through the Debug Authentication Tool. It includes
register manipulation, debug enablement, and verification capabilities.
"""

import logging

from spsdk.fuses.fuse_registers import FuseRegisters
from spsdk.fuses.fuses import Fuses
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import deprecated

logger = logging.getLogger(__name__)


class ShadowRegisters(Fuses):
    """SPSDK Shadow Registers Manager.

    This class provides control and management of shadow registers for NXP MCU devices.
    Shadow registers are temporary storage locations that mirror fuse values and can be
    modified without permanently altering the actual fuses, enabling safe testing and
    configuration validation.

    :cvar FEATURE: Database feature identifier for shadow registers operations.
    """

    FEATURE = DatabaseManager.SHADOW_REGS

    @classmethod
    def get_init_regs(cls, family: FamilyRevision) -> FuseRegisters:
        """Initialize the shadow registers from whole fuse list.

        Creates a FuseRegisters object containing only registers that support shadow registers,
        with computed fields and antipole registers properly configured and hidden.

        :param family: Family of device to be loaded.
        :return: Register class with loaded just fuses that supports shadow registers.
        """
        regs = super().get_init_regs(family)
        # keep only registers with shadow register address
        regs._registers = [reg for reg in regs._registers if reg.shadow_register_offset is not None]
        # same computed register hooks are feature dependent
        for reg in regs:
            reg.shadow_mode = True
        return regs

    @deprecated("Use 'read_all' instead. The method will be removed in next major release")
    def reload_registers(self) -> None:
        """Reload all the values in managed registers.

        This method iterates through all registers in the managed collection and
        refreshes their values by calling get_register for each one.
        """
        self.read_all()

    @deprecated("Use 'write_loaded' instead. The method will be removed in next major release")
    def set_loaded_registers(self, verify: bool = True) -> None:
        """Update shadow registers in target using their local values.

        This method iterates through all loaded registers and writes their current local values
        to the target device using the set_register method.

        :param verify: Verify write operation after setting each register.
        :raises SPSDKError: If register write operation fails.
        """
        self.write_loaded()

    @deprecated(
        "Use 'create_fuse_script' instead. The method will be removed in next major release"
    )
    def create_fuse_blhost_script(self, reg_list: list[str]) -> str:
        """Create BLHOST script to burn fuses.

        The method generates a script file that can be used with BLHOST tool to program
        fuses on the target device. It processes the register list, handles antipole
        registers, and creates appropriate efuse-program-once commands for each register.

        :param reg_list: List of register names to be burned to fuses.
        :raises SPSDKError: Register not found for the target device family.
        :return: Content of BLHOST script file as string.
        """
        return self.create_fuse_script(reg_list)

    @deprecated("Use 'write_single' instead. The method will be removed in next major release")
    def set_register(self, reg_name: str, data: int, verify: bool = True, raw: bool = True) -> None:
        """Set the value of the specified shadow register.

        Writes data to a shadow register on the target device through the debug probe.
        Supports both individual registers and group registers with sub-registers.

        :param reg_name: The register name to write to.
        :param data: The new data to be stored to shadow register.
        :param verify: Verify write operation after completion.
        :param raw: Do not use any modification hooks during value setting.
        :raises SPSDKDebugProbeError: The debug probe is not specified.
        :raises SPSDKError: General error with write of shadow register or register not found.
        :raises SPSDKVerificationError: Verification of written data failed.
        """
        self.set_value(reg_name, data, raw)
        self.write_single(reg_name, verify=verify)

    @deprecated("Use 'read_single' instead. The method will be removed in next major release")
    def get_register(self, reg_name: str, force: bool = False) -> bytes:
        """Get shadow register value from device.

        Reads the shadow register value from the connected device using the debug probe.
        For group registers, reads all sub-registers and combines their values.

        :param reg_name: The register name to read.
        :param force: Force read even when the fuse is marked as non-readable
        :raises SPSDKError: Register not found, invalid configuration, or read operation failed.
        :raises SPSDKDebugProbeError: Debug probe is not specified or communication failed.
        :return: The value of requested register in bytes.
        """
        self.read_single(reg_name, force=force)
        reg = self.registers.find_reg(reg_name, include_group_regs=True)
        return reg.get_bytes_value(raw=True)

    @deprecated("Use 'write_all' instead. The method will be removed in next major release")
    def set_all_registers(self, verify: bool = True) -> None:
        """Update all shadow registers in target using their local values.

        This method iterates through all registers and writes their current local values
        to the target device using the set_register method.

        :param verify: Verify write operation after setting each register.
        """
        self.write_all(verify)

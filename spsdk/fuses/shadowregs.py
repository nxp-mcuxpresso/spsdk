#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK shadow registers management for Debug Authentication Tool (DAT).

This module provides functionality for controlling and managing shadow registers
that enable debug access through the Debug Authentication Tool. It includes
register manipulation, debug enablement, and verification capabilities.
"""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk import __version__
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import StartDebugSession
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError
from spsdk.debuggers.utils import test_ahb_access
from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.fuses.fuse_registers import FuseRegister, FuseRegisters
from spsdk.utils.abstract_features import FeatureBaseClassComm
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import SPSDKRegsErrorRegisterNotFound

logger = logging.getLogger(__name__)


class ShadowRegisters(FeatureBaseClassComm):
    """SPSDK Shadow Registers Manager.

    This class provides control and management of shadow registers for NXP MCU devices.
    Shadow registers are temporary storage locations that mirror fuse values and can be
    modified without permanently altering the actual fuses, enabling safe testing and
    configuration validation.

    :cvar FEATURE: Database feature identifier for shadow registers operations.
    """

    FEATURE = DatabaseManager.SHADOW_REGS

    def __init__(
        self,
        family: FamilyRevision,
        debug_probe: Optional[DebugProbe] = None,
    ) -> None:
        """Initialize Shadow register class.

        Creates a new instance of the Shadow register class with the specified family
        and optional debug probe for fuse and shadow register operations.

        :param family: Target MCU family and revision information.
        :param debug_probe: Optional debug probe interface for hardware communication.
        """
        self.probe = debug_probe
        self.family = family
        self.db = get_db(family)
        self.family.revision = self.db.name
        self.offset_for_write = self.db.get_int(
            DatabaseManager.SHADOW_REGS, "write_address_offset", 0
        )

        self.fuse_mode = False
        self.registers = self._get_init_registers(self.family)
        self.computed_fields: dict[str, dict[str, str]] = self.db.get_dict(
            DatabaseManager.SHADOW_REGS, "computed_fields", {}
        )
        self.antipole_regs: dict[str, str] = self.db.get_dict(
            DatabaseManager.SHADOW_REGS, "inverted_regs", {}
        )
        self.possible_verification = self.db.get_bool(
            DatabaseManager.SHADOW_REGS, "possible_verification", True
        )
        # keep the separate, so we can distinguish the loaded registers
        self._loaded_registers: list[FuseRegister] = []

    def __repr__(self) -> str:
        """Get string representation of shadow registers.

        Returns a formatted string showing the family name for which these shadow registers are configured.

        :return: String representation in format "Shadow Registers for {family}".
        """
        return f"Shadow Registers for {self.family}"

    def __str__(self) -> str:
        """Get string representation of shadow register class.

        Returns a detailed string representation that includes both the object
        representation and the registers information.

        :return: String representation of the shadow register class.
        """
        ret = self.__repr__()
        ret += "\n" + str(self.registers)
        return ret

    @staticmethod
    def _get_init_registers(family: FamilyRevision) -> FuseRegisters:
        """Initialize the shadow registers from whole fuse list.

        Creates a FuseRegisters object containing only registers that support shadow registers,
        with computed fields and antipole registers properly configured and hidden.

        :param family: Family of device to be loaded.
        :return: Register class with loaded just fuses that supports shadow registers.
        """
        db = get_db(family)
        computed_fields: dict[str, dict[str, str]] = db.get_dict(
            DatabaseManager.SHADOW_REGS, "computed_fields", {}
        )
        antipole_regs: dict[str, str] = db.get_dict(
            DatabaseManager.SHADOW_REGS, "inverted_regs", {}
        )
        regs = FuseRegisters(
            family=family,
            base_endianness=Endianness.BIG,
        )
        regs_to_remove = []
        for reg in regs._registers:
            if reg.shadow_register_offset is None:
                regs_to_remove.append(reg.name)
        for reg_name in regs_to_remove:
            regs.remove_register(reg_name)

        # Set the computed field handler
        for computed_reg, fields in computed_fields.items():
            reg_obj = regs.get_reg(computed_reg)
            for bitfield in fields.keys():
                reg_obj.get_bitfield(bitfield).reserved = True
                logger.debug(f"Hiding bitfield: {bitfield} in {computed_reg}")

        # Set the antipolize handler
        for antipole_reg in antipole_regs.values():
            regs.get_reg(antipole_reg).reserved = True
            logger.debug(f"Hiding anti pole register: {antipole_reg}")

        return regs

    def _write_shadow_reg(self, addr: int, data: int, verify_mask: int = 0) -> None:
        """Write shadow register data to MCU.

        Writes shadow register data into MCU and optionally verifies the write operation
        by reading back the value and comparing it against the written data using the
        provided verify mask.

        :param addr: Shadow register address to write to.
        :param data: Shadow register data value to write.
        :param verify_mask: Bit mask for read-back verification, if 0 verification is disabled.
        :raises SPSDKDebugProbeError: When debug probe is not defined.
        :raises SPSDKVerificationError: When verification fails after write operation.
        """
        if not self.probe:
            raise SPSDKDebugProbeError(
                "Shadow registers: Cannot use the communication function without defined debug probe."
            )

        logger.info(f"Writing shadow register address: {hex(addr)}, data: {hex(data)}")
        write_address = (
            addr + self.offset_for_write
        )  # some device has different write address then read
        self.probe.mem_reg_write(write_address, data)

        if verify_mask and self.possible_verification:
            read_back = self.probe.mem_reg_read(addr)
            if (read_back & verify_mask) != (data & verify_mask):
                raise SPSDKVerificationError(
                    f"Written value: 0x{(data & verify_mask):08X}, read value: 0x{(read_back & verify_mask):08X}"
                )

    def reload_registers(self) -> None:
        """Reload all the values in managed registers.

        This method iterates through all registers in the managed collection and
        refreshes their values by calling get_register for each one.
        """
        for reg in self.registers._registers:
            self.get_register(reg.name)

    def set_all_registers(self, verify: bool = True) -> None:
        """Update all shadow registers in target using their local values.

        This method iterates through all registers and writes their current local values
        to the target device using the set_register method.

        :param verify: Verify write operation after setting each register.
        """
        for reg in self.registers._registers:
            self.set_register(reg.name, reg.get_value(raw=True), verify)

    def set_loaded_registers(self, verify: bool = True) -> None:
        """Update shadow registers in target using their local values.

        This method iterates through all loaded registers and writes their current local values
        to the target device using the set_register method.

        :param verify: Verify write operation after setting each register.
        :raises SPSDKError: If register write operation fails.
        """
        for reg in self._loaded_registers:
            self.set_register(reg.name, reg.get_value(raw=True), verify)

    def set_register(self, reg_name: str, data: Any, verify: bool = True, raw: bool = True) -> None:
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

        def write_reg(reg: FuseRegister) -> None:
            """Write fuse register to device shadow register.

            Writes the register value to the corresponding shadow register address on the device
            through the debug probe. Performs verification if enabled and handles register width
            validation.

            :param reg: Fuse register to write to device shadow register.
            :raises SPSDKDebugProbeError: Debug probe is not defined.
            :raises SPSDKError: Register width exceeds 32 bits or shadow register address not defined.
            :raises SPSDKVerificationError: Verification of written data failed.
            """
            if not self.probe:
                raise SPSDKDebugProbeError(
                    "Shadow registers: Cannot use the communication function without defined debug probe."
                )

            if reg.width > 32:
                raise SPSDKError(
                    f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to write to device."
                )
            # Create verify mask
            verify_mask = 0
            if verify:
                bitfields = reg.get_bitfields()
                if bitfields:
                    for bitfield in bitfields:
                        verify_mask = verify_mask | (((1 << bitfield.width) - 1) << bitfield.offset)
                else:
                    verify_mask = (1 << reg.width) - 1
            if reg.shadow_register_addr is None:
                raise SPSDKError(
                    f"Register {reg.name} does not have shadow register address defined"
                )
            try:
                self._write_shadow_reg(
                    addr=reg.shadow_register_addr,
                    data=reg.get_value(raw=True),
                    verify_mask=verify_mask,
                )
            except SPSDKVerificationError as e:
                raise SPSDKVerificationError(
                    f"Verification on register {reg.name} failed: {e}."
                    "Maybe a READ LOCK is set for that register."
                ) from e

        try:
            reg = self.registers.find_reg(reg_name, include_group_regs=True)
            reg.set_value(data, raw)
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    write_reg(sub_reg)
            else:
                write_reg(reg)
            # execute flash function handler if defined for a platform
            self.flush_func_handler()
        except SPSDKError as exc:
            raise SPSDKError(f"The set shadow register failed({str(exc)}).") from exc

    def get_register(self, reg_name: str) -> bytes:
        """Get shadow register value from device.

        Reads the shadow register value from the connected device using the debug probe.
        For group registers, reads all sub-registers and combines their values.

        :param reg_name: The register name to read.
        :raises SPSDKError: Register not found, invalid configuration, or read operation failed.
        :raises SPSDKDebugProbeError: Debug probe is not specified or communication failed.
        :return: The value of requested register in bytes.
        """

        def read_reg(reg: FuseRegister) -> None:
            """Read shadow register value from device and update the register.

            This method reads the current value from the device's shadow register
            and updates the provided FuseRegister object with the read value.

            :param reg: Fuse register to read shadow value for.
            :raises SPSDKError: Shadow register address not set or invalid register width.
            :raises SPSDKDebugProbeError: Debug probe not available for communication.
            """
            if not reg.shadow_register_addr:
                raise SPSDKError(f"Shadow register value is not set for register {reg.name}")
            if not self.probe:
                raise SPSDKDebugProbeError(
                    "Shadow registers: Cannot use the communication function without defined debug probe."
                )
            if reg.width > 32:
                raise SPSDKError(
                    f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to read from device."
                )
            reg.set_value(self.probe.mem_reg_read(reg.shadow_register_addr), raw=True)

        try:
            reg = self.registers.find_reg(reg_name, include_group_regs=True)

            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    read_reg(sub_reg)
            else:
                read_reg(reg)
            return reg.get_bytes_value(raw=True)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).") from exc

    def create_fuse_blhost_script(self, reg_list: list[str]) -> str:
        """Create BLHOST script to burn fuses.

        The method generates a script file that can be used with BLHOST tool to program
        fuses on the target device. It processes the register list, handles antipole
        registers, and creates appropriate efuse-program-once commands for each register.

        :param reg_list: List of register names to be burned to fuses.
        :raises SPSDKError: Register not found for the target device family.
        :return: Content of BLHOST script file as string.
        """

        def add_reg(reg: FuseRegister) -> str:
            """Generate fuse programming command for a register.

            Creates an efuse-program-once command string that can be used to burn
            the specified fuse register to OTP memory.

            :param reg: Fuse register to generate programming command for.
            :raises SPSDKError: If the OTP index is not a valid integer.
            :return: Command string for programming the fuse register.
            """
            otp_index = reg.otp_index
            if not isinstance(otp_index, int):
                raise SPSDKError(f"{otp_index} of {reg} is not a number")
            otp_value = "0x" + reg.get_bytes_value(raw=True).hex()
            burn_fuse = f"# Fuse {reg.name}, index {otp_index} and value: {otp_value}.\n"
            burn_fuse += f"efuse-program-once {hex(otp_index)} {otp_value}\n"
            return burn_fuse

        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {__version__}\n"
            f"# Chip: {self.family}\n\n\n"
        )
        # Update list by antipole opposites registers
        for ap_reg_src, ap_reg_dst in self.antipole_regs.items():
            if ap_reg_src in reg_list:
                reg_list.insert(reg_list.index(ap_reg_src) + 1, ap_reg_dst)
        self.fuse_mode = True
        for reg_name in reg_list:
            try:
                reg = self.registers.find_reg(reg_name, True)
                # do recalculation based on fuse mode sets to ON!
                reg.set_value(reg.get_value())
            except SPSDKRegsErrorRegisterNotFound as exc:
                self.fuse_mode = False
                raise SPSDKError(
                    f"Register {reg_name} has not found for {self.family} device."
                ) from exc

            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    ret += add_reg(sub_reg)
            else:
                ret += add_reg(reg)

        self.fuse_mode = False
        return ret

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema for shadow registers.

        The method builds validation schemas by combining family-specific schema with
        shadow registers schema, updating the registers properties based on the
        provided family configuration.

        :param family: Family description containing chip family and revision information.
        :raises SPSDKError: Family is not supported or schema generation fails.
        :return: List of validation schemas containing family and shadow registers schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.SHADOW_REGS)
        sch_family: dict[str, Any] = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        try:
            regs = cls._get_init_registers(family)
            sch_cfg["sr_registers"]["properties"]["registers"][
                "properties"
            ] = regs.get_validation_schema()["properties"]
            return [sch_family, sch_cfg["sr_registers"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    @classmethod
    def load_from_config(cls, config: Config, debug_probe: Optional[DebugProbe] = None) -> Self:
        """Load shadow registers configuration from config object.

        Creates a new shadow registers instance with the specified family and debug probe,
        then loads register values from the configuration. Automatically computes missing
        bitfields for registers with computed fields and handles antipole register pairs.

        :param config: Configuration object containing shadow registers settings.
        :param debug_probe: Optional debug probe interface for hardware communication.
        :return: Configured shadow registers instance with loaded register values.
        """
        family = FamilyRevision.load_from_config(config)
        sr = cls(family=family, debug_probe=debug_probe)
        cfg = config.get_config("registers")
        sr.registers.load_from_config(cfg)
        sr._loaded_registers = [
            sr.registers.find_reg(reg_name, include_group_regs=True) for reg_name in cfg.keys()
        ]
        # Updates necessary register values
        for reg_uid, bitfields_rec in sr.computed_fields.items():
            reg_name = sr.registers.get_reg(reg_uid).name
            if reg_name in cfg:
                reg = sr.registers.get_reg(reg_uid)
                for bitfield_uid, method in bitfields_rec.items():
                    bitfield_name = reg.get_bitfield(bitfield_uid).name
                    if isinstance(cfg[reg_name], dict) and bitfield_name not in cfg[reg_name]:
                        sr.compute_register(reg, method)
                        log_msg = (
                            f"The {reg_name} register has been recomputed, because "
                            f"it has been used in configuration and the bitfield {bitfield_name} "
                            "has not been specified"
                        )
                        logger.debug(log_msg)

        # Update also antipole registers if needed
        for src_uid, dst_uid in sr.antipole_regs.items():
            src_reg = sr.registers.get_reg(src_uid)
            dst_reg = sr.registers.get_reg(dst_uid)
            if src_reg.name in cfg and dst_reg.name not in cfg:
                sr.antipolize_register(src_reg, dst_reg)
                log_msg = (
                    f"The {src_reg.name} register has been used to compute antipole value, and it "
                    f"has been used in {dst_reg.name}."
                )
                logger.debug(log_msg)
                sr._loaded_registers.append(dst_reg)

        logger.debug("The shadow registers has been loaded from configuration.")
        return sr

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Create configuration for shadow registers.

        The method generates a configuration object containing family information and register data.
        Optionally filters to include only modified registers when diff mode is enabled.

        :param data_path: Path to store the data files of configuration.
        :param diff: If set, only changed registers will be placed in configuration.
        :return: Configuration object with family and register information.
        """
        ret = Config({"family": self.family.name, "revision": self.family.revision})
        ret["registers"] = self.registers.get_config(diff=diff)

        logger.debug("The shadow registers creates configuration.")
        return ret

    @staticmethod
    def antipolize_register(src: FuseRegister, dst: FuseRegister) -> None:
        """Antipolize given registers by applying bitwise XOR with 0xFFFFFFFF.

        This method takes the value from the source register and applies bitwise NOT operation
        (XOR with 0xFFFFFFFF) to create an antipole value, which is then set to the destination
        register.

        :param src: Input register to read the value from.
        :param dst: The antipole destination register where the inverted value will be stored.
        """
        dst.set_value(src.get_value(True) ^ 0xFFFFFFFF, raw=True)

    def flush_func_handler(self) -> None:
        """Execute the flush function handler for shadow registers.

        Determines the flush function name from the database configuration and executes
        the corresponding method if it exists on the current instance.

        :raises SPSDKError: When the specified flush function method doesn't exist.
        """
        flush_func = self.db.get_str(DatabaseManager.SHADOW_REGS, "flush_func", "")
        if flush_func:
            if hasattr(self, flush_func):
                method_ref = getattr(self, flush_func)
                method_ref()
            else:
                raise SPSDKError(f"The '{flush_func}' function doesn't exists.")

    def compute_register(self, reg: FuseRegister, method: str) -> None:
        """Recalculate register value using specified computation method.

        The method dynamically calls the specified computation function to update the register's value.
        The computation method must exist as an attribute of the current object.

        :param reg: Register to be recalculated.
        :param method: Method name to be used to recompute the register value.
        :raises SPSDKError: When the specified computing routine is not found.
        """
        if hasattr(self, method):
            method_ref = getattr(self, method)
            reg.set_value(method_ref(reg.get_value(True)), True)
        else:
            raise SPSDKError(f"The '{method}' compute function doesn't exists.")

    # CRC8 - ITU
    @staticmethod
    def crc_update(data: bytes, crc: int = 0, is_final: bool = True) -> int:
        """Compute CRC8 ITU checksum from given bytes.

        The function implements CRC8 ITU algorithm with polynomial 0x07 and final XOR value 0x55.
        Supports incremental CRC calculation for large data processing.

        :param data: Input data bytes to compute CRC checksum.
        :param crc: Initial CRC seed value for incremental calculation.
        :param is_final: Flag indicating whether to apply final XOR transformation.
        :return: Computed CRC8 checksum value.
        """
        k = 0
        data_len = len(data)
        while data_len != 0:
            data_len -= 1
            carry = data[k]
            k += 1
            for i in range(8):
                bit = (crc & 0x80) != 0
                if (carry & (0x80 >> i)) != 0:
                    bit = not bit
                crc <<= 1
                if bit:
                    crc ^= 0x07
            crc &= 0xFF
        if is_final:
            return (crc & 0xFF) ^ 0x55
        return crc & 0xFF

    @staticmethod
    def comalg_dcfg_cc_socu_crc8(val: int) -> int:
        """Compute CRC8 for DCFG_CC_SOCU register value.

        This function extracts the upper 24 bits of the input value, computes a CRC8
        checksum over those bytes, and replaces the lower 8 bits with the computed CRC.

        :param val: Input DCFG_CC_SOCU register value (32-bit integer).
        :return: DCFG_CC_SOCU value with CRC8 field in the lower 8 bits.
        """
        in_val = bytearray(3)
        for i in range(3):
            in_val[i] = (val >> (8 + i * 8)) & 0xFF
        val &= ~0xFF
        val |= ShadowRegisters.crc_update(in_val)
        return val

    def comalg_dcfg_cc_socu_test_en(self, val: int) -> int:
        """Configure DCFG_CC_SOCU register with appropriate test mode setting.

        The method modifies the DEV_TEST_EN bit in DCFG_CC_SOCU register based on the current
        fuse mode to satisfy MCU operational requirements.

        :param val: Input DCFG_CC_SOCU register value to be modified.
        :return: Modified DCFG_CC_SOCU value with test mode bit configured appropriately.
        """
        if self.fuse_mode:
            return val & ~0x80000000

        return val | 0x80000000

    def rw61x_update_scratch_reg(self) -> None:
        """Update scratch register for RW61x to enable shadow register functionality.

        This method writes a specific value to the scratch register address to activate
        the shadow register functionality on RW61x devices.

        :raises AssertionError: If the probe is not a DebugProbe instance.
        """
        assert isinstance(self.probe, DebugProbe)
        logger.debug("Flush shadow registers data")
        addr = 0x5003B498
        value = 0xA7C56B9E
        self.probe.mem_reg_write(addr, value)


def enable_debug(probe: DebugProbe, family: FamilyRevision) -> bool:
    """Enable debug access ports on devices with debug mailbox.

    The method checks if AHB access is available and if not, attempts to unlock
    the device using debug mailbox system. It handles probe reconnection and
    validates the unlock operation.

    :param probe: Initialized debug probe for device communication.
    :param family: Chip family and revision information.
    :return: True if debug port is enabled, False otherwise.
    :raises SPSDKError: Invalid input parameters or unlock method failed.
    """
    debug_enabled = False
    try:
        logger.debug("step 3: Check if AHB is enabled")

        if not test_ahb_access(probe):
            logger.debug("Locked Device. Launching unlock sequence.")
            # Reopen the probe after failed attempt of AHB Access
            probe.close()
            probe.open()
            probe.connect_safe()
            # Start debug mailbox system
            StartDebugSession(dm=DebugMailbox(debug_probe=probe, family=family)).run()

            # Recheck the AHB access
            if test_ahb_access(probe):
                logger.debug("Access granted")
                debug_enabled = True
            else:
                logger.debug("Enable debug operation failed!")
        else:
            logger.debug("Unlocked Device")
            debug_enabled = True

    except AttributeError as exc:
        raise SPSDKError(f"Invalid input parameters({str(exc)})") from exc

    except SPSDKDebugProbeError as exc:
        raise SPSDKError(f"Can't unlock device ({str(exc)})") from exc

    return debug_enabled

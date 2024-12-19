#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The shadow registers control DAT support file."""

import logging
from typing import Any, Optional

from spsdk import __version__
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import StartDebugSession
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError
from spsdk.debuggers.utils import test_ahb_access
from spsdk.exceptions import SPSDKError
from spsdk.fuses.fuse_registers import FuseRegister, FuseRegisters
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import SPSDKRegsErrorRegisterNotFound
from spsdk.utils.schema_validator import update_validation_schema_family

logger = logging.getLogger(__name__)


class IoVerificationError(SPSDKError):
    """The error during write verification - exception for use with SPSDK."""


class ShadowRegisters:
    """SPSDK support to control the shadow registers."""

    def __init__(
        self,
        family: str,
        revision: str = "latest",
        debug_probe: Optional[DebugProbe] = None,
    ) -> None:
        """Initialization of Shadow register class."""
        self.probe = debug_probe
        self.device = family
        self.db = get_db(family, revision)
        self.revision = self.db.name
        self.offset_for_write = self.db.get_int(
            DatabaseManager.SHADOW_REGS, "write_address_offset", 0
        )

        self.fuse_mode = False
        self.registers = self._get_init_registers(self.device, self.revision)
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

    @staticmethod
    def _get_init_registers(family: str, revision: str = "latest") -> FuseRegisters:
        """Initialize the shadow registers from whole fuse list.

        :param family: Family of device to be loaded
        :param revision: Chip revision, defaults to "latest"
        :return: Register class with loaded just fuses that supports shadow registers
        """
        db = get_db(family, revision)
        computed_fields: dict[str, dict[str, str]] = db.get_dict(
            DatabaseManager.SHADOW_REGS, "computed_fields", {}
        )
        antipole_regs: dict[str, str] = db.get_dict(
            DatabaseManager.SHADOW_REGS, "inverted_regs", {}
        )
        regs = FuseRegisters(
            family=family,
            revision=revision,
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
                reg_obj.get_bitfield(bitfield).hidden = True
                logger.debug(f"Hiding bitfield: {bitfield} in {computed_reg}")

        # Set the antipolize handler
        for antipole_reg in antipole_regs.values():
            regs.get_reg(antipole_reg).hidden = True
            logger.debug(f"Hiding anti pole register: {antipole_reg}")

        return regs

    def _write_shadow_reg(self, addr: int, data: int, verify_mask: int = 0) -> None:
        """The function write a shadow register.

        The function writes shadow register into MCU and verify the write if requested.

        param addr: Shadow register address.
        param data: Shadow register data to write.
        param verify_mask: Verify bit mask for read back and compare, if 0 verify is disable
        raises IoVerificationError
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
            if read_back & verify_mask != data & verify_mask:
                raise IoVerificationError(
                    f"The verification of written shadow register 0x{addr:08X} failed."
                    " Maybe a READ LOCK is set for that register."
                )

    def reload_registers(self) -> None:
        """Reload all the values in managed registers."""
        for reg in self.registers._registers:
            self.get_register(reg.name)

    def set_all_registers(self, verify: bool = True) -> None:
        """Update all shadow registers in target using their local values.

        :param verify: Verity write operation.
        """
        for reg in self.registers._registers:
            self.set_register(reg.name, reg.get_value(raw=True), verify)

    def set_loaded_registers(self, verify: bool = True) -> None:
        """Update shadow registers in target using their local values.

        :param verify: Verity write operation.
        """
        for reg in self._loaded_registers:
            self.set_register(reg.name, reg.get_value(raw=True), verify)

    def set_register(self, reg_name: str, data: Any, verify: bool = True, raw: bool = True) -> None:
        """The function sets the value of the specified register.

        :param reg_name: The register name.
        :param data: The new data to be stored to shadow register.
        :param verify: Verity write operation.
        :param raw: Do not use any modification hooks.
        :raises SPSDKDebugProbeError: The debug probe is not specified.
        :raises SPSDKError: General error with write of Shadow register.
        """

        def write_reg(reg: FuseRegister) -> None:
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
            self._write_shadow_reg(
                addr=reg.shadow_register_addr,
                data=reg.get_value(raw=True),
                verify_mask=verify_mask,
            )

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
        """The function returns value of the requested register.

        param reg: The register name.
        return: The value of requested register in bytes
        raises SPSDKDebugProbeError: The debug probe is not specified.
        """

        def read_reg(reg: FuseRegister) -> None:
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
        """The function creates the BLHOST script to burn fuses.

        :param reg_list: The list of register to be burned.
        :raises SPSDKError: Exception in case of not existing register.
        :return: Content of BLHOST script file.
        """

        def add_reg(reg: FuseRegister) -> str:
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
            f"# Chip: {self.device} rev:{self.revision}\n\n\n"
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
                    f"Register {reg_name} has not found for {self.device} device."
                ) from exc

            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    ret += add_reg(sub_reg)
            else:
                ret += add_reg(reg)

        self.fuse_mode = False
        return ret

    @staticmethod
    def get_supported_families() -> list[str]:
        """Return list of supported families."""
        return get_families(DatabaseManager.SHADOW_REGS)

    @classmethod
    def get_validation_schemas_family(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for Shadow registers supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.SHADOW_REGS)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], cls.get_supported_families())
        return [sch_family, sch_cfg["sr_device_back_compatible"]]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.SHADOW_REGS)
        sch_family: dict[str, Any] = get_schema_file("general")["family"]
        sch_family.pop("required")  # Due backward compatibility
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family, revision
        )
        try:
            regs = cls._get_init_registers(family, revision)
            sch_cfg["sr_registers"]["properties"]["registers"][
                "properties"
            ] = regs.get_validation_schema()["properties"]
            return [sch_family, sch_cfg["sr_device_back_compatible"], sch_cfg["sr_registers"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or revision {revision} is not supported") from exc

    def load_config(self, config: dict[str, Any]) -> None:
        """The function loads the configuration.

        :param config: The configuration of shadow registers.
        """
        cfg: dict = config["registers"]
        self.registers.load_yml_config(cfg)
        self._loaded_registers = [
            self.registers.find_reg(reg_name, include_group_regs=True) for reg_name in cfg.keys()
        ]
        # Updates necessary register values
        for reg_uid, bitfields_rec in self.computed_fields.items():
            reg_name = self.registers.get_reg(reg_uid).name
            if reg_name in cfg:
                reg = self.registers.get_reg(reg_uid)
                for bitfield_uid, method in bitfields_rec.items():
                    bitfield_name = reg.get_bitfield(bitfield_uid).name
                    if isinstance(cfg[reg_name], dict) and bitfield_name not in cfg[reg_name]:
                        self.compute_register(reg, method)
                        log_msg = (
                            f"The {reg_name} register has been recomputed, because "
                            f"it has been used in configuration and the bitfield {bitfield_name} "
                            "has not been specified"
                        )
                        logger.debug(log_msg)

        # Update also antipole registers if needed
        for src_uid, dst_uid in self.antipole_regs.items():
            src_reg = self.registers.get_reg(src_uid)
            dst_reg = self.registers.get_reg(dst_uid)
            if src_reg.name in cfg and dst_reg.name not in cfg:
                self.antipolize_register(src_reg, dst_reg)
                log_msg = (
                    f"The {src_reg.name} register has been used to compute antipole value, and it "
                    f"has been used in {dst_reg.name}."
                )
                logger.debug(log_msg)
                self._loaded_registers.append(dst_reg)

        logger.debug("The shadow registers has been loaded from configuration.")

    def get_config(self, diff: bool = False) -> dict[str, Any]:
        """The function creates the configuration.

        :param diff: If set, only changed registers will be placed in configuration.
        """
        ret: dict[str, Any] = {"family": self.device, "revision": self.revision}
        ret["registers"] = self.registers.get_config(diff)

        logger.debug("The shadow registers creates configuration.")
        return ret

    @staticmethod
    def antipolize_register(src: FuseRegister, dst: FuseRegister) -> None:
        """Antipolize given registers.

        :param src: Input register.
        :param dst: The antipole destination register.
        """
        dst.set_value(src.get_value(True) ^ 0xFFFFFFFF, raw=True)

    def flush_func_handler(self) -> None:
        """A function to determine and execute the flush-func handler.

        :param self: Input Value.
        :raises SPSDKError: Raises when the computing routine is not found.
        """
        flush_func = self.db.get_str(DatabaseManager.SHADOW_REGS, "flush_func", "")
        if flush_func:
            if hasattr(self, flush_func):
                method_ref = getattr(self, flush_func)
                method_ref()
            else:
                raise SPSDKError(f"The '{flush_func}' function doesn't exists.")

    def compute_register(self, reg: FuseRegister, method: str) -> None:
        """Recalculate register value.

        :param reg: Register to be recalculated.
        :param method: Method name to be use to recompute the register value.
        :raises SPSDKError: Raises when the computing routine is not found.
        """
        if hasattr(self, method):
            method_ref = getattr(self, method)
            reg.set_value(method_ref(reg.get_value(True)), True)
        else:
            raise SPSDKError(f"The '{method}' compute function doesn't exists.")

    # CRC8 - ITU
    @staticmethod
    def crc_update(data: bytes, crc: int = 0, is_final: bool = True) -> int:
        """The function compute the CRC8 ITU method from given bytes.

        :param data: Input data to compute CRC.
        :param crc: The seed for CRC.
        :param is_final: The flag the the function should return final result.
        :return: The CRC result.
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
        """Function that creates the crc for DCFG_CC_SOCU.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with computed CRC8 field.
        """
        in_val = bytearray(3)
        for i in range(3):
            in_val[i] = (val >> (8 + i * 8)) & 0xFF
        val &= ~0xFF
        val |= ShadowRegisters.crc_update(in_val)
        return val

    def comalg_dcfg_cc_socu_test_en(self, val: int) -> int:
        """Function fill up the DCFG_CC_SOCU DEV_TEST_EN set to True to satisfy MCU needs.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with optionally enabled test mode.
        """
        if self.fuse_mode:
            return val & ~0x80000000

        return val | 0x80000000

    def rw61x_update_scratch_reg(self) -> None:
        """Function updates scratch register for RW61x, This enables the shadow register functionality.

        :param self: Input Value.
        """
        assert isinstance(self.probe, DebugProbe)
        logger.debug("Flush shadow registers data")
        addr = 0x5003B498
        value = 0xA7C56B9E
        self.probe.mem_reg_write(addr, value)


def enable_debug(probe: DebugProbe, family: str) -> bool:
    """Function that enables debug access ports on devices with debug mailbox.

    :param probe: Initialized debug probe.
    :param family: Chip family name.
    :return: True if debug port is enabled, False otherwise
    :raises SPSDKError: Unlock method failed.
    """
    debug_enabled = False
    try:
        logger.debug("step 3: Check if AHB is enabled")

        if not test_ahb_access(probe):
            logger.debug("Locked Device. Launching unlock sequence.")

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

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The shadow registers control DAT support file."""

import logging
from typing import Any, Dict, List, Optional

from spsdk import __author__, __release__, __version__
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import StartDebugSession
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError
from spsdk.debuggers.utils import test_ahb_access
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import Endianness
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers, RegsRegister, SPSDKRegsErrorRegisterNotFound

logger = logging.getLogger(__name__)


class IoVerificationError(SPSDKError):
    """The error during write verification - exception for use with SPSDK."""


class ShadowRegisters:
    """SPSDK support to control the shadow registers."""

    def __init__(
        self,
        debug_probe: Optional[DebugProbe],
        config: RegConfig,
    ) -> None:
        """Initialization of Shadow register class."""
        self.probe = debug_probe
        self.config = config
        self.device = config.family
        self.offset = self.config.get_address()
        self.offset_for_read = self.config.get_address(alt_read_address=True)
        self.fuse_mode = False
        self.regs = Registers(self.device)

        self.regs.load_registers_from_xml(
            config.get_data_file(),
            grouped_regs=config.get_grouped_registers(),
        )

        # Set the computed field handler
        for reg, fields in self.config.get_computed_fields().items():
            reg_obj = self.regs.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

        # Set the antipolize handler
        for reg, antipole_reg in self.config.get_antipole_regs().items():
            src = self.regs.find_reg(reg)
            dst = self.regs.find_reg(antipole_reg)
            src.add_setvalue_hook(self.reg_antipolize_src_handler, dst)
            dst.add_setvalue_hook(self.reg_antipolize_dst_handler, src)

    def _write_shadow_reg(self, addr: int, data: int, verify_mask: int = 0) -> None:
        """The function write a shadow register.

        The function writes shadow register in to MCU and verify the write if requested.

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
        self.probe.mem_reg_write(addr, data)

        if verify_mask:
            read_back = self.probe.mem_reg_read(addr)
            if read_back & verify_mask != data & verify_mask:
                raise IoVerificationError(
                    f"The verification of written shadow register 0x{addr:08X} failed."
                    " Maybe a READ LOCK is set for that register."
                )

    def reload_registers(self) -> None:
        """Reload all the values in managed registers."""
        for reg in self.regs.get_registers():
            self.get_register(reg.name)

    def sets_all_registers(self, verify: bool = True) -> None:
        """Update all shadow registers in target by local values.

        :param verify: Verity write operation.
        """
        for reg in self.regs.get_registers():
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

        def write_reg(reg: RegsRegister) -> None:
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

            self._write_shadow_reg(
                addr=self.offset + reg.offset,
                data=reg.get_value(raw=True),
                verify_mask=verify_mask,
            )

        try:
            reg = self.regs.find_reg(reg_name, include_group_regs=True)
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

        def read_reg(reg: RegsRegister) -> None:
            if not self.probe:
                raise SPSDKDebugProbeError(
                    "Shadow registers: Cannot use the communication function without defined debug probe."
                )
            if reg.width > 32:
                raise SPSDKError(
                    f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to read from device."
                )
            reg.set_value(self.probe.mem_reg_read(self.offset_for_read + reg.offset), raw=True)

        try:
            reg = self.regs.find_reg(reg_name, include_group_regs=True)

            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    read_reg(sub_reg)
            else:
                read_reg(reg)
            return reg.get_bytes_value(raw=True)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).") from exc

    def create_fuse_blhost_script(self, reg_list: List[str]) -> str:
        """The function creates the BLHOST script to burn fuses.

        :param reg_list: The list of register to be burned.
        :raises SPSDKError: Exception in case of not existing register.
        :return: Content of BLHOST script file.
        """

        def add_reg(reg: RegsRegister) -> str:
            otp_index = reg.otp_index
            assert otp_index
            otp_value = "0x" + reg.get_bytes_value(raw=True).hex()
            burn_fuse = f"# Fuse {reg.name}, index {otp_index} and value: {otp_value}.\n"
            burn_fuse += f"efuse-program-once {hex(otp_index)} {otp_value}\n"
            return burn_fuse

        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {__version__}\n"
            f"# Chip: {self.device} rev:{self.config.revision}\n\n\n"
        )
        # Update list by antipole opposites registers
        for ap_reg_src, ap_reg_dst in self.config.get_antipole_regs().items():
            if ap_reg_src in reg_list:
                reg_list.insert(reg_list.index(ap_reg_src) + 1, ap_reg_dst)
        self.fuse_mode = True
        for reg_name in reg_list:
            try:
                reg = self.regs.find_reg(reg_name, True)
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
    def get_supported_families() -> List[str]:
        """Return list of supported families."""
        return get_families(DatabaseManager.SHADOW_REGS)

    @classmethod
    def get_validation_schemas_family(cls) -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for Shadow registers supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.SHADOW_REGS)
        sch_cfg["sr_family_rev"]["properties"]["family"]["enum"] = cls.get_supported_families()
        return [sch_cfg["sr_family_rev"]]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.SHADOW_REGS)
        try:
            db = get_db(family, revision)
            regs = Registers(family, Endianness.LITTLE)
            regs.load_registers_from_xml(
                db.get_file_path(DatabaseManager.SHADOW_REGS, "data_file"),
                grouped_regs=db.get_list(DatabaseManager.SHADOW_REGS, "grouped_registers"),
            )
            sch_cfg["sr_family_rev"]["properties"]["family"]["enum"] = cls.get_supported_families()
            sch_cfg["sr_family_rev"]["properties"]["family"]["template_value"] = family
            sch_cfg["sr_family_rev"]["properties"]["revision"]["template_value"] = revision
            sch_cfg["sr_registers"]["properties"]["registers"][
                "properties"
            ] = regs.get_validation_schema()["properties"]
            return [sch_cfg["sr_family_rev"], sch_cfg["sr_registers"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or revision {revision} is not supported") from exc

    def load_config(self, config: Dict[str, Any]) -> None:
        """The function loads the configuration.

        :param config: The configuration of shadow registers.
        """
        self.regs.load_yml_config(config["registers"])

        logger.debug("The shadow registers has been loaded from configuration.")

    def get_config(self, diff: bool = False) -> Dict[str, Any]:
        """The function creates the configuration.

        :param diff: If sett only changed registers will be placed in configuration.
        """
        ret: Dict[str, Any] = {"family": self.config.family, "revision": self.config.revision}
        ret["registers"] = self.regs.get_config(diff)

        logger.debug("The shadow registers creates configuration.")
        return ret

    @staticmethod
    def reg_antipolize_src_handler(val: int, context: Any) -> int:
        """Antipolize given register value.

        :param val: Input register value.
        :param context: The method context.
        :return: Antipolized value.
        """
        dst_reg: RegsRegister = context
        dst_reg.set_value(val ^ 0xFFFFFFFF, raw=True)
        return val

    @staticmethod
    def reg_antipolize_dst_handler(val: int, context: Any) -> int:
        """Keep same antipolized register value in computed register.

        :param val: Input register value.
        :param context: The method context.
        :return: Antipolized value.
        """
        src_reg: RegsRegister = context
        val = src_reg.get_value()
        new_val = val ^ 0xFFFFFFFF
        return new_val

    def flush_func_handler(self) -> None:
        """A function to determine and execute the flush-func handler.

        :param self: Input Value.
        :raises SPSDKError: Raises when the computing routine is not found.
        """
        flush_func = self.config.get_value("flush_func", "")
        if flush_func:
            if hasattr(self, flush_func):
                method_ref = getattr(self, flush_func)
                method_ref()
            else:
                raise SPSDKError(f"The '{flush_func}' function doesn't exists.")

    def reg_computed_fields_handler(self, val: bytes, context: Any) -> bytes:
        """Recalculate all fields for given register value.

        :param val: Input register value.
        :param context: The method context (fields).
        :return: recomputed value.
        :raises SPSDKError: Raises when the computing routine is not found.
        """
        fields: dict = context
        for method in fields.values():
            if hasattr(self, method):
                method_ref = getattr(self, method)
                val = method_ref(val)
            else:
                raise SPSDKError(f"The '{method}' compute function doesn't exists.")

        return val

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
        addr = 0x5003B498
        value = 0xA7C56B9E
        self._write_shadow_reg(addr=addr, data=value, verify_mask=True)

    @staticmethod
    def comalg_do_nothing(val: int) -> int:
        """Function that do nothing.

        :param val: Input Value.
        :return: Returns same value as it get.
        """
        return val


def enable_debug(probe: DebugProbe, ap_mem: int = 0) -> bool:
    """Function that enables debug access ports on devices with debug mailbox.

    :param probe: Initialized debug probe.
    :param ap_mem: Index of Debug access port for memory interface.
    :return: True if debug port is enabled, False otherwise
    :raises SPSDKError: Unlock method failed.
    """
    debug_enabled = False
    try:
        logger.debug("step 3: Check if AHB is enabled")

        if not test_ahb_access(probe, ap_mem):
            logger.debug("Locked Device. Launching unlock sequence.")

            # Start debug mailbox system
            StartDebugSession(dm=DebugMailbox(debug_probe=probe)).run()

            # Recheck the AHB access
            if test_ahb_access(probe, ap_mem):
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

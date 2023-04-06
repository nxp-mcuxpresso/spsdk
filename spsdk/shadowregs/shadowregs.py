#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The shadow registers control DAT support file."""

import logging
from typing import Any, List, Optional

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap as CM

from spsdk import SPSDK_YML_INDENT, SPSDKError, __author__, __release__, __version__
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.dm_commands import StartDebugSession
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError
from spsdk.debuggers.utils import test_ahb_access
from spsdk.utils.misc import (
    change_endianness,
    load_configuration,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers, RegsRegister, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.schema_validator import ConfigTemplate

logger = logging.getLogger(__name__)


class IoVerificationError(SPSDKError):
    """The error during write verification - exception for use with SPSDK."""


class ShadowRegisters:
    """SPSDK support to control the shadow registers."""

    def __init__(
        self,
        debug_probe: Optional[DebugProbe],
        config: RegConfig,
        device: str,
        revision: str = "latest",
    ) -> None:
        """Initialization of Shadow register class."""
        self.probe = debug_probe
        self.config = config
        self.device = device
        self.offset = value_to_int(self.config.get_address(self.device))
        self.fuse_mode = False

        self.regs = Registers(self.device)
        rev = revision or "latest"
        self.revision = (
            rev
            if rev != "latest"
            else config.devices.get_by_name(self.device).revisions.get_latest().name
        )
        self.regs.load_registers_from_xml(
            config.get_data_file(self.device, self.revision),
            grouped_regs=config.get_grouped_registers(self.device),
        )

        # Set the computed field handler
        for reg, fields in self.config.get_computed_fields(self.device).items():
            reg_obj = self.regs.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

        # Set the antipolize handler
        for reg, antipole_reg in self.config.get_antipole_regs(self.device).items():
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

        logger.debug(f"Writing shadow register address: {hex(addr)}, data: {hex(data)}")
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
            self.reload_register(reg)

    def sets_all_registers(self, verify: bool = True) -> None:
        """Update all shadow registers in target by local values.

        :param verify: Verity write operation.
        """
        for reg in self.regs.get_registers():
            self.set_register(reg.name, reg.get_value(), verify)

    def reload_register(self, reg: RegsRegister) -> None:
        """Reload the value in requested register.

        :param reg: The register to reload from the HW.
        """
        reg.set_value(self.get_register(reg.name), raw=True)

    def read_register(self, reg: RegsRegister) -> bytes:
        """Read the value in requested register.

        :param reg: The register to read from the HW.
        """
        return bytes(self.get_register(reg.name))

    def set_register(self, reg_name: str, data: Any, verify: bool = True) -> None:
        """The function sets the value of the specified register.

        :param reg_name: The register name.
        :param data: The new data to be stored to shadow register.
        :param verify: Verity write operation.
        :raises SPSDKDebugProbeError: The debug probe is not specified.
        :raises SPSDKError: General error with write of Shadow register.
        """

        def write_reg(base_address: int, reg: RegsRegister) -> None:
            if not self.probe:
                raise SPSDKDebugProbeError(
                    "Shadow registers: Cannot use the communication function without defined debug probe."
                )

            if reg.width > 32:
                raise SPSDKError(
                    f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to write to device."
                )
            # Create value
            value = reg.get_value()
            if reg.reverse:
                value = int.from_bytes(change_endianness(value_to_bytes(value)), "big")
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
                addr=base_address + reg.offset, data=value, verify_mask=verify_mask
            )

        try:
            reg = self.regs.find_reg(reg_name, include_group_regs=True)
            reg.set_value(data, raw=True)
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    write_reg(self.offset, sub_reg)
            else:
                write_reg(self.offset, reg=reg)

        except SPSDKError as exc:
            raise SPSDKError(f"The set shadow register failed({str(exc)}).") from exc

    def get_register(self, reg_name: str) -> bytes:
        """The function returns value of the requested register.

        param reg: The register name.
        return: The value of requested register in bytes
        raises SPSDKDebugProbeError: The debug probe is not specified.
        """

        def read_reg(base_address: int, reg: RegsRegister) -> bytes:
            if not self.probe:
                raise SPSDKDebugProbeError(
                    "Shadow registers: Cannot use the communication function without defined debug probe."
                )
            if reg.width > 32:
                raise SPSDKError(
                    f"Invalid width ({reg.width}b) of shadow register ({reg.name}) to read from device."
                )
            read_value = self.probe.mem_reg_read(base_address + reg.offset).to_bytes(4, "big")
            if reg.reverse:
                read_value = change_endianness(read_value)
            return read_value

        try:
            reg = self.regs.find_reg(reg_name, include_group_regs=True)

            ret = bytearray()
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs[:: -1 if reg.reverse_subregs_order else 1]:
                    ret.extend(read_reg(self.offset, sub_reg))
            else:
                ret.extend(read_reg(self.offset, reg=reg))
            return ret

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
            otp_value = "0x" + reg.get_bytes_value().hex()
            burn_fuse = f"# Fuse {reg.name}, index {otp_index} and value: {otp_value}.\n"
            burn_fuse += f"efuse-program-once {hex(otp_index)} {otp_value}\n"
            return burn_fuse

        ret = (
            "# BLHOST fuses programming script\n"
            f"# Generated by SPSDK {__version__}\n"
            f"# Chip: {self.device} rev:{self.revision}\n\n\n"
        )
        # Update list by antipole opposites registers
        for ap_reg_src, ap_reg_dst in self.config.get_antipole_regs(self.device).items():
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

    def create_yaml_config(self, file_name: str, raw: bool = False, diff: bool = False) -> None:
        """The function creates the configuration YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw output of configuration (including computed fields and anti-pole registers)
        :param diff: Get only configuration with difference value to reset state.
        """
        antipole_regs = None if raw else list(self.config.get_antipole_regs(self.device).values())
        computed_fields = None if raw else self.config.get_computed_fields(self.device)

        yaml = YAML()
        yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
        data = CM()

        description = CM()
        description.yaml_set_start_comment(
            f"NXP {self.device.upper()} Shadow registers configuration", indent=2
        )
        description.insert(1, "device", self.device, comment="The NXP device name.")
        description.insert(
            2, "version", __version__, comment="The SPSDK Shadow register tool version."
        )
        description.insert(3, "author", __author__, comment="The author of the configuration.")
        description.insert(4, "release", __release__, comment="The SPSDK release.")

        data["description"] = description
        data["registers"] = self.regs.create_yml_config(
            exclude_regs=antipole_regs,
            exclude_fields=computed_fields,
            indent=2,
            diff=diff,
        )
        write_file(ConfigTemplate.convert_cm_to_yaml(data), file_name, encoding="utf8")

    def load_yaml_config(self, file_name: str, raw: bool = False) -> None:
        """The function loads the configuration from YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw input of configuration (including computed fields and anti-pole registers)
        :raises SPSDKError: When the configuration file not found.
        """
        antipole_regs = None if raw else list(self.config.get_antipole_regs(self.device).values())
        computed_fields = None if raw else self.config.get_computed_fields(self.device)
        data = load_configuration(file_name)
        self.regs.load_yml_config(data["registers"], antipole_regs, computed_fields)
        if not raw:
            # Just update only configured registers
            exclude_hooks = list(set(self.regs.get_reg_names()) - set(data["registers"].keys()))
            self.regs.run_hooks(exclude_hooks)

        logger.debug("The shadow registers has been loaded from configuration.")

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

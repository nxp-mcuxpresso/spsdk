#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The shadow registers control DAT support file."""
import logging
from typing import Any
import math

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap as CM

from spsdk import __version__, __release__, __author__, SPSDK_YML_INDENT
from spsdk.utils.registers import Registers, RegsRegister
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.misc import change_endianism, value_to_bytes, reverse_bytes_in_longs
from spsdk.dat.dm_commands import StartDebugSession

from spsdk.exceptions import SPSDKError
from spsdk.debuggers.debug_probe import (DebugProbe, DebugProbeError)
from spsdk.dat.debug_mailbox import DebugMailbox

logger = logging.getLogger(__name__)

class IoVerificationError(SPSDKError):
    """The error during write verification - exception for use with SPSDK."""

class ShadowRegisters():
    """SPSDK support to control the shadow registers."""

    def __init__(self, debug_probe: DebugProbe, config: RegConfig, device: str, revision: str = "latest") -> None:
        """Initialization of Shadow register class."""
        self.probe = debug_probe
        self.config = config
        self.device = device
        self.offset = int(self.config.get_address(self.device, remove_underscore=True), 16)

        self.regs = Registers(self.device)
        rev = revision or "latest"
        rev = rev if rev != "latest" else config.get_latest_revision(self.device)
        self.regs.load_registers_from_xml(
            config.get_data_file(self.device, rev),
            grouped_regs=config.get_grouped_registers(self.device))

        # Set the computed field handler
        for reg, fields  in self.config.get_computed_fields(self.device).items():
            reg_obj = self.regs.find_reg(reg)
            reg_obj.add_setvalue_hook(self.reg_computed_fields_handler, fields)

        # Set the antipolize handler
        for reg, antipole_reg  in self.config.get_antipole_regs(self.device).items():
            src = self.regs.find_reg(reg)
            dst = self.regs.find_reg(antipole_reg)
            src.add_setvalue_hook(self.reg_antipolize_src_handler, dst)
            dst.add_setvalue_hook(self.reg_antipolize_dst_handler, src)

    def _write_shadow_reg(self, addr: int, data: int, verify: int = True) -> None:
        """The function write a shadow register.

        The function writes shadow register in to MCU and verify the write if requested.

        param addr: Shadow register address.
        param data: Shadow register data to write.
        param verify: If True the write is read back and compare, otherwise no check is done
        raises IoVerificationError
        """
        self.probe.mem_reg_write(addr, data)

        if verify:
            readback = self.probe.mem_reg_read(addr)
            if readback != data:
                raise IoVerificationError(f"The written data 0x{data:08X} to 0x{addr:08X} address are invalid.")

    def reload_registers(self) -> None:
        """Reload all the values in managed registers."""
        for reg in self.regs.get_registers():
            self.reload_register(reg)

    def sets_all_registers(self) -> None:
        """Update all shadow registers in target by local values."""
        for reg in self.regs.get_registers():
            self.set_register(reg.name, reg.get_value())

    def reload_register(self, reg: RegsRegister) -> None:
        """Reload the value in requested register.

        :param reg: The register to reload from the HW.
        """
        reg.set_value(self.get_register(reg.name))

    def set_register(self, reg_name: str, data: Any) -> None:
        """The function sets the value of the specified register.

        param reg: The register name.
        param data: The new data to be stored to shadow register.
        raises DebugProbeError: The debug probe is not specified.
        """
        if self.probe is None:
            raise DebugProbeError("There is no debug probe.")

        try:
            reg = self.regs.find_reg(reg_name)
            value = value_to_bytes(data)

            start_address = self.offset + reg.offset
            width = reg.width

            if width < len(value) * 8:
                raise SPSDKError(f"Invalid length of data for shadow register write.")

            if width < 32:
                width = 32

            data_aligned = bytearray(math.ceil(width / 8))
            data_aligned[len(data_aligned) - len(value) : len(data_aligned)] = value

            end_address = start_address + math.ceil(width / 8)
            addresses = range(start_address, end_address, 4)

            for i, addr in enumerate(addresses):
                val = data_aligned[i*4:i*4+4]
                self._write_shadow_reg(addr, int.from_bytes(change_endianism(val) if reg.reverse else val, "big"))

            reg.set_value(value, raw=True)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).")

    def get_register(self, reg_name: str) -> bytes:
        """The function returns value of the requested register.

        param reg: The register name.
        return: The value of requested register in bytes
        raises DebugProbeError: The debug probe is not specified.
        """
        if self.probe is None:
            raise DebugProbeError("There is no debug probe.")

        array = bytearray()
        try:
            reg = self.regs.find_reg(reg_name)

            start_address = self.offset + reg.offset
            width = reg.width

            if width < 32:
                width = 32

            if width == 32:
                array.extend(self.probe.mem_reg_read(start_address).to_bytes(4, "big"))
            else:
                end_address = start_address + math.ceil(width / 8)
                addresses = range(start_address, end_address, 4)

                for addr in addresses:
                    array.extend(self.probe.mem_reg_read(addr).to_bytes(4, "big"))

            result = reverse_bytes_in_longs(bytes(array)) if reg.reverse else bytes(array)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).")

        return result

    def create_yml_config(self, file_name: str, raw: bool = False) -> None:
        """The function creates the configuration YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw output of configuration (including computed fields and anti-pole registers)
        """
        antipole_regs = None if raw else list(self.config.get_antipole_regs(self.device).values())
        computed_fields = None if raw else self.config.get_computed_fields(self.device)

        yaml = YAML()
        yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
        data = CM()

        description = CM()
        description.yaml_set_start_comment(f"NXP {self.device.upper()} Shadow registers configuration", indent=2)
        description.insert(1, "device", self.device, comment="The NXP device name.")
        description.insert(2, "version", __version__, comment="The SPSDK Shadow register tool version.")
        description.insert(3, "author", __author__, comment="The author of the configuration.")
        description.insert(4, "release", __release__, comment="The SPSDK release.")

        data['description'] = description
        data['registers'] = self.regs.create_yml_config(
            exclude_regs=antipole_regs,
            exclude_fields=computed_fields,
            indent=2)
        with open(file_name, "w", encoding='utf8') as out_file:
            yaml.dump(data, out_file)

    def load_yml_config(self, file_name: str, raw: bool = False) -> None:
        """The function loads the configuration from YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw input of configuration (including computed fields and anti-pole registers)
        :raise SPSDKError: When the configuration file not found.
        """
        antipole_regs = None if raw else list(self.config.get_antipole_regs(self.device).values())
        computed_fields = None if raw else self.config.get_computed_fields(self.device)
        try:
            with open(file_name, "r", encoding='utf8') as yml_config_file:
                yaml = YAML()
                yaml.indent(sequence=4, offset=2)
                data = yaml.load(yml_config_file)
        except FileNotFoundError:
            raise SPSDKError("File with YML configuration doesn't exists.")

        self.regs.load_yml_config(data['registers'], antipole_regs, computed_fields)
        if not raw:
            # Just update only configured registers
            exclude_hooks = list(set(self.regs.get_reg_names())-set(data['registers'].keys()))
            self.regs.run_hooks(exclude_hooks)

        logger.debug(f"The shadow registers has been loaded from configuration.")

    def reg_antipolize_src_handler(self, val: bytes, context: Any) -> bytes:
        """Antipolize given register value.

        :param val: Input register value.
        :param context: The method context.
        :return: Antipolized value.
        """
        dst_reg: RegsRegister = context
        newval = [0]*len(val)
        for i, val_byte in enumerate(val):
            newval[i] = val_byte ^ 0xFF
        dst_reg.set_value(bytes(newval), raw=True)

        return val

    def reg_antipolize_dst_handler(self, val: bytes, context: Any) -> bytes:
        """Keep same antipolized register value in computed register.

        :param val: Input register value.
        :param context: The method context.
        :return: Antipolized value.
        """
        src_reg: RegsRegister = context
        val = src_reg.get_value()
        newval = [0]*len(val)
        for i, val_byte in enumerate(val):
            newval[i] = val_byte ^ 0xFF
        return bytes(newval)

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
                method_ref = getattr(self, method, None)
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
                if (carry & (0x80>>i)) != 0:
                    bit = not bit
                crc <<= 1
                if bit:
                    crc ^= 0x07
            crc &= 0xff
        if is_final:
            return (crc & 0xff) ^ 0x55
        return crc & 0xff

    @staticmethod
    def comalg_dcfg_cc_socu_crc8(val: bytes) -> bytes:
        """Function that creates the crc for DCFG_CC_SOCU.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with computed CRC8 field.
        """
        ret = [0]*4
        ret[0:3] = val[0:3]
        in_val = bytearray(val[0:3])
        in_val.reverse()
        ret[3] = ShadowRegisters.crc_update(in_val)
        return bytes(ret)

    @staticmethod
    def comalg_dcfg_cc_socu_rsvd(val: bytes) -> bytes:
        """Function fill up the DCFG_CC_SOCU RSVD filed by 0x40 to satisfy MCU needs.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with computed CRC8 field.
        """
        new_val = bytearray(val)
        new_val[0] &= ~0xFE
        new_val[0] |= 0x40
        return new_val

    @staticmethod
    def comalg_do_nothing(val: bytes) -> bytes:
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
        def test_ahb_access(ap_mem: int) -> bool:
            logger.debug("step T.1: Activate the correct AP")
            probe.coresight_reg_write(access_port=False, addr=2*4, data=ap_mem)

            logger.debug("step T.2: Set the AP access size and address mode")
            probe.coresight_reg_write(access_port=True,
                                      addr=probe.get_coresight_ap_address(ap_mem, 0*4),
                                      data=0x22000012)

            logger.debug("step T.3: Set the initial AHB address to access")
            probe.coresight_reg_write(access_port=True,
                                      addr=probe.get_coresight_ap_address(ap_mem, 1*4),
                                      data=0xE000ED00)

            logger.debug("step T.4: Access the memory system at that address")
            try:
                chip_id = probe.coresight_reg_read(access_port=True,
                                                   addr=probe.get_coresight_ap_address(ap_mem, 3*4))
                logger.debug(f"ChipID={chip_id:08X}")
            except DebugProbeError:
                chip_id = 0xFFFFFFFF
                logger.debug(f"ChipID can't be read")

            # Check if the device is locked
            return chip_id not in (0xFFFFFFFF, 0)

        logger.debug("step 3: Check if AHB is enabled")

        if not test_ahb_access(ap_mem):
            logger.debug("Locked Device. Launching unlock sequence.")

            # Start debug mailbox system
            StartDebugSession(dm=DebugMailbox(debug_probe=probe)).run()

            # Recheck the AHB access
            if test_ahb_access(ap_mem):
                logger.debug(f"Access granted")
                debug_enabled = True
            else:
                logger.debug(f"Enable debug operation failed!")
        else:
            logger.debug("Unlocked Device")
            debug_enabled = True

    except AttributeError as exc:
        raise SPSDKError(f"Invalid input parameters({str(exc)})")

    except DebugProbeError as exc:
        raise SPSDKError(f"Can't unlock device ({str(exc)})")

    return debug_enabled

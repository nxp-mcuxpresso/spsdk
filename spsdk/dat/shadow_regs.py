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
import ruamel.yaml

from spsdk.utils.registers import Registers, RegsRegister, RegConfig, BitfieldNotFound, value_to_bytes
from spsdk.dat.dm_commands import StartDebugSession

from spsdk.exceptions import SPSDKError
from spsdk.debuggers.debug_probe import (DebugProbe, DebugProbeError)
from spsdk.dat.debug_mailbox import DebugMailbox

logger = logging.getLogger(__name__)

class IoVerificationError(SPSDKError):
    """The error during wrie verification - exception for use with SPSDK."""

class ShadowRegisters():
    """SPSDK support to control the shadow registers."""

    def __init__(self, debug_probe: DebugProbe, config: RegConfig, device: str, revision: str = "latest") -> None:
        """Initialization of Shadow register class."""
        self._probe = debug_probe
        self.config = config
        self.device = device
        self.offset = int(self.config.get_address(self.device, remove_underscore=True), 16)

        self.regs = Registers(self.device)
        rev = revision if revision != "latest" else config.get_latest_revision(self.device)
        self.regs.load_registers_from_xml(config.get_data_file(self.device, rev))

    def _write_shadow_reg(self, addr: int, data: int, verify: int = True) -> None:
        """The function write a shadow register.

        The funstion writes shadow register in to MCU and verify the write if requested.

        param addr: Shadow register address.
        param data: Shadow register data to write.
        param verify: If True the write is read back and compare, otherwise no check is done
        raises IoVerificationError
        """
        self._probe.mem_reg_write(addr, data)

        if verify:
            readback = self._probe.mem_reg_read(addr)
            if readback != data:
                raise IoVerificationError(f"The written data 0x{data:08X} to 0x{addr:08X} address are invalid.")

    def reload_registers(self) -> None:
        """Reload all the values in managed registers."""
        for reg in self.regs.registers:
            self.reload_register(reg)

    def sets_all_registers(self) -> None:
        """Update all shadow registers in target by local values."""
        for reg in self.regs.registers:
            self.set_register(reg.name, reg.get_value())

    def reload_register(self, reg: RegsRegister) -> None:
        """Reload the value in requested register.

        :param reg: The register to reload from the HW.
        """
        reg.set_value(self.get_register(reg.name))

    @staticmethod
    def _reverse_bytes_in_longs(arr: bytearray) -> bytearray:
        """The function reverse byte order in longs from input bytes.

        param arr: Input array.
        :return: New array with reversed bytes.
        :raises ValueError: Raises when invalid value is in input.
        """
        arr_len = len(arr)
        if arr_len % 4 != 0:
            raise ValueError("The input array is not in modulo 4!")

        result = bytearray()

        for x in range(arr_len):
            word = bytearray(arr[x*4:x*4+4])
            word.reverse()
            result.extend(word)
        return result

    def set_register(self, reg_name: str, data: Any) -> None:
        """The function sets the value of the specified register.

        param reg: The register name.
        param data: The new data to be stored to shadow register.
        raises DebugProbeError: The debug probe is not specified.
        """
        if self._probe is None:
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

            data_alligned = bytearray(math.ceil(width / 8))
            data_alligned[len(data_alligned) - len(value) : len(data_alligned)] = value

            if reg.reverse:
                data_alligned = self._reverse_bytes_in_longs(data_alligned)

            if width == 32:
                self._write_shadow_reg(start_address, int.from_bytes(data_alligned[:4], "big"))
            else:
                end_address = start_address + math.ceil(width / 8)
                addresses = range(start_address, end_address, 4)

                i = 0
                for addr in addresses:
                    self._write_shadow_reg(addr, int.from_bytes(data_alligned[i:i+4], "big"))
                    i += 4

            reg.set_value(value)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).")

    def get_register(self, reg_name: str) -> bytes:
        """The function returns value of the requested register.

        param reg: The register name.
        return: The value of requested register in bytes
        raises DebugProbeError: The debug probe is not specified.
        """
        if self._probe is None:
            raise DebugProbeError("There is no debug probe.")

        result = bytearray()
        try:
            reg = self.regs.find_reg(reg_name)

            start_address = self.offset + reg.offset
            width = reg.width

            if width < 32:
                width = 32

            if width == 32:
                result.extend(self._probe.mem_reg_read(start_address).to_bytes(4, "big"))
            else:
                end_address = start_address + math.ceil(width / 8)
                addresses = range(start_address, end_address, 4)

                for addr in addresses:
                    result.extend(self._probe.mem_reg_read(addr).to_bytes(4, "big"))

            if reg.reverse:
                result = self._reverse_bytes_in_longs(result)

        except SPSDKError as exc:
            raise SPSDKError(f"The get shadow register failed({str(exc)}).")

        return result

    def create_yml_config(self, file_name: str, raw: bool = False) -> None:
        """The function creates the configuration YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw output of configuration (including computed fields and anti-pole registers)
        """
        CM = ruamel.yaml.comments.CommentedMap  # defaults to block style

        antipole_regs = self.config.get_antipole_regs(self.device)
        computed_fields = self.config.get_computed_fields(self.device)

        yaml = YAML()
        yaml.indent(sequence=4, offset=2)
        data = CM()
        data["registers"] = CM()

        for reg in self.regs.registers:
            if not raw and reg.name in antipole_regs.values():
                continue
            reg_yml = CM()
            reg_yml.yaml_set_start_comment("Reg Description:" + reg.description)
            reg_yml.insert(1, "name", reg.name, comment="The name of the register")
            data["registers"][reg.name] = reg_yml
            if len(reg.get_bitfields()) > 0:
                btf_yml = CM()
                reg_yml["bitfields"] = btf_yml
                for i, bitf in enumerate(reg.get_bitfields()):
                    if not raw and reg.name in computed_fields.keys() and bitf.name in computed_fields[reg.name].keys():
                        continue
                    possible_values = ""
                    if bitf.has_enums():
                        # print the comments as a hint of possible values
                        possible_values = f", (Possible values: {', '.join(bitf.get_enum_names())})"
                    btf_yml.insert(i,
                                   bitf.name,
                                   bitf.get_enum_value(),
                                   comment=f"The width: {bitf.width} bits{possible_values}")
            else:
                reg_yml.insert(2, "value", reg.get_hex_value(), comment="The value of the register")

        with open(file_name, "w") as out_file:
            yaml.dump(data, out_file)

    def load_yml_config(self, file_name: str, raw: bool = False) -> None:
        """The function loads the configuration from YML file.

        :param file_name: The file_name (without extension) of stored configuration.
        :param raw: Raw input of configuration (including computed fields and anti-pole registers)
        :raise SPSDKError: When the configuration file not found.
        """
        antipole_regs = self.config.get_antipole_regs(self.device)
        computed_fields = self.config.get_computed_fields(self.device)
        try:
            with open(file_name, "r") as yml_config_file:
                yaml = YAML()
                yaml.indent(sequence=4, offset=2)
                data = yaml.load(yml_config_file)
        except FileNotFoundError:
            raise SPSDKError("File with YML configuration doesn't exists.")

        for reg in data["registers"].keys():
            if not raw and reg in antipole_regs.values():
                continue
            if reg not in self.regs.get_reg_names():
                continue
            #The loaded register is our
            if "value" in data["registers"][reg].keys():
                val = data['registers'][reg]['value']
                val = val.replace("0x", "")
                self.regs.find_reg(reg).set_value(bytes.fromhex(val))
            elif "bitfields" in data["registers"][reg].keys():
                for bitf_name in data["registers"][reg]["bitfields"]:
                    try:
                        self.regs.find_reg(reg).find_bitfield(bitf_name)
                    except BitfieldNotFound:
                        continue
                    if not raw and reg in computed_fields.keys() and bitf_name in computed_fields[reg].keys():
                        continue
                    bitf = self.regs.find_reg(reg).find_bitfield(bitf_name)
                    if bitf.has_enums():
                        #solve the bitfields store in enums string
                        bitf.set_enum_value(data["registers"][reg]["bitfields"][bitf_name])
                    else:
                        #load bitfield data
                        bitf.set_value(int(data["registers"][reg]["bitfields"][bitf_name]))
            else:
                logger.error(f"There are no data for {reg} register.")

            if not raw and reg in computed_fields.keys():
                # Check the computed fields
                for field in computed_fields[reg].keys():
                    val = self.regs.find_reg(reg).get_value()
                    if hasattr(self, computed_fields[reg][field]):
                        method = getattr(self, computed_fields[reg][field], None)
                        computed_val = method(val)
                        self.regs.find_reg(reg).set_value(computed_val)
                    else:
                        raise SPSDKError(f"The '{computed_fields[reg][field]}' compute function doesn't exists.")

            if not raw and reg in antipole_regs.keys():
                #Write also anti-pole value
                val = self.regs.find_reg(reg).get_value()
                self.regs.find_reg(antipole_regs[reg]).set_value(self.antipolize_reg(val))

            logger.debug(f"The register {reg} has been loaded from configuration.")

    @staticmethod
    def antipolize_reg(val: bytes) -> bytes:
        """Antipolize given register value.

        :param val: Input register value.
        :return: Antipolized value.
        """
        newval = [0]*len(val)
        for i, val_byte in enumerate(val):
            newval[i] = val_byte ^ 0xFF
        return bytes(newval)

    # CRC8 - ITU
    @staticmethod
    def crc_update(data: bytes, crc: int = 0, is_final: bool = True) -> int:
        """The function compute the CRC8 ITU method from given bytes.

        :param data: Input data to compute CRC.
        :param crc: The seed for CRC.
        :param is_final: The flag the the function should retrn final result.
        :return: The CRC result.
        """
        k = 0
        data_len = len(data)
        while data_len != 0:
            data_len -= 1
            c = data[k]
            k += 1
            for i in range(8):
                bit = (crc & 0x80) != 0
                if (c & (0x80>>i)) != 0:
                    bit = not bit
                crc <<= 1
                if bit:
                    crc ^= 0x07
            crc &= 0xff
        if is_final:
            return (crc & 0xff) ^ 0x55
        else:
            return crc & 0xff


    def comalg_dcfg_cc_socu_crc8(self, val: bytes) -> bytes:
        """Function that creates the crc for DCFG_CC_SOCU.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with computed CRC8 field.
        """
        ret = [0]*4
        ret[0:3] = val[0:3]
        input = bytearray(val[0:3])
        input.reverse()
        ret[3] = self.crc_update(input)
        return bytes(ret)

    def comalg_dcfg_cc_socu_rsvd(self, val: bytes) -> bytes:
        """Function fill up the DCFG_CC_SOCU RSVD filed by 0x40 to satisfy MCU needs.

        :param val: Input DCFG_CC_SOCU Value.
        :return: Returns the value of DCFG_CC_SOCU with computed CRC8 field.
        """
        new_val = bytearray(val)
        new_val[0] &= ~0xFE
        new_val[0] |= 0x40
        return new_val

    def comalg_do_nothig(self, val: bytes) -> bytes:
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
            dbg_mlbx = DebugMailbox(debug_probe=probe)
            StartDebugSession(dm=dbg_mlbx).run()

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

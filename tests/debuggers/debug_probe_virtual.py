#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Virtual Debug probes support used for product testing."""

import json
import logging
from json.decoder import JSONDecodeError
import struct
from typing import Any

from spsdk.debuggers.debug_probe import (
    DebugProbe,
    DebugProbes,
    ProbeDescription,
    SPSDKDebugProbeError,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
)

logger = logging.getLogger(__name__)


class DebugProbeVirtual(DebugProbe):
    """Class to define Virtual package interface for NXP SPSDK."""

    UNIQUE_SERIAL = "Virtual_DebugProbe_SPSDK"

    def __init__(self, hardware_id: str, options: dict = None) -> None:
        """The Virtual class initialization.

        The Virtual initialization function for SPSDK library to support various DEBUG PROBES.
        """
        super().__init__(hardware_id, options)

        self.opened = False
        self.connected = False
        self.virtual_memory: dict[Any, Any] = {}
        self.virtual_memory_substituted: dict[Any, Any] = {}
        self.coresight_ap: dict[Any, Any] = {}
        self.coresight_ap_substituted: dict[Any, Any] = {}
        self.coresight_dp: dict[Any, Any] = {}
        self.coresight_ap_write_exception = 0
        self.coresight_dp_write_exception = 0
        self.coresight_mem_read_exception = 0
        self.coresight_dp_substituted: dict[Any, Any] = {}

        if options is not None:
            if "exc" in options.keys():
                raise SPSDKDebugProbeError("Forced exception from constructor.")
            if "subs_ap" in options.keys():
                self.set_coresight_ap_substitute_data(
                    self._load_subs_from_param(options["subs_ap"])
                )
            if "subs_dp" in options.keys():
                self.set_coresight_dp_substitute_data(
                    self._load_subs_from_param(options["subs_dp"])
                )
            if "subs_mem" in options.keys():
                self.set_virtual_memory_substitute_data(
                    self._load_subs_from_param(options["subs_mem"])
                )
            if "mem_read_exp" in options.keys():
                self.mem_read_cause_exception(self._load_subs_from_param(options["mem_read_exp"]))

        # setup IDR register of standard AP:
        self.coresight_ap[DebugProbe.get_coresight_ap_address(2, 0xFC)] = 0x002A0000

        logger.debug("The SPSDK Virtual Interface has been initialized")

    def mem_block_write(self, addr: int, data: bytes) -> None:
        """Write a block of data to memory using 32-bit values."""
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("Debug probe is not opened.")

        if not 0 <= addr < (2**32) - 3:
            raise SPSDKDebugProbeError("Invalid address: must be a 32-bit value")

        # Pad data to multiple of 4 bytes if necessary
        padded_data = data + b"\x00" * ((4 - len(data) % 4) % 4)

        for i in range(0, len(padded_data), 4):
            word = struct.unpack("<I", padded_data[i : i + 4])[0]
            self.virtual_memory[(addr + i) // 4] = word

    def mem_block_read(self, addr: int, size: int) -> bytes:
        """Read a block of data from memory using 32-bit values."""
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("Debug probe is not opened.")

        if not 0 <= addr < (2**32) - 3:
            raise SPSDKDebugProbeError("Invalid address: must be a 32-bit value")

        result = bytearray()
        for i in range(0, size, 4):
            word = self.virtual_memory.get((addr + i) // 4, 0)
            result.extend(struct.pack("<I", word))

        return bytes(result[:size])

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None, options: dict = None) -> list:
        """Get all connected probes over Virtual.

        This functions returns the list of all connected probes in system by Virtual package.
        :param hardware_id: None to list all probes, otherwise the the only probe with matching
            hardware id is listed.
        :param options: The options dictionary
        :return: probe_description
        :raises SPSDKDebugProbeError: In case of invoked test Exception.
        """
        probes = DebugProbes()

        if options is not None and "exc" in options.keys():
            raise SPSDKDebugProbeError("Forced exception from discovery function.")

        # Find this 'probe' just in case of direct request (user must know the hardware id :-) )
        if hardware_id == DebugProbeVirtual.UNIQUE_SERIAL:
            probes.append(
                ProbeDescription(
                    "Virtual",
                    DebugProbeVirtual.UNIQUE_SERIAL,
                    "Special virtual debug probe used for product testing",
                    DebugProbeVirtual,
                )
            )
        return probes

    def open(self) -> None:
        """Open Virtual interface for NXP SPSDK.

        The Virtual opening function for SPSDK library to support various DEBUG PROBES.
        """
        self.opened = True

    def connect(self) -> None:
        """Connect to target.

        The Virtual connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.
        """
        self.connected = True

    def close(self) -> None:
        """Close Virtual interface.

        The Virtual closing function for SPSDK library to support various DEBUG PROBES.
        """
        self.connected = False
        self.opened = False

    def _get_requested_value(self, values: dict, subs_values: dict, addr: Any) -> int:
        """Method to return back the requested value.

        :param values: The dictionary with already loaded values.
        :param subs_values: The dictionary with substituted values.
        :param addr: Address of value.
        :return: Value by address.
        :raises SPSDKDebugProbeError: General virtual probe error.
        """
        if subs_values and addr in subs_values.keys():
            if len(subs_values[addr]) > 0:
                svalue = subs_values[addr].pop()
                if isinstance(svalue, int):
                    return svalue
                if isinstance(svalue, str) and svalue == "Exception":
                    raise SPSDKDebugProbeError("Simulated Debug probe exception")

        return int(values[addr]) if addr in values.keys() else 0

    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened
        :raises SPSDKDebugProbeError: General virtual probe error.
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if self.coresight_mem_read_exception > 0:
            self.coresight_mem_read_exception -= 1
            raise SPSDKDebugProbeTransferError("The Coresight memory read operation failed.")

        return self._get_requested_value(self.virtual_memory, self.virtual_memory_substituted, addr)

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.
        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        self.virtual_memory[addr] = data

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over Virtual interface.

        The Virtual read coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened
        :raises SPSDKDebugProbeError: General virtual probe error.
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")
        # As first try to solve AP requests
        if access_port:
            return self._get_requested_value(self.coresight_ap, self.coresight_ap_substituted, addr)

        # DP requests
        return self._get_requested_value(self.coresight_dp, self.coresight_dp_substituted, addr)

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register over Virtual interface.

        The Virtual write coresight register function for SPSDK library to support various DEBUG PROBES.
        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeTransferError: The IO operation failed
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if access_port:
            if self.coresight_ap_write_exception > 0:
                self.coresight_ap_write_exception -= 1
                raise SPSDKDebugProbeTransferError("The Coresight write operation failed.")
            self.coresight_ap[addr] = data
        else:
            if self.coresight_dp_write_exception > 0:
                self.coresight_dp_write_exception -= 1
                raise SPSDKDebugProbeTransferError("The Coresight write operation failed.")
            self.coresight_dp[addr] = data

    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted(pulled down), if False the reset line is not affected.
        """
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        logger.debug(
            f"The Virtual probe {'de-' if not assert_reset else ''}assert reset line  of virtual target."
        )

    def reset(self) -> None:
        """Reset a target.

        It resets a target.
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened
        """
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        logger.debug("The Virtual probe did reset of virtual target.")

    def clear(self, only_substitute: bool = False) -> None:
        """Clear the buffered values.

        :param only_substitute: When set, it clears just substitute data.
        """
        if not only_substitute:
            self.coresight_dp.clear()
            self.coresight_ap.clear()
            self.virtual_memory.clear()

        self.coresight_dp_substituted.clear()
        self.coresight_ap_write_exception = 0
        self.coresight_dp_write_exception = 0
        self.coresight_mem_read_exception = 0
        self.coresight_ap_substituted.clear()
        self.virtual_memory_substituted.clear()

    def set_virtual_memory_substitute_data(self, substitute_data: dict) -> None:
        """Set the virtual memory read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.virtual_memory_substituted = substitute_data

    def set_coresight_dp_substitute_data(self, substitute_data: dict) -> None:
        """Set the virtual memory read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.coresight_dp_substituted = substitute_data

    def set_coresight_ap_substitute_data(self, substitute_data: dict) -> None:
        """Set the coresight AP read substitute data.

        :param substitute_data: Dictionary of list of substitute data.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()

        self.coresight_ap_substituted = substitute_data

    def dp_write_cause_exception(self, count: int = 1) -> None:
        """Attempt to write to DP register cause exception.

        :param count: number of exception in row.
        """
        self.coresight_dp_write_exception = count

    def ap_write_cause_exception(self, count: int = 1) -> None:
        """Attempt to write to AP register cause exception.

        :param count: number of exception in row.
        """
        self.coresight_ap_write_exception = count

    def mem_read_cause_exception(self, count: int = 1) -> None:
        """Attempt to memory read cause exception.

        :param count: number of exception in row.
        """
        self.coresight_mem_read_exception = count

    def _load_subs_from_param(self, arg: str) -> dict:
        """Get the substituted values from input arguments.

        :param arg: Input string arguments with substitute values.
        :return: List of values for the substituted values.
        :raises SPSDKDebugProbeError: The input string is not able do parse.
        """
        try:
            subs_data_raw = json.loads(arg)
            subs_data = {}
            for key in subs_data_raw.keys():
                subs_data[int(key)] = subs_data_raw[key]
            return subs_data
        except (TypeError, JSONDecodeError) as exc:
            raise SPSDKDebugProbeError(f"Cannot parse substituted values: ({str(exc)})")

    def debug_halt(self) -> None:
        """Halt the CPU execution."""
        pass

    def debug_resume(self) -> None:
        """Resume the CPU execution."""
        pass

    def debug_step(self) -> None:
        """Step the CPU execution."""
        pass

    def read_dp_idr(self) -> int:
        """Read Debug port identification register."""
        return 0x12345678

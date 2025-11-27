#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Virtual Debug Probe implementation for testing.

This module provides a virtual debug probe implementation used for product testing
and development scenarios where physical debug hardware is not available or needed.
The virtual probe simulates debug operations through JSON-based communication.
"""

import json
import logging
import struct
from json.decoder import JSONDecodeError
from typing import Any, Optional

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
    """Virtual debug probe implementation for SPSDK testing and simulation.

    This class provides a software-based debug probe that simulates hardware debug probe
    functionality for testing purposes. It supports memory substitution, CoreSight AP/DP
    register simulation, and configurable exception scenarios to enable comprehensive
    testing of SPSDK debug operations without requiring physical hardware.

    :cvar UNIQUE_SERIAL: Default serial identifier for virtual debug probe instances.
    """

    UNIQUE_SERIAL = "Virtual_DebugProbe_SPSDK"

    def __init__(self, hardware_id: str, options: Optional[dict[Any, Any]] = None) -> None:
        """Initialize Virtual debug probe for testing and simulation.

        Creates a virtual debug probe instance that simulates hardware debug probe functionality
        for testing purposes. Supports memory substitution, CoreSight AP/DP register simulation,
        and configurable exception scenarios.

        :param hardware_id: Unique identifier for the virtual hardware probe.
        :param options: Optional configuration dictionary supporting keys: 'exc' (force constructor exception),
             'subs_ap' (AP register substitutions), 'subs_dp' (DP register substitutions),
             'subs_mem' (memory substitutions), 'mem_read_exp' (memory read exception trigger).
        :raises SPSDKDebugProbeError: When 'exc' option is provided to force exception during initialization.
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
                self.mem_read_cause_exception(int(options["mem_read_exp"]))

        # setup IDR register of standard AP:
        self.coresight_ap[DebugProbe.get_coresight_ap_address(2, 0xFC)] = 0x002A0000

        logger.debug("The SPSDK Virtual Interface has been initialized")

    def mem_block_write(self, addr: int, data: bytes) -> None:
        """Write a block of data to memory using 32-bit values.

        The method writes data to virtual memory by padding it to 4-byte alignment
        and storing it as 32-bit words in little-endian format.

        :param addr: Memory address to write to (must be within 32-bit range).
        :param data: Binary data to write to memory.
        :raises SPSDKDebugProbeNotOpenError: Debug probe is not opened.
        :raises SPSDKDebugProbeError: Invalid address provided.
        """
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
        """Read a block of data from memory using 32-bit values.

        Reads data from the virtual memory in 4-byte chunks and returns the requested
        number of bytes. The method accesses virtual memory using word-aligned addresses
        and packs the data in little-endian format.

        :param addr: Memory address to read from (must be valid 32-bit address).
        :param size: Number of bytes to read from memory.
        :raises SPSDKDebugProbeNotOpenError: Debug probe is not opened.
        :raises SPSDKDebugProbeError: Invalid address provided.
        :return: Block of data read from memory.
        """
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
    def get_connected_probes(
        cls, hardware_id: Optional[str] = None, options: Optional[dict[Any, Any]] = None
    ) -> DebugProbes:
        """Get all connected probes over Virtual.

        This function returns the list of all connected probes in system by Virtual package.
        For testing purposes, it can return a virtual debug probe when the correct hardware ID
        is provided, or raise an exception when specified in options.

        :param hardware_id: None to list all probes, otherwise only the probe with matching
            hardware ID is listed.
        :param options: The options dictionary that may contain 'exc' key to force an exception.
        :return: Collection of available debug probes.
        :raises SPSDKDebugProbeError: In case of invoked test exception.
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
        This method sets the interface state to opened without performing any actual hardware operations.
        """
        self.opened = True

    def connect(self) -> None:
        """Connect to target.

        Establishes a virtual connection to the target device for debugging purposes.
        This virtual implementation simulates the connection process by setting the
        connected state to True, enabling the debug probe for DAT (Debug Authentication Tool) operations.
        """
        self.connected = True

    def connect_safe(self) -> None:
        """Connect to target in safe manner.

        The Virtual connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.
        """
        self.connect()

    def close(self) -> None:
        """Close the virtual debug probe interface.

        Sets the connection and opened status flags to False, effectively
        disconnecting the virtual debug probe from the SPSDK library.
        """
        self.connected = False
        self.opened = False

    def _get_requested_value(self, values: dict, subs_values: dict, addr: Any) -> int:
        """Get the requested value from values or substituted values dictionary.

        The method first checks if the address exists in substituted values and returns
        the popped value. If the substituted value is "Exception", it raises an error.
        Otherwise, it returns the value from the main values dictionary or 0 if not found.

        :param values: The dictionary with already loaded values.
        :param subs_values: The dictionary with substituted values that take priority.
        :param addr: Address of the requested value.
        :return: Value found at the specified address, or 0 if address not found.
        :raises SPSDKDebugProbeError: When substituted value is "Exception" string.
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

        This method reads a 32-bit register from the memory space of the MCU using
        the virtual debug probe interface.

        :param addr: The register address to read from.
        :raises SPSDKDebugProbeNotOpenError: The virtual probe is not opened.
        :raises SPSDKDebugProbeTransferError: The coresight memory read operation failed.
        :return: The read value of addressed register (4 bytes).
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        if self.coresight_mem_read_exception > 0:
            self.coresight_mem_read_exception -= 1
            raise SPSDKDebugProbeTransferError("The Coresight memory read operation failed.")

        return self._get_requested_value(self.virtual_memory, self.virtual_memory_substituted, addr)

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This method writes a 32-bit data value to a specified memory address
        in the virtual MCU memory space for debug probe simulation.

        :param addr: The register address to write to.
        :param data: The 32-bit data value to be written into the register.
        :raises SPSDKDebugProbeNotOpenError: The virtual debug probe is not opened or connected.
        """
        if not (self.opened and self.connected):
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        self.virtual_memory[addr] = data

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register over Virtual interface.

        The Virtual read coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: If True, the Access Port (AP) register will be read (default), otherwise
            the Debug Port register will be read.
        :param addr: The register address.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: The IO operation failed.
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is NOT opened.
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

        :param access_port: If True, the Access Port (AP) register will be written (default),
            otherwise the Debug Port (DP) register will be written.
        :param addr: The register address.
        :param data: The data to be written into register.
        :raises SPSDKDebugProbeTransferError: The IO operation failed.
        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is not opened.
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

        :param assert_reset: If True, the reset line is asserted (pulled down), if False the reset line is not affected.
        :raises SPSDKDebugProbeNotOpenError: When the debug probe is not opened yet.
        """
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        logger.debug(
            f"The Virtual probe {'de-' if not assert_reset else ''}assert reset line  of virtual target."
        )

    def reset(self) -> None:
        """Reset the target device.

        Performs a reset operation on the virtual target device through the debug probe.

        :raises SPSDKDebugProbeNotOpenError: The Virtual probe is not opened yet.
        """
        if not self.opened:
            raise SPSDKDebugProbeNotOpenError("The Virtual debug probe is not opened yet")

        logger.debug("The Virtual probe did reset of virtual target.")

    def clear(self, only_substitute: bool = False) -> None:
        """Clear the buffered values.

        The method clears buffered data from CoreSight DP/AP and virtual memory.
        When only_substitute is True, it preserves the main buffers and only
        clears substitute data and resets exception counters.

        :param only_substitute: When set, it clears just substitute data and exceptions.
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

        The method reverses each list in the substitute data dictionary to prepare
        it for memory read operations in LIFO order.

        :param substitute_data: Dictionary where keys are memory addresses or identifiers
                               and values are lists of substitute data bytes to be returned
                               during virtual memory reads.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.virtual_memory_substituted = substitute_data

    def set_coresight_dp_substitute_data(self, substitute_data: dict) -> None:
        """Set the virtual memory read substitute data.

        The method reverses each list in the substitute data dictionary to prepare
        the data for consumption during virtual debug operations.

        :param substitute_data: Dictionary containing lists of substitute data values
                               that will be used during virtual memory operations.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()
        self.coresight_dp_substituted = substitute_data

    def set_coresight_ap_substitute_data(self, substitute_data: dict) -> None:
        """Set the coresight AP read substitute data.

        The method reverses the order of data lists in the substitute data dictionary
        to prepare them for consumption during debug operations.

        :param substitute_data: Dictionary containing lists of substitute data values
                               for coresight Access Port operations. The lists will be
                               reversed in-place to match expected consumption order.
        """
        for key in substitute_data.keys():
            substitute_data[key].reverse()

        self.coresight_ap_substituted = substitute_data

    def dp_write_cause_exception(self, count: int = 1) -> None:
        """Configure the debug probe to simulate DP write exceptions.

        This method sets up the virtual debug probe to throw exceptions when attempting
        to write to Debug Port (DP) registers for testing error handling scenarios.

        :param count: Number of consecutive exceptions to simulate.
        """
        self.coresight_dp_write_exception = count

    def ap_write_cause_exception(self, count: int = 1) -> None:
        """Configure the debug probe to simulate AP write exceptions.

        This method sets up the virtual debug probe to throw exceptions when attempting
        to write to Access Port (AP) registers, useful for testing error handling scenarios.

        :param count: Number of consecutive exceptions to simulate when writing to AP registers.
        """
        self.coresight_ap_write_exception = count

    def mem_read_cause_exception(self, count: int = 1) -> None:
        """Configure memory read operations to cause exceptions for testing purposes.

        This method sets up the debug probe to simulate memory read failures by causing
        a specified number of consecutive exceptions during memory read operations.

        :param count: Number of consecutive exceptions to trigger during memory reads.
        """
        self.coresight_mem_read_exception = count

    def _load_subs_from_param(self, arg: str) -> dict:
        """Get the substituted values from input arguments.

        Parses JSON string containing substitution values and converts string keys to integer keys.

        :param arg: Input JSON string with substitute values where keys should be numeric.
        :raises SPSDKDebugProbeError: The input string cannot be parsed as valid JSON.
        :return: Dictionary with integer keys and corresponding substitution values.
        """
        try:
            subs_data_raw = json.loads(arg)
            subs_data = {}
            for key in subs_data_raw.keys():
                subs_data[int(key)] = subs_data_raw[key]
            return subs_data
        except (TypeError, JSONDecodeError) as exc:
            raise SPSDKDebugProbeError(f"Cannot parse substituted values: ({str(exc)})") from exc

    def debug_halt(self) -> None:
        """Halt the CPU execution.

        This method stops the processor from executing instructions, putting it into
        a halted state where debugging operations can be performed safely.

        :raises SPSDKError: If the debug probe fails to halt the CPU.
        """

    def debug_resume(self) -> None:
        """Resume the CPU execution.

        This method resumes the execution of the CPU that was previously halted
        or paused during debugging operations.
        """

    def debug_step(self) -> None:
        """Step the CPU execution by one instruction.

        This method advances the CPU execution by a single instruction step,
        allowing for detailed debugging and instruction-level control of the target processor.
        """

    def read_dp_idr(self) -> int:
        """Read Debug port identification register.

        :return: Debug port identification register value as a 32-bit integer.
        """
        return 0x12345678

    def coresight_reg_read_safe(
        self, access_port: bool = True, addr: int = 0, max_retries: int = 3
    ) -> int:
        """Read CoreSight register with retry mechanism.

        This method provides a safe wrapper around coresight_reg_read with built-in
        retry logic for improved reliability in production environments.

        :param access_port: True for Access Port register, False for Debug Port register.
        :param addr: Register address to read from.
        :param max_retries: Maximum number of retry attempts on failure.
        :return: Register value read from the specified address.
        """
        return self.coresight_reg_read(access_port=access_port, addr=addr)

    def coresight_reg_write_safe(
        self, access_port: bool = True, addr: int = 0, data: int = 0, max_retries: int = 3
    ) -> None:
        """Write CoreSight register data with retry mechanism for safety.

        This method provides a safe wrapper around coresight_reg_write by implementing
        a retry mechanism, though the current implementation doesn't utilize the retry
        functionality yet.

        :param access_port: True for Access Port register, False for Debug Port register.
        :param addr: Register address to write to.
        :param data: Data value to write to the register.
        :param max_retries: Maximum number of retry attempts (currently unused).
        """
        self.coresight_reg_write(access_port=access_port, addr=addr, data=data)

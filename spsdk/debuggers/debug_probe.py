#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

import functools
import logging
from abc import ABC, abstractmethod
from time import sleep
from typing import Optional, Type, no_type_check

import colorama
import prettytable

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Timeout, value_to_int

logger = logging.getLogger(__name__)

# Debugging options
DISABLE_AP_SELECT_CACHING = False


class SPSDKDebugProbeError(SPSDKError):
    """The general issue with debug probe exception for use with SPSDK."""


class SPSDKProbeNotFoundError(SPSDKDebugProbeError):
    """The Probe not found exception for use with SPSDK."""


class SPSDKMultipleProbesError(SPSDKDebugProbeError):
    """Multiple probes found exception for use with SPSDK."""


class SPSDKDebugProbeTransferError(SPSDKDebugProbeError):
    """The communication error exception for use with SPSDK."""


class SPSDKDebugProbeNotOpenError(SPSDKDebugProbeError):
    """The debug probe is not opened exception for use with SPSDK."""


class DebugProbe(ABC):
    """Abstraction class to define SPSDK debug probes interface."""

    NAME = "Abstract"

    # Constants to detect the debug mailbox access port
    APBANKSEL = 0x000000F0
    APBANK_SHIFT = 4
    APADDR = 0x00FFFFFF
    APSEL = 0xFF000000
    APSEL_SHIFT = 24
    APSEL_APBANKSEL = APSEL | APBANKSEL

    DP_IDR_REG = 0x00  # Read access
    DP_ABORT_REG = 0x00  # Write Access
    DP_CTRL_STAT_REG = 0x04

    AP_IDR_REG = 0xFC

    CSYSPWRUPACK = 0x80 << 24
    CSYSPWRUPREQ = 0x40 << 24
    CDBGPWRUPACK = 0x20 << 24
    CDBGPWRUPREQ = 0x10 << 24
    MASKLANE = 0x0F << 8

    # Constants for DHCSR, Debug Halting Control and Status Register
    DHCSR_REG = 0xE000EDF0
    DHCSR_DEBUGKEY = 0xA05F0000
    DHCSR_C_DEBUGEN = 0x1
    DHCSR_C_HALT = 0x2
    DHCSR_C_STEP = 0x4

    RESET_TIME = 0.1
    AFTER_RESET_TIME = 0.05

    def __init__(self, hardware_id: str, options: Optional[dict] = None) -> None:
        """This is general initialization function for SPSDK library to support various DEBUG PROBES.

        :param hardware_id: Open probe with selected hardware ID
        :param options: The options dictionary
        """
        self.hardware_id = hardware_id
        self.options = options or {}
        self.family = None
        family = self.options.pop("family", None)
        revision = self.options.pop("revision", None)
        if family:
            self.family = FamilyRevision(family, revision)
        self.mem_ap_ix = -1

    @classmethod
    @abstractmethod
    def get_connected_probes(
        cls, hardware_id: Optional[str] = None, options: Optional[dict] = None
    ) -> "DebugProbes":
        """Functions returns the list of all connected probes in system.

        There is option to look for just for one debug probe defined by its hardware ID.

        :param hardware_id: None to list all probes, otherwise the the only probe with
            matching hardware id is listed.
        :param options: The options dictionary
        :return: List of ProbeDescription
        """

    @classmethod
    def get_options_help(cls) -> dict[str, str]:
        """Get full list of options of debug probe.

        :return: Dictionary with individual options. Key is parameter name and value the help text.
        """
        return {
            "test_address": "Address for testing memory AP, default "
            "is tested address in RAM MCU memory range",
            "enable_recovery_reset": "Enable hardware reset during debug connection recovery. "
            "WARNING: This will restart the target chip and lose current state (default: False)",
        }

    @staticmethod
    def get_coresight_ap_address(access_port: int, address: int) -> int:
        """Return computed address of coresight access port register.

        :param access_port: Index of access port 0-255.
        :param address: Register address.
        :return: Coresight address.
        :raises SPSDKError: In case of invalid value.
        """
        if access_port > 255:
            raise SPSDKValueError("Invalid value of access port")

        return access_port << DebugProbe.APSEL_SHIFT | address

    @abstractmethod
    def open(self) -> None:
        """Debug probe open.

        General opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to opening the debug probe
        """

    @abstractmethod
    def connect(self) -> None:
        """Debug probe connect.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target
        """

    @abstractmethod
    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target
        """

    @abstractmethod
    def close(self) -> None:
        """Debug probe close.

        This is general closing function for SPSDK library to support various DEBUG PROBES.
        """

    @abstractmethod
    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: The register address
        :return: The read value of addressed register (4 bytes)
        """

    @abstractmethod
    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        """

    @abstractmethod
    def mem_block_read(self, addr: int, size: int) -> bytes:
        """Read a block of memory from the MCU.

        This method handles non-aligned addresses and sizes, providing flexibility
        for various memory operations.

        :param addr: The starting address to read from.
        :param size: The number of bytes to read.
        :return: The read data as a bytes object.
        :raises SPSDKDebugProbeError: If there's an error during the read operation.
        """

    @abstractmethod
    def mem_block_write(self, addr: int, data: bytes) -> None:
        """Write a block of memory to the MCU.

        This method handles non-aligned addresses and sizes, allowing for flexible
        memory write operations.

        :param addr: The starting address to write to.
        :param data: The data to be written, as a bytes object.
        :raises SPSDKDebugProbeError: If there's an error during the write operation.
        """

    @abstractmethod
    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register.

        It reads coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        """

    @abstractmethod
    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register.

        It writes coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        """

    @abstractmethod
    def coresight_reg_read_safe(
        self, access_port: bool = True, addr: int = 0, max_retries: int = 3
    ) -> int:
        """Safe coresight register read with error handling and recovery.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :param max_retries: Maximum number of retry attempts
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail
        """

    @abstractmethod
    def coresight_reg_write_safe(
        self, access_port: bool = True, addr: int = 0, data: int = 0, max_retries: int = 3
    ) -> None:
        """Internal coresight register write with error handling and recovery.

        :param access_port: if True, the Access Port (AP) register will be written(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :param max_retries: Maximum number of retry attempts
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail
        """

    @abstractmethod
    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted(pulled down), if False the reset line is not affected.
        """

    def reset(self) -> None:
        """Reset a target.

        It resets a target.
        """
        self.assert_reset_line(True)
        sleep(self.RESET_TIME)
        self.assert_reset_line(False)
        sleep(self.AFTER_RESET_TIME)

    @abstractmethod
    def read_dp_idr(self) -> int:
        """Read Debug port identification register."""

    @abstractmethod
    def debug_halt(self) -> None:
        """Halt the CPU execution."""

    @abstractmethod
    def debug_resume(self) -> None:
        """Resume the CPU execution."""

    @abstractmethod
    def debug_step(self) -> None:
        """Step the CPU execution."""


class DebugProbeCoreSightOnly(DebugProbe):
    """Abstraction class to define SPSDK debug probes interface."""

    NAME = "local_help"

    # Add these class constants
    # Control/Status Word (CSW) bit definitions for size
    CSW_SIZE_8BIT = 0x00000000  # 8-bit size
    CSW_SIZE_16BIT = 0x00000001  # 16-bit size
    CSW_SIZE_32BIT = 0x00000002  # 32-bit size

    # Control/Status Word (CSW) bit definitions for address increment
    CSW_ADDRINC_OFF = 0x00000000  # No address increment
    CSW_ADDRINC_SINGLE = 0x00000010  # Single address increment
    CSW_ADDRINC_PACKED = 0x00000020  # Packed address increment

    # Control/Status Word (CSW) other bit definitions
    CSW_DEVICEEN = 0x00000040  # Device enable
    CSW_TRINPROG = 0x00000080  # Transfer in progress
    CSW_HPROT = 0x02000000  # Hprot
    CSW_MASTER_DEBUG = 0x20000000  # Master debug
    CSW_DBGSWENABLE = 0x80000000  # Debug software enable

    CSW_FULL_DEBUG = (
        CSW_MASTER_DEBUG
        | CSW_HPROT
        | CSW_DEVICEEN
        | CSW_DBGSWENABLE
        | CSW_SIZE_32BIT
        | CSW_ADDRINC_SINGLE
    )  # Enables full debug capabilities with 32-bit access and single address increment

    # Constants for register addresses
    CSW_REG = 0x00
    TAR_REG = 0x04
    DRW_REG = 0x0C

    # Add these new DP_CTRL_STAT register bit definitions
    DP_CTRL_STAT_STICKYORUN = 0x02  # Sticky Overrun Error
    DP_CTRL_STAT_STICKYCMP = 0x10  # Sticky Compare Error
    DP_CTRL_STAT_STICKYERR = 0x20  # Sticky Error
    DP_CTRL_STAT_READOK = 0x40  # Read OK
    DP_CTRL_STAT_WDATAERR = 0x80  # Write Data Error

    # Combined error mask for all sticky error flags
    DP_CTRL_STAT_ERROR_MASK = (
        DP_CTRL_STAT_STICKYORUN
        | DP_CTRL_STAT_STICKYCMP
        | DP_CTRL_STAT_STICKYERR
        | DP_CTRL_STAT_WDATAERR
    )  # 0xB2

    def __init__(self, hardware_id: str, options: Optional[dict[str, str]] = None) -> None:
        """This is general initialization function for SPSDK library to support various DEBUG PROBES.

        :param hardware_id: Open probe with selected hardware ID
        :param options: The options dictionary
        """
        super().__init__(hardware_id, options)
        self.last_accessed_ap = -1
        self.disable_reinit = (
            False  # Keep it here to backward compatibility with debug probe plugins
        )

    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target
        """
        try:
            self.connect()
        except Exception as e:
            if self.recover_debug_connection():
                self.connect()
                return
            raise e

    def coresight_reg_write_safe(
        self, access_port: bool = True, addr: int = 0, data: int = 0, max_retries: int = 3
    ) -> None:
        """Internal coresight register write with error handling and recovery.

        :param access_port: if True, the Access Port (AP) register will be written(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :param max_retries: Maximum number of retry attempts
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(max_retries):
            try:
                # Call the concrete implementation (to be implemented by subclasses)
                self.coresight_reg_write(access_port, addr, data)
                return  # Success

            except SPSDKDebugProbeTransferError as e:
                last_exception = e
                logger.debug(
                    f"CoreSight register write failed (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:  # Don't recover on last attempt
                    try:
                        logger.debug("Attempting debug connection recovery")
                        if self.recover_debug_connection():
                            logger.debug("Recovery successful, retrying operation")
                            continue
                        else:
                            logger.warning(
                                "CoreSight register write failed and recovery failed also :-("
                            )
                    except Exception as recovery_error:
                        logger.debug(f"Recovery attempt failed: {recovery_error}")

            except Exception as e:
                # Handle unexpected errors
                last_exception = SPSDKDebugProbeTransferError(
                    f"Unexpected error during coresight write: {e}"
                )
                logger.error(f"Unexpected error in coresight register write: {e}")
                break

        # All attempts failed
        raise SPSDKDebugProbeTransferError(
            f"CoreSight register write failed after {max_retries} attempts. "
            f"Address: 0x{addr:08X}, Data: 0x{data:08X}, AP: {access_port}. Last error: {last_exception}"
        )

    def coresight_reg_read_safe(
        self, access_port: bool = True, addr: int = 0, max_retries: int = 3
    ) -> int:
        """Safe coresight register read with error handling and recovery.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :param max_retries: Maximum number of retry attempts
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(max_retries):
            try:
                # Call the concrete implementation (to be implemented by subclasses)
                return self.coresight_reg_read(access_port, addr)

            except SPSDKDebugProbeTransferError as e:
                last_exception = e
                logger.debug(
                    f"CoreSight register read failed (attempt {attempt + 1}/{max_retries}): {e}"
                )

                if attempt < max_retries - 1:  # Don't recover on last attempt
                    try:
                        logger.debug("Attempting debug connection recovery")
                        if self.recover_debug_connection():
                            logger.debug("Recovery successful, retrying operation")
                            continue
                        else:
                            logger.warning(
                                "CoreSight register read failed and recovery failed also :-("
                            )

                    except Exception as recovery_error:
                        logger.debug(f"Recovery attempt failed: {recovery_error}")

            except Exception as e:
                # Handle unexpected errors
                last_exception = SPSDKDebugProbeTransferError(
                    f"Unexpected error during coresight read: {e}"
                )
                logger.error(f"Unexpected error in coresight register read: {e}")
                break

        # All attempts failed
        raise SPSDKDebugProbeTransferError(
            f"CoreSight register read failed after {max_retries} attempts. "
            f"Address: 0x{addr:08X}, AP: {access_port}. Last error: {last_exception}"
        )

    @no_type_check
    # pylint: disable=no-self-argument,missing-type-doc
    def get_mem_ap(func):
        """Decorator function that secure the getting right MEM AP ix for first use.

        :param func: Decorated function.
        """
        POSSIBLE_MEM_AP_IX = [0, 1, 3]
        DEFAULT_TEST_MEM_AP_ADDRESS = 0x2000_0000

        @functools.wraps(func)
        def wrapper(self: "DebugProbeCoreSightOnly", *args, **kwargs):
            status = False
            test_address = value_to_int(
                self.options.get("test_address", DEFAULT_TEST_MEM_AP_ADDRESS)
            )
            if self.mem_ap_ix < 0:
                logger.debug(f"Trying MEM AP on address {hex(test_address)}")
                # Try to find MEM AP
                for i in POSSIBLE_MEM_AP_IX:
                    try:
                        idr = self.coresight_reg_read(
                            access_port=True,
                            addr=self.get_coresight_ap_address(
                                access_port=i, address=self.AP_IDR_REG
                            ),
                        )
                        # Extract IDR fields used for lookup. TODO solve that
                        ap_class = (idr & 0x1E000) >> 13
                        if ap_class == 8:
                            try:
                                # Enter debug state and halt
                                dhcsr_reg = self._mem_reg_read(mem_ap_ix=i, addr=self.DHCSR_REG)
                                logger.debug(f"Value of DHCSR register = {hex(dhcsr_reg)}")
                                self._mem_reg_write(
                                    mem_ap_ix=i,
                                    addr=self.DHCSR_REG,
                                    data=(
                                        self.DHCSR_DEBUGKEY
                                        | self.DHCSR_C_HALT
                                        | self.DHCSR_C_DEBUGEN
                                    ),
                                )
                                try:
                                    self._mem_reg_read(mem_ap_ix=i, addr=test_address)
                                    status = True
                                except SPSDKError:
                                    logger.debug(
                                        f"Read operation on AP{i} fails at {hex(test_address)} address"
                                    )
                                finally:
                                    # Exit debug state
                                    self._mem_reg_write(
                                        mem_ap_ix=i,
                                        addr=self.DHCSR_REG,
                                        data=dhcsr_reg,
                                    )
                                if not status:
                                    continue
                            except SPSDKError:
                                continue

                            self.mem_ap_ix = i
                            logger.debug(f"Found memory access port at AP{i}, IDR: 0x{idr:08X}")
                            break
                    except SPSDKError:
                        pass

                if self.mem_ap_ix < 0:
                    raise SPSDKDebugProbeError("The memory access port is not found!")
            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    def _mem_reg_read(self, mem_ap_ix: int, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param mem_ap_ix: The index of memory access port
        :param addr: The register address
        :return: The read value of addressed register (4 bytes)
        :raises SPSDKDebugProbeTransferError: Error occur during memory transfer.
        """
        try:
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.CSW_REG),
                data=self.CSW_FULL_DEBUG,
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.TAR_REG),
                data=addr,
            )

            return self.coresight_reg_read_safe(
                access_port=True, addr=self.get_coresight_ap_address(mem_ap_ix, self.DRW_REG)
            )
        except SPSDKError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed read memory({str(exc)})") from exc

    @get_mem_ap
    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: The register address
        :return: The read value of addressed register (4 bytes)
        """
        return self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=addr)

    def _mem_reg_write(self, mem_ap_ix: int, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param mem_ap_ix: The index of memory access port
        :param addr: the register address
        :param data: the data to be written into register
        :raises SPSDKDebugProbeTransferError: Error occur during memory transfer.
        """
        try:
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.CSW_REG),
                data=self.CSW_FULL_DEBUG,
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.TAR_REG),
                data=addr,
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.DRW_REG),
                data=data,
            )
            self.coresight_reg_read_safe(access_port=False, addr=self.DP_CTRL_STAT_REG)
        except SPSDKError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed write memory({str(exc)})") from exc

    @get_mem_ap
    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        """
        return self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=addr, data=data)

    @get_mem_ap
    def mem_block_read(self, addr: int, size: int) -> bytes:
        """Read a block of memory from the MCU, handling non-aligned addresses and sizes.

        This method implements a chunked reading approach to overcome the 1KB auto-increment
        limitation of the ARM Cortex Debug Access Port (DAP).

        :param addr: The starting address to read from.
        :param size: The number of bytes to read.
        :return: The read data as a bytes object.
        """
        result = bytearray()
        aligned_addr = addr & ~0x3
        end_addr = addr + size
        aligned_end = (end_addr + 3) & ~0x3

        while aligned_addr < aligned_end:
            chunk_size = min(0x400, aligned_end - aligned_addr)

            # Set up for block transfer
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.CSW_REG),
                data=self.CSW_FULL_DEBUG,  # Auto-increment enabled
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.TAR_REG),
                data=aligned_addr,
            )

            # Read data in blocks
            for _ in range(0, chunk_size, 4):
                value = self.coresight_reg_read_safe(
                    access_port=True,
                    addr=self.get_coresight_ap_address(self.mem_ap_ix, self.DRW_REG),
                )
                result.extend(value.to_bytes(4, "little"))

            aligned_addr += chunk_size

        # Trim the result to the exact requested size
        return bytes(result[addr - (addr & ~0x3) : addr - (addr & ~0x3) + size])

    @get_mem_ap
    def mem_block_write(self, addr: int, data: bytes) -> None:
        """Write a block of memory to the MCU, handling unaligned addresses and sizes.

        This method implements a three-stage writing approach:
        1. Handles initial unaligned bytes using 8-bit writes.
        2. Performs bulk 32-bit aligned writes for the main data block.
        3. Handles any remaining bytes using 8-bit writes.

        This approach ensures efficient writing for aligned data while correctly
        handling unaligned start and end addresses.

        :param addr: The starting address to write to.
        :param data: The data to be written, as a bytes object.
        :raises SPSDKDebugProbeTransferError: If there's an error during the write operation.
        """
        end_addr = addr + len(data)
        data_index = 0

        # Handle initial unaligned bytes
        if addr % 4 != 0:
            aligned_addr = addr & ~0x3
            word = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr)
            bytes_to_write = min(4 - (addr % 4), end_addr - addr)
            for i in range(bytes_to_write):
                byte_pos = (addr + i) % 4
                word &= ~(0xFF << (byte_pos * 8))
                word |= data[data_index + i] << (byte_pos * 8)

            self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr, data=word)

            addr += bytes_to_write
            data_index += bytes_to_write

        # Handle 32-bit aligned writes
        while addr + 4 <= end_addr:
            chunk_end = min((addr + 0x400) & ~0x3FF, end_addr)
            chunk_size = chunk_end - addr

            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.CSW_REG),
                data=self.CSW_FULL_DEBUG,
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.TAR_REG),
                data=addr,
            )

            for _ in range(0, chunk_size, 4):
                value = int.from_bytes(data[data_index : data_index + 4], "little")
                self.coresight_reg_write_safe(
                    access_port=True,
                    addr=self.get_coresight_ap_address(self.mem_ap_ix, self.DRW_REG),
                    data=value,
                )
                addr += 4
                data_index += 4

        # Handle remaining bytes
        while addr < end_addr:
            aligned_addr = addr & ~0x3
            word = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr)
            bytes_to_write = min(4 - (addr % 4), end_addr - addr)

            for i in range(bytes_to_write):
                byte_pos = (addr + i) % 4
                word &= ~(0xFF << (byte_pos * 8))
                word |= data[data_index + i] << (byte_pos * 8)

            self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr, data=word)

            addr += bytes_to_write
            data_index += bytes_to_write

    def clear_sticky_errors(self) -> None:
        """Clear sticky errors of Debug port interface."""
        if self.options.get("use_jtag") is not None:
            # Currently clear_sticky_errors has been defined only for SWD (uncleared for JTAG-DP)
            self.coresight_reg_write(access_port=False, addr=4, data=0x50000F20)
        try:
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            logger.debug(f"Checked Sticky Errors: {hex(ctrl_stat)}")
            if ctrl_stat & 0xB2:
                errors = "\n"
                if ctrl_stat & 0x02:
                    errors += "\n  - STICKYORUN: Sticky Overrun"
                if ctrl_stat & 0x10:
                    errors += "\n  - STICKYCMP: Mismatch occur during a pushed-compare operation"
                if ctrl_stat & 0x20:
                    errors += "\n  - STICKYERR: Sticky Error - AP transaction failed"
                if ctrl_stat & 0x80:
                    errors += "\n  - WDATAERR: Write data error occur"
                logger.debug(f"Debug interface: Sticky error(s) detected:{errors}")

                # Clear The sticky errors
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
        except SPSDKError as e:
            try:
                logger.debug("Read sticky errors failed, sending ABORT request.")
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKError:
                pass
            else:
                raise SPSDKDebugProbeTransferError(
                    "Cannot reestablish the Debug probe communication - please reset the board."
                ) from e
        finally:
            self.last_accessed_ap = -1

    def _reinit_target(self) -> None:
        """Re-initialize the Probe connection.

        This is obsolete method kept here just for backward
        compatibility reasons in debug probe plugins.
        """

    def _target_power_control(self, sys_power: bool = False, debug_power: bool = False) -> None:
        """Power control of the target.

        :param sys_power: Control the target system power state.
        :param debug_power: Control the target debug power state.
        :raises SPSDKTimeoutError: Timeout on power enable operation.
        """
        logger.debug(
            f"Power Control the debug connection:\nSystem power: {sys_power}\nDebug power: {debug_power}"
        )
        # Request change of target power
        req = self.MASKLANE
        check_status = 0
        if sys_power:
            req |= self.CSYSPWRUPREQ
            check_status |= self.CSYSPWRUPACK
        if debug_power:
            req |= self.CDBGPWRUPREQ
            check_status |= self.CDBGPWRUPACK
        self.coresight_reg_write(access_port=False, addr=self.DP_CTRL_STAT_REG, data=req)

        # Check the state (check these statuses that are set)
        ret = 0
        timeout = Timeout(1, units="s")
        while (ret & (self.CDBGPWRUPACK | self.CSYSPWRUPACK)) != check_status:
            if timeout.overflow():
                raise SPSDKTimeoutError(
                    "The Debug Mailbox power control operation ends on timeout."
                )
            ret = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
        self.last_accessed_ap = -1

    def power_up_target(self) -> None:
        """Power up the target for the Probe connection."""
        logger.debug("Power up the debug connection")
        # Enable the whole power of target :-)
        self._target_power_control(sys_power=True, debug_power=True)

    def power_down_target(self) -> None:
        """Power down the target for the Probe connection."""
        logger.debug("Power down the debug connection")
        # First of all power down system power
        self._target_power_control(sys_power=False, debug_power=True)
        # As a second step, power off also debug power
        self._target_power_control(sys_power=False, debug_power=False)

    def select_ap(self, addr: int) -> None:
        """Helper function to select the access port in DP.

        :param addr: Requested AP access address.
        """
        if self.last_accessed_ap != addr & self.APSEL_APBANKSEL or DISABLE_AP_SELECT_CACHING:
            addr = addr & self.APSEL_APBANKSEL
            self.last_accessed_ap = addr
            self.coresight_reg_write_safe(access_port=False, addr=0x08, data=addr)
            logger.debug(
                f"Selected AP: {(self.last_accessed_ap & self.APSEL)>>self.APSEL_SHIFT}, "
                f"Bank: {hex((self.last_accessed_ap & self.APBANKSEL) >> self.APBANK_SHIFT)}"
            )

    def read_dp_idr(self) -> int:
        """Read Debug port identification register."""
        return self.coresight_reg_read_safe(access_port=False, addr=self.DP_IDR_REG)

    def recover_debug_connection(self) -> bool:
        """Progressive recovery strategy following ARM CoreSight best practices.

        :return: True if recovery successful, False otherwise.
        """
        recovery_steps = [
            self._level1_soft_recovery,
            self._level2_power_cycle_recovery,
            self._level3_probe_reconnect_recovery,
            self._level4_hard_reset_recovery,
        ]

        for step_num, recovery_step in enumerate(recovery_steps, 1):
            logger.debug(f"Attempting recovery level {step_num}")
            try:
                if recovery_step():
                    logger.debug(f"Recovery successful at level {step_num}")
                    return True
            except Exception as e:
                logger.warning(f"Recovery level {step_num} failed: {e}")
                continue

        logger.error("All recovery attempts failed")
        return False

    def _level1_soft_recovery(self) -> bool:
        """Clear sticky errors and verify basic DP access."""
        try:
            # Step 1: Read current DP CTRL/STAT
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            logger.debug(f"Current DP CTRL/STAT: 0x{ctrl_stat:08x}")

            # Step 2: Clear all sticky error flags
            self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)

            # Step 3: Wait for errors to clear
            sleep(0.01)

            # Step 4: Verify DP is responsive
            dp_idr = self.read_dp_idr()
            if dp_idr == 0 or dp_idr == 0xFFFFFFFF:
                return False

            # Step 5: Reset AP selection cache
            self.last_accessed_ap = -1

            # Step 6: Test basic DP access and read possible errors
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            return (ctrl_stat & self.DP_CTRL_STAT_ERROR_MASK) == 0

        except Exception:
            return False

    def _level2_power_cycle_recovery(self) -> bool:
        """Power cycle debug and system domains."""
        try:
            # Step 1: Power down in correct sequence
            self._target_power_control(sys_power=False, debug_power=True)
            sleep(0.1)
            self._target_power_control(sys_power=False, debug_power=False)
            sleep(0.1)

            # Step 2: Clear any residual errors
            try:
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKDebugProbeTransferError:
                pass  # May fail if DP is not accessible

            # Step 3: Power up in correct sequence
            self._target_power_control(sys_power=False, debug_power=True)
            sleep(0.05)
            self._target_power_control(sys_power=True, debug_power=True)
            sleep(0.05)

            # Step 4: Verify power up successful
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            power_ok = (ctrl_stat & self.CDBGPWRUPACK) and (ctrl_stat & self.CSYSPWRUPACK)

            if power_ok:
                self.last_accessed_ap = -1
                self.mem_ap_ix = -1  # Force AP re-detection
                # Step 5: Test basic DP access and read possible errors
                ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
                return (ctrl_stat & self.DP_CTRL_STAT_ERROR_MASK) == 0

            return False

        except Exception:
            return False

    def _level3_probe_reconnect_recovery(self) -> bool:
        """Reconnect the debug probe interface."""
        try:
            # Step 1: Close current connection
            self.close()
            sleep(0.2)

            # Step 2: Re-open probe
            self.open()
            sleep(0.1)

            # Step 3: Re-establish target connection
            self.connect()

            # Step 4: Verify basic functionality
            dp_idr = self.read_dp_idr()
            return dp_idr != 0 and dp_idr != 0xFFFFFFFF

        except Exception:
            return False

    def _level4_hard_reset_recovery(self) -> bool:
        """Perform hardware reset sequence."""
        # Check if recovery reset is enabled
        if not self.options.get("enable_recovery_reset", False):
            logger.debug("Hardware reset recovery disabled by user option")
            return False

        logger.warning(
            "Performing hardware reset recovery - this will restart the target chip "
            "and all current state (registers, RAM contents, execution context) will be lost"
        )
        try:
            # Step 1: Assert reset while maintaining debug power
            self._target_power_control(sys_power=True, debug_power=True)
            self.assert_reset_line(True)
            sleep(0.1)

            # Step 2: Clear errors while in reset
            try:
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKDebugProbeTransferError:
                pass

            # Step 3: Release reset
            self.assert_reset_line(False)
            sleep(0.1)  # Allow target to boot

            # Step 4: Re-establish debug connection
            self._target_power_control(sys_power=True, debug_power=True)

            # Step 5: Verify connection
            dp_idr = self.read_dp_idr()
            if dp_idr != 0 and dp_idr != 0xFFFFFFFF:
                self.last_accessed_ap = -1
                self.mem_ap_ix = -1
                return True

            return False

        except Exception:
            return False

    @get_mem_ap
    def debug_halt(self) -> None:
        """Halt the CPU execution."""
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_HALT | self.DHCSR_C_DEBUGEN),
        )

    @get_mem_ap
    def debug_resume(self) -> None:
        """Resume the CPU execution."""
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY),
        )

    @get_mem_ap
    def debug_step(self) -> None:
        """Step the CPU execution."""
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_STEP | self.DHCSR_C_DEBUGEN),
        )

    def __del__(self) -> None:
        """General Debug Probe 'END' event handler."""
        try:
            self.close()
        except NotImplementedError:
            pass


class ProbeDescription:
    """NamedTuple for DAT record of debug probe description."""

    def __init__(
        self,
        interface: str,
        hardware_id: str,
        description: str,
        probe: Type[DebugProbe],
    ) -> None:
        """Initialization of Debug probe description class.

        param interface: Probe Interface.
        param hardware_id: Probe Hardware ID(Identification).
        param description: Probe Text description.
        param probe: Probe name of the class.
        """
        self.interface = interface
        self.hardware_id = hardware_id
        self.description = description
        self.probe = probe

    def get_probe(self, options: Optional[dict] = None) -> DebugProbe:
        """Get instance of probe.

        :param options: The dictionary with options
        :return: Instance of described probe.
        """
        return self.probe(hardware_id=self.hardware_id, options=options)

    def __str__(self) -> str:
        """Provide string representation of debug probe."""
        return f"Debug probe: {self.interface}; {self.description}. S/N:{self.hardware_id}"

    def __repr__(self) -> str:
        return f"Debug probe: {self.interface}"


class DebugProbes(list[ProbeDescription]):
    """Helper class for debug probe selection. This class accepts only ProbeDescription object."""

    def __str__(self) -> str:
        """Prints the List of Probes to nice colored table."""
        table = prettytable.PrettyTable(["#", "Interface", "Id", "Description"])
        table.align = "l"
        table.header = True
        table.border = True
        table.hrules = prettytable.HRuleStyle.HEADER
        table.vrules = prettytable.VRuleStyle.NONE
        i = 0
        for probe in self:
            table.add_row(
                [
                    colorama.Fore.YELLOW + str(i),
                    colorama.Fore.WHITE + probe.interface,
                    colorama.Fore.CYAN + probe.hardware_id,
                    colorama.Fore.GREEN + probe.description,
                ]
            )
            i += 1
        return table.get_string() + colorama.Style.RESET_ALL

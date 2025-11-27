#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK debug probe interface and management utilities.

This module provides abstract base classes and concrete implementations for debug probe
communication, supporting various debug interfaces across NXP MCU portfolio. It includes
probe discovery, connection management, and CoreSight debug operations.
"""

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
    """SPSDK Debug Probe exception for debug probe related errors.

    This exception is raised when debug probe operations fail or encounter
    errors during communication, initialization, or other debug probe specific
    operations within the SPSDK framework.
    """


class SPSDKProbeNotFoundError(SPSDKDebugProbeError):
    """SPSDK debug probe not found exception.

    Exception raised when a requested debug probe cannot be found or is not available
    for connection during SPSDK debugging operations.
    """


class SPSDKMultipleProbesError(SPSDKDebugProbeError):
    """SPSDK exception for multiple debug probes found error.

    This exception is raised when multiple debug probes are detected during
    probe discovery or selection operations, requiring explicit probe
    specification to resolve the ambiguity.
    """


class SPSDKDebugProbeTransferError(SPSDKDebugProbeError):
    """SPSDK Debug Probe Transfer Error Exception.

    Exception raised when communication transfer operations fail during debug probe interactions.
    This error indicates issues with data transmission between the host and target device
    through the debug probe interface.
    """


class SPSDKDebugProbeNotOpenError(SPSDKDebugProbeError):
    """Exception raised when attempting to use a debug probe that is not opened.

    This exception is thrown when operations are performed on a debug probe
    instance that has not been properly opened or has been closed.
    """


class DebugProbe(ABC):
    """Abstract base class for SPSDK debug probe interfaces.

    This class defines the common interface and constants for all debug probes
    supported by SPSDK, providing standardized access to target devices through
    various debug probe hardware implementations.

    :cvar NAME: Debug probe implementation name identifier.
    :cvar APBANKSEL: Access Port bank selection mask for debug mailbox detection.
    :cvar DP_IDR_REG: Debug Port Identification Register address.
    :cvar DP_CTRL_STAT_REG: Debug Port Control/Status Register address.
    :cvar DHCSR_REG: Debug Halting Control and Status Register address.
    :cvar DHCSR_DEBUGKEY: Debug key value for DHCSR register access.
    """

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
        """Initialize debug probe with hardware ID and configuration options.

        This is general initialization function for SPSDK library to support various DEBUG PROBES.
        Sets up the probe connection parameters, family configuration, and memory access point index.

        :param hardware_id: Hardware identifier to open specific debug probe
        :param options: Configuration dictionary containing family, revision and other probe settings
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
        """Get connected debug probes in the system.

        Retrieves a list of all connected debug probes, with an option to filter by hardware ID.

        :param hardware_id: Hardware ID to filter for specific probe, None to list all probes.
        :param options: Additional options for probe discovery.
        :return: Collection of connected debug probes.
        """

    @classmethod
    def get_options_help(cls) -> dict[str, str]:
        """Get full list of options of debug probe.

        The method returns a dictionary containing all available configuration options
        for the debug probe with their corresponding help descriptions.

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
        """Compute the coresight access port register address.

        The method combines the access port index with the register address using
        bit shifting to create the final coresight address for debug operations.

        :param access_port: Index of access port (0-255).
        :param address: Register address offset.
        :return: Computed coresight address.
        :raises SPSDKValueError: If access port index exceeds 255.
        """
        if access_port > 255:
            raise SPSDKValueError("Invalid value of access port")

        return access_port << DebugProbe.APSEL_SHIFT | address

    @abstractmethod
    def open(self) -> None:
        """Open debug probe connection.

        Establishes connection to the debug probe hardware, initializing communication
        interface and preparing the probe for debugging operations.

        :raises SPSDKError: When debug probe connection fails or probe is not available.
        """

    @abstractmethod
    def connect(self) -> None:
        """Connect to the debug probe.

        Initializes the connection to the target device through the debug probe.
        This is a general connecting function that supports various debug probe types
        across the SPSDK library.

        :raises SPSDKError: If the connection to the debug probe fails.
        :raises SPSDKTimeoutError: If the connection attempt times out.
        """

    @abstractmethod
    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and establishes
        communication with the debug probe hardware.

        :raises SPSDKError: When connection to debug probe fails.
        :raises SPSDKTimeoutError: When connection timeout occurs.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the debug probe connection.

        This method provides a unified interface for closing debug probe connections
        across different debug probe implementations in the SPSDK library.
        """

    @abstractmethod
    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This method reads a 32-bit register from the memory space of the target MCU through
        the debug probe interface.

        :param addr: The register address to read from.
        :return: The read value of addressed register (4 bytes).
        """

    @abstractmethod
    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This method writes a 32-bit value to a specified register address in the MCU's memory
        space through the debug probe interface.

        :param addr: The register address to write to.
        :param data: The 32-bit data value to be written into the register.
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

        :param access_port: if True, the Access Port (AP) register will be read (default),
            otherwise the Debug Port (DP) register will be read.
        :param addr: the register address.
        :return: The read value of addressed register (4 bytes).
        """

    @abstractmethod
    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register.

        It writes coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be written (default),
            otherwise the Debug Port register will be written.
        :param addr: the register address.
        :param data: the data to be written into register.
        """

    @abstractmethod
    def coresight_reg_read_safe(
        self, access_port: bool = True, addr: int = 0, max_retries: int = 3
    ) -> int:
        """Safe coresight register read with error handling and recovery.

        Performs a safe read operation on CoreSight registers with automatic retry
        mechanism in case of transfer failures.

        :param access_port: If True, reads Access Port (AP) register, otherwise reads
            Debug Port (DP) register.
        :param addr: Register address to read from.
        :param max_retries: Maximum number of retry attempts on failure.
        :return: Read value of the addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail.
        """

    @abstractmethod
    def coresight_reg_write_safe(
        self, access_port: bool = True, addr: int = 0, data: int = 0, max_retries: int = 3
    ) -> None:
        """Write CoreSight register with error handling and recovery.

        Internal method that performs CoreSight register write operations with automatic
        retry mechanism and error recovery capabilities.

        :param access_port: If True, writes to Access Port (AP) register, otherwise to Debug Port (DP).
        :param addr: Register address to write to.
        :param data: Data value to write into the register.
        :param max_retries: Maximum number of retry attempts on failure.
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail.
        """

    @abstractmethod
    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted (pulled down), if False the reset line
            is not affected.
        """

    def reset(self) -> None:
        """Reset the target device.

        Performs a hardware reset by asserting the reset line, waiting for the reset duration,
        then deasserting the reset line and waiting for the post-reset stabilization period.
        """
        self.assert_reset_line(True)
        sleep(self.RESET_TIME)
        self.assert_reset_line(False)
        sleep(self.AFTER_RESET_TIME)

    @abstractmethod
    def read_dp_idr(self) -> int:
        """Read Debug port identification register.

        :return: Debug port identification register value.
        """

    @abstractmethod
    def debug_halt(self) -> None:
        """Halt the CPU execution.

        This method stops the target CPU from executing instructions, putting it into
        a halted state for debugging purposes.

        :raises SPSDKError: If the halt operation fails or the debug probe is not connected.
        """

    @abstractmethod
    def debug_resume(self) -> None:
        """Resume the CPU execution.

        This method continues the execution of the target CPU from its current state,
        typically used after the CPU has been halted or paused during debugging operations.

        :raises SPSDKError: If the debug probe communication fails or the target is not connected.
        """

    @abstractmethod
    def debug_step(self) -> None:
        """Step the CPU execution by one instruction.

        This method advances the CPU execution by a single instruction step,
        allowing for detailed debugging and program flow analysis.

        :raises SPSDKError: When the debug step operation fails.
        :raises SPSDKConnectionError: When the debug probe connection is lost.
        """


class DebugProbeCoreSightOnly(DebugProbe):
    """SPSDK Debug Probe with CoreSight-only interface support.

    This class provides a specialized debug probe implementation that focuses exclusively on
    CoreSight debug architecture operations. It extends the base DebugProbe class with
    ARM CoreSight-specific register definitions and memory access patterns for debugging
    ARM Cortex-based MCUs.

    :cvar NAME: Debug probe identifier name.
    :cvar CSW_SIZE_8BIT: Control/Status Word 8-bit transfer size configuration.
    :cvar CSW_SIZE_16BIT: Control/Status Word 16-bit transfer size configuration.
    :cvar CSW_SIZE_32BIT: Control/Status Word 32-bit transfer size configuration.
    :cvar CSW_ADDRINC_OFF: Control/Status Word no address increment mode.
    :cvar CSW_ADDRINC_SINGLE: Control/Status Word single address increment mode.
    :cvar CSW_ADDRINC_PACKED: Control/Status Word packed address increment mode.
    :cvar CSW_DEVICEEN: Control/Status Word device enable flag.
    :cvar CSW_TRINPROG: Control/Status Word transfer in progress flag.
    :cvar CSW_HPROT: Control/Status Word HPROT signal configuration.
    :cvar CSW_MASTER_DEBUG: Control/Status Word master debug enable flag.
    :cvar CSW_DBGSWENABLE: Control/Status Word debug software enable flag.
    :cvar CSW_FULL_DEBUG: Combined CSW configuration for full debug capabilities.
    :cvar CSW_REG: CoreSight Control/Status Word register address.
    :cvar TAR_REG: CoreSight Transfer Address register address.
    :cvar DRW_REG: CoreSight Data Read/Write register address.
    :cvar DP_CTRL_STAT_ERROR_MASK: Combined error mask for Debug Port status flags.
    """

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
        """Initialize debug probe with hardware ID and options.

        General initialization function for SPSDK library to support various debug probes.

        :param hardware_id: Hardware ID of the debug probe to open
        :param options: Optional dictionary with probe-specific configuration options
        """
        super().__init__(hardware_id, options)
        self.last_accessed_ap = -1
        self.disable_reinit = (
            False  # Keep it here to backward compatibility with debug probe plugins
        )

    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and attempts recovery
        if the initial connection fails.

        :raises Exception: Re-raises the original connection exception if recovery fails.
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
        """Write CoreSight register with automatic retry and error recovery.

        Performs a CoreSight register write operation with built-in error handling and automatic
        recovery attempts. If the initial write fails, the method attempts to recover the debug
        connection and retry the operation up to the specified maximum number of attempts.

        :param access_port: If True, writes to Access Port register, otherwise Debug Port register
        :param addr: Register address to write to
        :param data: Data value to write into the register
        :param max_retries: Maximum number of retry attempts before giving up
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

        This method attempts to read a CoreSight register with automatic retry and recovery
        mechanisms. If a read fails, it will attempt to recover the debug connection and
        retry the operation up to the specified maximum number of attempts.

        :param access_port: If True, reads Access Port (AP) register, otherwise Debug Port (DP).
        :param addr: The register address to read from.
        :param max_retries: Maximum number of retry attempts before giving up.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail.
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
        """Decorator that ensures correct Memory Access Port index is found before first use.

        This decorator automatically discovers and configures the appropriate Memory Access Port (MEM AP)
        by testing possible AP indices and validating memory access functionality. It performs CoreSight
        AP identification, enters debug state, tests memory access, and restores the original state.

        :param func: The function to be decorated that requires MEM AP access.
        :return: Decorated function wrapper.
        :raises SPSDKDebugProbeError: When no valid memory access port is found.
        """
        POSSIBLE_MEM_AP_IX = [0, 1, 3]
        DEFAULT_TEST_MEM_AP_ADDRESS = 0x2000_0000

        @functools.wraps(func)
        def wrapper(self: "DebugProbeCoreSightOnly", *args, **kwargs):
            """Wrapper function to ensure memory access port (MEM AP) is discovered before execution.

            This decorator automatically discovers and configures the memory access port by iterating
            through possible AP indices, validating each one by checking the IDR register for class 8
            (MEM AP), entering debug state, and performing a test memory read operation.

            :param self: DebugProbeCoreSightOnly instance
            :param args: Positional arguments passed to the wrapped function
            :param kwargs: Keyword arguments passed to the wrapped function
            :raises SPSDKDebugProbeError: When memory access port cannot be found
            :return: Result of the wrapped function execution
            """
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

        This function reads a 32-bit register in memory space of MCU for SPSDK library
        to support various debug probes.

        :param mem_ap_ix: The index of memory access port.
        :param addr: The register address.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: Error occurs during memory transfer.
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

        This method reads a 32-bit register from the memory space of the connected MCU
        using the configured debug probe interface.

        :param addr: The register address to read from.
        :return: The read value of addressed register (4 bytes).
        """
        return self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=addr)

    def _mem_reg_write(self, mem_ap_ix: int, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This function writes a 32-bit register in the memory space of the MCU through the
        CoreSight debug interface using the specified memory access port.

        :param mem_ap_ix: The index of memory access port.
        :param addr: The register address to write to.
        :param data: The 32-bit data to be written into the register.
        :raises SPSDKDebugProbeTransferError: Error occurs during memory transfer.
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

        This method writes a 32-bit value to a specified register address in the MCU's memory
        space using the configured memory access port.

        :param addr: The register address to write to.
        :param data: The 32-bit data value to be written into the register.
        """
        return self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=addr, data=data)

    @get_mem_ap
    def mem_block_read(self, addr: int, size: int) -> bytes:
        """Read a block of memory from the MCU, handling non-aligned addresses and sizes.

        This method implements a chunked reading approach to overcome the 1KB auto-increment
        limitation of the ARM Cortex Debug Access Port (DAP). The method handles memory alignment
        automatically and reads data in 1KB chunks to ensure reliable operation.

        :param addr: The starting memory address to read from.
        :param size: The number of bytes to read from memory.
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
        """Clear sticky errors of Debug port interface.

        This method reads the debug port control/status register to check for sticky errors
        and clears them if found. For JTAG interface, it performs an additional write operation.
        The method handles communication failures gracefully by attempting recovery.

        :raises SPSDKDebugProbeTransferError: When debug probe communication cannot be reestablished.
        """
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

        This is an obsolete method kept here just for backward compatibility reasons
        in debug probe plugins.
        """

    def _target_power_control(self, sys_power: bool = False, debug_power: bool = False) -> None:
        """Control power state of the target device.

        This method manages both system and debug power states of the target device
        through CoreSight debug port control/status register operations.

        :param sys_power: Enable or disable target system power state.
        :param debug_power: Enable or disable target debug power state.
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
        """Power up the target for the Probe connection.

        This method enables both system and debug power to establish a proper
        connection with the target device through the debug probe.

        :raises SPSDKError: If power control operation fails.
        """
        logger.debug("Power up the debug connection")
        # Enable the whole power of target :-)
        self._target_power_control(sys_power=True, debug_power=True)

    def power_down_target(self) -> None:
        """Power down the target for the Probe connection.

        This method performs a two-step power down sequence: first disabling system power
        while maintaining debug power, then disabling debug power completely to ensure
        proper target shutdown.
        """
        logger.debug("Power down the debug connection")
        # First of all power down system power
        self._target_power_control(sys_power=False, debug_power=True)
        # As a second step, power off also debug power
        self._target_power_control(sys_power=False, debug_power=False)

    def select_ap(self, addr: int) -> None:
        """Select the access port in Debug Port (DP).

        This method configures the Debug Port to access a specific Access Port by writing
        to the SELECT register. It includes caching optimization to avoid redundant writes
        when the same AP is already selected.

        :param addr: Requested AP access address containing AP selection and bank information.
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
        """Read Debug port identification register.

        :return: Debug port identification register value.
        """
        return self.coresight_reg_read_safe(access_port=False, addr=self.DP_IDR_REG)

    def recover_debug_connection(self) -> bool:
        """Recover debug connection using progressive recovery strategy.

        Implements ARM CoreSight best practices by attempting multiple recovery levels
        in sequence: soft recovery, power cycle recovery, probe reconnect recovery,
        and hard reset recovery. Each level is progressively more invasive.

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
        """Clear sticky errors and verify basic DP access.

        Performs level 1 soft recovery by clearing all sticky error flags in the Debug Port,
        waiting for errors to clear, and verifying that the DP is responsive. This is a
        gentle recovery method that doesn't reset the target system.

        :return: True if recovery was successful and DP is accessible without errors,
                 False otherwise.
        """
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
        """Perform level 2 power cycle recovery for debug and system domains.

        This recovery method performs a complete power cycle sequence of both debug and system
        power domains to recover from communication errors. It includes proper sequencing,
        error clearing, and verification of successful power restoration.

        :return: True if power cycle recovery was successful and no errors remain, False otherwise.
        """
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
        """Perform level 3 probe reconnection recovery procedure.

        This method attempts to recover a debug probe connection by performing a complete
        reconnection sequence including closing the current connection, reopening the probe,
        re-establishing target connection, and verifying basic functionality through DP IDR read.

        :return: True if reconnection was successful and probe is functional, False otherwise.
        """
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
        """Perform level 4 hardware reset recovery sequence.

        This method performs a complete hardware reset of the target chip to recover from
        severe debug connection issues. The reset sequence includes asserting the reset line,
        clearing debug errors, releasing reset, and re-establishing the debug connection.
        All target state including registers, RAM contents, and execution context will be lost.

        :return: True if hardware reset recovery was successful and debug connection was
                 re-established, False otherwise.
        """
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
        """Halt the CPU execution.

        This method stops the CPU by writing to the Debug Halting Control and Status Register
        (DHCSR) with the appropriate debug key, halt, and debug enable flags.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_HALT | self.DHCSR_C_DEBUGEN),
        )

    @get_mem_ap
    def debug_resume(self) -> None:
        """Resume the CPU execution.

        This method clears the debug halt bit in the Debug Halting Control and Status Register
        (DHCSR) to allow the CPU to continue execution from its current state.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY),
        )

    @get_mem_ap
    def debug_step(self) -> None:
        """Step the CPU execution by one instruction.

        This method performs a single-step operation on the target CPU by writing
        to the Debug Halting Control and Status Register (DHCSR) with appropriate
        control bits to enable debug mode and execute one instruction.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_STEP | self.DHCSR_C_DEBUGEN),
        )

    def __del__(self) -> None:
        """Clean up resources when the debug probe object is destroyed.

        This destructor method ensures proper cleanup by attempting to close the debug probe
        connection when the object is being garbage collected. It safely handles cases where
        the close method is not implemented by catching NotImplementedError.

        :raises NotImplementedError: When the close method is not implemented (handled internally).
        """
        try:
            self.close()
        except NotImplementedError:
            pass


class ProbeDescription:
    """Debug probe description container.

    This class encapsulates information about a debug probe including its interface,
    hardware identification, description, and the probe class type. It provides
    a standardized way to describe and instantiate debug probes within the SPSDK
    framework.
    """

    def __init__(
        self,
        interface: str,
        hardware_id: str,
        description: str,
        probe: Type[DebugProbe],
    ) -> None:
        """Initialize Debug probe description class.

        :param interface: Probe interface type.
        :param hardware_id: Probe hardware ID for identification.
        :param description: Text description of the probe.
        :param probe: Debug probe class type.
        """
        self.interface = interface
        self.hardware_id = hardware_id
        self.description = description
        self.probe = probe

    def get_probe(self, options: Optional[dict] = None) -> DebugProbe:
        """Get instance of debug probe.

        Creates and returns a new instance of the debug probe with the specified hardware ID
        and optional configuration parameters.

        :param options: Optional dictionary containing probe-specific configuration options.
        :return: Instance of the debug probe ready for use.
        """
        return self.probe(hardware_id=self.hardware_id, options=options)

    def __str__(self) -> str:
        """Provide string representation of debug probe.

        Creates a formatted string containing the debug probe's interface type,
        description, and hardware serial number for easy identification and logging.

        :return: Formatted string with probe interface, description, and serial number.
        """
        return f"Debug probe: {self.interface}; {self.description}. S/N:{self.hardware_id}"

    def __repr__(self) -> str:
        """Return string representation of the debug probe.

        :return: String containing debug probe interface information.
        """
        return f"Debug probe: {self.interface}"


class DebugProbes(list[ProbeDescription]):
    """Debug probe collection for hardware selection and display.

    This class extends a list to specifically manage ProbeDescription objects,
    providing formatted output capabilities for debug probe selection interfaces.
    The class ensures type safety by accepting only ProbeDescription instances
    and offers colored table representation for user-friendly probe listing.
    """

    def __str__(self) -> str:
        """Return string representation of debug probes list.

        Creates a formatted table with colored output showing all available debug probes
        with their interface, hardware ID, and description.

        :return: Formatted table string with colored probe information.
        """
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

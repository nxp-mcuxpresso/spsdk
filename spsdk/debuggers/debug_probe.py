#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

import functools
import logging
from time import sleep
from typing import Any, Dict, List, Optional, no_type_check

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)

# Debugging options
DISABLE_AP_SELECT_CACHING = False


class SPSDKDebugProbeError(SPSDKError):
    """The general issue with debug probe exception for use with SPSDK."""


class SPSDKProbeNotFoundError(SPSDKDebugProbeError):
    """The Probe not found exception for use with SPSDK."""


class SPSDKDebugProbeTransferError(SPSDKDebugProbeError):
    """The communication error exception for use with SPSDK."""


class SPSDKDebugProbeNotOpenError(SPSDKDebugProbeError):
    """The debug probe is not opened exception for use with SPSDK."""


class DebugProbe:
    """Abstraction class to define SPSDK debug probes interface."""

    # Constants to detect the debug mailbox access port
    APBANKSEL = 0x000000F0
    APBANK_SHIFT = 4
    APADDR = 0x00FFFFFF
    APSEL = 0xFF000000
    APSEL_SHIFT = 24
    APSEL_APBANKSEL = APSEL | APBANKSEL

    DP_ABORT_REG = 0x00
    DP_CTRL_STAT_REG = 0x04
    IDR_REG = 0xFC

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

    RESET_TIME = 0.1
    AFTER_RESET_TIME = 0.05
    TEST_MEM_AP_ADDRESS = 0x2000_8000

    def __init__(self, hardware_id: str, options: Optional[Dict] = None) -> None:
        """This is general initialization function for SPSDK library to support various DEBUG PROBES.

        :param hardware_id: Open probe with selected hardware ID
        :param options: The options dictionary
        """
        self.hardware_id = hardware_id
        self.options = options or {}
        self.disable_reinit = False
        self.last_accessed_ap = -1
        self.mem_ap_ix = -1

    @classmethod
    def get_connected_probes(
        cls, hardware_id: Optional[str] = None, options: Optional[Dict] = None
    ) -> list:
        """Functions returns the list of all connected probes in system.

        There is option to look for just for one debug probe defined by its hardware ID.

        :param hardware_id: None to list all probes, otherwise the the only probe with
            matching hardware id is listed.
        :param options: The options dictionary
        :return: ProbeDescription
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @staticmethod
    def get_options_help() -> Dict[str, str]:
        """Get full list of options of debug probe.

        :return: Dictionary with individual options. Key is parameter name and value the help text.
        """
        return {}

    def open(self) -> None:
        """Debug probe open.

        General opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def close(self) -> None:
        """Debug probe close.

        This is general closing function for SPSDK library to support various DEBUG PROBES.

        :raises NotImplementedError: Derived class has to implement this method
        """

    @no_type_check
    # pylint: disable=no-self-argument
    def get_mem_ap(func: Any) -> Any:
        """Decorator function that secure the getting right MEM AP ix for first use.

        :param func: Decorated function.
        """
        POSSIBLE_MEM_AP_IX = [0, 1, 3]

        @functools.wraps(func)
        def wrapper(self: "DebugProbe", *args, **kwargs) -> Any:
            if self.mem_ap_ix < 0:
                # Try to find MEM AP
                for i in POSSIBLE_MEM_AP_IX:
                    try:
                        idr = self.coresight_reg_read(
                            access_port=True,
                            addr=self.get_coresight_ap_address(access_port=i, address=self.IDR_REG),
                        )
                        # Extract IDR fields used for lookup. TODO solve that
                        ap_class = (idr & 0x1E000) >> 13
                        if ap_class == 8:
                            try:
                                # Enter debug state and halt
                                self._mem_reg_read(mem_ap_ix=i, addr=self.DHCSR_REG)
                                self._mem_reg_write(
                                    mem_ap_ix=i,
                                    addr=self.DHCSR_REG,
                                    data=(
                                        self.DHCSR_DEBUGKEY
                                        | self.DHCSR_C_HALT
                                        | self.DHCSR_C_DEBUGEN
                                    ),
                                )
                                self._mem_reg_read(mem_ap_ix=i, addr=self.TEST_MEM_AP_ADDRESS)
                                # Exit debug state
                                self._mem_reg_write(
                                    mem_ap_ix=i,
                                    addr=self.DHCSR_REG,
                                    data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_DEBUGEN),
                                )
                                self._mem_reg_write(
                                    mem_ap_ix=i, addr=self.DHCSR_REG, data=self.DHCSR_DEBUGKEY
                                )
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
            self.coresight_reg_write(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, 0 * 4),
                data=0x22000012,
            )
            self.coresight_reg_write(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, 1 * 4),
                data=addr,
            )

            return self.coresight_reg_read(
                access_port=True, addr=self.get_coresight_ap_address(mem_ap_ix, 3 * 4)
            )
        except SPSDKError as exc:
            self.clear_sticky_errors()
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
            self.coresight_reg_write(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, 0 * 4),
                data=0x22000012,
            )
            self.coresight_reg_write(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, 1 * 4),
                data=addr,
            )
            self.coresight_reg_write(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, 3 * 4),
                data=data,
            )
            self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
        except SPSDKError as exc:
            self.clear_sticky_errors()
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

    @classmethod
    def get_coresight_ap_address(cls, access_port: int, address: int) -> int:
        """Return computed address of coresight access port register.

        :param access_port: Index of access port 0-255.
        :param address: Register address.
        :return: Coresight address.
        :raises SPSDKError: In case of invalid value.
        """
        if access_port > 255:
            raise SPSDKValueError("Invalid value of access port")

        return access_port << cls.APSEL_SHIFT | address

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register.

        It reads coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register.

        It writes coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def clear_sticky_errors(self) -> None:
        """Clear sticky errors of Debug port interface."""
        if self.options.get("use_jtag") is not None:
            # Currently clear_sticky_errors has been defined only for SWD (uncleared for JTAG-DP)
            self.coresight_reg_write(access_port=False, addr=4, data=0x50000F20)
        disable_reinit = self.disable_reinit
        try:
            self.disable_reinit = True
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            # Check if any of error flags is set:
            # - WDATAERR, bit[7]
            # - STICKYERR, bit[5]
            # - STICKYCMP, bit[4]
            # - STICKYORUN, bit[1]
            logger.debug(f"Checked Sticky Errors: {hex(ctrl_stat)}")
            if ctrl_stat & 0xB2 or (ctrl_stat & 0x00000040) == 0:
                errors = "\n"
                if ctrl_stat & 0x02:
                    errors += "\n  - STICKYORUN: Sticky Overrun"
                if ctrl_stat & 0x10:
                    errors += "\n  - STICKYCMP: Mismatch occur during a pushed-compare operation"
                if ctrl_stat & 0x20:
                    errors += "\n  - STICKYERR: Sticky Error - AP transaction failed"
                if ctrl_stat & 0x80:
                    errors += "\n  - WDATAERR: Write data error occur"
                if (ctrl_stat & 0x00000040) == 0:
                    errors += "\n  - READOK: Read operation failed"
                if ctrl_stat & 0xB2:
                    logger.debug(f"Debug interface: Sticky error(s) detected:{errors}")
                else:
                    logger.debug(f"Debug interface: Read OK fail detected:{errors}")
                # Clear The sticky errors
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
        except SPSDKError as e:
            try:
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKError:
                pass
            else:
                raise SPSDKDebugProbeTransferError(
                    "Cannot reestablish the Debug probe communication - please reset the board."
                ) from e
        finally:
            self.disable_reinit = disable_reinit
            self.last_accessed_ap = -1

    def _reinit_target(self) -> None:
        """Re-initialize the Probe connection."""
        if not self.disable_reinit:
            self.disable_reinit = True
            logger.debug("Trying to re-initialize debug connection")
            try:
                self.power_down_target()
                self.power_up_target()
                self.clear_sticky_errors()
            finally:
                self.disable_reinit = False

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
            self.coresight_reg_write(access_port=False, addr=0x08, data=addr)
            logger.debug(
                f"Selected AP: {(self.last_accessed_ap & self.APSEL)>>self.APSEL_SHIFT}, "
                f"Bank: {hex((self.last_accessed_ap & self.APBANKSEL) >> self.APBANK_SHIFT)}"
            )

    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted(pulled down), if False the reset line is not affected.
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def reset(self) -> None:
        """Reset a target.

        It resets a target.
        """
        self.assert_reset_line(True)
        sleep(self.RESET_TIME)
        self.assert_reset_line(False)
        sleep(self.AFTER_RESET_TIME)

    def __del__(self) -> None:
        """General Debug Probe 'END' event handler."""
        try:
            self.close()
        except NotImplementedError:
            pass

    def get_ap_list(self, ap_filter: Optional[List[int]] = None) -> Dict[int, int]:
        """Gets the dictionary of AP IDR's active in target.

        :param ap_filter: List of AP be scanned - otherwise all range will be used[0-255].
        :return: Dictionary with active AP's. Key is index of AP, value is IDR value.
        """
        ret: Dict[int, int] = {}
        for i in ap_filter or range(256):
            try:
                idr = self.coresight_reg_read(
                    access_port=True,
                    addr=self.get_coresight_ap_address(access_port=i, address=self.IDR_REG),
                )
            except SPSDKError:
                pass
            else:
                if idr != 0:
                    logger.debug(f"Find AP{i} with IDR value:{hex(idr)}")
                    ret[i] = idr

        return ret

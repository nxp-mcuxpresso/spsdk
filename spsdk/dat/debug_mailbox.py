#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Debug Mailbox communication interface.

This module provides functionality for communicating with NXP MCU debug mailbox
through debug probes, enabling secure provisioning and debugging operations.
Key components:
- DebugMailbox: Main class for debug mailbox communication
- DebugMailboxError: Exception handling for mailbox operations
"""

import functools
import logging
from time import sleep
from typing import Any, no_type_check

from spsdk.debuggers.debug_probe import DebugProbe
from spsdk.exceptions import SPSDKError, SPSDKIOError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)


class DebugMailboxError(RuntimeError):
    """Debug Mailbox operation error exception.

    Exception raised when Debug Mailbox operations fail due to communication
    errors, invalid responses, or hardware-related issues during secure
    provisioning operations.
    """


class DebugMailbox:
    """Debug Mailbox communication interface for NXP MCU devices.

    This class provides a standardized interface for communicating with the debug mailbox
    functionality present in NXP MCU devices. It handles the low-level protocol operations,
    register access, and synchronization required for debug authentication and provisioning
    operations through the debug probe connection.
    The debug mailbox enables secure communication between external tools and the device's
    ROM code or secure firmware, supporting operations like authentication challenges,
    key provisioning, and secure debug unlock procedures.
    """

    def __init__(
        self,
        debug_probe: DebugProbe,
        family: FamilyRevision,
        reset: bool = True,
        moredelay: float = 0.0,
        op_timeout: int = 1000,
    ) -> None:
        """Initialize DebugMailbox object.

        Establishes connection to the debug mailbox by performing resynchronization request
        and waiting for acknowledgement from ROM code.

        :param debug_probe: Debug probe instance for communication.
        :param family: Chip family and revision information.
        :param reset: Do reset of debug mailbox during initialization, defaults to True.
        :param moredelay: Time of extra delay after reset sequence in seconds, defaults to 0.0.
        :param op_timeout: Atomic operation timeout in milliseconds, defaults to 1000.
        :raises SPSDKIOError: Connection timeout or communication failure with debug mailbox.
        """
        # setup debug port / access point
        self.family = family
        self.dbgmlbx_ap_ix = -1
        self.non_standard_statuses = {}
        self.command_delays: dict[str, float] = {}
        if family:
            db = get_db(family)
            self.dbgmlbx_ap_ix = db.get_int(DatabaseManager.DAT, "dmbox_ap_ix", -1)
            self.non_standard_statuses = db.get_dict(
                DatabaseManager.DAT, "non_standard_statuses", {}
            )
            self.command_delays = db.get_dict(DatabaseManager.DAT, "command_delays", {})
        self.debug_probe = debug_probe

        self.reset = reset
        self.moredelay = moredelay
        # setup registers and register bitfields
        self.registers: dict[str, dict[str, Any]] = REGISTERS
        # set internal operation timeout
        self.op_timeout = op_timeout

        # Proceed with initiation (Resynchronization request)

        # The communication to the DM is initiated by the debugger.
        # It does so by writing the RESYNCH_REQ bit of the CSW (Control and Status Word)
        # register to 1. It then needs to reset the chip so that ROM code can observe
        # this request.
        # In order to reset the chip, the debugger can either pull the
        # reset line of the chip, or set the CHIP_RESET_REQ (This can be done at the
        # same time as setting the RESYNCH_REQ bit).

        logger.debug(f"Reset mode: {self.reset!r}")
        if self.reset:
            self.dbgmlbx_reg_write(
                addr=self.registers["CSW"]["address"],
                data=self.registers["CSW"]["bits"]["RESYNCH_REQ"]
                | self.registers["CSW"]["bits"]["CHIP_RESET_REQ"],
            )

        # Acknowledgement of initiation

        # After performing the initiation, the debugger must read back the CSW register.
        # The DM will stall the debugger until the ROM code has serviced the resynchronization request.
        # The ROM does this by performing a soft reset of the DM block, thus resetting
        # the request bit/s which were set by the debugger.
        # Therefore, the debugger must read back 0x0 in CSW to know that the initiation
        # request has been serviced.

        if self.moredelay > 0.001:
            sleep(self.moredelay)

        ret = None
        retries = 20

        while ret is None or (ret & self.registers["CSW"]["bits"]["REQ_PENDING"]):
            try:
                ret = self.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
            except SPSDKError:
                pass
            retries -= 1
            if retries == 0:
                raise SPSDKIOError("TransferTimeoutError limit exceeded!")
            sleep(0.05)

    def read_idr(self) -> int:
        """Read IDR of debug mailbox.

        Reads the Identification Register (IDR) value from the debug mailbox Access Port
        and validates it against the expected value. Issues a warning if the values don't match.

        :return: IDR value of debug mailbox AP.
        """
        idr = self.dbgmlbx_reg_read(addr=self.registers["IDR"]["address"])
        if idr != self.registers["IDR"]["expected"]:
            logger.warning(
                f"The read IDR value({hex(idr)}) doesn't match the expected "
                f"value: {hex(self.registers['IDR']['expected'])}"
            )
        return idr

    def close(self) -> None:
        """Close the debug mailbox session.

        This method properly closes the connection to the debug probe and cleans up
        any associated resources.
        """
        self.debug_probe.close()

    def spin_read(self, reg: int) -> int:
        """Perform atomic read operation from debug mailbox register.

        This method continuously attempts to read from the specified register until successful
        or timeout occurs. It handles transient errors by retrying with a small delay.

        :param reg: Register address to read from.
        :return: Value read from the register.
        :raises SPSDKTimeoutError: When read operation exceeds defined operation timeout.
        """
        ret = None
        timeout = Timeout(self.op_timeout, units="ms")
        while ret is None:
            try:
                ret = self.dbgmlbx_reg_read(addr=reg)
            except SPSDKError as e:
                logger.debug(str(e))
                logger.debug(f"read exception  {reg:#08X}")
                if timeout.overflow():
                    raise SPSDKTimeoutError(
                        f"The Debug Mailbox read operation ends on timeout. ({str(e)})"
                    ) from e
                sleep(0.1)

        return ret

    def spin_write(self, reg: int, value: int) -> None:
        """Perform atomic write operation to debug mailbox.

        The method writes data to the specified register and waits for the ROM code to process
        the request. It includes retry logic with timeout handling to ensure reliable operation.

        :param reg: Register address to write to.
        :param value: Value to write to the register.
        :raises SPSDKTimeoutError: When write operation exceeds defined operation timeout.
        """
        timeout = Timeout(self.op_timeout, units="ms")
        while True:
            try:
                self.dbgmlbx_reg_write(addr=reg, data=value)
                # wait for rom code to read the data
                while True:
                    ret = self.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
                    if (ret & self.registers["CSW"]["bits"]["REQ_PENDING"]) == 0:
                        break
                    if timeout.overflow():
                        raise SPSDKTimeoutError("Mailbox command request pending timeout.")

                return
            except SPSDKError as e:
                logger.debug(str(e))
                logger.debug(f"write exception addr={reg:#08X}, val={value:#08X}")
                if timeout.overflow():
                    raise SPSDKTimeoutError(
                        f"The Debug Mailbox write operation ends on timeout. ({str(e)})"
                    ) from e
                sleep(0.1)

    @no_type_check
    # pylint: disable=no-self-argument
    def get_dbgmlbx_ap(func: Any):
        """Decorator function that secures getting the correct DEBUG MAILBOX AP index for first use.

        The decorator automatically detects the debug mailbox access port index by trying
        predefined possible indices and validating against the expected IDR register value.
        If no valid access port is found, it raises an exception.

        :param func: The function to be decorated that requires debug mailbox access.
        :raises SPSDKError: When debug mailbox access port cannot be found.
        :return: Decorated function wrapper.
        """
        POSSIBLE_DBGMLBX_AP_IX = [2, 0, 1, 3, 8]

        @functools.wraps(func)
        def wrapper(self: "DebugMailbox", *args, **kwargs):
            """Wrapper function to auto-detect debug mailbox access port if not specified.

            This decorator automatically detects the debug mailbox access port index by iterating
            through possible access port indices and checking the IDR register value. If the
            access port index is already set (>= 0), the wrapped function is called directly.

            :param self: DebugMailbox instance.
            :param args: Variable length argument list to pass to wrapped function.
            :param kwargs: Arbitrary keyword arguments to pass to wrapped function.
            :raises SPSDKError: When debug mailbox access port cannot be found.
            :return: Result of the wrapped function call.
            """
            if self.dbgmlbx_ap_ix < 0:
                # Try to find DEBUG MAILBOX AP
                logger.warning(
                    "The debug mailbox access port index is not specified, trying autodetection."
                )
                for i in POSSIBLE_DBGMLBX_AP_IX:
                    try:
                        idr = self.debug_probe.coresight_reg_read_safe(
                            access_port=True,
                            addr=self.debug_probe.get_coresight_ap_address(
                                access_port=i, address=self.registers["IDR"]["address"]
                            ),
                        )
                        if idr == self.registers["IDR"]["expected"]:
                            self.dbgmlbx_ap_ix = i
                            logger.debug(
                                f"Found debug mailbox access port at AP{i}, IDR: 0x{idr:08X}"
                            )
                            break
                    except SPSDKError:
                        pass

                if self.dbgmlbx_ap_ix < 0:
                    raise SPSDKError("The debug mailbox access port is not found!")

            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    @get_dbgmlbx_ap
    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This function reads a debug mailbox register through the debug probe interface to support
        various debug probes in the SPSDK library.

        :param addr: The register address to read from.
        :return: The read value of addressed register (4 bytes).
        """
        return self.debug_probe.coresight_reg_read_safe(
            addr=self.debug_probe.get_coresight_ap_address(
                access_port=self.dbgmlbx_ap_ix, address=addr
            )
        )

    @get_dbgmlbx_ap
    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        Writes data to a specified register address in the debug mailbox access port
        using the configured debug probe's CoreSight interface.

        :param addr: Register address to write to.
        :param data: Data value to write into the register.
        """
        self.debug_probe.coresight_reg_write_safe(
            addr=self.debug_probe.get_coresight_ap_address(
                access_port=self.dbgmlbx_ap_ix, address=addr
            ),
            data=data,
        )


REGISTERS: dict[str, Any] = {
    # Control and Status Word (CSW) is used to control
    # the Debug Mailbox communication
    "CSW": {
        "address": 0x00,
        "bits": {
            # Debugger will set this bit to 1 to request a resynchronization
            "RESYNCH_REQ": (1 << 0),
            # Request is pending from debugger (i.e unread value in REQUEST)
            "REQ_PENDING": (1 << 1),
            # Debugger overrun error
            # (previous REQUEST overwritten before being picked up by ROM)
            "DBG_OR_ERR": (1 << 2),
            # AHB overrun Error (Return value overwritten by ROM)
            "AHB_OR_ERR": (1 << 3),
            # Soft Reset for DM (write-only from AHB,
            # not readable and self-clearing).
            # A write to this bit will cause a soft reset for DM.
            "SOFT_RESET": (1 << 4),
            # Write only bit. Once written will cause the chip to reset
            # (note that the DM is not reset by this reset as it is
            #   only resettable by a SOFT reset or a POR/BOD event)
            "CHIP_RESET_REQ": (1 << 5),
        },
    },
    # Request register is used to send data from debugger to device
    "REQUEST": {
        "address": 0x04,
    },
    # Return register is used to send data from device to debugger
    # Note: Any read from debugger side will be stalled until new data is present.
    "RETURN": {
        "address": 0x08,
    },
    # IDR register is used to identify the access port
    "IDR": {
        "address": 0xFC,
        "expected": 0x002A0000,
    },
}

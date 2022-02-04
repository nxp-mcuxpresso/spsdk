#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for NXP SPSDK DebugMailbox support."""

import logging
from time import sleep
from typing import Any, Dict

from spsdk import SPSDKError
from spsdk.debuggers.debug_probe import DebugProbe
from spsdk.exceptions import SPSDKIOError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)


class DebugMailboxError(RuntimeError):
    """Class for DebugMailboxError."""


class DebugMailbox:
    """Class for DebugMailbox."""

    def __init__(
        self,
        debug_probe: DebugProbe,
        reset: bool = True,
        moredelay: float = 1.0,
        op_timeout: int = 4000,
    ) -> None:
        """Initialize DebugMailbox object.

        :param debug_probe: Debug probe instantion.
        :param reset: Do reset of debug mailbox during initialization, defaults to True.
        :param moredelay: Time of extra delay after reset sequence, defaults to 1.0.
        :param op_timeout: Atomic operation timeout, defaults to 4000.
        :raises SPSDKIOError: Various kind of vulnerabilities during connection to debug mailbox.
        """
        # setup debug port / access point

        self.debug_probe = debug_probe
        self.reset = reset
        self.moredelay = moredelay
        # setup registers and register bitfields
        self.registers: Dict[str, Dict[str, Any]] = REGISTERS
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
            self.debug_probe.dbgmlbx_reg_write(
                addr=self.registers["CSW"]["address"],
                data=self.registers["CSW"]["bits"]["RESYNCH_REQ"]
                | self.registers["CSW"]["bits"]["CHIP_RESET_REQ"],
            )

        # Acknowledgement of initiation

        # After performing the initiation, the debugger must readback the CSW register.
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
                ret = self.debug_probe.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
            except SPSDKError:
                pass
            retries -= 1
            if retries == 0:
                raise SPSDKIOError("TransferTimeoutError limit exceeded!")
            sleep(0.05)

    def close(self) -> None:
        """Close session."""
        self.debug_probe.close()

    def spin_read(self, reg: int) -> int:
        """Do atomic read operation to debugmailbox.

        :param reg: Register address.
        :return: Read value.
        :raises SPSDKTimeoutError: When read operation exceed defined operation timeout.
        """
        ret = None
        timeout = Timeout(self.op_timeout, units="ms")
        while ret is None:
            try:
                ret = self.debug_probe.dbgmlbx_reg_read(addr=reg)
            except SPSDKError as e:
                logger.error(str(e))
                logger.error(f"read exception  {reg:#08X}")
                if timeout.overflow():
                    raise SPSDKTimeoutError(
                        f"The Debug Mailbox read operation ends on timeout. ({str(e)})"
                    ) from e
                sleep(0.01)

        return ret

    def spin_write(self, reg: int, value: int) -> None:
        """Do atomic write operation to debugmailbox.

        :param reg: Register address.
        :param value: Value to write.
        :raises SPSDKTimeoutError: When write operation exceed defined operation timeout.
        """
        timeout = Timeout(self.op_timeout, units="ms")
        while True:
            try:
                self.debug_probe.dbgmlbx_reg_write(addr=reg, data=value)
                # wait for rom code to read the data
                while True:
                    ret = self.debug_probe.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
                    if (ret & self.registers["CSW"]["bits"]["REQ_PENDING"]) == 0:
                        break
                    if timeout.overflow():
                        raise SPSDKTimeoutError("Mailbox command request pending timeout.")

                return
            except SPSDKError as e:
                logger.error(str(e))
                logger.error(f"write exception addr={reg:#08X}, val={value:#08X}")
                if timeout.overflow():
                    raise SPSDKTimeoutError(
                        f"The Debug Mailbox write operation ends on timeout. ({str(e)})"
                    ) from e
                sleep(0.01)


REGISTERS: Dict[str, Any] = {
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

#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Mailbox communication interface.

This module provides functionality for communicating with NXP MCU debug mailbox
through debug probes, enabling secure provisioning and debugging operations.
Key components:
- DebugMailbox: Main class for debug mailbox communication
- DebugMailboxError: Exception handling for mailbox operations
"""

import logging
from time import sleep
from typing import Any

from spsdk.debuggers.debug_probe import DebugProbe
from spsdk.exceptions import SPSDKError, SPSDKIOError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)

# Default timeout in milliseconds of waiting for the debug mailbox ready (idle) state after reset
DEFAULT_DM_READY_TIMEOUT = 1000
# Default CSW bit mask of bits that must be clear before the debug mailbox is considered ready.
# The ROM/ELE code soft-resets the DM block once it services the resynchronization request,
# which clears RESYNCH_REQ, REQ_PENDING and CHIP_RESET_REQ. Bit 6 (RETURN_PENDING) is part of
# the mask as well, because no return value may be pending before the first command is sent.
DEFAULT_DM_READY_CSW_MASK = 0x63


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
        moredelay: float | None = None,
        op_timeout: int = 1000,
    ) -> None:
        """Initialize DebugMailbox object.

        Establishes connection to the debug mailbox by performing resynchronization request
        and waiting for acknowledgement from ROM code.

        :param debug_probe: Debug probe instance for communication.
        :param family: Chip family and revision information.
        :param reset: Do reset of debug mailbox during initialization, defaults to True.
        :param moredelay: Time of extra delay after reset sequence in seconds, defaults to None
            which means the family specific 'more_delay' value from the database is used.
        :param op_timeout: Atomic operation timeout in milliseconds, defaults to 1000.
        :raises SPSDKIOError: Connection timeout or communication failure with debug mailbox.
        """
        # setup debug port / access point
        self.family = family
        self.non_standard_statuses = {}
        self.command_delays: dict[str, float] = {}
        self.debug_probe = debug_probe
        if family:
            db = get_db(family)
            if hasattr(self.debug_probe, "dbgmlbx_ap_ix"):
                assert isinstance(self.debug_probe.dbgmlbx_ap_ix, int)
                self.dbgmlbx_ap_ix = db.get_int(DatabaseManager.DAT, "dmbox_ap_ix", -1)
                if self.dbgmlbx_ap_ix >= 0:
                    self.debug_probe.dbgmlbx_ap_ix = self.dbgmlbx_ap_ix
            self.non_standard_statuses = db.get_dict(
                DatabaseManager.DAT, "non_standard_statuses", {}
            )
            self.command_delays = db.get_dict(DatabaseManager.DAT, "command_delays", {})
            self.csw_supports_return_pending_flag = db.get_bool(
                DatabaseManager.DAT, "csw_supports_return_pending_flag", False
            )
            self.dm_ready_csw_mask = db.get_int(
                DatabaseManager.DAT, "dm_ready_csw_mask", DEFAULT_DM_READY_CSW_MASK
            )
            self.dm_ready_timeout = db.get_int(
                DatabaseManager.DAT, "dm_ready_timeout", DEFAULT_DM_READY_TIMEOUT
            )
            if moredelay is None:
                moredelay = float(db.get_value(DatabaseManager.DAT, "more_delay", 0.0))
        else:
            self.csw_supports_return_pending_flag = False
            self.dm_ready_csw_mask = DEFAULT_DM_READY_CSW_MASK
            self.dm_ready_timeout = DEFAULT_DM_READY_TIMEOUT

        self.reset = reset
        self.moredelay = moredelay or 0.0
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
            self.debug_probe.dbgmlbx_reg_write(
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

        # The extra delay ('--timing' or the family default 'more_delay' from the database)
        # gives slow boot flows time to finish, for example ELE hybrid/PQC boot, where
        # 'dbg_auth_init' issues the DM soft reset only after the post-quantum key material
        # has been processed.
        if self.moredelay > 0.001:
            logger.debug(f"Delay after reset before CSW sampling: {self.moredelay}s")
            sleep(self.moredelay)

        self.wait_for_dm_ready()

        logger.debug(f"Read DM ID: {hex(self.read_idr())}")

    def wait_for_dm_ready(self) -> None:
        """Wait until the debug mailbox reports a ready (idle) state in CSW.

        The debug mailbox is ready once the ROM/ELE code has serviced the resynchronization
        request by soft-resetting the DM block, which clears all request bits in CSW. Any
        bit set in the ready mask means the handshake is still in progress, so the poll
        continues instead of proceeding with a stale/busy mailbox.

        When the resynchronization request was issued (``reset`` is True) the full
        ``dm_ready_csw_mask`` is awaited, since the specification requires CSW to read back
        as ``0x0``. Without a reset no handshake is pending, so only the ``REQ_PENDING`` bit
        is checked to keep the original ``--no-reset`` behavior.

        Polling on a busy CSW value is important for ELE based devices using hybrid (PQC)
        keys, where the ELE boot and ``dbg_auth_init`` DM soft reset take noticeably longer
        than the classic ECDSA flow. Sampling CSW only once there returns a transient value
        such as ``0x61`` (RESYNCH_REQ | CHIP_RESET_REQ | RETURN_PENDING) and the subsequent
        ENTER command fails.

        :raises SPSDKIOError: The debug mailbox did not become ready within the timeout.
        """
        mask = (
            self.dm_ready_csw_mask if self.reset else self.registers["CSW"]["bits"]["REQ_PENDING"]
        )
        logger.debug(f"Waiting for DM ready, CSW mask: {hex(mask)}")

        ret = None
        timeout = Timeout(self.dm_ready_timeout, units="ms")
        while ret is None or (ret & mask):
            try:
                ret = self.debug_probe.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
                logger.debug(
                    f"Wait for DM ready by reading CSW register: {hex(ret)}"
                    f" (pending: {self.decode_csw_bits(ret & mask)})"
                )
            except SPSDKError as e:
                logger.debug(f"CSW read failed while waiting for DM ready: {e!s}")
                ret = None
            if timeout.overflow():
                raise SPSDKIOError(
                    "The Debug Mailbox is not ready"
                    + (
                        f"; last CSW value: {hex(ret)}"
                        f" (pending bits: {self.decode_csw_bits(ret & mask)})"
                        if ret is not None
                        else " (CSW register is not readable)"
                    )
                    + f". Timeout of {self.dm_ready_timeout} ms exceeded. Advice: increase the"
                    " post reset delay by the '--timing' option of nxpdebugmbox."
                )
            sleep(0.05)

    def decode_csw_bits(self, csw: int) -> str:
        """Decode a CSW register value into a human readable list of bit names.

        :param csw: CSW register value to decode.
        :return: Comma separated names of the bits set in the value, or 'none' when clear.
        """
        names = [name for name, mask in self.registers["CSW"]["bits"].items() if csw & mask]
        return ", ".join(names) if names else "none"

    def read_idr(self) -> int:
        """Read IDR of debug mailbox.

        Reads the Identification Register (IDR) value from the debug mailbox Access Port.

        :return: IDR value of debug mailbox AP.
        """
        return self.debug_probe.dbgmlbx_reg_read(addr=self.registers["IDR"]["address"])

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
                ret = self.debug_probe.dbgmlbx_reg_read(addr=reg)
            except SPSDKError as e:
                logger.debug(str(e))
                logger.debug(f"read exception  {reg:#08X}")
                if timeout.overflow():
                    raise SPSDKTimeoutError(
                        f"The Debug Mailbox read operation ends on timeout. ({e!s})"
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
                self.debug_probe.dbgmlbx_reg_write(addr=reg, data=value)
                # wait for rom code to read the data
                while True:
                    ret = self.debug_probe.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
                    logger.debug(f"Wait for Request pending clear: {hex(ret)}")
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
                        f"The Debug Mailbox write operation ends on timeout. ({e!s})"
                    ) from e
                sleep(0.1)

    def read_return(self) -> int:
        """Read return value from debug mailbox.

        If the chip supports the RETURN_PENDING flag in CSW (bit 6), this method
        polls CSW until the flag is set before reading the RETURN register.
        Otherwise, it falls back to a simple spin_read on the RETURN register.

        :return: Return value from the device.
        :raises SPSDKTimeoutError: When read operation exceeds defined operation timeout.
        """
        if self.csw_supports_return_pending_flag:
            ret = None
            timeout = Timeout(self.op_timeout, units="ms")
            while ret is None or ret & self.registers["CSW"]["bits"]["RETURN_PENDING"] == 0:
                try:
                    ret = self.debug_probe.dbgmlbx_reg_read(addr=self.registers["CSW"]["address"])
                except SPSDKError as e:
                    logger.debug(str(e))
                    logger.debug("Read exception on CSW register")
                    if timeout.overflow():
                        raise SPSDKTimeoutError(
                            f"The Debug Mailbox read operation ends on timeout. ({e!s})"
                        ) from e
                    sleep(0.1)

            return self.debug_probe.dbgmlbx_reg_read(addr=self.registers["RETURN"]["address"])

        return self.spin_read(self.registers["RETURN"]["address"])

    def write_debug_password(self, password: bytes) -> None:
        """Write debug password to the debug mailbox.

        This function writes a debug password through the debug mailbox interface.
        The password is written in multiple register writes.

        :param password: The debug password bytes to write.
        :raises SPSDKError: When password write operation fails.
        """
        if len(password) != 16:
            raise SPSDKError("Debug password must be 32 bytes long")

        # Write password in 4-byte chunks
        for i in range(0, len(password), 4):
            data = int.from_bytes(password[i : i + 4], byteorder="big")
            self.debug_probe.dbgmlbx_reg_write(
                addr=self.registers["AUTH0"]["address"] + i, data=data
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
            # Indicates that a value is waiting to be read by the debugger from Return Value (RETURN). If the
            # debugger reads Return Value (RETURN), then this bit will be automatically cleared by hardware.
            "RETURN_PENDING": (1 << 6),
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
    "AUTH0": {
        "address": 0x80,
    },
}

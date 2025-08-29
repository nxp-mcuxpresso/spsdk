#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for Debug Mailbox."""
import time
from typing import Any, Optional, Union

from spsdk.dat.debug_mailbox import DebugMailbox, logger
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import format_value
from spsdk.utils.spsdk_enum import SpsdkEnum


class DebugMailboxCommandID(SpsdkEnum):
    """Enumeration of all Debug Mailbox commands.

    This enum provides a centralized reference for all command IDs, names,
    and descriptions used in the Debug Mailbox protocol.
    """

    # Base command
    GENERAL = (0x00, "GENERAL", "Dummy command")

    # Basic operations
    START = (0x01, "START", "Start Debug Mailbox")
    GET_CRP_LEVEL = (0x02, "GET_CRP_LEVEL", "Get Code Read Protection Level")
    ERASE_FLASH = (0x03, "ERASE_FLASH", "Erase entire Flash memory")
    EXIT = (0x04, "EXIT", "Exit Debug Mailbox")

    # Mode control
    ENTER_ISP_MODE = (0x05, "ENTER_ISP_MODE", "Enter In-System Programming mode")
    SET_FA_MODE = (0x06, "SET_FA_MODE", "Set Fault Analysis mode")
    START_DBG_SESSION = (0x07, "START_DBG_SESSION", "Start Debug Session")

    # Authentication
    ENTER_BLANK_DEBUG_AUTH = (0x08, "ENTER_BLANK_DEBUG_AUTH", "Enter Blank Debug Authentication")

    # Flash operations
    WRITE_TO_FLASH = (0x09, "WRITE_TO_FLASH", "Write data to Flash memory")
    ERASE_ONE_SECTOR = (0x0B, "ERASE_ONE_SECTOR", "Erase a single Flash sector")

    # Authentication commands
    DBG_AUTH_START = (0x10, "DBG_AUTH_START", "Start Debug Authentication")
    DBG_AUTH_RESP = (0x11, "DBG_AUTH_RESP", "Debug Authentication Response")
    NXP_DBG_AUTH_START = (0x12, "NXP_DBG_AUTH_START", "NXP-specific Debug Authentication Start")
    NXP_DBG_AUTH_RESP = (0x13, "NXP_DBG_AUTH_RESP", "NXP-specific Debug Authentication Response")

    # Provisioning commands
    NXP_SSF_INSERT_CERT = (
        0x14,
        "NXP_SSF_INSERT_CERT",
        "Create self-signed certificate as part of Self sign flow ",
    )
    NXP_EXEC_PROV_FW = (0x15, "NXP_EXEC_PROV_FW", "Execute Provisioning NXP Firmware")


class DebugMailboxCommandID2(SpsdkEnum):
    """Enumeration of all Debug Mailbox commands.

    Different implementation for some devices.
    """

    # Provisioning commands
    NXP_SSF_INSERT_DUK = (
        0x12,
        "NXP_SSF_INSERT_DUK",
        "Create NXP PUF AC code store area as part of Self sign flow (SSF)",
    )
    NXP_EXEC_PROV_FW = (0x13, "NXP_EXEC_PROV_FW", "Execute Provisioning NXP Firmware")


STANDARD_ERROR_CODES = {
    # 0x0000_0000: "Command succeeded",
    0x0010_0001: "Debug mode not entered. This is returned if other commands are sent prior to the 'Enter DM-AP'",
    0x0010_0002: (
        "Command not recognized. A command was received other than is "
        "supported by device in current life cycle"
    ),
    0x0010_0003: "Command failed",
}


class DebugMailboxCommand:
    """Class for DebugMailboxCommand."""

    # default delay after sending a command, in seconds
    DELAY_DEFAULT = 0.03
    CMD: Union[DebugMailboxCommandID, DebugMailboxCommandID2] = DebugMailboxCommandID.GENERAL

    def __init__(
        self,
        dm: DebugMailbox,
        paramlen: int = 0,
        resplen: int = 0,
        delay: Optional[float] = None,
        response_delay: Optional[float] = None,
    ):
        """Initialize."""
        self.dm = dm
        self.paramlen = paramlen
        self.resplen = resplen
        self.delay = delay or self.dm.command_delays.get(self.CMD.label, self.DELAY_DEFAULT)
        self.response_delay = response_delay

    def run(self, params: Optional[list[int]] = None) -> list[Any]:
        """Run DebugMailboxCommand."""
        paramslen = len(params) if params else 0
        if paramslen != self.paramlen:
            raise SPSDKError(
                "Provided parameters length is not equal to command parameters length!"
            )

        req = self.CMD.tag | (self.paramlen << 16)
        logger.debug(f"<- spin_write: {format_value(req, 32)}")
        self.dm.spin_write(self.dm.registers["REQUEST"]["address"], req)

        # Wait to allow reset of internal logic of debug mailbox
        if self.delay != self.DELAY_DEFAULT:
            logger.info(
                f" Applying non-standard delay: {self.delay} seconds to execute {self.CMD.label}"
            )
        time.sleep(self.delay)

        if params:
            for i in range(paramslen):
                ret = self.dm.spin_read(self.dm.registers["RETURN"]["address"])
                logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
                if (ret & 0xFFFF) != 0xA5A5:
                    if ret in STANDARD_ERROR_CODES:
                        error_msg = STANDARD_ERROR_CODES[ret]
                        raise SPSDKError(f"Debug Mailbox Command Error: {error_msg}")
                    raise SPSDKError(
                        f"Device did not send correct ACK answer! Unexpected response: {hex(ret)}"
                    )

                if ((ret >> 16) & 0xFFFF) != (self.paramlen - i):
                    raise SPSDKError(
                        "Device expects parameters of different length we can provide!"
                    )
                logger.debug(f"<- spin_write: {format_value(params[i], 32)}")
                self.dm.spin_write(self.dm.registers["REQUEST"]["address"], params[i])

        ret = self.dm.spin_read(self.dm.registers["RETURN"]["address"])
        logger.debug(f"-> spin_read:  {format_value(ret, 32)}")

        # Solve non standard statuses before checking error indication
        if (
            self.CMD.tag in self.dm.non_standard_statuses
            and ret in self.dm.non_standard_statuses[self.CMD.tag]
        ):
            return [ret]

        # bit 31 is flag in new protocol version
        # new_protocol = bool(ret >> 31)
        error_indication = bool(ret >> 20) and not bool(self.resplen)
        # solve the case that response is in legacy protocol and there is some
        # unwanted bits in none expected data. In this case return valid read data.
        if not self.resplen and not error_indication:
            return [ret]

        resplen = (ret >> 16) & 0x7FFF
        status = ret & 0xFFFF

        if status != 0:
            if status in STANDARD_ERROR_CODES:
                error_msg = STANDARD_ERROR_CODES[status]
                raise SPSDKError(f"Debug Mailbox Command Error: {error_msg}")
            raise SPSDKError(f"Status code is not success: {hex(status)} !")

        if resplen != self.resplen:  # MSB is used to show it is the new protocol -> 0x7FFF
            raise SPSDKError(
                "Device wants to send us different size than expected! "
                f"Device wants {resplen}, but it gets {self.resplen}"
            )

        # do not send ack, in case no data follows
        if resplen == 0:
            return []

        if self.response_delay:
            logger.info(f"Applying response delay: {self.response_delay} seconds")
            time.sleep(self.response_delay)

        # ack the response
        ack = 0xA5A5 | (self.resplen << 16)
        logger.debug(f"<- spin_write: {format_value(ack, 32)}")
        self.dm.spin_write(self.dm.registers["REQUEST"]["address"], ack)

        response = []
        for i in range(self.resplen):
            ret = self.dm.spin_read(self.dm.registers["RETURN"]["address"])
            logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
            response.append(ret)
            ack = 0xA5A5 | ((self.resplen - i - 1) << 16)
            logger.debug(f"<- spin_write: {format_value(ack, 32)}")
            self.dm.spin_write(self.dm.registers["REQUEST"]["address"], ack)
        return response

    def run_safe(self, raise_if_failure: bool = True, **args: Any) -> Optional[list[Any]]:
        """Run a command and abort on first failure instead of looping forever."""
        try:
            return self.run(**args)
        except (SPSDKTimeoutError, TimeoutError) as error:
            if raise_if_failure:
                raise SPSDKTimeoutError("Timeout occurred") from error
            logger.error(str(error))
        return None


class StartDebugMailbox(DebugMailboxCommand):
    """Class for StartDebugMailbox."""

    CMD = DebugMailboxCommandID.START  # Cmd ID: 0x01


class GetCRPLevel(DebugMailboxCommand):
    """Class for Get CRP Level."""

    CMD = DebugMailboxCommandID.GET_CRP_LEVEL  # Cmd ID: 0x02


class EraseFlash(DebugMailboxCommand):
    """Class for Erase Flash."""

    CMD = DebugMailboxCommandID.ERASE_FLASH  # Cmd ID: 0x03

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm)


class ExitDebugMailbox(DebugMailboxCommand):
    """Class for ExitDebugMailbox."""

    CMD = DebugMailboxCommandID.EXIT  # Cmd ID: 0x04


class EnterISPMode(DebugMailboxCommand):
    """Class for EnterISPMode."""

    CMD = DebugMailboxCommandID.ENTER_ISP_MODE  # Cmd ID: 0x05

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=1)


class SetFaultAnalysisMode(DebugMailboxCommand):
    """Class for SetFaultAnalysisMode."""

    CMD = DebugMailboxCommandID.SET_FA_MODE  # Cmd ID: 0x06

    def __init__(self, dm: DebugMailbox, paramlen: int = 0) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)


class StartDebugSession(DebugMailboxCommand):
    """Class for StartDebugSession."""

    CMD = DebugMailboxCommandID.START_DBG_SESSION  # Cmd ID: 0x07


class EnterBlankDebugAuthentication(DebugMailboxCommand):
    """Class for EnterBlankDebugAuthentication."""

    CMD = DebugMailboxCommandID.ENTER_BLANK_DEBUG_AUTH  # Cmd ID: 0x08

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=8)


class WriteToFlash(DebugMailboxCommand):
    """Class for Write To Flash."""

    CMD = DebugMailboxCommandID.WRITE_TO_FLASH  # Cmd ID: 0x09

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=5)


class EraseOneSector(DebugMailboxCommand):
    """Class for Erase One Sector."""

    CMD = DebugMailboxCommandID.ERASE_ONE_SECTOR  # Cmd ID: 0x0B

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=1)


class DebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    CMD = DebugMailboxCommandID.DBG_AUTH_START  # Cmd ID: 0x10

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class DebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    CMD = DebugMailboxCommandID.DBG_AUTH_RESP  # Cmd ID: 0x11

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)


class NxpDebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    CMD = DebugMailboxCommandID.NXP_DBG_AUTH_START  # Cmd ID: 0x12

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class NxpDebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    CMD = DebugMailboxCommandID.NXP_DBG_AUTH_RESP  # Cmd ID: 0x13

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)


class NxpSsfInsertDuk(DebugMailboxCommand):
    """Class to create NXP PUF AC code store area as part of Self sign flow (SSF)."""

    CMD = DebugMailboxCommandID2.NXP_SSF_INSERT_DUK  # Cmd ID: 0x12

    def __init__(self, dm: DebugMailbox, paramlen: int = 8, resplen: int = 16) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen, resplen=resplen)


class NxpExecuteProvisioningFw(DebugMailboxCommand):
    """Class for Execute provisioning firmware command."""

    CMD = DebugMailboxCommandID2.NXP_EXEC_PROV_FW  # Cmd ID: 0x13


class NxpSsfInsertCert(DebugMailboxCommand):
    """Command to create self-signed certificate as part of Self sign flow (SSF)."""

    CMD = DebugMailboxCommandID.NXP_SSF_INSERT_CERT  # Cmd ID: 0x14

    def __init__(
        self,
        dm: DebugMailbox,
        paramlen: int = 8,
        resplen: int = 0x2B8,
        response_delay: float = 1.0,
    ) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen, resplen=resplen, response_delay=response_delay)

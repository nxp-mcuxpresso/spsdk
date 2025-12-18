#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Mailbox command implementations.

This module provides command classes for interacting with NXP MCU debug mailboxes,
including authentication, flash operations, and debug session management.
"""

import time
from typing import Any, Optional, Union

from spsdk.dat.debug_mailbox import DebugMailbox, logger
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import format_value
from spsdk.utils.spsdk_enum import SpsdkEnum


class DebugMailboxCommandID(SpsdkEnum):
    """Debug Mailbox command identifier enumeration.

    This enumeration defines all available command IDs used in the Debug Mailbox
    protocol for NXP MCUs. Each command includes an ID value, name, and description
    covering basic operations, mode control, authentication, flash operations, and
    provisioning functionality.
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

    SET_BRICKED_MODE = (0x16, "SET_BRICKED_MODE", "Set device bricked mode")


class DebugMailboxCommandID2(SpsdkEnum):
    """Debug Mailbox Command ID enumeration for specific device implementations.

    This enumeration defines command identifiers used by the Debug Mailbox interface
    for devices that require alternative command implementations compared to the
    standard command set.
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
    """Debug Mailbox command executor for NXP MCU communication.

    This class provides a standardized interface for executing debug mailbox commands
    on NXP MCUs. It handles command formatting, parameter validation, timing delays,
    and response processing for reliable debug mailbox communication.

    :cvar DELAY_DEFAULT: Default delay after sending a command in seconds.
    :cvar CMD: Command identifier for the debug mailbox operation.
    """

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
        """Initialize Debug Mailbox command.

        Sets up the command with the specified debug mailbox instance and configuration
        parameters for command execution timing and data lengths.

        :param dm: Debug mailbox instance for command execution.
        :param paramlen: Length of command parameters in bytes, defaults to 0.
        :param resplen: Expected length of response data in bytes, defaults to 0.
        :param delay: Custom delay before command execution in seconds, uses default if None.
        :param response_delay: Custom delay after command execution in seconds, optional.
        """
        self.dm = dm
        self.paramlen = paramlen
        self.resplen = resplen
        self.delay = delay or self.dm.command_delays.get(self.CMD.label, self.DELAY_DEFAULT)
        self.response_delay = response_delay

    def run(self, params: Optional[list[int]] = None) -> list[Any]:
        """Execute debug mailbox command with optional parameters.

        Sends command to debug mailbox, handles parameter transmission, waits for response,
        and validates the communication protocol. Supports both legacy and new protocol versions
        with proper error handling and acknowledgment sequences.

        :param params: Optional list of integer parameters to send with the command.
        :raises SPSDKError: When parameter length mismatch, device communication errors,
                           status codes indicate failure, or protocol validation fails.
        :return: List of response values from the debug mailbox command execution.
        """
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
        """Run a command and abort on first failure instead of looping forever.

        This method provides a safe wrapper around the run method that handles timeout
        exceptions gracefully and prevents infinite loops on command failures.

        :param raise_if_failure: If True, re-raises timeout exceptions; if False, logs
            errors and returns None.
        :param args: Additional keyword arguments passed to the underlying run method.
        :raises SPSDKTimeoutError: When a timeout occurs and raise_if_failure is True.
        :return: Result from the run method on success, None on timeout when
            raise_if_failure is False.
        """
        try:
            return self.run(**args)
        except (SPSDKTimeoutError, TimeoutError) as error:
            if raise_if_failure:
                raise SPSDKTimeoutError("Timeout occurred") from error
            logger.error(str(error))
        return None


class StartDebugMailbox(DebugMailboxCommand):
    """Debug mailbox command for starting debug session.

    This command initiates the debug mailbox communication protocol,
    enabling debug operations on the target device.

    :cvar CMD: Command identifier for start debug mailbox operation.
    """

    CMD = DebugMailboxCommandID.START  # Cmd ID: 0x01


class GetCRPLevel(DebugMailboxCommand):
    """Debug Mailbox command for retrieving Code Read Protection (CRP) level.

    This command queries the target device to obtain the current CRP level,
    which determines the level of code protection and debug access restrictions
    applied to the MCU.

    :cvar CMD: Command identifier for Get CRP Level operation.
    """

    CMD = DebugMailboxCommandID.GET_CRP_LEVEL  # Cmd ID: 0x02


class EraseFlash(DebugMailboxCommand):
    """Debug Mailbox command for erasing flash memory.

    This command provides functionality to erase flash memory through the debug
    mailbox interface, allowing secure provisioning operations to clear flash
    content before programming new data.

    :cvar CMD: Command identifier for erase flash operation.
    """

    CMD = DebugMailboxCommandID.ERASE_FLASH  # Cmd ID: 0x03

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance to be used for command execution.
        """
        super().__init__(dm)


class ExitDebugMailbox(DebugMailboxCommand):
    """Debug mailbox command for exiting debug mode.

    This command instructs the target device to exit the debug mailbox
    communication mode and return to normal operation.

    :cvar CMD: Command identifier for exit debug mailbox operation.
    """

    CMD = DebugMailboxCommandID.EXIT  # Cmd ID: 0x04


class EnterISPMode(DebugMailboxCommand):
    """Debug Mailbox command for entering In-System Programming mode.

    This command instructs the target device to enter ISP mode, allowing
    for firmware updates and programming operations through the debug mailbox
    interface.

    :cvar CMD: Command identifier for Enter ISP Mode operation.
    """

    CMD = DebugMailboxCommandID.ENTER_ISP_MODE  # Cmd ID: 0x05

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance to be used for command execution.
        """
        super().__init__(dm, paramlen=1)


class SetFaultAnalysisMode(DebugMailboxCommand):
    """Debug mailbox command for setting fault analysis mode.

    This command configures the fault analysis mode in the target device's
    debug mailbox, enabling or disabling fault analysis capabilities for
    debugging and diagnostic purposes.

    :cvar CMD: Command identifier for set fault analysis mode operation.
    """

    CMD = DebugMailboxCommandID.SET_FA_MODE  # Cmd ID: 0x06

    def __init__(self, dm: DebugMailbox, paramlen: int = 0) -> None:
        """Initialize Debug Mailbox command.

        :param dm: Debug mailbox instance for communication.
        :param paramlen: Length of command parameters in bytes, defaults to 0.
        """
        super().__init__(dm, paramlen=paramlen)


class StartDebugSession(DebugMailboxCommand):
    """Debug mailbox command for starting a debug session.

    This command initiates a debug session through the debug mailbox interface,
    allowing debugger tools to establish communication with the target device.

    :cvar CMD: Command identifier for start debug session operation.
    """

    CMD = DebugMailboxCommandID.START_DBG_SESSION  # Cmd ID: 0x07


class EnterBlankDebugAuthentication(DebugMailboxCommand):
    """Debug mailbox command for entering blank debug authentication mode.

    This command initiates blank debug authentication, which allows debug access
    without requiring authentication credentials. This is typically used in
    development scenarios where security restrictions need to be bypassed.

    :cvar CMD: Command identifier for blank debug authentication entry.
    """

    CMD = DebugMailboxCommandID.ENTER_BLANK_DEBUG_AUTH  # Cmd ID: 0x08

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance to be used for command execution.
        """
        super().__init__(dm, paramlen=8)


class SetBrickedMode(DebugMailboxCommand):
    """Class for SetBrickedMode."""

    CMD = DebugMailboxCommandID.SET_BRICKED_MODE  # Cmd ID: 0x16


class WriteToFlash(DebugMailboxCommand):
    """Debug Mailbox command for writing data to flash memory.

    This command handles the write-to-flash operation through the debug mailbox
    interface, allowing data to be programmed into the target device's flash
    memory during debug or provisioning operations.

    :cvar CMD: Command identifier for write-to-flash operation.
    """

    CMD = DebugMailboxCommandID.WRITE_TO_FLASH  # Cmd ID: 0x09

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance to be used for command execution.
        """
        super().__init__(dm, paramlen=5)


class EraseOneSector(DebugMailboxCommand):
    """Debug mailbox command for erasing a single flash memory sector.

    This command provides functionality to erase one specific sector in the target
    device's flash memory through the debug mailbox interface.

    :cvar CMD: Command identifier for erase one sector operation.
    """

    CMD = DebugMailboxCommandID.ERASE_ONE_SECTOR  # Cmd ID: 0x0B

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance to be used for command execution.
        """
        super().__init__(dm, paramlen=1)


class DebugAuthenticationStart(DebugMailboxCommand):
    """Debug authentication start command for secure debug access.

    This command initiates the debug authentication process in the debug mailbox,
    allowing secure access to debug features on NXP MCUs. The command supports
    different hash algorithms (SHA256/SHA384) with configurable response lengths.

    :cvar CMD: Command identifier for debug authentication start operation.
    """

    CMD = DebugMailboxCommandID.DBG_AUTH_START  # Cmd ID: 0x10

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize Debug Mailbox command.

        Sets up the command with the specified Debug Mailbox instance and response length.
        The response length determines the expected size of the command response in words,
        with default supporting SHA256 (26 words = 104 bytes) and optional SHA384 support
        (30 words = 120 bytes).

        :param dm: Debug Mailbox instance to use for command execution.
        :param resplen: Expected response length in words, defaults to 26 for SHA256.
        """
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class DebugAuthenticationResponse(DebugMailboxCommand):
    """Debug authentication response command for secure debug mailbox communication.

    This class represents a response message in the debug authentication protocol,
    handling the reply from the target device during secure debug session establishment.

    :cvar CMD: Command identifier for debug authentication response (0x11).
    """

    CMD = DebugMailboxCommandID.DBG_AUTH_RESP  # Cmd ID: 0x11

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize Debug Mailbox command.

        :param dm: Debug mailbox instance for communication.
        :param paramlen: Length of command parameters in bytes.
        """
        super().__init__(dm, paramlen=paramlen)


class NxpDebugAuthenticationStart(DebugMailboxCommand):
    """NXP Debug Authentication Start command for debug mailbox operations.

    This class implements the debug authentication start command that initiates
    the authentication process for NXP debug operations through the debug mailbox
    interface. It handles the initial phase of secure debug authentication.

    :cvar CMD: Command identifier for NXP debug authentication start operation.
    """

    CMD = DebugMailboxCommandID.NXP_DBG_AUTH_START  # Cmd ID: 0x12

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize Debug Mailbox command.

        Sets up the command with specified debug mailbox instance and response length.
        The response length determines the hash algorithm used: 26 words (104 bytes)
        for SHA256 or 30 words (120 bytes) for SHA384.

        :param dm: Debug mailbox instance for communication.
        :param resplen: Expected response length in words, defaults to 26 for SHA256.
        """
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class NxpDebugAuthenticationResponse(DebugMailboxCommand):
    """NXP Debug Authentication Response command for debug mailbox communication.

    This class represents a response command used in the NXP debug authentication
    process, handling the authentication response data through the debug mailbox
    interface.

    :cvar CMD: Command identifier for NXP debug authentication response (0x13).
    """

    CMD = DebugMailboxCommandID.NXP_DBG_AUTH_RESP  # Cmd ID: 0x13

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize Debug Mailbox command.

        :param dm: Debug mailbox instance for communication.
        :param paramlen: Length of command parameters in bytes.
        """
        super().__init__(dm, paramlen=paramlen)


class NxpSsfInsertDuk(DebugMailboxCommand):
    """NXP SSF Insert DUK debug mailbox command.

    This class implements the NXP Self Sign Flow (SSF) Insert Device Unique Key (DUK)
    command for creating PUF AC code store area through the debug mailbox interface.

    :cvar CMD: Debug mailbox command identifier for NXP SSF Insert DUK operation.
    """

    CMD = DebugMailboxCommandID2.NXP_SSF_INSERT_DUK  # Cmd ID: 0x12

    def __init__(self, dm: DebugMailbox, paramlen: int = 8, resplen: int = 16) -> None:
        """Initialize the debug mailbox command.

        :param dm: Debug mailbox instance for communication.
        :param paramlen: Length of command parameters in bytes, defaults to 8.
        :param resplen: Length of expected response in bytes, defaults to 16.
        """
        super().__init__(dm, paramlen=paramlen, resplen=resplen)


class NxpExecuteProvisioningFw(DebugMailboxCommand):
    """Debug mailbox command for executing provisioning firmware.

    This command triggers the execution of provisioning firmware on NXP MCU devices
    through the debug mailbox interface, enabling secure provisioning operations.

    :cvar CMD: Command identifier for NXP execute provisioning firmware operation.
    """

    CMD = DebugMailboxCommandID2.NXP_EXEC_PROV_FW  # Cmd ID: 0x13


class NxpSsfInsertCert(DebugMailboxCommand):
    """NXP Self-Signed Flow certificate insertion command.

    This debug mailbox command handles the creation and insertion of self-signed certificates
    as part of NXP's Self Sign Flow (SSF) provisioning process for secure boot operations.

    :cvar CMD: Command identifier for NXP SSF certificate insertion operation.
    """

    CMD = DebugMailboxCommandID.NXP_SSF_INSERT_CERT  # Cmd ID: 0x14

    def __init__(
        self,
        dm: DebugMailbox,
        paramlen: int = 8,
        resplen: int = 0x2B8,
        response_delay: float = 1.0,
    ) -> None:
        """Initialize the debug mailbox command.

        Sets up the command with specified parameter length, response length, and response delay
        for debug mailbox communication.

        :param dm: Debug mailbox instance for communication.
        :param paramlen: Length of command parameters in bytes.
        :param resplen: Expected response length in bytes.
        :param response_delay: Delay in seconds to wait for response.
        """
        super().__init__(dm, paramlen=paramlen, resplen=resplen, response_delay=response_delay)

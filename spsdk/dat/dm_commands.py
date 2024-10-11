#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for Debug Mailbox."""
import time
from typing import Any, Optional

from spsdk.dat.debug_mailbox import DebugMailbox, logger
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import format_value


class DebugMailboxCommand:
    """Class for DebugMailboxCommand."""

    # default delay after sending a command, in seconds
    DELAY_DEFAULT = 0.03
    CMD_ID = 0
    CMD_NAME = "General"

    def __init__(
        self,
        dm: DebugMailbox,
        paramlen: int = 0,
        resplen: int = 0,
        delay: float = DELAY_DEFAULT,
    ):
        """Initialize."""
        self.dm = dm
        self.paramlen = paramlen
        self.resplen = resplen
        self.delay = delay

    def run(self, params: Optional[list[int]] = None) -> list[Any]:
        """Run DebugMailboxCommand."""
        paramslen = len(params) if params else 0
        if paramslen != self.paramlen:
            raise SPSDKError(
                "Provided parameters length is not equal to command parameters length!"
            )

        req = self.CMD_ID | (self.paramlen << 16)
        logger.debug(f"<- spin_write: {format_value(req, 32)}")
        self.dm.spin_write(self.dm.registers["REQUEST"]["address"], req)

        # Wait to allow reset of internal logic of debug mailbox
        time.sleep(self.delay)

        if params:
            for i in range(paramslen):
                ret = self.dm.spin_read(self.dm.registers["RETURN"]["address"])
                logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
                if (ret & 0xFFFF) != 0xA5A5:
                    raise SPSDKError("Device did not send correct ACK answer!")
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
            self.CMD_ID in self.dm.non_standard_statuses
            and ret in self.dm.non_standard_statuses[self.CMD_ID]
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
            raise SPSDKError(f"Status code is not success: {status} !")

        if resplen != self.resplen:  # MSB is used to show it is the new protocol -> 0x7FFF
            raise SPSDKError("Device wants to send us different size than expected!")

        # do not send ack, in case no data follows
        if resplen == 0:
            return []

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

    CMD_ID = 1
    CMD_NAME = "START_DBG_MB"


class GetCRPLevel(DebugMailboxCommand):
    """Class for Get CRP Level."""

    CMD_ID = 2
    CMD_NAME = "GET_CRP_LEVEL"


class EraseFlash(DebugMailboxCommand):
    """Class for Erase Flash."""

    CMD_ID = 3
    CMD_NAME = "ERASE_FLASH"

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, delay=0.5)


class ExitDebugMailbox(DebugMailboxCommand):
    """Class for ExitDebugMailbox."""

    CMD_ID = 4
    CMD_NAME = "EXIT_DBG_MB"


class EnterISPMode(DebugMailboxCommand):
    """Class for EnterISPMode."""

    CMD_ID = 5
    CMD_NAME = "ENTER_ISP_MODE"

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=1)


class SetFaultAnalysisMode(DebugMailboxCommand):
    """Class for SetFaultAnalysisMode."""

    CMD_ID = 6
    CMD_NAME = "SET_FA_MODE"

    def __init__(self, dm: DebugMailbox, paramlen: int = 0) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)


class StartDebugSession(DebugMailboxCommand):
    """Class for StartDebugSession."""

    CMD_ID = 7
    CMD_NAME = "START_DBG_SESSION"


class EnterBlankDebugAuthentication(DebugMailboxCommand):
    """Class for EnterBlankDebugAuthentication."""

    CMD_ID = 8
    CMD_NAME = "ENTER_BLANK_DEBUG_AUTH"

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=8)


class WriteToFlash(DebugMailboxCommand):
    """Class for Write To Flash."""

    CMD_ID = 9
    CMD_NAME = "WRITE_TO_FLASH"

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=5)


class EraseOneSector(DebugMailboxCommand):
    """Class for Erase One Sector."""

    CMD_ID = 11
    CMD_NAME = "ERASE_ONE_SECTOR"

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=1)


class DebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    CMD_ID = 16
    CMD_NAME = "DBG_AUTH_START"

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class DebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    CMD_ID = 17
    CMD_NAME = "DBG_AUTH_RESP"

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)


class NxpDebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    CMD_ID = 18
    CMD_NAME = "NXP_DBG_AUTH_START"

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, resplen=resplen)


class NxpDebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    CMD_ID = 19
    CMD_NAME = "NXP_DBG_AUTH_RESP"

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, paramlen=paramlen)

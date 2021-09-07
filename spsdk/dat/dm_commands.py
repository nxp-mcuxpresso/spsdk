#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for Debug Mailbox."""
import time
from typing import Any, List

from spsdk import SPSDKError
from spsdk.utils.misc import format_value

from .debug_mailbox import DebugMailbox, logger


class DebugMailboxCommand:
    """Class for DebugMailboxCommand."""

    def __init__(
        self,
        dm: DebugMailbox,
        id: int,
        name: str = "",
        paramlen: int = 0,
        resplen: int = 0,
    ):
        """Initialize."""
        self.dm = dm
        self.paramlen = paramlen
        self.resplen = resplen
        self.id = id
        self.name = name

    def run(self, params: list = []) -> List[Any]:
        """Run DebugMailboxCommand."""
        if len(params) != self.paramlen:
            raise SPSDKError(
                "Provided parameters length is not equal to command parameters length!"
            )

        req = self.id | (self.paramlen << 16)
        logger.debug(f"<- spin_write: {format_value(req, 32)}")
        self.dm.spin_write(self.dm.registers.REQUEST.address, req)

        # Wait 30ms to allow reset of internal logic of debug mailbox
        time.sleep(0.03)

        for i in range(self.paramlen):
            ret = self.dm.spin_read(self.dm.registers.RETURN.address)
            logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
            if (ret & 0xFFFF) != 0xA5A5:
                raise SPSDKError("Device did not send correct ACK answer!")
            if ((ret >> 16) & 0xFFFF) != (self.paramlen - i):
                raise SPSDKError("Device expects parameters of different length we can provide!")
            logger.debug(f"<- spin_write: {format_value(params[i], 32)}")
            self.dm.spin_write(self.dm.registers.REQUEST.address, params[i])

        ret = self.dm.spin_read(self.dm.registers.RETURN.address)
        logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
        resplen = (ret >> 16) & 0x7FFF
        status = ret & 0xFFFF

        if resplen != self.resplen:  # MSB is used to show it is the new protocol -> 0x7FFF
            raise SPSDKError("Device wants to send us different size than expected!")

        if status != 0:
            raise SPSDKError(f"Status code is not success: {ret & 0xFFFF} !")

        # do not send ack, in case no data follows
        if resplen == 0:
            return []

        # ack the response
        ack = 0xA5A5 | (self.resplen << 16)
        logger.debug(f"<- spin_write: {format_value(ack, 32)}")
        self.dm.spin_write(self.dm.registers.REQUEST.address, ack)

        response = []
        for i in range(self.resplen):
            ret = self.dm.spin_read(self.dm.registers.RETURN.address)
            logger.debug(f"-> spin_read:  {format_value(ret, 32)}")
            response.append(ret)
            ack = 0xA5A5 | ((self.resplen - i - 1) << 16)
            logger.debug(f"<- spin_write: {format_value(ack, 32)}")
            self.dm.spin_write(self.dm.registers.REQUEST.address, ack)
        return response


class StartDebugMailbox(DebugMailboxCommand):
    """Class for StartDebugMailbox."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(StartDebugMailbox, self).__init__(dm, id=1, name="START_DBG_MB")


class GetCRPLevel(DebugMailboxCommand):
    """Class for Get CRP Level."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(GetCRPLevel, self).__init__(dm, id=2, name="GET_CRP_LEVEL")


class EraseFlash(DebugMailboxCommand):
    """Class for Erase Flash."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(EraseFlash, self).__init__(dm, id=3, name="ERASE_FLASH")


class ExitDebugMailbox(DebugMailboxCommand):
    """Class for ExitDebugMailbox."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(ExitDebugMailbox, self).__init__(dm, id=4, name="EXIT_DBG_MB")


class EnterISPMode(DebugMailboxCommand):
    """Class for EnterISPMode."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(EnterISPMode, self).__init__(dm, id=5, name="ENTER_ISP_MODE", paramlen=1)


class SetFaultAnalysisMode(DebugMailboxCommand):
    """Class for SetFaultAnalysisMode."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(SetFaultAnalysisMode, self).__init__(dm, id=6, name="SET_FA_MODE")


class StartDebugSession(DebugMailboxCommand):
    """Class for StartDebugSession."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super(StartDebugSession, self).__init__(dm, id=7, name="START_DBG_SESSION")


class DebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super(DebugAuthenticationStart, self).__init__(
            dm, id=16, name="DBG_AUTH_START", resplen=resplen
        )


class DebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super(DebugAuthenticationResponse, self).__init__(
            dm, id=17, name="DBG_AUTH_RESP", paramlen=paramlen
        )

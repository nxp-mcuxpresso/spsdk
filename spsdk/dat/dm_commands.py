#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for Debug Mailbox."""
import time
from typing import Any, List, Optional

from spsdk.dat.debug_mailbox import DebugMailbox, logger
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import format_value


class DebugMailboxCommand:
    """Class for DebugMailboxCommand."""

    STATUS_IS_DATA_MASK = 0x00
    # default delay after sending a command, in seconds
    DELAY_DEFAULT = 0.03

    def __init__(
        self,
        dm: DebugMailbox,
        id: int,  # pylint: disable=redefined-builtin
        name: str = "",
        paramlen: int = 0,
        resplen: int = 0,
        delay: float = DELAY_DEFAULT,
    ):
        """Initialize."""
        self.dm = dm
        self.paramlen = paramlen
        self.resplen = resplen
        self.id = id
        self.name = name
        self.delay = delay

    def run(self, params: Optional[List[int]] = None) -> List[Any]:
        """Run DebugMailboxCommand."""
        paramslen = len(params) if params else 0
        if paramslen != self.paramlen:
            raise SPSDKError(
                "Provided parameters length is not equal to command parameters length!"
            )

        req = self.id | (self.paramlen << 16)
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

    def run_safe(self, raise_if_failure: bool = True, **args: Any) -> Optional[List[Any]]:
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

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=1, name="START_DBG_MB")


class GetCRPLevel(DebugMailboxCommand):
    """Class for Get CRP Level."""

    # Set STATUS_IS_DATA_MASK to range 0-255, because larger life cycle is not expected
    STATUS_IS_DATA_MASK = 0xFF

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=2, name="GET_CRP_LEVEL")


class EraseFlash(DebugMailboxCommand):
    """Class for Erase Flash."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=3, name="ERASE_FLASH", delay=0.5)


class ExitDebugMailbox(DebugMailboxCommand):
    """Class for ExitDebugMailbox."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=4, name="EXIT_DBG_MB")


class EnterISPMode(DebugMailboxCommand):
    """Class for EnterISPMode."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=5, name="ENTER_ISP_MODE", paramlen=1)


class EnterBlankDebugAuthentication(DebugMailboxCommand):
    """Class for EnterBlankDebugAuthentication."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=0x8, name="ENTER_BLANK_DEBUG_AUTH", paramlen=8)


class SetFaultAnalysisMode(DebugMailboxCommand):
    """Class for SetFaultAnalysisMode."""

    def __init__(self, dm: DebugMailbox, paramlen: int = 0) -> None:
        """Initialize."""
        super().__init__(dm, id=6, name="SET_FA_MODE", paramlen=paramlen)


class StartDebugSession(DebugMailboxCommand):
    """Class for StartDebugSession."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=7, name="START_DBG_SESSION")


class DebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, id=16, name="DBG_AUTH_START", resplen=resplen)


class DebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, id=17, name="DBG_AUTH_RESP", paramlen=paramlen)


class NxpDebugAuthenticationStart(DebugMailboxCommand):
    """Class for DebugAuthenticationStart."""

    def __init__(self, dm: DebugMailbox, resplen: int = 26) -> None:
        """Initialize."""
        # 26 words == 104 bytes (SHA256 - 32 Bytes)
        # 30 words == 120 bytes (SHA384 - 48 Bytes)
        super().__init__(dm, id=18, name="NXP_DBG_AUTH_START", resplen=resplen)


class NxpDebugAuthenticationResponse(DebugMailboxCommand):
    """Class for DebugAuthenticationResponse."""

    def __init__(self, dm: DebugMailbox, paramlen: int) -> None:
        """Initialize."""
        super().__init__(dm, id=19, name="NXP_DBG_AUTH_RESP", paramlen=paramlen)


class StartDebugSessions(DebugMailboxCommand):
    """Class for StartDebugSessions."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=7, name="START_DEBUG_SESSION")


class EraseOneSector(DebugMailboxCommand):
    """Class for Erase One Sector."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=11, name="ERASE_ONE_SECTOR", paramlen=1)


class WriteToFlash(DebugMailboxCommand):
    """Class for Write To Flash."""

    def __init__(self, dm: DebugMailbox) -> None:
        """Initialize."""
        super().__init__(dm, id=9, name="WRITE_TO_FLASH", paramlen=5)

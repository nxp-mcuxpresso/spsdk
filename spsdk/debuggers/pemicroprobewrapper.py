#!/usr/bin/env python
#
# Copyright (c) 2020 P&E Microcomputer Systems, Inc
# All rights reserved.
# Visit us at www.pemicro.com
#
# SPDX-License-Identifier:
# BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# o Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
# o Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# o Neither the names of the copyright holders nor the names of the
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""Module for PemicroProbe."""
from .pemicrounitacmp import pemicroUnitAcmp


class pemicroProbeWrapper(object):
    """Class for pemicroProbeWrapper."""

    def __init__(self, apnumber: int, hardwareid: str = None) -> None:
        """Initialize the tool internal state.

        Open and initialize the probe, and select the AP specified in apnumber.
        If the underlying probe support and/or initialization
        in any way relies on the presence of a core AP, this needs
        to be subverted. The NXP debug mailbox AP is not a core AP.

        :param apnumber: Debug Mailbox AP (typically AP 2 for NXP devices)
        :param hardwareid: ID of Hardware
        """
        self.apNumber = apnumber
        self.connectedToDebugHardware = False
        self.connectedToTarget = False

        # Load the PEmicro debug communications library
        self.pemicroProbeLibrary = pemicroUnitAcmp()

        # Connect to PEmicro Debug Hardware
        if not self.pemicroProbeLibrary.connectToDebugCable(debugHardwareNameIpOrSerialnum=hardwareid):
            return
        self.connectedToDebugHardware = True

        # Connect to target device trhough PEmicro Debug Hardware
        if not self.pemicroProbeLibrary.establishCommunicationsWithTarget():
            return
        self.connectedToTarget = True

    def write_reg(self, addr: int, value: int) -> None:
        """Write register.

        :param addr:  Debug mailbox AP register offset (ref: Users Manual)
        #            CSW     0x00
        #            REQUEST 0x04
        #            RETURN  0x08
        #            ID      0xFC
        :param value:
        """
        self.pemicroProbeLibrary.writeApRegister(self.apNumber, addr, value, now=False)

    def read_reg(self, addr: int, now: bool = True, requiresDelay: bool = False) -> int:
        """Read register.

        :param addr: Debug mailbox AP register offset (ref: Users Manual)
        #            CSW     0x00
        #            REQUEST 0x04
        #            RETURN  0x08
        #            ID      0xFC
        :param now: Do not cache the read operation, True/False. Default is True.
        This parameter is not in use by the DebugMailbox object.
        :param requiresDelay: Read delay for a response. The DebugMailbox layer already has wait
        and/or retry loops pending a response
        :return: value from register
        """
        return self.pemicroProbeLibrary.readApRegister(self.apNumber, addr)

    def close(self) -> None:
        """Close."""
        self.pemicroProbeLibrary.close()

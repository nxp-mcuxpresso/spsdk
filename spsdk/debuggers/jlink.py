#!/usr/bin/env python
#
# jlink.py
#
# Copyright (c) 2017-2020 NXP
# All rights reserved.
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
"""Module for JLink actions."""
import subprocess
import os.path
import pylink
import pylink.protocols.swd as swd
from time import sleep


class JLinkWrapper(object):
    """Class for JLinkWrapper."""
    def __init__(self, apnumber: int, serial_no: int = None,
                 ip_addr: str = None) -> None:
        """Initialize.

        :param apnumber:  ap number
        :param serial_no: serial number
        :param ip_addr: ip address
        """
        self.apnumber = apnumber
        self.jlink = pylink.JLink()

        self.jlink.open(serial_no=serial_no, ip_addr=ip_addr)
        self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        # self.jlink.set_speed(4000)
        # MUST BE UNUSED self.jlink.connect("CORTEX-M33", verbose=True)
        self.jlink.coresight_configure()
        # Use coresight_read/write API - True (default)
        # or the original swd interface- False (this did not work properly)
        self.use_coresight_rw = True

        # Select ISP - AP
        if not self.use_coresight_rw:
            request = swd.WriteRequest(2, data=(0x000000F0 | (apnumber << 24)), ap=False)
            response = request.send(self.jlink)
            assert response.ack(), "No ack from JLink"
        else:
            self.jlink.coresight_write(reg=2, data=(0x000000F0 | (apnumber << 24)), ap=False)

        if not self.use_coresight_rw:
            request = swd.WriteRequest(2, data=(0x00000000 | (apnumber << 24)), ap=False)
            response = request.send(self.jlink)
            assert response.ack(), "No ack from JLink"
        else:
            self.jlink.coresight_write(reg=2, data=(0x00000000 | (apnumber << 24)), ap=False)

    def write_reg(self, addr: int, value: int) -> None:
        """Write register.

        :param addr: the register index
        :param value: which will be written to register
        """
        if not self.use_coresight_rw:
            request = swd.WriteRequest(addr // 4, data=value, ap=True)
            response = request.send(self.jlink)
            assert response.ack(), "No ack from JLink"
        else:
            self.jlink.coresight_write(reg=addr // 4, data=value, ap=True)

    def read_reg(self, addr: int, now: bool = True,
                 requiresDelay: bool = False) -> bytes:
        """Read register.

        :param addr: the register index
        :param now: bool value
        :param requiresDelay: if the delay is required, there is sleep for 0.1 second
        :return:
        """
        if not self.use_coresight_rw:
            request = swd.ReadRequest(addr // 4, ap=True)
            response = request.send(self.jlink)
            if requiresDelay is True:
                sleep(0.1)
            request2 = swd.ReadRequest(3, ap=False)
            response2 = request2.send(self.jlink)
            return response2.data
        else:
            return self.jlink.coresight_read(reg=addr // 4, ap=True)

    def close(self) -> None:
        """Close the interface."""
        self.jlink.close()

# redlink.py
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
"""Module for RedLinkWrapper."""
import subprocess
import os.path


class RedLinkWrapper:
    """Class for RedLinkWrapper."""
    def __init__(self, apnumber: int = 2, rltool_path: str = None) -> None:
        """Initialize.

        :param apnumber: ap number
        :param rltool_path: path, where the process is located
        """
        self.rltool_path = rltool_path or "rltool.exe"
        assert os.path.isfile(self.rltool_path), \
            "Cannot find rltool.exe at " + self.rltool_path + ", please use -t argument and set a valid path rltool.exe"
        self.apnumber = apnumber
        self.process = subprocess.Popen(self.rltool_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert self.process.stdin and self.process.stdout
        self.__drop(1)
        self.process.stdin.write(b"srv probelist\n")
        probes = self.process.stdout.readline()
        self.__drop(7)
        probe_index = probes.split(b"Index = ")[1].strip()
        self.process.stdin.write(b"srv probeopenbyindex " + probe_index + b"\n")
        self.process.stdin.write(b"srv wireswdconnect " + probe_index + b"\n")
        self.process.stdin.write(b"srv selectprobecore " + probe_index + b" 0\n")
        self.process.stdin.write(b"srv cmwritedp " + probe_index + b" 0 4 0x50000F00\n")
        self.process.stdin.write(b"srv coreconfig " + probe_index + b"\n")
        self.process.stdin.write(b"srv cminitapdp " + probe_index + b" 0\n")
        self.process.stdin.write(b"srv cmwritedp " + probe_index + b" 0 2 0x020000F0\n")
        self.process.stdin.write(b"srv selectprobecore " + probe_index + b" 0x20\n")
        self.process.stdin.write(b"srv cmwritedp " + probe_index + b" 0 2 0x02000000\n")
        self.__drop(4)
        self.probe_index = probe_index

    def __drop(self, count: int) -> None:
        """Read lines from process's stdout."""
        assert self.process.stdout
        for _ in range(count):
            self.process.stdout.readline()

    def write_reg(self, addr: int, value: int) -> None:
        """Write register.

        :param addr: register offset
        :param value: value to be written
        """
        assert self.process.stdin and self.process.stdout
        request = "srv cmwriteap " + str(self.probe_index) + " 0" + (" %d " % (addr / 4)) + (" 0x%X" % value) + "\n"
        self.process.stdin.write(request.encode(encoding='utf-8'))

    def read_reg(self, addr: int, _now: bool = True) -> int:
        """Read register.

        :param addr: register offset
        :param _now: Do not cache the read operation, True/False. Default is True.
        :return: value read from register
        """
        assert self.process.stdin and self.process.stdout
        request = "srv cmreadap " + str(self.probe_index) + " 0" + (" %d" % (addr / 4)) + "\n"
        self.process.stdin.write(request.encode(encoding='utf-8'))
        value = self.process.stdout.readline()
        value = value.split('> '.encode(encoding='utf-8'))[-1].strip()
        return int(value, 16)

    def close(self) -> None:
        """Close the interface."""
        pass

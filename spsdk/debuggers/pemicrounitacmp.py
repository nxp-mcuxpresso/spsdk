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
"""Moduler for pemicroUnitAcmp."""
import ctypes
import os.path
import platform
from ctypes import *

PortType_Autodetect = 99
PortType_ParallelPortCable = 1
PortType_PCIBDMLightning = 2
PortType_USBMultilink = 3
PortType_CycloneProMaxSerial = 4
PortType_CycloneProMaxUSB = 5
PortType_CycloneProMaxEthernet = 6
PortType_OpenSDAUSB = 9

# Special Features for Power Management
pwr_set_power_options = 0x38000001
pwr_turn_power_on = 0x38000011
pwr_turn_power_off = 0x38000012

# Special Features for debug communications mode
pe_arm_set_communications_mode = 0x44000001
pe_arm_set_debug_comm_swd = 0x00000000
pe_arm_set_debug_comm_jtag = 0x00000001

pe_arm_enable_debug_module = 0x44000002
pe_arm_write_ap_register = 0x44000003
pe_arm_read_ap_register = 0x44000004
pe_arm_write_dp_register = 0x44000007
pe_arm_read_dp_register = 0x44000008
pe_arm_flush_any_queued_data = 0x44000005

pe_arm_get_last_swd_status = 0x44000006
pe_arm_swd_status_ack = 0x04
pe_arm_swd_status_wait = 0x02
pe_arm_swd_status_fault = 0x01

# Special Features for Setting current device and core
pe_generic_get_device_list = 0x58004000
pe_generic_select_device = 0x58004001
pe_generic_get_core_list = 0x58004002
pe_generic_select_core = 0x58004003
pe_set_default_application_files_directory = 0x58006000


class pemicroUnitAcmp(object):
    """Class for pemicroUnitAcmp."""
    def getUserFriendlySystemName(self) -> str:
        """Get more friendly system name."""
        if platform.system() == "Windows":
            return "Windows"
        else:
            if platform.system() == "Linux":
                return "Linux"
            else:
                if platform.system() == "Darwin":
                    return "MacOS"
                else:
                    return "Unknown"

    def __init__(self) -> None:
        """Initialize."""
        b_is_python_64bit = (ctypes.sizeof(ctypes.c_void_p) == 8)
        osutilitypath = os.path.join("libraries", self.getUserFriendlySystemName(), "PEMicro")
        if self.getUserFriendlySystemName() == "Windows":
            if b_is_python_64bit:
                self.name = "unitacmp-64.dll"
            else:
                self.name = "unitacmp-32.dll"
        else:
            if self.getUserFriendlySystemName() == "Linux":
                self.name = "unitacmp-64.so"
            else:
                self.name = "unitacmp-64.dylib"

        # load the library
        self.libraryLoaded = False
        self.connectedToDebugCable = False
        try:
            # Look in System Folders
            self.libraryPath = ''
            self.lib = cdll.LoadLibrary(self.name)
        except:
            try:
                # Look in the folder with .py file
                self.libraryPath = os.path.dirname(__file__)
                self.lib = cdll.LoadLibrary(os.path.join(self.libraryPath, self.name))
            except:
                # Look in a structured subfolder
                self.libraryPath = os.path.join(os.path.dirname(__file__), osutilitypath)
                self.lib = cdll.LoadLibrary(os.path.join(self.libraryPath, self.name))
        if self.lib:
            self.libraryLoaded = True
            self.lib.pe_special_features.argtypes = [c_ulong, c_bool, c_ulong, c_ulong, c_ulong, c_void_p, c_void_p]
            self.lib.pe_special_features.restype = c_bool

            self.lib.open_port.argtypes = [c_ulong, c_ulong]
            self.lib.open_port.restype = c_bool

            self.lib.open_port_by_identifier.argtypes = [c_char_p]
            self.lib.open_port_by_identifier.restype = c_bool

            self.lib.reenumerate_all_port_types.restype = c_bool

            self.lib.get_enumerated_number_of_ports.argtypes = [c_ulong]
            self.lib.get_enumerated_number_of_ports.restype = c_ulong

            self.lib.get_port_descriptor_short.argtypes = [c_ulong, c_ulong]
            self.lib.get_port_descriptor_short.restype = c_char_p

            self.lib.get_port_descriptor.argtypes = [c_ulong, c_ulong]
            self.lib.get_port_descriptor.restype = c_char_p

            self.lib.get_dll_version.restype = c_ushort

            self.lib.set_debug_shift_frequency.argtypes = [c_ulong]

            self.lib.pe_special_features(pe_set_default_application_files_directory, True, 0, 0, 0,
                                         c_char_p(self.libraryPath.encode('utf-8')), 0)

    def close(self) -> None:
        """Close connection."""
        if not self.connectedToDebugCable:
            return
        # Close any open connections to hardware
        self.lib.pe_special_features(pe_arm_flush_any_queued_data, True, 0, 0, 0, 0, 0)
        self.lib.close_port()
        self.connectedToDebugCable = False


    def __del__(self) -> None:
        self.close()

    def listPorts(self) -> list:
        """Gather information about attached probes."""
        if not self.libraryLoaded:
            raise ValueError("No PEMICRO Library is loaded!")
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            return []
        ports = list()

        for ii in range(numports):
            ports.append({
                "id": self.lib.get_port_descriptor_short(PortType_Autodetect, ii + 1).decode("utf-8"),
                "description": self.lib.get_port_descriptor(PortType_Autodetect, ii + 1).decode("utf-8")
            })
        return ports

    def printPorts(self, ports: list) -> None:
        """Print information about attached probes."""
        if ports == None or len(ports) == 0:
            print('No hardware detected locally.')
        for i, port in enumerate(ports):
            print("{ix:>2}: {id} => {desc}".format(ix=i, id=port["id"], desc=port["description"]))

    def listPortsDescription(self) -> None:
        """Lists the port's description."""
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            print('No hardware detected locally.')
        for ii in range(numports):
            print((self.lib.get_port_descriptor_short(PortType_Autodetect, ii + 1).decode().encode(
                "utf-8") + ' : ' + self.lib.get_port_descriptor(PortType_Autodetect, ii + 1).decode().encode("utf-8")))

    def listPortsName(self) -> None:
        """Lists the port's name."""
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            print('No hardware detected locally.')
        for ii in range(numports):
            print((self.lib.get_port_descriptor_short(PortType_Autodetect, ii + 1).decode().encode("utf-8")))
        return

    def connectToDebugCable(self, debugHardwareNameIpOrSerialnum: str = None) -> bool:
        """Connect to debug cable.

        :param debugHardwareNameIpOrSerialnum: Debug HW name ip or serial number
        :return: True/False
        """
        if not self.libraryLoaded:
            return False

        self.connectedToDebugCable = False
        if debugHardwareNameIpOrSerialnum is None:
            # USB1 is a generic identifier which will select the first autodetected USB pemicro device
            portName = c_char_p('USB1'.encode('utf-8'))
        else:
            # This identifier can be the debug hardware's IP address, assigned name, serial number, or generic
            # identifier (USB1, ETHERNET1)
            portName = c_char_p(debugHardwareNameIpOrSerialnum.encode('utf-8'))
        if not self.lib.open_port_by_identifier(portName):
            return False
        self.connectedToDebugCable = True
        return True

    def establishCommunicationsWithTarget(self, swdMode: bool = True, shiftSpeed: int = 1000000) -> bool:
        """Establishing connection with the target."""
        # connectToDebugCable must be used first to connect to the debug hardware
        if not self.libraryLoaded:
            return False
        if not self.connectedToDebugCable:
            return False
        if swdMode:
            self.lib.pe_special_features(pe_arm_set_communications_mode, True, pe_arm_set_debug_comm_swd, 0, 0, 0, 0)
        else:
            self.lib.pe_special_features(pe_arm_set_communications_mode, True, pe_arm_set_debug_comm_jtag, 0, 0, 0, 0)
        # Set 1Mhz Shift Rate
        self.lib.set_debug_shift_frequency(shiftSpeed)
        # Communicate to the target, power up debug module, check  (powering it up). Looks for arm IDCODE to verify
        # connection.
        return self.lib.pe_special_features(pe_arm_enable_debug_module, True, 0, 0, 0, 0, 0)

    def writeApRegister(self, apselect: int, addr: int, value: int, now: bool = False) -> None:
        """Write Ap register."""
        if not self.connectedToDebugCable:
            return
        self.lib.pe_special_features(pe_arm_write_ap_register, now, apselect, addr, value, 0, 0)
        return

    def readApRegister(self, apselect: int, addr: int,
                       now: bool = True, requiresDelay: bool = False) -> int:
        """Read Ap register.

        :param apselect:
        :param addr: register offset
        :param now: do not cache the read operation, True/False.
        :param requiresDelay: Read delay for a response.
        :return: value read from register
        """
        if not self.connectedToDebugCable:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_read_ap_register, True, apselect, addr, 0, byref(retVal), 0)
        return retVal.value

    def writeDpRegister(self, addr: int, value: int,
                        now: bool = False) -> None:
        """Write Dp register.

        :param addr: register offset
        :param value: value, which will be written to register
        :param now: do not cache the read operation, True/False.
        """
        if not self.connectedToDebugCable:
            return
        self.lib.pe_special_features(pe_arm_write_dp_register, now, addr, value, 0, 0, 0)
        return

    def readDpRegister(self, addr: int, now: bool = True,
                       requiresDelay: bool = False) -> int:
        """Read Dp register.

        :param addr: register offset
        :param now: do not cache the read operation, True/False. Default is True.
        :param requiresDelay: Read delay for a response.
        :return:
        """
        if not self.connectedToDebugCable:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_read_dp_register, True, addr, 0, 0, byref(retVal), 0)
        return retVal.value

    def lastSwdStatus(self) -> int:
        """Gets the last swd status."""
        if not self.libraryLoaded:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_get_last_swd_status, True, 0, 0, 0, byref(retVal), 0)
        return retVal.value

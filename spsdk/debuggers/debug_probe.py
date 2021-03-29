#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

from typing import Dict

from spsdk.exceptions import SPSDKError

class DebugProbeError(SPSDKError):
    """The general issue with debug probe exception for use with SPSDK."""

class ProbeNotFoundError(DebugProbeError):
    """The Probe not found exception for use with SPSDK."""

class DebugMailBoxAPNotFoundError(DebugProbeError):
    """The target doesn't have debug mailbox access port exception for use with SPSDK."""

class DebugProbeTransferError(DebugProbeError):
    """The communication error exception for use with SPSDK."""

class DebugProbeNotOpenError(DebugProbeError):
    """The debug probe is not opened exception for use with SPSDK."""

class DebugProbeMemoryInterfaceAPNotFoundError(DebugProbeError):
    """The target doesn't have memory interface access port exception for use with SPSDK."""

class DebugProbeMemoryInterfaceNotEnabled(DebugProbeError):
    """The target doesn't have memory interface enabled exception for use with SPSDK."""

class DebugProbe():
    """Abstraction class to define SPSDK debug probes interface."""

    # Constants to detect the debug mailbox access port
    APBANKSEL = 0x000000f0
    APADDR = 0x00ffffff
    APSEL = 0xff000000
    APSEL_SHIFT = 24
    APSEL_APBANKSEL = APSEL | APBANKSEL

    def __init__(self, hardware_id: str, user_params: Dict = None) -> None:
        """This is general initialization function for SPSDK library to support various DEBUG PROBES.

        :param hardware_id: Open probe with selected hardware ID
        :param user_params: The user params dictionary
        """
        self.hardware_id = hardware_id
        self.user_params = user_params
        self.enabled_memory_interface = True
        self.dbgmlbx_ap_ix = -1

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None, user_params: Dict = None) -> list:
        """Functions returns the list of all connected probes in system.

        There is option to look for just for one debug probe defined by its hardware ID.

        :param hardware_id: None to list all probes, otherwise the the only probe with
            matching hardware id is listed.
        :param user_params: The user params dictionary
        :return: ProbeDescription
        :raises NotImplementedError: The get_connected_probes is NOT implemented
        """
        raise NotImplementedError

    @property
    def debug_mailbox_access_port(self) -> int:
        """Returns debug mailbox access port.

        In case that the access port is not detected or selected, it returns value less than zero.

        :return: Index of Debug MailBox Access port.
        """
        return self.dbgmlbx_ap_ix

    @debug_mailbox_access_port.setter
    def debug_mailbox_access_port(self, value: int) -> None:
        """Force the debug mailbox access port.

        For special cases it could be used the forcing of the debug mailbox access port index.

        :param value: Forced value of Debug Mailbox Access port.
        """
        self.dbgmlbx_ap_ix = value


    def open(self) -> None:
        """Debug probe open.

        General opening function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and enable using debug probe
        for DAT purposes.

        :raises NotImplementedError: The open is NOT implemented
        """
        raise NotImplementedError

    def enable_memory_interface(self) -> None:
        """Debug probe enabling memory interface.

        General memory interface enabling method (it should be called after open method) for SPSDK library
        to support various DEBUG PROBES. The function is used to initialize the target memory interface
        and enable using memory access of target over debug probe.
        """

    def close(self) -> None:
        """Debug probe close.

        This is general closing function for SPSDK library to support various DEBUG PROBES.

        :raises NotImplementedError: The close is NOT implemented
        """
        raise NotImplementedError

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This is read debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: The dbgmlbx_reg_read is NOT implemented
        """
        raise NotImplementedError

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        This is write debug mailbox register function for SPSDK library to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: The dbgmlbx_reg_write is NOT implemented
        """
        raise NotImplementedError

    def mem_reg_read(self, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This is read 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: The mem_reg_read is NOT implemented
        """
        raise NotImplementedError

    def mem_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This is write 32-bit register in memory space of MCU function for SPSDK library
        to support various DEBUG PROBES.

        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: The mem_reg_write is NOT implemented
        """
        raise NotImplementedError

    @classmethod
    def get_coresight_ap_address(cls, access_port: int, address: int) -> int:
        """Return computed address of coresight access port register.

        :param access_port: Index of access port 0-255.
        :param address: Register address.
        :return: Coresight address.
        :raises ValueError: In case of invalid value.
        """
        if access_port > 255:
            raise ValueError

        return access_port << cls.APSEL_SHIFT | address

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register.

        It reads coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read(default), otherwise the Debug Port
        :param addr: the register address
        :return: The read value of addressed register (4 bytes)
        :raises NotImplementedError: The coresight_reg_read is NOT implemented
        """
        raise NotImplementedError

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register.

        It writes coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be write(default), otherwise the Debug Port
        :param addr: the register address
        :param data: the data to be written into register
        :raises NotImplementedError: The coresight_reg_read is NOT implemented
        """
        raise NotImplementedError

    def reset(self) -> None:
        """Reset a target.

        It resets a target.

        :raises NotImplementedError: The coresight_reg_read is NOT implemented
        """
        raise NotImplementedError

    def __del__(self) -> None:
        """General Debug Probe 'END' event handler."""
        self.close()

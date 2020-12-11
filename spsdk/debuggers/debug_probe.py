#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

from typing import List, Any

from spsdk.exceptions import SPSDKError

class ProbeDescription():
    """NamedTuple for DAT record of debug probe description."""
    interface: str
    hardware_id: str
    description: str
    probe: "DebugProbe"

    def __init__(self, interface: str, hardware_id: str, description: str, probe: Any) -> None:
        """Initialization of Debug probe dscription class.

        param interface: Probe Interface.
        param hardware_id: Probe Hardware ID(Identification).
        param description: Probe Text description.
        param probe: Probe name of the class.
        """
        self.interface = interface
        self.hardware_id = hardware_id
        self.description = description
        self.probe = probe

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

class DebugProbe():
    """Abstraction class to define SPSDK debug probes interface."""

    # Constants to detect the debug mailbox access port
    APBANKSEL = 0x000000f0
    APSEL = 0xff000000
    APSEL_SHIFT = 24
    APSEL_APBANKSEL = APSEL | APBANKSEL

    def __init__(self, hardware_id: str, ip_address: str = None) -> None:
        """This is general initialization function for SPSDK library to support various DEBUG PROBES.

        :param hardware_id: Open probe with selected hardware ID
        :param ip_address: The IP Address
        """
        self.hardware_id = hardware_id
        self.ip_address = ip_address
        self.dbgmlbx_ap_ix = -1

    @classmethod
    def get_connected_probes(cls, hardware_id: str = None) -> List[ProbeDescription]:
        """Functions returns the list of all connected probes in system.

        There is option to look for just for one debug porbe defined by its hardware ID.
        :param hardware_id: None to list all probes, otherwice the the only probe with matching
            hardware id is listed.
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

    def __del__(self) -> None:
        """General Debug Probe 'END' event handler."""
        self.close()

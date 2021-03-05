#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

import logging
from typing import Dict, Any, Type
import prettytable
import colorama

# Import all supported debug probe classes
from spsdk.debuggers.debug_probe_pyocd import DebugProbePyOCD
from spsdk.debuggers.debug_probe_jlink import DebugProbePyLink
from spsdk.debuggers.debug_probe_pemicro import DebugProbePemicro
from spsdk.debuggers.debug_probe import DebugProbeError, ProbeNotFoundError, DebugProbe

PROBES = {
    "pyocd":   DebugProbePyOCD,
    "jlink":   DebugProbePyLink,
    "pemicro": DebugProbePemicro,
}

logger = logging.getLogger(__name__)

class ProbeDescription():
    """NamedTuple for DAT record of debug probe description."""

    def __init__(self, interface: str, hardware_id: str, description: str, probe: Type[DebugProbe]) -> None:
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

    def get_probe(self, user_params: Dict = None) -> Any:
        """Get instance of probe.

        :param user_params: The dictionary with optional user parameters
        :return: Instance of described probe.
        """
        return self.probe(hardware_id=self.hardware_id, user_params=user_params)

class DebugProbes(list):
    """Helper class for debug probe selection. This class accepts only ProbeDescription object."""

    def append(self, item: ProbeDescription) -> None:
        """Overriding build-in function by check the type.

        :param item: ProbeDestription item.
        :raises TypeError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super(DebugProbes, self).append(item)
        else:
            raise TypeError('The list accepts only ProbeDescription object')

    def insert(self, index: int, item: ProbeDescription) -> None:
        """Overriding build-in function by check the type.

        :param item: ProbeDestription item.
        :param index: Index in list to insert.
        :raises TypeError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super(DebugProbes, self).insert(index, item)
        else:
            raise TypeError('The list accepts only ProbeDescription object')

    def select_probe(self, silent: bool = False) -> ProbeDescription:
        """Perform Probe selection.

        :param silent: When it True, the functions selct the probe if applicable without any prints to log
        :return: The record of selected DebugProbe
        :raises ProbeNotFoundError: No probe has been founded
        """
        if len(self) == 0:
            if not silent:
                print("There is no any debug probe connected in system!")
            raise ProbeNotFoundError("There is no any debug probe connected in system!")

        if not silent or len(self) > 1:
            self.print()

        if len(self) == 1:
            # Automatically gets and use only one option\
            i_selected = 0
        else:
            print("Please choose the debug probe: ", end='')
            i_selected = int(input())
            if i_selected > len(self)-1:
                print("The choosen probe index is out of range")
                raise ProbeNotFoundError("The choosen probe index is out of range")

        return self[i_selected]

    def print(self) -> None:
        """Prints the List of Probes to nice colored table."""
        colorama.init()

        # Print all PyOCD probes and then Pemicro with local index
        table = prettytable.PrettyTable(["#", "Interface", "Id", "Description"])
        table.align = 'l'
        table.header = True
        table.border = True
        table.hrules = prettytable.HEADER
        table.vrules = prettytable.NONE
        i = 0
        for probe in self:
            table.add_row([
                colorama.Fore.YELLOW + str(i),
                colorama.Fore.WHITE + probe.interface,
                colorama.Fore.CYAN + probe.hardware_id,
                colorama.Fore.GREEN + probe.description,
                ])
            i += 1
        print(table)
        print(colorama.Style.RESET_ALL, end='')

class DebugProbeUtils():
    """The SPSDK debug probes utilities class.

    The SPSDK debug probes utilities, that helps user to find and open the real
    hardware debug probe to establish connection with hardware.
    """
    @staticmethod
    def get_connected_probes(interface: str = None, hardware_id: str = None, user_params: Dict = None) -> DebugProbes:
        """Functions returns the list of all connected probes in system.

        The caller could restrict the scanned interfaces by specification of hardware ID.

        :param interface: None to scan all interfaces, otherwice the selected interface is scanned only.
        :param hardware_id: None to list all probes, otherwice the the only probe with matching
        :param user_params: The dictionary with optional user parameters
        hardware id is listed.
        :return: list of probe_description's
        """
        probes = DebugProbes()
        for probe_key in PROBES:
            if (interface is None) or (interface.lower() == probe_key):
                try:
                    probes.extend(PROBES[probe_key].get_connected_probes(hardware_id, user_params))
                except DebugProbeError as exc:
                    logger.warning(f"The {probe_key} debug probe support is not ready({str(exc)}).")

        return probes

    @staticmethod
    def get_probe(interface: str = None, hardware_id: str = None, user_params: Dict = None) -> DebugProbe:
        """Function returns the instance of the debug probe by input identicication ID's.

        If the Hardware ID  is not specified, the first in the list iis returned. If no probe is found in system
        the function returns None.
        :param interface: None to scan all interfaces, otherwice the selected interface is scanned only.
        :param hardware_id: None to list all probes, otherwice the the only probe with matching
        hardware id is listed.
        :param user_params: The dictionary with optional user parameters
        :return: instance of DebugProbe
        :raises ProbeNotFoundError: No probe has been founded
        """
        probes = DebugProbeUtils.get_connected_probes(interface=interface, hardware_id=hardware_id)

        if len(probes) > 0:
            return probes[0].probe(hardware_id=hardware_id, user_params=user_params)

        raise ProbeNotFoundError("The choosen probe index is out of range")

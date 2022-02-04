#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

import logging
from typing import Any, Dict, Type

import colorama
import prettytable

from spsdk import SPSDKError
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError, SPSDKProbeNotFoundError
from spsdk.debuggers.debug_probe_jlink import DebugProbePyLink
from spsdk.debuggers.debug_probe_pemicro import DebugProbePemicro

# Import all supported debug probe classes
from spsdk.debuggers.debug_probe_pyocd import DebugProbePyOCD

PROBES = {
    "pyocd": DebugProbePyOCD,
    "jlink": DebugProbePyLink,
    "pemicro": DebugProbePemicro,
}

logger = logging.getLogger(__name__)

colorama.init()


class ProbeDescription:
    """NamedTuple for DAT record of debug probe description."""

    def __init__(
        self,
        interface: str,
        hardware_id: str,
        description: str,
        probe: Type[DebugProbe],
    ) -> None:
        """Initialization of Debug probe description class.

        param interface: Probe Interface.
        param hardware_id: Probe Hardware ID(Identification).
        param description: Probe Text description.
        param probe: Probe name of the class.
        """
        self.interface = interface
        self.hardware_id = hardware_id
        self.description = description
        self.probe = probe

    def get_probe(self, user_params: Dict = None) -> DebugProbe:
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
        :raises SPSDKError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super(DebugProbes, self).append(item)
        else:
            raise SPSDKError("The list accepts only ProbeDescription object")

    def insert(self, index: int, item: ProbeDescription) -> None:
        """Overriding build-in function by check the type.

        :param item: ProbeDestription item.
        :param index: Index in list to insert.
        :raises SPSDKError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super(DebugProbes, self).insert(index, item)
        else:
            raise SPSDKError("The list accepts only ProbeDescription object")

    def select_probe(self, silent: bool = False) -> ProbeDescription:
        """Perform Probe selection.

        :param silent: When it True, the functions select the probe if applicable without any prints to log
        :return: The record of selected DebugProbe
        :raises SPSDKProbeNotFoundError: No probe has been founded
        """
        if len(self) == 0:
            if not silent:
                print("There is no any debug probe connected in system!")
            raise SPSDKProbeNotFoundError("There is no any debug probe connected in system!")

        if not silent or len(self) > 1:  # pragma: no cover
            self.print()

        if len(self) == 1:
            # Automatically gets and use only one option\
            i_selected = 0
        else:  # pragma: no cover
            print("Please choose the debug probe: ", end="")
            i_selected = int(input())
            if i_selected > len(self) - 1:
                print("The chosen probe index is out of range")
                raise SPSDKProbeNotFoundError("The chosen probe index is out of range")

        return self[i_selected]

    def print(self) -> None:
        """Prints the List of Probes to nice colored table."""
        # Print all PyOCD probes and then Pemicro with local index
        table = prettytable.PrettyTable(["#", "Interface", "Id", "Description"])
        table.align = "l"
        table.header = True
        table.border = True
        table.hrules = prettytable.HEADER
        table.vrules = prettytable.NONE
        i = 0
        for probe in self:
            table.add_row(
                [
                    colorama.Fore.YELLOW + str(i),
                    colorama.Fore.WHITE + probe.interface,
                    colorama.Fore.CYAN + probe.hardware_id,
                    colorama.Fore.GREEN + probe.description,
                ]
            )
            i += 1
        print(table)
        print(colorama.Style.RESET_ALL, end="")


class DebugProbeUtils:
    """The SPSDK debug probes utilities class.

    The SPSDK debug probes utilities, that helps user to find and open the real
    hardware debug probe to establish connection with hardware.
    """

    @staticmethod
    def get_connected_probes(
        interface: str = None, hardware_id: str = None, user_params: Dict = None
    ) -> DebugProbes:
        """Functions returns the list of all connected probes in system.

        The caller could restrict the scanned interfaces by specification of hardware ID.

        :param interface: None to scan all interfaces, otherwise the selected interface is scanned only.
        :param hardware_id: None to list all probes, otherwise the the only probe with matching
        :param user_params: The dictionary with optional user parameters
            hardware id is listed.
        :return: list of probe_description's
        """
        probes = DebugProbes()
        for probe_key in PROBES:
            if (interface is None) or (interface.lower() == probe_key):
                try:
                    probes.extend(PROBES[probe_key].get_connected_probes(hardware_id, user_params))
                except SPSDKDebugProbeError as exc:
                    logger.warning(f"The {probe_key} debug probe support is not ready({str(exc)}).")

        return probes


def test_ahb_access(probe: DebugProbe, ap_mem: int = 0) -> bool:
    """The function safely test the access of debug probe to AHB in target.

    :param probe: Probe object to use for test.
    :param ap_mem: Index of memory access port., defaults to 0
    :return: True is access to AHB is granted, False otherwise.
    """
    ahb_enabled = False
    logger.debug("step T.1: Activate the correct AP")
    probe.coresight_reg_write(access_port=False, addr=2 * 4, data=ap_mem)

    try:
        logger.debug("step T.2: Set the AP access size and address mode")
        probe.coresight_reg_write(
            access_port=True,
            addr=probe.get_coresight_ap_address(ap_mem, 0 * 4),
            data=0x22000012,
        )

        logger.debug("step T.3: Set the initial AHB address to access")
        probe.coresight_reg_write(
            access_port=True,
            addr=probe.get_coresight_ap_address(ap_mem, 1 * 4),
            data=0x20000000,
        )

        logger.debug("step T.4: Access the memory system at that address")

        value = probe.coresight_reg_read(
            access_port=True, addr=probe.get_coresight_ap_address(ap_mem, 3 * 4)
        )
        logger.debug(f"Read value at 0x2000_0000 is {value:08X}")
        ahb_enabled = True

    except SPSDKDebugProbeError:
        logger.debug("Chip has NOT enabled AHB access.")

    return ahb_enabled

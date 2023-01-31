#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for DebugMailbox Debug probes support."""

import contextlib
import logging
from typing import Dict, Iterator, Optional, Type

import colorama
import prettytable

from spsdk import SPSDKError
from spsdk.debuggers.debug_probe import DebugProbe, SPSDKDebugProbeError, SPSDKProbeNotFoundError
from spsdk.debuggers.debug_probe_jlink import DebugProbePyLink
from spsdk.debuggers.debug_probe_pemicro import DebugProbePemicro

# Import all supported debug probe classes
from spsdk.debuggers.debug_probe_pyocd import DebugProbePyOCD

PROBES: Dict[str, Type[DebugProbe]] = {
    "pyocd": DebugProbePyOCD,
    "jlink": DebugProbePyLink,
    "pemicro": DebugProbePemicro,
}

logger = logging.getLogger(__name__)


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

    def get_probe(self, options: Optional[Dict] = None) -> DebugProbe:
        """Get instance of probe.

        :param options: The dictionary with options
        :return: Instance of described probe.
        """
        return self.probe(hardware_id=self.hardware_id, options=options)


class DebugProbes(list):
    """Helper class for debug probe selection. This class accepts only ProbeDescription object."""

    def append(self, item: ProbeDescription) -> None:
        """Overriding build-in function by check the type.

        :param item: ProbeDescription item.
        :raises SPSDKError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super().append(item)
        else:
            raise SPSDKError("The list accepts only ProbeDescription object")

    def insert(self, index: int, item: ProbeDescription) -> None:  # type: ignore[override]
        """Overriding build-in function by check the type.

        :param item: ProbeDescription item.
        :param index: Index in list to insert.
        :raises SPSDKError: Invalid input types has been used.
        """
        if isinstance(item, ProbeDescription):
            super().insert(index, item)
        else:
            raise SPSDKError("The list accepts only ProbeDescription object")

    def select_probe(self, silent: bool = False) -> ProbeDescription:
        """Perform Probe selection.

        :param silent: When it True, the functions select the probe if applicable without any prints to log
        :return: The record of selected DebugProbe
        :raises SPSDKProbeNotFoundError: No probe has been founded
        """
        if len(self) == 0:
            raise SPSDKProbeNotFoundError("There is no debug probe connected in system!")

        if not silent or len(self) > 1:  # pragma: no cover
            self.print()

        if len(self) == 1:
            # Automatically gets and use only one option\
            i_selected = 0
        else:  # pragma: no cover
            print("Please choose the debug probe: ", end="")
            i_selected = int(input())
            if i_selected > len(self) - 1:
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
        print(table.get_string() + colorama.Style.RESET_ALL)


class DebugProbeUtils:
    """The SPSDK debug probes utilities class.

    The SPSDK debug probes utilities, that helps user to find and open the real
    hardware debug probe to establish connection with hardware.
    """

    @staticmethod
    def get_connected_probes(
        interface: Optional[str] = None,
        hardware_id: Optional[str] = None,
        options: Optional[Dict] = None,
    ) -> DebugProbes:
        """Functions returns the list of all connected probes in system.

        The caller could restrict the scanned interfaces by specification of hardware ID.

        :param interface: None to scan all interfaces, otherwise the selected interface is scanned only.
        :param hardware_id: None to list all probes, otherwise the the only probe with matching
        :param options: The dictionary with optional options
            hardware id is listed.
        :return: list of probe_description's
        """
        probes = DebugProbes()
        for key, probe in PROBES.items():
            if (interface is None) or (interface.lower() == key):
                try:
                    probes.extend(probe.get_connected_probes(hardware_id, options))
                except SPSDKDebugProbeError as exc:
                    logger.warning(f"The {key} debug probe support is not ready({str(exc)}).")

        return probes


def test_ahb_access(probe: DebugProbe, ap_mem: Optional[int] = None, invasive: bool = True) -> bool:
    """The function safely test the access of debug probe to AHB in target.

    :param probe: Probe object to use for test.
    :param ap_mem: Index of memory access port, defaults to 0
    :param invasive: Invasive type of test (temporary changed destination RAM value)
    :return: True is access to AHB is granted, False otherwise.
    """
    ahb_enabled = False
    bck_mem_ap = probe.mem_ap_ix
    probe.mem_ap_ix = ap_mem or probe.mem_ap_ix
    try:
        test_value = probe.mem_reg_read(probe.TEST_MEM_AP_ADDRESS)
        logger.debug(
            f"Test Connection: Read value at {hex(probe.TEST_MEM_AP_ADDRESS)} is {test_value:08X}"
        )
        if invasive:
            probe.mem_reg_write(addr=probe.TEST_MEM_AP_ADDRESS, data=test_value ^ 0xAAAAAAAA)
            test_read = probe.mem_reg_read(probe.TEST_MEM_AP_ADDRESS)
            probe.mem_reg_write(addr=probe.TEST_MEM_AP_ADDRESS, data=test_value)
            if test_read != test_value ^ 0xAAAAAAAA:
                raise SPSDKError("Test connection verification failed")
        ahb_enabled = True

    except SPSDKError as exc:
        logger.debug(f"Test Connection: Chip has NOT enabled AHB access. {str(exc)}")
    finally:
        probe.mem_ap_ix = bck_mem_ap

    return ahb_enabled


@contextlib.contextmanager
def open_debug_probe(
    interface: Optional[str] = None,
    serial_no: Optional[str] = None,
    debug_probe_params: Optional[Dict] = None,
) -> Iterator[DebugProbe]:
    """Method opens DebugProbe object based on input arguments.

    :param interface: None to scan all interfaces, otherwise the selected interface is scanned only.
    :param serial_no: None to list all probes, otherwise the the only probe with matching
    :param debug_probe_params: The dictionary with optional options
        hardware id is listed.
    :return: Active DebugProbe object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    debug_probes = DebugProbeUtils.get_connected_probes(
        interface=interface, hardware_id=serial_no, options=debug_probe_params
    )
    selected_probe = debug_probes.select_probe()
    debug_probe = selected_probe.get_probe(debug_probe_params)
    debug_probe.open()

    try:
        yield debug_probe
    except SPSDKError as exc:
        raise exc
    finally:
        debug_probe.close()

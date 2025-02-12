#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for DebugMailbox Debug probes support."""

import contextlib
import logging
from types import ModuleType
from typing import Callable, Iterator, Optional, Type

from spsdk import SPSDK_INTERACTIVE_DISABLED
from spsdk.debuggers.debug_probe import (
    DebugProbe,
    DebugProbes,
    ProbeDescription,
    SPSDKDebugProbeError,
    SPSDKMultipleProbesError,
    SPSDKProbeNotFoundError,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.plugins import PluginsManager, PluginType

logger = logging.getLogger(__name__)

PROBES: dict[str, Type[DebugProbe]] = {}


def get_connected_probes(
    interface: Optional[str] = None,
    hardware_id: Optional[str] = None,
    options: Optional[dict] = None,
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


def select_probe(
    probes: DebugProbes,
    silent: bool = False,
    # pylint: disable=used-before-assignment # PyLint thinks print is a variable
    print_func: Callable = print,
    input_func: Callable[[], str] = input,
) -> ProbeDescription:
    """Perform Probe selection.

    :param probes: The input list of probes
    :param silent: When it True, the functions select the probe if applicable without any prints to log
    :param print_func: Custom function to print data, defaults to print
    :param input_func: Custom function to handle user input, defaults to input
    :return: The record of selected DebugProbe
    :raises SPSDKProbeNotFoundError: No probe has been founded
    :raises SPSDKMultipleProbesError: Multiple probes have been found in non-interactive mode
    """
    probe_len = len(probes)
    if probe_len == 0:
        raise SPSDKProbeNotFoundError(
            "Debug probe with defined parameters is not connected in system!"
        )

    if not silent or probe_len > 1:  # pragma: no cover
        print_func(str(probes))

    if probe_len == 1:
        # Automatically gets and use only one option\
        i_selected = 0
    else:  # pragma: no cover
        if SPSDK_INTERACTIVE_DISABLED:
            raise SPSDKMultipleProbesError(
                "Multiple probes found. The interactive mode is turned off."
                "You can change it setting the 'SPSDK_INTERACTIVE_DISABLED' environment variable"
            )
        print_func("Please choose the debug probe: ")
        i_selected = int(input_func())
        if i_selected > probe_len - 1:
            raise SPSDKProbeNotFoundError("The chosen probe index is out of range")

    return probes[i_selected]


def get_test_address(family: str, revision: str = "latest") -> int:
    """Get AHB access test address for the device.

    The address is stored in SPSDK database. I worst case that address is not found, exception is raised.
    :raises SPSDKError: The address is not stored in database.
    """
    db = get_db(device=family, revision=revision)
    try:
        return db.get_int(
            DatabaseManager.DAT, "test_address", db.get_int(DatabaseManager.COMM_BUFFER, "address")
        )
    except SPSDKError as exc:
        raise SPSDKError(
            f"Can't get test AHB access address for {family}, revision: {revision}"
        ) from exc


def test_ahb_access(
    probe: DebugProbe,
    ap_mem: Optional[int] = None,
    invasive: bool = True,
    test_mem_address: Optional[int] = None,
) -> bool:
    """The function safely test the access of debug probe to AHB in target.

    :param probe: Probe object to use for test.
    :param ap_mem: Index of memory access port, defaults to 0
    :param invasive: Invasive type of test (temporary changed destination RAM value)
    :param test_mem_address: The address in volatile memory usable to test AHB memory access.
    :return: True is access to AHB is granted, False otherwise.
    """
    ahb_enabled = False
    bck_mem_ap = probe.mem_ap_ix
    probe.mem_ap_ix = ap_mem or probe.mem_ap_ix
    if test_mem_address is None:
        test_mem_address = probe.options.get("test_address")
        if test_mem_address is None:
            logger.warning(
                "The test address is not specified. The standard address that "
                "doesn't fit all devices is used: 0x2000_0000"
            )
            test_mem_address = 0x2000_0000

    try:
        # Enter debug state and halt
        probe.mem_reg_read(probe.DHCSR_REG)
        probe.mem_reg_write(
            addr=probe.DHCSR_REG,
            data=(probe.DHCSR_DEBUGKEY | probe.DHCSR_C_HALT | probe.DHCSR_C_DEBUGEN),
        )
        test_value = probe.mem_reg_read(test_mem_address)
        logger.debug(f"Test Connection: Read value at {hex(test_mem_address)} is {test_value:08X}")
        if invasive:
            probe.mem_reg_write(addr=test_mem_address, data=test_value ^ 0xAAAAAAAA)
            test_read = probe.mem_reg_read(test_mem_address)
            probe.mem_reg_write(addr=test_mem_address, data=test_value)
            if test_read != test_value ^ 0xAAAAAAAA:
                raise SPSDKError("Test connection verification failed")
        ahb_enabled = True
        # Exit debug state
        probe.mem_reg_write(
            addr=probe.DHCSR_REG, data=(probe.DHCSR_DEBUGKEY | probe.DHCSR_C_DEBUGEN)
        )
        probe.mem_reg_write(addr=probe.DHCSR_REG, data=probe.DHCSR_DEBUGKEY)

    except SPSDKError as exc:
        logger.debug(f"Test Connection: Chip has NOT enabled AHB access. {str(exc)}")
        if probe.options.get("use_jtag") is not None:
            # For JTAG it appears clearing sticky bits needed after failed AHB access
            probe.coresight_reg_write(access_port=False, addr=4, data=0x50000F20)
    finally:
        probe.mem_ap_ix = bck_mem_ap

    return ahb_enabled


@contextlib.contextmanager
def open_debug_probe(
    interface: Optional[str] = None,
    serial_no: Optional[str] = None,
    debug_probe_params: Optional[dict] = None,
    print_func: Callable[[str], None] = print,
    input_func: Callable[[], str] = input,
) -> Iterator[DebugProbe]:
    """Method opens DebugProbe object based on input arguments.

    :param interface: None to scan all interfaces, otherwise the selected interface is scanned only.
    :param serial_no: None to list all probes, otherwise the the only probe with matching
    :param debug_probe_params: The dictionary with optional options hardware id is listed.
    :param print_func: Custom function to print data, defaults to print
    :param input_func: Custom function to handle user input, defaults to input
    :return: Active DebugProbe object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    debug_probes = get_connected_probes(
        interface=interface, hardware_id=serial_no, options=debug_probe_params
    )
    selected_probe = select_probe(debug_probes, print_func=print_func, input_func=input_func)
    try:
        debug_probe = selected_probe.get_probe(debug_probe_params)
        debug_probe.open()
    except SPSDKError as exc:
        raise SPSDKDebugProbeError(
            f"Cannot open selected probe: {selected_probe}. Maybe, it has been disconnected from system."
        ) from exc
    try:
        yield debug_probe
    except SPSDKError as exc:
        raise exc
    finally:
        debug_probe.close()


def get_all_debug_probe_plugins() -> dict[str, Type[DebugProbe]]:
    """Get dictionary of all available debug probe types."""

    def get_subclasses(
        base_class: Type,
    ) -> dict[str, Type[DebugProbe]]:
        """Recursively find all subclasses."""
        subclasses = {}
        for subclass in base_class.__subclasses__():
            subclasses_dict = get_subclasses(subclass)
            if subclasses_dict:
                subclasses.update(subclasses_dict)
            else:
                # Do NOT add inner level of classes - just last one
                subclasses[subclass.NAME] = subclass
        return subclasses

    load_debug_probe_plugins()
    return get_subclasses(DebugProbe)


def load_debug_probe_plugins() -> dict[str, ModuleType]:
    """Load all installed signature provider plugins."""
    plugins_manager = PluginsManager()
    plugins_manager.load_from_entrypoints(PluginType.DEBUG_PROBE.label)
    return plugins_manager.plugins


def load_all_probe_types() -> None:
    """Method to load the current list of all debug probe types."""
    global PROBES  # pylint: disable=global-statement
    PROBES = get_all_debug_probe_plugins()


# Do initial fill up
load_all_probe_types()

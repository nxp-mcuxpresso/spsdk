#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK debug probe utilities and management functions.

This module provides comprehensive functionality for discovering, selecting,
and managing debug probes across different hardware interfaces. It includes
utilities for probe detection, connection testing, and plugin loading for
various debug probe types supported by SPSDK.
"""

import contextlib
import inspect
from collections.abc import Callable, Iterator
from types import ModuleType

from spsdk import SPSDK_INTERACTIVE_DISABLED, get_logger
from spsdk.debuggers.debug_probe import (
    DebugProbe,
    DebugProbes,
    ProbeDescription,
    SPSDKDebugProbeError,
    SPSDKMultipleProbesError,
    SPSDKProbeNotFoundError,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import value_to_int
from spsdk.utils.plugins import PluginsManager, PluginType

logger = get_logger(__name__)

PROBES: dict[str, type[DebugProbe]] = {}


def get_connected_probes(
    interface: str | None = None,
    hardware_id: str | None = None,
    options: dict | None = None,
    architecture: str | None = None,
) -> DebugProbes:
    """Get connected debug probes in the system.

    The caller can restrict the scanned interfaces by specifying interface type, hardware ID,
    or architecture. Probes with an ``ARCHITECTURE`` other than ``"abstract"`` are excluded when
    their architecture does not match, so DSC probes are automatically hidden when looking for a
    Cortex-M device and vice-versa.

    :param interface: Interface type to scan, None to scan all available interfaces.
    :param hardware_id: Hardware ID filter, None to list all probes or specific ID to match.
    :param options: Optional configuration dictionary for probe scanning.
    :param architecture: DB architecture string (e.g. ``"arm-cortex"``, ``"dsc56800ex"``)
        used to filter probe types. None disables filtering.
    :return: Collection of connected debug probes matching the specified criteria.
    """
    probes = DebugProbes()
    for key, probe in PROBES.items():
        if (interface is None) or (interface.lower() == key):
            # Skip probes that declare a specific architecture that doesn't match
            if (
                architecture
                and probe.ARCHITECTURE != "abstract"
                and probe.ARCHITECTURE != architecture
            ):
                logger.debug(
                    f"Skipping probe '{key}' (architecture '{probe.ARCHITECTURE}',"
                    f" requested '{architecture}')"
                )
                continue
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
    """Select debug probe from available probes.

    Handles automatic selection when only one probe is available, or prompts user
    for selection when multiple probes are found. Supports silent mode and custom
    input/output functions for testing.

    :param probes: List of available debug probes to select from.
    :param silent: If True, suppress output when only one probe is available.
    :param print_func: Custom function for output, defaults to print.
    :param input_func: Custom function for user input, defaults to input.
    :return: Selected probe description.
    :raises SPSDKProbeNotFoundError: No probe found or invalid selection index.
    :raises SPSDKMultipleProbesError: Multiple probes found in non-interactive mode.
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


def get_test_address(family: FamilyRevision) -> int:
    """Get AHB access test address for the device.

    The address is stored in SPSDK database. In worst case that address is not found, exception is raised.

    :param family: Family revision specification for the target device.
    :return: Test address for AHB access verification.
    :raises SPSDKError: The address is not stored in database.
    """
    db = get_db(family)
    try:
        return db.get_int(DatabaseManager.DAT, "test_address")
    except SPSDKError:
        try:
            return db.get_int(DatabaseManager.COMM_BUFFER, "address")
        except SPSDKError as exc:
            raise SPSDKError(f"Can't get test AHB access address for {family}") from exc


def test_ahb_access(
    probe: DebugProbe,
    ap_mem: int | None = None,
    invasive: bool = True,
    test_mem_address: int | None = None,
) -> bool:
    """Test the access of debug probe to AHB in target safely.

    The function performs a safe test to verify if the debug probe has access to the AHB
    (Advanced High-performance Bus) in the target device. It can perform both non-invasive
    and invasive tests depending on the configuration.

    :param probe: Debug probe object to use for testing.
    :param ap_mem: Index of memory access port, defaults to current probe setting.
    :param invasive: Enable invasive test that temporarily modifies destination RAM value.
    :param test_mem_address: Address in volatile memory for testing AHB memory access.
    :raises SPSDKError: When test connection verification fails during invasive testing.
    :return: True if access to AHB is granted, False otherwise.
    """
    ahb_enabled = False
    was_halted = False  # safe default; updated inside try once MEM-AP is confirmed

    if test_mem_address is None:
        test_mem_address = probe.options.get("test_address")
        if test_mem_address is None:
            logger.warning(
                "The test address is not specified. The standard address that "
                "doesn't fit all devices is used: 0x2000_0000"
            )
            test_mem_address = 0x2000_0000
        test_mem_address = value_to_int(test_mem_address)
    try:
        # Check CPU state first — is_cpu_halted() triggers MEM-AP discovery.
        # If MEM-AP is not yet accessible (e.g. right after POR, before debug unlock),
        # SPSDKDebugProbeError is raised here and caught below so the caller
        # (fuses.py::enable_debug) can proceed to the debug-mailbox unlock sequence.
        was_halted = probe.is_cpu_halted()
        # Enter debug state and halt
        probe.debug_halt()
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
        if not was_halted:
            probe.debug_resume()

    except SPSDKError as exc:
        logger.debug(f"Test Connection: Chip has NOT enabled AHB access. {str(exc)}")

    return ahb_enabled


@contextlib.contextmanager
def open_debug_probe(
    interface: str | None = None,
    serial_no: str | None = None,
    debug_probe_params: dict | None = None,
    print_func: Callable[[str], None] = print,
    input_func: Callable[[], str] = input,
    architecture: str | None = None,
) -> Iterator[DebugProbe]:
    """Open debug probe as context manager.

    The method scans for available debug probes based on the provided criteria,
    allows user selection if multiple probes are found, opens the selected probe,
    and yields it as a context manager that automatically closes the probe when done.

    If *architecture* is not supplied and *debug_probe_params* contains a ``"family"`` key
    (set by :meth:`DebugProbeParams.set_family`), the architecture is looked up from the
    device database and passed to :func:`get_connected_probes` for automatic filtering.

    :param interface: Interface type to scan, None to scan all available interfaces.
    :param serial_no: Serial number of specific probe, None to list all available probes.
    :param debug_probe_params: Dictionary with optional debug probe configuration parameters.
    :param print_func: Custom function to print data, defaults to print.
    :param input_func: Custom function to handle user input, defaults to input.
    :param architecture: DB architecture string to filter probe types. When None the value
        is derived automatically from *debug_probe_params* if a family is present.
    :return: Active DebugProbe object as context manager.
    :raises SPSDKDebugProbeError: Cannot open selected probe or probe disconnected.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    # Auto-derive architecture from the family stored in debug_probe_params
    if architecture is None and debug_probe_params:
        family_name = debug_probe_params.get("family")
        if family_name:
            try:
                family = FamilyRevision(
                    name=str(family_name),
                    revision=str(debug_probe_params.get("revision", "latest")),
                )
                architecture = get_db(family).device.info.architecture
                logger.debug(
                    f"Auto-detected probe architecture '{architecture}' for family '{family_name}'"
                )
            except SPSDKError:
                pass  # Non-fatal: proceed without architecture filtering

    debug_probes = get_connected_probes(
        interface=interface,
        hardware_id=serial_no,
        options=debug_probe_params,
        architecture=architecture,
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


def _defines_new_abstract_methods(cls: type, parent: type) -> bool:
    """Check if a class introduces new abstract methods not present in its parent."""
    parent_abstracts: frozenset[str] = getattr(parent, "__abstractmethods__", frozenset())
    for name, method in inspect.getmembers(cls):
        if getattr(method, "__isabstractmethod__", False) and name not in parent_abstracts:
            return True
    return False


def get_all_debug_probe_plugins() -> dict[str, type[DebugProbe]]:
    """Get dictionary of all available debug probe types.

    This method loads all debug probe plugins and returns a mapping of probe names
    to their corresponding DebugProbe class types. It recursively searches through
    all DebugProbe subclasses to build the complete registry.

    :return: Dictionary mapping debug probe names to their DebugProbe class types.
    """

    def get_subclasses(
        base_class: type[DebugProbe],
    ) -> dict[str, type[DebugProbe]]:
        """Recursively find all subclasses of a given base class.

        The method traverses the inheritance hierarchy and collects only the leaf
        subclasses (those without further subclasses) mapped by their NAME attribute.

        :param base_class: The base class to find subclasses for.
        :return: Dictionary mapping subclass names to subclass types.
        """
        subclasses = {}
        for subclass in base_class.__subclasses__():
            subclasses_dict = get_subclasses(subclass)
            if subclasses_dict:
                subclasses.update(subclasses_dict)
            elif not _defines_new_abstract_methods(subclass, base_class):
                # Do NOT add inner level of classes - just last one
                subclasses[subclass.NAME] = subclass
        return subclasses

    load_debug_probe_plugins()
    return get_subclasses(DebugProbe)  # type: ignore[type-abstract]


def load_debug_probe_plugins() -> dict[str, ModuleType]:
    """Load all installed debug probe plugins.

    Discovers and loads debug probe plugins from entry points using the plugins manager.

    :return: Dictionary mapping plugin names to their corresponding module objects.
    """
    plugins_manager = PluginsManager()
    plugins_manager.load_from_entrypoints(PluginType.DEBUG_PROBE.label)
    return plugins_manager.plugins


def load_all_probe_types() -> None:
    """Load the current list of all debug probe types.

    This method initializes the global PROBES variable by retrieving all available
    debug probe plugins from the system.
    """
    global PROBES  # pylint: disable=global-statement
    PROBES = get_all_debug_probe_plugins()


# Do initial fill up
load_all_probe_types()

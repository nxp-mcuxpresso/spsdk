#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK debug probe base interface and infrastructure.

This module is the **foundation** of the SPSDK debug-probe subsystem.  It
defines the contracts (abstract base class, exceptions, enumerations) that
every concrete probe implementation must fulfil, plus the
:class:`ProbeDescription` / :class:`DebugProbes` helpers used for probe
discovery and selection.

Design goals
------------

* **Hardware independence** — the rest of SPSDK calls only the API defined in
  :class:`DebugProbe`.  Switching from J-Link to PyOCD to a custom probe
  requires zero changes in application code.
* **Architecture independence** — a single ``space`` parameter on every memory
  method (:class:`MemorySpace`) makes ARM and DSC targets look identical to the
  caller.  The concrete implementation decides how to honour a PROGRAM-space
  request.
* **Plugin-friendly** — new probe hardware can be added as an installable
  Python package without touching the SPSDK core.

Class hierarchy
---------------

.. code-block:: text

    DebugProbe  (ABC — this module)
    ├── DebugProbeCoreSightOnly   (spsdk.debuggers.debug_probe_arm)
    │     ARM CoreSight / SWD / JTAG; MEM-AP, debug mailbox AP
    └── DebugProbeDsc             (spsdk.debuggers.debug_probe_dsc)
          DSC56800EX OnCE; DATA bus and PROGRAM bus

Memory spaces
-------------

:class:`MemorySpace` reflects the hardware reality of the DSC Harvard
architecture:

``MemorySpace.DATA``
    The default.  Accesses the **X: data bus** (DSC) or the normal AHB/AXI
    fabric (ARM).  Supports 16- and 32-bit word transfers.

``MemorySpace.PROGRAM``
    DSC **P: program bus** only.  Because the P: bus is instruction-addressed,
    the DSC OnCE engine must use an R3-register-indirect move sequence to reach
    it — a detail hidden inside :class:`~spsdk.debuggers.debug_probe_dsc.DebugProbeDsc`.
    Passing ``MemorySpace.PROGRAM`` to an ARM probe raises
    :class:`~spsdk.exceptions.SPSDKError` immediately, making unintended
    cross-architecture use a hard error rather than silent data corruption.

Concrete implementations live in separate modules:

* :mod:`spsdk.debuggers.debug_probe_arm` — ARM CoreSight (``DebugProbeCoreSightOnly``)
* :mod:`spsdk.debuggers.debug_probe_dsc` — DSC56800EX (``DebugProbeDsc``)

Both names are also re-exported from this module for backward compatibility
with existing plugins and third-party code.
"""

from abc import ABC, abstractmethod
from time import sleep

import colorama
import prettytable

from spsdk import get_logger
from spsdk.exceptions import SPSDKError
from spsdk.utils.family import FamilyRevision
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = get_logger(__name__)

# Debugging options
DISABLE_AP_SELECT_CACHING = False


class SPSDKDebugProbeError(SPSDKError):
    """SPSDK Debug Probe exception for debug probe related errors.

    This exception is raised when debug probe operations fail or encounter
    errors during communication, initialization, or other debug probe specific
    operations within the SPSDK framework.
    """


class SPSDKProbeNotFoundError(SPSDKDebugProbeError):
    """SPSDK debug probe not found exception.

    Exception raised when a requested debug probe cannot be found or is not available
    for connection during SPSDK debugging operations.
    """


class SPSDKMultipleProbesError(SPSDKDebugProbeError):
    """SPSDK exception for multiple debug probes found error.

    This exception is raised when multiple debug probes are detected during
    probe discovery or selection operations, requiring explicit probe
    specification to resolve the ambiguity.
    """


class SPSDKDebugProbeTransferError(SPSDKDebugProbeError):
    """SPSDK Debug Probe Transfer Error Exception.

    Exception raised when communication transfer operations fail during debug probe interactions.
    This error indicates issues with data transmission between the host and target device
    through the debug probe interface.
    """


class SPSDKDebugProbeNotOpenError(SPSDKDebugProbeError):
    """Exception raised when attempting to use a debug probe that is not opened.

    This exception is thrown when operations are performed on a debug probe
    instance that has not been properly opened or has been closed.
    """


class MemorySpace(SpsdkEnum):
    """Memory space selector for debug probe memory access operations.

    DSC56800EX architecture has two separate memory buses. DATA bus supports
    16-bit and 32-bit word access via absolute addressing. PROGRAM bus supports
    only 16-bit word access via R3-register-indirect addressing.
    For non-DSC (e.g. ARM) probes only DATA is valid; passing PROGRAM raises SPSDKError.
    """

    DATA = (0, "data", "Data memory bus (X: space) — default, 16/32-bit word access")
    PROGRAM = (1, "program", "Program memory bus (P: space, DSC only) — 16-bit word access only")


class DebugProbe(ABC):
    """Abstract base class for SPSDK debug probe interfaces.

    This class defines the common interface and constants for all debug probes
    supported by SPSDK, providing standardized access to target devices through
    various debug probe hardware implementations.

    :cvar NAME: Debug probe implementation name identifier.
    :cvar APBANKSEL: Access Port bank selection mask for debug mailbox detection.
    :cvar DP_IDR_REG: Debug Port Identification Register address.
    :cvar DP_CTRL_STAT_REG: Debug Port Control/Status Register address.
    :cvar DHCSR_REG: Debug Halting Control and Status Register address.
    :cvar DHCSR_DEBUGKEY: Debug key value for DHCSR register access.
    :cvar ARCHITECTURE: DB architecture identifier for this probe family. ``"abstract"`` means
        no restriction — the probe works with any architecture.
    """

    ARCHITECTURE = "abstract"
    NAME = "abstract"

    RESET_TIME = 0.1
    AFTER_RESET_TIME = 0.05

    def __init__(self, hardware_id: str, options: dict | None = None) -> None:
        """Initialize debug probe with hardware ID and configuration options.

        This is general initialization function for SPSDK library to support various DEBUG PROBES.
        Sets up the probe connection parameters, family configuration, and memory access point index.

        :param hardware_id: Hardware identifier to open specific debug probe
        :param options: Configuration dictionary containing family, revision and other probe settings
        """
        self.hardware_id = hardware_id
        self.options = dict(options or {})
        self.family = None
        family = self.options.pop("family", None)
        revision = self.options.pop("revision", "latest")
        if family:
            self.family = FamilyRevision(family, revision)

    def __enter__(self) -> "DebugProbe":
        """Enter context manager - open the debug probe.

        This method is called when entering a 'with' statement block.
        It opens the debug probe connection, making it ready for use.

        :return: Self reference to the debug probe instance.
        :raises SPSDKError: If opening the debug probe fails.

        Example:
            with debug_probe:
                debug_probe.connect()
                # Use debug probe
        """
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Exit context manager - close the debug probe.

        This method is called when exiting a 'with' statement block.
        It ensures the debug probe is properly closed, even if an
        exception occurred during the context.

        :param exc_type: Exception type if an exception was raised, None otherwise.
        :param exc_val: Exception value if an exception was raised, None otherwise.
        :param exc_tb: Exception traceback if an exception was raised, None otherwise.

        Example:
            with debug_probe:
                debug_probe.connect()
                # Use debug probe
            # Probe is automatically closed here
        """
        self.close()

    @classmethod
    @abstractmethod
    def get_connected_probes(
        cls, hardware_id: str | None = None, options: dict | None = None
    ) -> "DebugProbes":
        """Get connected debug probes in the system.

        Retrieves a list of all connected debug probes, with an option to filter by hardware ID.

        :param hardware_id: Hardware ID to filter for specific probe, None to list all probes.
        :param options: Additional options for probe discovery.
        :return: Collection of connected debug probes.
        """

    @classmethod
    def get_options_help(cls) -> dict[str, str]:
        """Get full list of options of debug probe.

        The method returns a dictionary containing all available configuration options
        for the debug probe with their corresponding help descriptions.

        :return: Dictionary with individual options. Key is parameter name and value the help text.
        """
        return {
            "test_address": "Address for testing memory AP, default "
            "is tested address in RAM MCU memory range",
            "enable_recovery_reset": "Enable hardware reset during debug connection recovery. "
            "WARNING: This will restart the target chip and lose current state (default: False)",
        }

    @abstractmethod
    def open(self) -> None:
        """Open debug probe connection.

        Establishes connection to the debug probe hardware, initializing communication
        interface and preparing the probe for debugging operations.

        :raises SPSDKError: When debug probe connection fails or probe is not available.
        """

    @abstractmethod
    def connect(self) -> None:
        """Connect to the debug probe.

        Initializes the connection to the target device through the debug probe.
        This is a general connecting function that supports various debug probe types
        across the SPSDK library.

        :raises SPSDKError: If the connection to the debug probe fails.
        :raises SPSDKTimeoutError: If the connection attempt times out.
        """

    @abstractmethod
    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and establishes
        communication with the debug probe hardware.

        :raises SPSDKError: When connection to debug probe fails.
        :raises SPSDKTimeoutError: When connection timeout occurs.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the debug probe connection.

        This method provides a unified interface for closing debug probe connections
        across different debug probe implementations in the SPSDK library.
        """

    @abstractmethod
    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This function reads a debug mailbox register through the debug probe interface to support
        various debug probes in the SPSDK library.

        :param addr: The register address to read from.
        :return: The read value of addressed register (4 bytes).
        """

    @abstractmethod
    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        Writes data to a specified register address in the debug mailbox access port
        using the configured debug probe's CoreSight interface.

        :param addr: Register address to write to.
        :param data: Data value to write into the register.
        """

    @abstractmethod
    def mem_reg_read(self, addr: int = 0, space: MemorySpace = MemorySpace.DATA) -> int:
        """Read 32-bit register in memory space of MCU.

        This method reads a 32-bit register from the memory space of the target MCU through
        the debug probe interface.

        :param addr: The register address to read from.
        :param space: Memory space selector. Defaults to DATA. PROGRAM is only valid for
            DSC architecture probes; ARM probes raise SPSDKError for non-DATA spaces.
        :return: The read value of addressed register (4 bytes).
        """

    @abstractmethod
    def mem_reg_write(
        self, addr: int = 0, data: int = 0, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write 32-bit register in memory space of MCU.

        This method writes a 32-bit value to a specified register address in the MCU's memory
        space through the debug probe interface.

        :param addr: The register address to write to.
        :param data: The 32-bit data value to be written into the register.
        :param space: Memory space selector. Defaults to DATA. PROGRAM is only valid for
            DSC architecture probes; ARM probes raise SPSDKError for non-DATA spaces.
        """

    @abstractmethod
    def mem_block_read(self, addr: int, size: int, space: MemorySpace = MemorySpace.DATA) -> bytes:
        """Read a block of memory from the MCU.

        This method handles non-aligned addresses and sizes, providing flexibility
        for various memory operations.

        :param addr: The starting address to read from.
        :param size: The number of bytes to read.
        :param space: Memory space selector. Defaults to DATA. PROGRAM is only valid for
            DSC architecture probes; ARM probes raise SPSDKError for non-DATA spaces.
        :return: The read data as a bytes object.
        :raises SPSDKDebugProbeError: If there's an error during the read operation.
        """

    @abstractmethod
    def mem_block_write(
        self, addr: int, data: bytes, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write a block of memory to the MCU.

        This method handles non-aligned addresses and sizes, allowing for flexible
        memory write operations.

        :param addr: The starting address to write to.
        :param data: The data to be written, as a bytes object.
        :param space: Memory space selector. Defaults to DATA. PROGRAM is only valid for
            DSC architecture probes; ARM probes raise SPSDKError for non-DATA spaces.
        :raises SPSDKDebugProbeError: If there's an error during the write operation.
        """

    @abstractmethod
    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line at a target.

        :param assert_reset: If True, the reset line is asserted (pulled down), if False the reset line
            is not affected.
        """

    def reset(self) -> None:
        """Reset the target device.

        Performs a hardware reset by asserting the reset line, waiting for the reset duration,
        then deasserting the reset line and waiting for the post-reset stabilization period.
        """
        logger.debug("Resetting target device by HW reset line")
        self.assert_reset_line(True)
        sleep(self.RESET_TIME)
        self.assert_reset_line(False)
        sleep(self.AFTER_RESET_TIME)

    @abstractmethod
    def debug_halt(self) -> None:
        """Halt the CPU execution.

        This method stops the target CPU from executing instructions, putting it into
        a halted state for debugging purposes.

        :raises SPSDKError: If the halt operation fails or the debug probe is not connected.
        """

    @abstractmethod
    def debug_resume(self) -> None:
        """Resume the CPU execution.

        This method continues the execution of the target CPU from its current state,
        typically used after the CPU has been halted or paused during debugging operations.

        :raises SPSDKError: If the debug probe communication fails or the target is not connected.
        """

    @abstractmethod
    def debug_step(self) -> None:
        """Step the CPU execution by one instruction.

        This method advances the CPU execution by a single instruction step,
        allowing for detailed debugging and program flow analysis.

        :raises SPSDKError: When the debug step operation fails.
        :raises SPSDKConnectionError: When the debug probe connection is lost.
        """

    @abstractmethod
    def is_cpu_halted(self) -> bool:
        """Check if the CPU is currently halted.

        This method queries the hardware state directly without caching.

        :return: True if CPU is halted, False if CPU is running.
        :raises SPSDKDebugProbeError: If the check operation fails.
        """

    @abstractmethod
    def read_dp_idr(self) -> int:
        """Read Debug port identification register.

        :return: Debug port identification register value.
        """


class ProbeDescription:
    """Debug probe description container.

    This class encapsulates information about a debug probe including its interface,
    hardware identification, description, and the probe class type. It provides
    a standardized way to describe and instantiate debug probes within the SPSDK
    framework.
    """

    def __init__(
        self, interface: str, hardware_id: str, description: str, probe: type[DebugProbe]
    ) -> None:
        """Initialize Debug probe description class.

        :param interface: Probe interface type.
        :param hardware_id: Probe hardware ID for identification.
        :param description: Text description of the probe.
        :param probe: Debug probe class type.
        """
        self.interface = interface
        self.hardware_id = hardware_id
        self.description = description
        self.probe = probe

    @property
    def architecture(self) -> str:
        """Return the probe's architecture identifier string.

        :return: The ARCHITECTURE class variable of the underlying probe class.
        """
        return self.probe.ARCHITECTURE

    def get_probe(self, options: dict | None = None) -> DebugProbe:
        """Get instance of debug probe.

        Creates and returns a new instance of the debug probe with the specified hardware ID
        and optional configuration parameters.

        :param options: Optional dictionary containing probe-specific configuration options.
        :return: Instance of the debug probe ready for use.
        """
        return self.probe(hardware_id=self.hardware_id, options=options)

    def __str__(self) -> str:
        """Provide string representation of debug probe.

        Creates a formatted string containing the debug probe's interface type,
        description, and hardware serial number for easy identification and logging.

        :return: Formatted string with probe interface, description, and serial number.
        """
        return f"Debug probe: {self.interface}; {self.description}. S/N:{self.hardware_id}, {self.probe.ARCHITECTURE}"

    def __repr__(self) -> str:
        """Return string representation of the debug probe.

        :return: String containing debug probe interface information.
        """
        return f"Debug probe: {self.interface}"


class DebugProbes(list[ProbeDescription]):
    """Debug probe collection for hardware selection and display.

    This class extends a list to specifically manage ProbeDescription objects,
    providing formatted output capabilities for debug probe selection interfaces.
    The class ensures type safety by accepting only ProbeDescription instances
    and offers colored table representation for user-friendly probe listing.
    """

    def __str__(self) -> str:
        """Return string representation of debug probes list.

        Creates a formatted table with colored output showing all available debug probes
        with their interface, hardware ID, and description.

        :return: Formatted table string with colored probe information.
        """
        header = ["#", "Interface", "Id", "Description", "Architecture"]
        table = prettytable.PrettyTable(header)
        table.align = "l"
        table.header = True
        table.border = True
        table.hrules = prettytable.HRuleStyle.HEADER
        table.vrules = prettytable.VRuleStyle.NONE
        i = 0
        for probe in self:
            hardware_id = probe.hardware_id or "Not available"
            table.add_row(
                [
                    colorama.Fore.YELLOW + str(i),
                    colorama.Fore.WHITE + probe.interface,
                    colorama.Fore.CYAN + hardware_id,
                    colorama.Fore.GREEN + probe.description,
                    colorama.Fore.CYAN + probe.probe.ARCHITECTURE,
                ]
            )
            i += 1
        return table.get_string() + colorama.Style.RESET_ALL


from spsdk.debuggers.debug_probe_arm import (  # noqa: E402  # pylint: disable=wrong-import-position
    DebugProbeCoreSightOnly,
)

# ---------------------------------------------------------------------------
# Backward-compatibility re-exports.
# Concrete probe classes were moved to their own modules to keep this file
# within the pylint too-many-lines limit.  Existing code that imports these
# names from ``spsdk.debuggers.debug_probe`` continues to work unchanged.
# ---------------------------------------------------------------------------
from spsdk.debuggers.debug_probe_dsc import (  # noqa: E402  # pylint: disable=wrong-import-position
    DebugProbeDsc,
    TapConfig,
)

__all__ = [
    "DebugProbe",
    "DebugProbeDsc",
    "DebugProbeCoreSightOnly",
    "DebugProbes",
    "MemorySpace",
    "ProbeDescription",
    "SPSDKDebugProbeError",
    "SPSDKDebugProbeNotOpenError",
    "SPSDKDebugProbeTransferError",
    "SPSDKMultipleProbesError",
    "SPSDKProbeNotFoundError",
    "TapConfig",
]

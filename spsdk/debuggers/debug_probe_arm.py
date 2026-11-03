#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK ARM CoreSight debug probe implementation.

Background — ARM CoreSight debug architecture
---------------------------------------------

All NXP Cortex-M MCUs (LPC, MCX, i.MX RT, MIMXRT, Kinetis, …) implement the
ARM **CoreSight** debug and trace architecture.  The debug port (DP) is exposed
over either **SWD** (two-wire: SWDIO + SWDCLK) or **JTAG** (four-wire).  The
DP acts as a gateway into a chain of **Access Ports** (APs); each AP gives
access to a different on-chip resource:

``MEM-AP`` (AHB-AP / AXI-AP)
    The workhorse.  Provides 8/16/32-bit read/write access to any address on
    the chip's AHB or AXI bus — which includes SRAM, flash, and peripheral
    registers.  The base address of the MEM-AP is chip-specific and is stored
    in SPSDK's device database so the correct AP index is selected
    automatically.

``Debug Mailbox AP``
    An NXP-proprietary AP present on LPC, MCX, and related families.  It
    implements a command/response protocol used to:

    - Inject a *debug credential* signed with the device's debug authentication
      key, enabling authenticated debug on RoT-locked parts.
    - Activate the *ISP* mode entry path.
    - Perform device-level reset without cycling the power rail.

Why a separate ``DebugProbeCoreSightOnly`` class?
-------------------------------------------------

The SPSDK probe hierarchy separates *protocol concerns* (how to talk to the
hardware) from *application concerns* (what to do with that access).
:class:`DebugProbeCoreSightOnly` provides all ARM-specific protocol
intelligence:

* CoreSight AP address calculation
  (:meth:`~DebugProbeCoreSightOnly.get_coresight_ap_address`)
* MEM-AP discovery and CSW (Control/Status Word) configuration
  — including the chip-specific ``preserve_csw_ro_bits`` flag that prevents
  overwriting hardware-managed bits on MCX E-series and similar devices.
* Debug mailbox AP auto-detection by scanning IDR values.
* Debug port power-up / power-down sequences and sticky-error recovery with
  four progressive recovery levels (soft → power cycle → probe reconnect →
  hardware reset).
* CPU halt/resume/step via DHCSR (Debug Halting Control and Status Register).

Memory space handling
---------------------

ARM does not have a separate PROGRAM bus.  If a caller passes
``space=MemorySpace.PROGRAM`` to any memory method, the implementation raises
:class:`~spsdk.exceptions.SPSDKError` immediately — this is an intentional
hard failure to catch accidental cross-architecture code sharing.  Only
``MemorySpace.DATA`` (the default) is valid on ARM targets.

Plugin development
------------------

To support a new physical probe (e.g. a proprietary USB-JTAG adapter), derive
from :class:`DebugProbeCoreSightOnly` and implement the four abstract methods:

* :meth:`~spsdk.debuggers.debug_probe.DebugProbe.open`
* :meth:`~spsdk.debuggers.debug_probe.DebugProbe.close`
* :meth:`~spsdk.debuggers.debug_probe.DebugProbe.connect`
* :meth:`~spsdk.debuggers.debug_probe.DebugProbe.coresight_reg_read` /
  :meth:`~spsdk.debuggers.debug_probe.DebugProbe.coresight_reg_write`

Register as a ``spsdk.debug_probe`` entry-point and SPSDK will discover the
plugin automatically.  See ``examples/plugins/README.md`` for a Cookiecutter
template.
"""

import functools
from abc import abstractmethod
from time import sleep
from typing import Any, no_type_check

from spsdk import get_logger
from spsdk.debuggers.debug_probe import (
    DISABLE_AP_SELECT_CACHING,
    DebugProbe,
    DebugProbeProtocol,
    MemorySpace,
    SPSDKDebugProbeError,
    SPSDKDebugProbeTransferError,
)
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import get_db
from spsdk.utils.misc import Timeout, value_to_int

logger = get_logger(__name__)

# Shared CoreSight transaction tracer. Both debug-probe plugins (J-Link, MCU-Link, ...)
# emit their high-level DP/AP read/write operations through this single logger using an
# identical line format, so the resulting TRACE streams are directly comparable between
# probes (e.g. when correlating with a logic analyzer capture on the physical SWD line).
cs_trace_logger = get_logger("spsdk.probe.trace")


class DebugProbeCoreSightOnly(DebugProbe):
    """SPSDK Debug Probe with CoreSight-only interface support.

    This class provides a specialized debug probe implementation that focuses exclusively on
    CoreSight debug architecture operations. It extends the base DebugProbe class with
    ARM CoreSight-specific register definitions and memory access patterns for debugging
    ARM Cortex-based MCUs.

    :cvar NAME: Debug probe identifier name.
    :cvar CSW_SIZE_8BIT: Control/Status Word 8-bit transfer size configuration.
    :cvar CSW_SIZE_16BIT: Control/Status Word 16-bit transfer size configuration.
    :cvar CSW_SIZE_32BIT: Control/Status Word 32-bit transfer size configuration.
    :cvar CSW_ADDRINC_OFF: Control/Status Word no address increment mode.
    :cvar CSW_ADDRINC_SINGLE: Control/Status Word single address increment mode.
    :cvar CSW_ADDRINC_PACKED: Control/Status Word packed address increment mode.
    :cvar CSW_DEVICEEN: Control/Status Word device enable flag.
    :cvar CSW_TRINPROG: Control/Status Word transfer in progress flag.
    :cvar CSW_HPROT: Control/Status Word HPROT signal configuration.
    :cvar CSW_MASTER_DEBUG: Control/Status Word master debug enable flag.
    :cvar CSW_DBGSWENABLE: Control/Status Word debug software enable flag.
    :cvar CSW_FULL_DEBUG: Combined CSW configuration for full debug capabilities.
    :cvar CSW_REG: CoreSight Control/Status Word register address.
    :cvar TAR_REG: CoreSight Transfer Address register address.
    :cvar DRW_REG: CoreSight Data Read/Write register address.
    :cvar DP_CTRL_STAT_ERROR_MASK: Combined error mask for Debug Port status flags.
    """

    ARCHITECTURE = "arm-cortex"
    NAME = "base-arm"
    SUPPORTED_PROTOCOLS: tuple[DebugProbeProtocol, ...] = (DebugProbeProtocol.SWD,)
    SUPPORTED_VERSIONS: tuple[int, ...] = (5,)  # ADIv5 is natively supported

    # Constants to detect the debug mailbox access port
    APBANKSEL = 0x000000F0
    APBANK_SHIFT = 4
    APADDR = 0x00FFFFFF
    APSEL = 0xFF000000
    APSEL_SHIFT = 24
    APSEL_APBANKSEL = APSEL | APBANKSEL

    # ADIv6 (CoreSight 600 / DPv3) constants
    SELECT_APADDR_MASK = 0xFFFFFFF0  # ADIv6 AP address mask (bits [31:4])
    SELECT_DPBANKSEL_MASK = 0x0000000F  # ADIv6 DP bank select mask (bits [3:0])
    DPVER_MASK = 0x0000F000  # DP version field in DP_IDR (bits [15:12])
    DPVER_SHIFT = 12
    DPVER_ADIv6 = 3  # DP version value for ADIv6 (DPv3)
    AP_IDR_REG_ADIv6 = 0xDFC  # APv2 IDR register address (ADIv6)

    # ADIv6 DP address size autodetection. DPIDR1 (DP bank 1) reports the address size
    # of the DP address bus in its ASIZE field; when ASIZE > 32 the SELECT1 register
    # (upper 32 bits of the AP address) is implemented and 64-bit AP addresses are used.
    ADIV6_DPIDR1_REG = 0x00  # DPIDR1 register offset within DP bank 1
    ADIV6_DPBANKSEL_MASK = 0x0000000F  # DP SELECT bits [3:0]: DP bank select
    ADIV6_DPIDR1_ASIZE_MASK = 0x0000007F  # DPIDR1 ASIZE field (bits [6:0])
    ADIV6_SELECT_REG = 0x08  # DP SELECT register (holds AP address bits [31:4] + DPBANKSEL)
    ADIV6_SELECT1_REG = 0x14  # DP SELECT1 register (upper AP address bits [63:32])
    ADIV6_ADDR_SIZE_32 = 32  # Address size threshold; > 32 implies SELECT1 is present

    # Default ADIv5 AP indices to probe when auto-detecting the memory access port.
    ADIV5_MEM_AP_INDICES = [0, 1, 3]

    # Default ADIv5 AP indices to probe when auto-detecting the debug mailbox access port.
    ADIV5_DBGMLBX_AP_INDICES = [2, 0, 1, 3, 8]

    # ADIv6 CoreSight component enumeration constants. In ADIv6 the access ports are
    # memory-mapped and discovered by walking the ROM table hierarchy rooted at the
    # DP BASEPTR, instead of probing a fixed 0-255 index range.
    # ADIv6 BASEPTR0/1 live at DP register offset 0x0 in DP banks 2 and 3
    # respectively (like DPIDR1 at offset 0x0 in bank 1). DPBANKSEL (SELECT
    # bits [3:0]) must be set to the bank before reading offset 0x0; reading a
    # fixed offset 0x08/0x0C in bank 0 returns SELECT/RDBUFF readback, not the
    # base pointer.
    ADIV6_DP_BASEPTR_REG = 0x00  # BASEPTR0/1 register offset within their DP banks
    ADIV6_DP_BASEPTR0_BANK = 0x2  # DPBANKSEL value exposing BASEPTR0
    ADIV6_DP_BASEPTR1_BANK = 0x3  # DPBANKSEL value exposing BASEPTR1

    ADIV6_BASEPTR_VALID_MASK = 0x1  # BASEPTR0 bit0: 1 = valid base pointer
    ADIV6_BASEPTR_ADDR_MASK = 0xFFFFFFFFFFFFF000  # 4KB-aligned base address mask

    # CoreSight component ID / ROM table register offsets (relative to the 4KB block).
    # These are common CoreSight architecture definitions (not ADIv6-specific).
    CIDR1_OFFSET = 0xFF4  # Component ID Register 1 (holds component class)
    DEVTYPE_OFFSET = 0xFCC  # Device Type register
    DEVARCH_OFFSET = 0xFBC  # Device Architecture register

    CIDR1_CLASS_MASK = 0xF0  # Component class field in CIDR1
    CIDR1_CLASS_ROM = 0x10  # Class 0x1: ROM table
    CIDR1_CLASS_CORESIGHT = 0x90  # Class 0x9: CoreSight component (may be an AP)

    DEVTYPE_MEM_AP = 0x11  # Device Type value for a Memory Access Port
    DEVARCH_ARCHID_MASK = 0xFFF  # ARCHID field mask in DEVARCH
    DEVARCH_MEM_AP = 0x0A17  # CoreSight architecture ID for a generic MEM-AP
    # CoreSight SoC-600 (ADIv6) ROM tables are Class 0x9 components identified by
    # their DEVARCH ARCHID rather than the legacy Class 0x1 CIDR1 encoding.
    DEVARCH_CLASS9_ROM = 0x0AF7  # CoreSight architecture ID for a Class 9 ROM table

    DBGMLBX_IDR_VALUE = 0x002A0000  # Known IDR value of the NXP Debug Mailbox AP

    ROM_ENTRY_PRESENT_MASK = 0x1  # ROM table entry bit0: 1 = present
    ROM_ENTRY_OFFSET_MASK = 0xFFFFF000  # ROM entry address offset field (4KB aligned)
    ROM_ENTRY_SIGN_BIT = 0x80000000  # Sign bit of the 32-bit relative offset
    ROM_ENTRY_SIGN_EXTEND = 0x100000000  # Value subtracted for negative offsets

    ADIV6_MAX_ROM_DEPTH = 8  # Recursion guard for pathological/looping ROM tables

    DP_IDR_REG = 0x00  # Read access
    DP_ABORT_REG = 0x00  # Write Access
    DP_CTRL_STAT_REG = 0x04

    AP_IDR_REG = 0xFC  # APv1 IDR register address (ADIv5)

    CSYSPWRUPACK = 0x80 << 24
    CSYSPWRUPREQ = 0x40 << 24
    CDBGPWRUPACK = 0x20 << 24
    CDBGPWRUPREQ = 0x10 << 24
    MASKLANE = 0x0F << 8

    # Constants for DHCSR, Debug Halting Control and Status Register
    DHCSR_REG = 0xE000EDF0
    DHCSR_DEBUGKEY = 0xA05F0000
    DHCSR_C_DEBUGEN = 0x1
    DHCSR_C_HALT = 0x2
    DHCSR_C_STEP = 0x4
    DHCSR_S_REGRDY = 0x00010000  # Register R/W transfer via DCRSR/DCRDR has completed
    DHCSR_S_HALT = 0x00020000

    # Constants for DCRSR/DCRDR, Debug Core Register Selector/Data Register.
    # These addresses and the core-register numbering below are part of the fixed
    # ARMv6-M/v7-M/v8-M Private Peripheral Bus (PPB) memory map, i.e. identical across
    # all Cortex-M based devices regardless of family/vendor.
    DCRSR_REG = 0xE000EDF4
    DCRDR_REG = 0xE000EDF8
    DCRSR_REGWNR = 0x00010000  # Direction bit: 1 = write core register, 0 = read

    # Core register numbers as defined by the ARM debug architecture (DCRSR REGSEL field).
    CORE_REG_SP = 13  # R13, current Stack Pointer (alias of MSP/PSP based on CONTROL.SPSEL)
    CORE_REG_LR = 14  # R14, Link Register
    CORE_REG_PC = 15  # R15, Program Counter (DebugReturnAddress)
    CORE_REG_XPSR = 16
    CORE_REG_MSP = 17  # Main Stack Pointer (banked, independent of CONTROL.SPSEL)
    CORE_REG_PSP = 18  # Process Stack Pointer (banked, independent of CONTROL.SPSEL)

    # Add these class constants
    # Control/Status Word (CSW) bit definitions for size
    CSW_SIZE_8BIT = 0x00000000  # 8-bit size
    CSW_SIZE_16BIT = 0x00000001  # 16-bit size
    CSW_SIZE_32BIT = 0x00000002  # 32-bit size

    # Control/Status Word (CSW) bit definitions for address increment
    CSW_ADDRINC_OFF = 0x00000000  # No address increment
    CSW_ADDRINC_SINGLE = 0x00000010  # Single address increment
    CSW_ADDRINC_PACKED = 0x00000020  # Packed address increment

    # Control/Status Word (CSW) other bit definitions
    CSW_DEVICEEN = 0x00000040  # Device enable
    CSW_TRINPROG = 0x00000080  # Transfer in progress
    CSW_HPROT = 0x02000000  # Hprot
    CSW_MASTER_DEBUG = 0x20000000  # Master debug
    CSW_DBGSWENABLE = 0x80000000  # Debug software enable

    CSW_FULL_DEBUG = (
        CSW_MASTER_DEBUG
        | CSW_HPROT
        | CSW_DEVICEEN
        | CSW_DBGSWENABLE
        | CSW_SIZE_32BIT
        | CSW_ADDRINC_SINGLE
    )  # Enables full debug capabilities with 32-bit access and single address increment

    # Constants for register addresses
    CSW_REG = 0x00
    TAR_REG = 0x04
    DRW_REG = 0x0C

    # Add these new DP_CTRL_STAT register bit definitions
    DP_CTRL_STAT_STICKYORUN = 0x02  # Sticky Overrun Error
    DP_CTRL_STAT_STICKYCMP = 0x10  # Sticky Compare Error
    DP_CTRL_STAT_STICKYERR = 0x20  # Sticky Error
    DP_CTRL_STAT_READOK = 0x40  # Read OK
    DP_CTRL_STAT_WDATAERR = 0x80  # Write Data Error

    # Combined error mask for all sticky error flags
    DP_CTRL_STAT_ERROR_MASK = (
        DP_CTRL_STAT_STICKYORUN
        | DP_CTRL_STAT_STICKYCMP
        | DP_CTRL_STAT_STICKYERR
        | DP_CTRL_STAT_WDATAERR
    )  # 0xB2

    def __init__(self, hardware_id: str, options: dict[str, str] | None = None) -> None:
        """Initialize debug probe with hardware ID and options.

        General initialization function for SPSDK library to support various debug probes.

        :param hardware_id: Hardware ID of the debug probe to open
        :param options: Optional dictionary with probe-specific configuration options
        """
        super().__init__(hardware_id, options)
        self.mem_ap_ix = -1
        self.dbgmlbx_ap_ix = -1
        self.dbgmlbx_ap_validated = False
        self.adi_version = 5  # Default to ADIv5 (will be detected after connect)
        # ADIv6 AP address size in bits (detected from DPIDR1.ASIZE after connect).
        # When > 32 the SELECT1 register is used to carry the upper AP address bits.
        self.adiv6_addr_size = 32

        self.last_accessed_ap = -1

        # Extend the base debug_access_status dict (probe_connected, dp_idr_ok) with
        # ARM CoreSight specific gates. Each gate is recorded (True/False) as soon as
        # the corresponding code path discovers its result; None means the gate was
        # never exercised during this session (e.g. SDA-AP is only present on some
        # families). See spsdk.debuggers.utils.render_debug_access_status_table() for
        # the human-readable rendering.
        self.debug_access_status.update(
            {
                "dp_power_domains_ok": None,
                "ap_idr_ok": None,
                "ap_dbgswenable": None,
                "sda_dbgenctrl_written": None,
                "core_dhcsr_ok": None,
                "ahb_system_bus_ok": None,
                "dbgmlbx_ap_idr_ok": None,
            }
        )

        self.enable_power_domains_after_connect = False
        self.enable_sda_debug_paths_after_connect = False
        self.preserve_csw_ro_bits = False
        self.mem_ap_scan_write_before_read = False
        self.disable_reinit = (
            False  # Keep it here to backward compatibility with debug probe plugins
        )
        # True when the device database pins a fixed MEM-AP index, meaning the AP-scan
        # loop in get_mem_ap() is skipped entirely and its associated diagnostic gates
        # (ap_idr_ok, ap_dbgswenable) can therefore never be exercised. Used by
        # get_never_tested_debug_access_gates() below to render those gates as "N/A"
        # instead of the misleading "NOT TESTED" in the diagnostic table.
        self.mem_ap_fixed_from_db = False
        if self.family:
            db = get_db(self.family)
            self.enable_power_domains_after_connect = db.get_bool(
                DatabaseManager.DEBUG_PROBE, "enable_power_domains_after_connect", False
            )
            self.enable_sda_debug_paths_after_connect = db.get_bool(
                DatabaseManager.DEBUG_PROBE, "enable_sda_debug_paths_after_connect", False
            )
            self.preserve_csw_ro_bits = db.get_bool(
                DatabaseManager.DEBUG_PROBE, "mem_ap_preserve_csw_ro_bits", False
            )
            self.mem_ap_scan_write_before_read = db.get_bool(
                DatabaseManager.DEBUG_PROBE, "mem_ap_scan_write_before_read", False
            )
            self.mem_ap_ix = db.get_int(DatabaseManager.DEBUG_PROBE, "mem_ap_index", -1)
            self.mem_ap_fixed_from_db = self.mem_ap_ix >= 0
            if self.mem_ap_fixed_from_db:
                logger.debug(
                    f"Using fixed mem_ap_index={self.mem_ap_ix} from device database "
                    "(skipping AP scan)."
                )

            if DatabaseManager.DAT in db.features:
                self.dbgmlbx_ap_ix = db.get_int(DatabaseManager.DAT, "dmbox_ap_ix", -1)

    def get_debug_probe_protocol(self) -> DebugProbeProtocol:
        """Get effective ARM debug probe protocol.

        :return: Effective debug probe protocol. If not specified, SWD is used.
        :raises SPSDKDebugProbeError: JTAG protocol is requested but unsupported.
        """
        protocol = self.protocol or DebugProbeProtocol.SWD
        if protocol not in self.SUPPORTED_PROTOCOLS:
            raise SPSDKDebugProbeError(
                f"Debug probe '{self.NAME}' does not support {protocol.label.upper()} protocol."
            )
        return protocol

    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        General connecting function for SPSDK library to support various DEBUG PROBES.
        The function is used to initialize the connection to target and attempts recovery
        if the initial connection fails.

        :raises Exception: Re-raises the original connection exception if recovery fails.
        """
        try:
            self.connect()
        except Exception:
            self.debug_access_status["probe_connected"] = False
            if self.recover_debug_connection():
                self.connect()
                self.debug_access_status["probe_connected"] = True
                return
            raise

        self.debug_access_status["probe_connected"] = True
        self._init_debug_access_after_connect()

    @abstractmethod
    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read coresight register.

        It reads coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be read (default),
            otherwise the Debug Port (DP) register will be read.
        :param addr: the register address.
        :return: The read value of addressed register (4 bytes).
        """

    @abstractmethod
    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write coresight register.

        It writes coresight register function for SPSDK library to support various DEBUG PROBES.

        :param access_port: if True, the Access Port (AP) register will be written (default),
            otherwise the Debug Port register will be written.
        :param addr: the register address.
        :param data: the data to be written into register.
        """

    def get_coresight_ap_address(self, access_port: int, address: int) -> int:
        """Compute the coresight access port register address (ADIv5/ADIv6 aware).

        For ADIv5 the access port is an AP index (0-255) shifted to bits [31:24]
        and combined with the register offset.
        For ADIv6 the access port is already a real AP base address, so it is only
        ORed with the register offset.

        :param access_port: AP index (ADIv5) or AP base address (ADIv6).
        :param address: Register address offset.
        :return: Computed coresight address.
        :raises SPSDKValueError: If access port index exceeds 255 (ADIv5 only).
        """
        if self.adi_version == 6:
            # ADIv6: access_port is already a real AP address (e.g., 0x00002000).
            # Just OR with the register offset.
            return access_port | address
        # ADIv5: access_port is an index (0-255), shift to bits [31:24].
        if access_port > 255:
            raise SPSDKValueError("Invalid value of access port")
        return access_port << self.APSEL_SHIFT | address

    def _trace_port_label(self, access_port: bool, addr: int) -> str:
        """Build the port label for a CoreSight trace line (ADIv5/ADIv6 aware).

        For the Debug Port the label is always "DP". For the Access Port the label
        depends on the detected ADI version: on ADIv5 the AP is selected by an index
        encoded in bits [31:24], while on ADIv6 the AP is a memory-mapped base address
        carried in the DP SELECT register (self.last_accessed_ap).

        :param access_port: True if the Access Port (AP) is targeted, False for Debug Port (DP).
        :param addr: The CoreSight register address of the transaction.
        :return: Human-readable port label used in the unified trace stream.
        """
        if not access_port:
            return "DP"
        if self.adi_version == 6:
            # In ADIv6 the AP is not indexed; report the currently selected base address.
            return f"AP@0x{self.last_accessed_ap & self.SELECT_APADDR_MASK:08X}"
        return f"AP{(addr & self.APSEL) >> self.APSEL_SHIFT}"

    def trace_cs_read(self, access_port: bool, addr: int, data: int) -> None:
        """Trace a completed high-level CoreSight register read in a unified format.

        Emits a single line on the shared ``spsdk.probe.trace`` logger so the TRACE
        stream is identical across all debug-probe plugins and can be compared directly.

        :param access_port: True if the Access Port (AP) was read, False for Debug Port (DP).
        :param addr: The CoreSight register address that was read.
        :param data: The 32-bit value that was read.
        """
        port = self._trace_port_label(access_port, addr)
        cs_trace_logger.trace(f"CS RD {port} addr=0x{addr:08X} data=0x{data:08X}")

    def trace_cs_write(self, access_port: bool, addr: int, data: int) -> None:
        """Trace a completed high-level CoreSight register write in a unified format.

        Emits a single line on the shared ``spsdk.probe.trace`` logger so the TRACE
        stream is identical across all debug-probe plugins and can be compared directly.

        :param access_port: True if the Access Port (AP) was written, False for Debug Port (DP).
        :param addr: The CoreSight register address that was written.
        :param data: The 32-bit value that was written.
        """
        port = f"AP{(addr & self.APSEL) >> self.APSEL_SHIFT}" if access_port else "DP"
        cs_trace_logger.trace(f"CS WR {port} addr=0x{addr:08X} data=0x{data:08X}")

    def trace_cs_event(self, message: str) -> None:
        """Trace a high-level probe event (connect, power-up, reset, ...) in a unified format.

        Emits a single line on the shared ``spsdk.probe.trace`` logger so the TRACE
        stream is identical across all debug-probe plugins and can be compared directly.

        :param message: Human-readable description of the event.
        """
        cs_trace_logger.trace(f"CS EV {message}")

    def _init_debug_access_after_connect(self) -> None:
        """Initialize optional device-specific debug access after connect."""
        # Detect ADI version (ADIv5 vs ADIv6) from DP_IDR
        self._detect_adi_version()

        if self.enable_power_domains_after_connect:
            try:
                self.power_up_target()
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Post-connect power domain init skipped: {e}")

        if self.enable_sda_debug_paths_after_connect:
            try:
                if not self.family:
                    return
                sda_ap_ix = get_db(self.family).get_int(DatabaseManager.DAT, "sda_ap_index", -1)
                if sda_ap_ix >= 0:
                    self.coresight_reg_write(
                        access_port=True,
                        addr=self.get_coresight_ap_address(sda_ap_ix, 0x80),
                        data=0x10000010,  # DBGENCTRL: GDBGEN (bit28) | CDBGEN (bit4)
                    )
                    self.debug_access_status["sda_dbgenctrl_written"] = True
                    logger.debug(
                        f"Written DBGENCTRL (GDBGEN|CDBGEN) to SDA-AP {sda_ap_ix} "
                        "to enable debug paths."
                    )
            except Exception as e:  # noqa: BLE001
                self.debug_access_status["sda_dbgenctrl_written"] = False
                logger.debug(f"SDA-AP DBGENCTRL init skipped: {e}")

    def coresight_reg_write_safe(
        self, access_port: bool = True, addr: int = 0, data: int = 0, max_retries: int = 3
    ) -> None:
        """Write CoreSight register with automatic retry and error recovery.

        Performs a CoreSight register write operation with built-in error handling and automatic
        recovery attempts. If the initial write fails, the method attempts to recover the debug
        connection and retry the operation up to the specified maximum number of attempts.

        :param access_port: If True, writes to Access Port register, otherwise Debug Port register
        :param addr: Register address to write to
        :param data: Data value to write into the register
        :param max_retries: Maximum number of retry attempts before giving up
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(max_retries):
            try:
                # Call the concrete implementation (to be implemented by subclasses)
                self.coresight_reg_write(access_port, addr, data)
                return  # Success

            except SPSDKDebugProbeTransferError as e:
                last_exception = e
                logger.debug(
                    f"CoreSight register write failed (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:  # Don't recover on last attempt
                    try:
                        logger.debug("Attempting debug connection recovery")
                        if self.recover_debug_connection():
                            logger.debug("Recovery successful, retrying operation")
                            continue
                        else:
                            logger.debug(
                                "CoreSight register write failed and recovery failed also :-("
                            )
                    except Exception as recovery_error:  # noqa: BLE001
                        logger.debug(f"Recovery attempt failed: {recovery_error}")

            except Exception as e:  # noqa: BLE001
                # Handle unexpected errors
                last_exception = SPSDKDebugProbeTransferError(
                    f"Unexpected error during coresight write: {e}"
                )
                logger.error(f"Unexpected error in coresight register write: {e}")
                break

        # All attempts failed
        raise SPSDKDebugProbeTransferError(
            f"CoreSight register write failed after {max_retries} attempts. "
            f"Address: 0x{addr:08X}, Data: 0x{data:08X}, AP: {access_port}. Last error: {last_exception}"
        )

    def coresight_reg_read_safe(
        self, access_port: bool = True, addr: int = 0, max_retries: int = 3
    ) -> int:
        """Safe coresight register read with error handling and recovery.

        This method attempts to read a CoreSight register with automatic retry and recovery
        mechanisms. If a read fails, it will attempt to recover the debug connection and
        retry the operation up to the specified maximum number of attempts.

        :param access_port: If True, reads Access Port (AP) register, otherwise Debug Port (DP).
        :param addr: The register address to read from.
        :param max_retries: Maximum number of retry attempts before giving up.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: If all retry attempts fail.
        """
        last_exception = None

        for attempt in range(max_retries):
            try:
                # Call the concrete implementation (to be implemented by subclasses)
                return self.coresight_reg_read(access_port, addr)

            except SPSDKDebugProbeTransferError as e:
                last_exception = e
                logger.debug(
                    f"CoreSight register read failed (attempt {attempt + 1}/{max_retries}): {e}"
                )

                if attempt < max_retries - 1:  # Don't recover on last attempt
                    try:
                        logger.debug("Attempting debug connection recovery")
                        if self.recover_debug_connection():
                            logger.debug("Recovery successful, retrying operation")
                            continue
                        else:
                            logger.debug(
                                "CoreSight register read failed and recovery failed also :-("
                            )

                    except Exception as recovery_error:  # noqa: BLE001
                        logger.debug(f"Recovery attempt failed: {recovery_error}")

            except Exception as e:  # noqa: BLE001
                # Handle unexpected errors
                last_exception = SPSDKDebugProbeTransferError(
                    f"Unexpected error during coresight read: {e}"
                )
                logger.error(f"Unexpected error in coresight register read: {e}")
                break

        # All attempts failed
        raise SPSDKDebugProbeTransferError(
            f"CoreSight register read failed after {max_retries} attempts. "
            f"Address: 0x{addr:08X}, AP: {access_port}. Last error: {last_exception}"
        )

    @no_type_check
    # pylint: disable=no-self-argument,missing-type-doc
    def get_mem_ap(func):
        """Decorator that ensures correct Memory Access Port index is found before first use.

        This decorator automatically discovers and configures the appropriate Memory Access Port (MEM AP)
        by testing possible AP indices and validating memory access functionality. It performs CoreSight
        AP identification, enters debug state, tests memory access, and restores the original state.

        :param func: The function to be decorated that requires MEM AP access.
        :return: Decorated function wrapper.
        :raises SPSDKDebugProbeError: When no valid memory access port is found.
        """
        DEFAULT_TEST_MEM_AP_ADDRESS = 0x2000_0000

        @functools.wraps(func)
        def wrapper(self: "DebugProbeCoreSightOnly", *args, **kwargs):
            """Wrapper function to ensure memory access port (MEM AP) is discovered before execution.

            This decorator automatically discovers and configures the memory access port by iterating
            through possible AP indices, validating each one by checking the IDR register for class 8
            (MEM AP), entering debug state, and performing a test memory read operation.

            :param self: DebugProbeCoreSightOnly instance
            :param args: Positional arguments passed to the wrapped function
            :param kwargs: Keyword arguments passed to the wrapped function
            :raises SPSDKDebugProbeError: When memory access port cannot be found
            :return: Result of the wrapped function execution
            """
            status = False
            test_address = value_to_int(
                self.options.get("test_address", DEFAULT_TEST_MEM_AP_ADDRESS)
            )

            if self.mem_ap_ix < 0:
                logger.debug(f"Trying MEM AP on address {hex(test_address)}")
                # Try to find MEM AP
                for i, known_idr in self._ap_scan_candidates(self.ADIV5_MEM_AP_INDICES):
                    try:
                        logger.debug(f"Testing AP {hex(i)} for memory access")
                        # Reuse the IDR already read during ADIv6 enumeration when known
                        # (non-zero); otherwise read it now (always the case for ADIv5).
                        if known_idr:
                            idr = known_idr
                        else:
                            idr = self.coresight_reg_read(
                                access_port=True,
                                addr=self.get_coresight_ap_address(
                                    access_port=i, address=self._ap_idr_reg()
                                ),
                            )
                        logger.debug(f"AP{i} IDR: 0x{idr:08X}")
                        # Extract IDR fields used for lookup. TODO solve that
                        ap_class = (idr & 0x1E000) >> 13
                        ap_type = idr & 0xF
                        # class=8 is MEM-AP; type=1/5=AHB-AP, type=4=AXI-AP.
                        # Skip APB-AP (type=2,6) which cannot access general SRAM.
                        if ap_class == 8 and ap_type in (1, 4, 5):
                            try:
                                dhcsr_reg = None
                                # Read CSW first to check DbgSwEnable (bit31).
                                # DbgSwEnable is a RO hardware signal that reflects whether
                                # the CPU's DBGEN is asserted. DHCSR at 0xE000EDF0 is only
                                # accessible via the CPU's local AHB-AP when DBGEN is set.
                                # Attempting DHCSR on APs where DbgSwEnable=0 causes a bus
                                # fault -> STICKYERR -> CMSIS-DAP probes get stuck. Skip
                                # DHCSR entirely when DbgSwEnable=0.
                                dbgswenable = True
                                if self.preserve_csw_ro_bits:
                                    ap_csw = self._safe_csw_value(i, single_increment=True)
                                    dbgswenable = bool(ap_csw & 0x80000000)
                                    self.debug_access_status["ap_dbgswenable"] = dbgswenable
                                try:
                                    if dbgswenable:
                                        # Enter debug state and halt (requires DHCSR on APB/PPB)
                                        dhcsr_reg = self._mem_reg_read(
                                            mem_ap_ix=i, addr=self.DHCSR_REG
                                        )
                                        logger.debug(f"Value of DHCSR register = {hex(dhcsr_reg)}")
                                        self.debug_access_status["core_dhcsr_ok"] = True
                                        self._mem_reg_write(
                                            mem_ap_ix=i,
                                            addr=self.DHCSR_REG,
                                            data=(
                                                self.DHCSR_DEBUGKEY
                                                | self.DHCSR_C_HALT
                                                | self.DHCSR_C_DEBUGEN
                                            ),
                                        )
                                    else:
                                        logger.debug(
                                            f"AP{i} CSW.DbgSwEnable=0, skipping DHCSR halt"
                                        )
                                except SPSDKError:
                                    # DHCSR not accessible via this AP (e.g., AHB-AP on
                                    # devices where debug registers are on a separate APB bus).
                                    # Proceed with memory test without CPU halt.
                                    self.debug_access_status["core_dhcsr_ok"] = False
                                    logger.debug(
                                        f"DHCSR not accessible via AP{i} "
                                        "(trying memory test without CPU halt)"
                                    )
                                    # The 3×3 DHCSR read retries above leave STICKYERR set.
                                    # Clear it now so the next CSW read in _safe_csw_value
                                    # doesn't immediately get ACK FAULT. Use safe version since
                                    # DP may already be in a broken state.
                                    try:
                                        self.coresight_reg_write_safe(
                                            access_port=False,
                                            addr=self.DP_ABORT_REG,
                                            data=0x1F,
                                        )
                                    except Exception as exc:
                                        logger.debug(
                                            f"Failed to clear sticky errors after DHCSR read: {exc}",
                                            exc_info=True,
                                        )
                                try:
                                    if self.mem_ap_scan_write_before_read:
                                        # Write before read to initialize ECC-protected SRAM.
                                        # On devices with ECC (e.g. MCXE31B), reading
                                        # uninitialized SRAM causes an ECC fault -> SLVERR ->
                                        # DRW FAULT. A prior write initializes the ECC bits
                                        # and also verifies write access.
                                        test_pattern = 0xA5A5A5A5
                                        self._mem_reg_write(
                                            mem_ap_ix=i, addr=test_address, data=test_pattern
                                        )
                                        read_back = self._mem_reg_read(
                                            mem_ap_ix=i, addr=test_address
                                        )
                                        if read_back != test_pattern:
                                            raise SPSDKError(
                                                f"Memory verify failed at {hex(test_address)}: "
                                                f"wrote {test_pattern:#010x}, "
                                                f"read {read_back:#010x}"
                                            )
                                    else:
                                        self._mem_reg_read(mem_ap_ix=i, addr=test_address)
                                    status = True
                                    self.debug_access_status["ahb_system_bus_ok"] = True
                                except SPSDKError:
                                    self.debug_access_status["ahb_system_bus_ok"] = False
                                    logger.debug(
                                        f"Read operation on AP{i} fails at {hex(test_address)} address"
                                    )
                                finally:
                                    if dhcsr_reg is not None:
                                        # Exit debug state.
                                        # DHCSR writes require KEY in bits [31:16]; preserve
                                        # original control bits from the low halfword only.
                                        self._mem_reg_write(
                                            mem_ap_ix=i,
                                            addr=self.DHCSR_REG,
                                            data=self.DHCSR_DEBUGKEY | (dhcsr_reg & 0xFFFF),
                                        )
                                if not status:
                                    # Clear any sticky errors from failed CSW/DRW before
                                    # moving to the next AP - otherwise the next AP's IDR
                                    # read will immediately get ACK FAULT. Use safe version since
                                    # DP may already be in a broken state.
                                    try:
                                        self.coresight_reg_write_safe(
                                            access_port=False,
                                            addr=self.DP_ABORT_REG,
                                            data=0x1F,
                                        )
                                    except Exception as exc:
                                        logger.debug(
                                            f"Failed to clear sticky errors after memory test: {exc}",
                                            exc_info=True,
                                        )
                                    continue
                            except SPSDKError:
                                continue

                            self.mem_ap_ix = i
                            self.debug_access_status["ap_idr_ok"] = True
                            logger.debug(f"Found memory access port at AP{i}, IDR: 0x{idr:08X}")
                            break
                    except SPSDKError as e:
                        logger.debug(f"AP{i} IDR read failed: {e}")
                        try:
                            # Clear sticky error flags so next AP scan starts clean.
                            # A failed AP read sets STICKYERR in DP CTRL/STAT, which
                            # would cause all subsequent AP reads to fault as well.
                            # Use safe version for robust error recovery.
                            self.coresight_reg_write_safe(
                                access_port=False, addr=self.DP_ABORT_REG, data=0x1F
                            )
                        except Exception as exc:
                            logger.debug(f"Failed to clear AP sticky errors: {exc}", exc_info=True)

                if self.mem_ap_ix < 0:
                    self.debug_access_status["ap_idr_ok"] = False
                    raise SPSDKDebugProbeError("The memory access port is not found!")
            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    def _safe_csw_value(self, mem_ap_ix: int, single_increment: bool = True) -> int:
        """Compute a safe CSW value by read-modify-write to preserve RO hardware bits.

        Different APs have different read-only (RO) bits in their CSW register that reflect
        hardware signals (e.g. DbgSwEnable=DBGEN, SPIDEN, HNONSEC). Writing 0 to an RO=1
        bit or writing 1 to an RO=0 bit causes SLVERR -> WIRE ACK FAULT on the next SWD
        transaction, breaking the entire AP scan.

        This method reads the current CSW and only modifies the truly writable lower bits:
        - Bits [2:0] SIZE -> 32-bit word (0b010)
        - Bits [5:4] ADDRINC -> single (0b01) or packed (0b10)
        - Bit [6] DEVICEEN -> 1

        All upper bits (hardware security/protection signals) are preserved unchanged.

        :param mem_ap_ix: AP index to read/write CSW for.
        :param single_increment: If True use single address increment, else packed.
        :return: Safe CSW value with only RW bits modified, RO bits preserved.
        """
        csw_addr = self.get_coresight_ap_address(mem_ap_ix, self.CSW_REG)
        addrinc = self.CSW_ADDRINC_SINGLE if single_increment else self.CSW_ADDRINC_PACKED
        rw_bits = self.CSW_SIZE_32BIT | addrinc | self.CSW_DEVICEEN  # 0x52 or 0x62
        try:
            current_csw = self.coresight_reg_read_safe(access_port=True, addr=csw_addr)
            # Mask out only bits [6:0] (RW), preserve bits [31:7] (may be RO)
            return (current_csw & 0xFFFFFF80) | rw_bits
        except SPSDKDebugProbeTransferError:
            # Fallback: use CSW_FULL_DEBUG. May fail on strict RO implementations but
            # is the correct value for standard Cortex-M APs.
            return self.CSW_FULL_DEBUG

    def _get_csw_value(self, mem_ap_ix: int, single_increment: bool = True) -> int:
        """Get CSW value for memory transfer.

        :param mem_ap_ix: AP index to configure CSW for.
        :param single_increment: If True use single address increment, else packed.
        :return: CSW value for memory transfer.
        """
        if self.preserve_csw_ro_bits:
            return self._safe_csw_value(mem_ap_ix, single_increment=single_increment)
        addrinc = self.CSW_ADDRINC_SINGLE if single_increment else self.CSW_ADDRINC_PACKED
        return (
            self.CSW_FULL_DEBUG & ~(self.CSW_ADDRINC_SINGLE | self.CSW_ADDRINC_PACKED)
        ) | addrinc

    def _mem_reg_read(self, mem_ap_ix: int, addr: int = 0) -> int:
        """Read 32-bit register in memory space of MCU.

        This function reads a 32-bit register in memory space of MCU for SPSDK library
        to support various debug probes.

        :param mem_ap_ix: The index of memory access port.
        :param addr: The register address.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeTransferError: Error occurs during memory transfer.
        """
        try:
            csw_addr = self.get_coresight_ap_address(mem_ap_ix, self.CSW_REG)
            self.coresight_reg_write_safe(
                access_port=True,
                addr=csw_addr,
                data=self._get_csw_value(mem_ap_ix, single_increment=True),
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.TAR_REG),
                data=addr,
            )

            return self.coresight_reg_read_safe(
                access_port=True, addr=self.get_coresight_ap_address(mem_ap_ix, self.DRW_REG)
            )
        except SPSDKError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed read memory({exc!s})") from exc

    @get_mem_ap
    def mem_reg_read(self, addr: int = 0, space: MemorySpace = MemorySpace.DATA) -> int:
        """Read 32-bit register in memory space of MCU.

        This method reads a 32-bit register from the memory space of the connected MCU
        using the configured debug probe interface.

        :param addr: The register address to read from.
        :param space: Memory space selector. Must be DATA; PROGRAM is not supported on ARM probes.
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKError: If space is not DATA.
        """
        if space != MemorySpace.DATA:
            raise SPSDKError(
                f"Memory space '{space.label}' is not supported on ARM CoreSight probes. Only 'data' is valid."
            )
        return self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=addr)

    def _mem_reg_write(self, mem_ap_ix: int, addr: int = 0, data: int = 0) -> None:
        """Write 32-bit register in memory space of MCU.

        This function writes a 32-bit register in the memory space of the MCU through the
        CoreSight debug interface using the specified memory access port.

        :param mem_ap_ix: The index of memory access port.
        :param addr: The register address to write to.
        :param data: The 32-bit data to be written into the register.
        :raises SPSDKDebugProbeTransferError: Error occurs during memory transfer.
        """
        try:
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.CSW_REG),
                data=self._get_csw_value(mem_ap_ix, single_increment=True),
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.TAR_REG),
                data=addr,
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(mem_ap_ix, self.DRW_REG),
                data=data,
            )
            self.coresight_reg_read_safe(access_port=False, addr=self.DP_CTRL_STAT_REG)
        except SPSDKError as exc:
            raise SPSDKDebugProbeTransferError(f"Failed write memory({exc!s})") from exc

    @get_mem_ap
    def mem_reg_write(
        self, addr: int = 0, data: int = 0, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write 32-bit register in memory space of MCU.

        This method writes a 32-bit value to a specified register address in the MCU's memory
        space using the configured memory access port.

        :param addr: The register address to write to.
        :param data: The 32-bit data value to be written into the register.
        :param space: Memory space selector. Must be DATA; PROGRAM is not supported on ARM probes.
        :raises SPSDKError: If space is not DATA.
        """
        if space != MemorySpace.DATA:
            raise SPSDKError(
                f"Memory space '{space.label}' is not supported on ARM CoreSight probes. Only 'data' is valid."
            )
        return self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=addr, data=data)

    @get_mem_ap
    def mem_block_read(self, addr: int, size: int, space: MemorySpace = MemorySpace.DATA) -> bytes:
        """Read a block of memory from the MCU, handling non-aligned addresses and sizes.

        This method implements a chunked reading approach to overcome the 1KB auto-increment
        limitation of the ARM Cortex Debug Access Port (DAP). The method handles memory alignment
        automatically and reads data in 1KB chunks to ensure reliable operation.

        :param addr: The starting memory address to read from.
        :param size: The number of bytes to read from memory.
        :param space: Memory space selector. Must be DATA; PROGRAM is not supported on ARM probes.
        :return: The read data as a bytes object.
        :raises SPSDKError: If space is not DATA.
        """
        if space != MemorySpace.DATA:
            raise SPSDKError(
                f"Memory space '{space.label}' is not supported on ARM CoreSight probes. Only 'data' is valid."
            )
        result = bytearray()
        aligned_addr = addr & ~0x3
        end_addr = addr + size
        aligned_end = (end_addr + 3) & ~0x3

        while aligned_addr < aligned_end:
            chunk_size = min(0x400, aligned_end - aligned_addr)

            # Set up for block transfer
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.CSW_REG),
                data=self._get_csw_value(self.mem_ap_ix, single_increment=True),
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.TAR_REG),
                data=aligned_addr,
            )

            # Read data in blocks
            for _ in range(0, chunk_size, 4):
                value = self.coresight_reg_read_safe(
                    access_port=True,
                    addr=self.get_coresight_ap_address(self.mem_ap_ix, self.DRW_REG),
                )
                result.extend(value.to_bytes(4, "little"))

            aligned_addr += chunk_size

        # Trim the result to the exact requested size
        return bytes(result[addr - (addr & ~0x3) : addr - (addr & ~0x3) + size])

    @get_mem_ap
    def mem_block_write(
        self, addr: int, data: bytes, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write a block of memory to the MCU, handling unaligned addresses and sizes.

        This method implements a three-stage writing approach:
        1. Handles initial unaligned bytes using 8-bit writes.
        2. Performs bulk 32-bit aligned writes for the main data block.
        3. Handles any remaining bytes using 8-bit writes.
        This approach ensures efficient writing for aligned data while correctly
        handling unaligned start and end addresses.

        :param addr: The starting address to write to.
        :param data: The data to be written, as a bytes object.
        :param space: Memory space selector. Must be DATA; PROGRAM is not supported on ARM probes.
        :raises SPSDKError: If space is not DATA.
        :raises SPSDKDebugProbeTransferError: If there's an error during the write operation.
        """
        if space != MemorySpace.DATA:
            raise SPSDKError(
                f"Memory space '{space.label}' is not supported on ARM CoreSight probes. Only 'data' is valid."
            )
        end_addr = addr + len(data)
        data_index = 0

        # Handle initial unaligned bytes
        if addr % 4 != 0:
            aligned_addr = addr & ~0x3
            word = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr)
            bytes_to_write = min(4 - (addr % 4), end_addr - addr)
            for i in range(bytes_to_write):
                byte_pos = (addr + i) % 4
                word &= ~(0xFF << (byte_pos * 8))
                word |= data[data_index + i] << (byte_pos * 8)

            self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr, data=word)

            addr += bytes_to_write
            data_index += bytes_to_write

        # Handle 32-bit aligned writes
        while addr + 4 <= end_addr:
            chunk_end = min((addr + 0x400) & ~0x3FF, end_addr)
            chunk_size = chunk_end - addr

            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.CSW_REG),
                data=self._get_csw_value(self.mem_ap_ix, single_increment=True),
            )
            self.coresight_reg_write_safe(
                access_port=True,
                addr=self.get_coresight_ap_address(self.mem_ap_ix, self.TAR_REG),
                data=addr,
            )

            for _ in range(0, chunk_size, 4):
                value = int.from_bytes(data[data_index : data_index + 4], "little")
                self.coresight_reg_write_safe(
                    access_port=True,
                    addr=self.get_coresight_ap_address(self.mem_ap_ix, self.DRW_REG),
                    data=value,
                )
                addr += 4
                data_index += 4

        # Handle remaining bytes
        while addr < end_addr:
            aligned_addr = addr & ~0x3
            word = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr)
            bytes_to_write = min(4 - (addr % 4), end_addr - addr)

            for i in range(bytes_to_write):
                byte_pos = (addr + i) % 4
                word &= ~(0xFF << (byte_pos * 8))
                word |= data[data_index + i] << (byte_pos * 8)

            self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=aligned_addr, data=word)

            addr += bytes_to_write
            data_index += bytes_to_write

    @no_type_check
    # pylint: disable=no-self-argument
    def get_dbgmlbx_ap(func: Any):
        """Decorator function that secures getting the correct DEBUG MAILBOX AP index for first use.

        The decorator automatically detects the debug mailbox access port index by trying
        predefined possible indices and validating against the expected IDR register value.
        If no valid access port is found, it raises an exception.

        :param func: The function to be decorated that requires debug mailbox access.
        :raises SPSDKError: When debug mailbox access port cannot be found.
        :return: Decorated function wrapper.
        """
        IDR_ADDRESS = 0xFC
        IDR_VALUE = 0x002A0000

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            """Wrapper function to auto-detect debug mailbox access port if not specified.

            This decorator automatically detects the debug mailbox access port index by iterating
            through possible access port indices and checking the IDR register value. If the
            access port index is already set (>= 0), the wrapped function is called directly.

            :param self: DebugMailbox instance.
            :param args: Variable length argument list to pass to wrapped function.
            :param kwargs: Arbitrary keyword arguments to pass to wrapped function.
            :raises SPSDKError: When debug mailbox access port cannot be found.
            :return: Result of the wrapped function call.
            """
            if self.dbgmlbx_ap_ix < 0:
                # Try to find DEBUG MAILBOX AP
                logger.warning(
                    "The debug mailbox access port index is not specified, trying autodetection."
                )
                for i, known_idr in self._ap_scan_candidates(self.ADIV5_DBGMLBX_AP_INDICES):
                    try:
                        # Reuse the IDR already read during ADIv6 enumeration when known
                        # (non-zero); otherwise read it now (always the case for ADIv5).
                        if known_idr:
                            idr = known_idr
                        else:
                            idr = self.coresight_reg_read_safe(
                                access_port=True,
                                addr=self.get_coresight_ap_address(
                                    access_port=i, address=self._dbgmlbx_idr_address(IDR_ADDRESS)
                                ),
                            )
                        if idr == IDR_VALUE:
                            self.dbgmlbx_ap_ix = i
                            self.dbgmlbx_ap_validated = True
                            self.debug_access_status["dbgmlbx_ap_idr_ok"] = True
                            logger.debug(
                                f"Found debug mailbox access port at AP{i}, IDR: 0x{idr:08X}"
                            )
                            break
                    except SPSDKError:
                        pass

                if self.dbgmlbx_ap_ix < 0:
                    self.debug_access_status["dbgmlbx_ap_idr_ok"] = False
                    raise SPSDKError("The debug mailbox access port is not found!")

            if not self.dbgmlbx_ap_validated:
                idr = self.coresight_reg_read_safe(
                    access_port=True,
                    addr=self.get_coresight_ap_address(
                        access_port=self.dbgmlbx_ap_ix,
                        address=self._dbgmlbx_idr_address(IDR_ADDRESS),
                    ),
                )
                if idr != IDR_VALUE:
                    self.debug_access_status["dbgmlbx_ap_idr_ok"] = False
                    raise SPSDKError(
                        f"The debug mailbox AP{self.dbgmlbx_ap_ix} IDR value({hex(idr)}) "
                        f"doesn't match the expected value: {hex(IDR_VALUE)}"
                    )
                self.dbgmlbx_ap_validated = True
                self.debug_access_status["dbgmlbx_ap_idr_ok"] = True

            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    @get_dbgmlbx_ap
    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This function reads a debug mailbox register through the debug probe interface to support
        various debug probes in the SPSDK library.

        :param addr: The register address to read from.
        :return: The read value of addressed register (4 bytes).
        """
        return self.coresight_reg_read(
            addr=self.get_coresight_ap_address(access_port=self.dbgmlbx_ap_ix, address=addr)
        )

    @get_dbgmlbx_ap
    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        Writes data to a specified register address in the debug mailbox access port
        using the configured debug probe's CoreSight interface.

        :param addr: Register address to write to.
        :param data: Data value to write into the register.
        """
        self.coresight_reg_write(
            addr=self.get_coresight_ap_address(access_port=self.dbgmlbx_ap_ix, address=addr),
            data=data,
        )

    def clear_sticky_errors(self) -> None:
        """Clear sticky errors of Debug port interface.

        This method reads the debug port control/status register to check for sticky errors
        and clears them if found. For JTAG interface, it performs an additional write operation.
        The method handles communication failures gracefully by attempting recovery.

        :raises SPSDKDebugProbeTransferError: When debug probe communication cannot be reestablished.
        """
        if self.protocol == DebugProbeProtocol.JTAG:
            # Currently clear_sticky_errors has been defined only for SWD (uncleared for JTAG-DP)
            self.coresight_reg_write(access_port=False, addr=4, data=0x50000F20)
        try:
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            logger.debug(f"Checked Sticky Errors: {hex(ctrl_stat)}")
            if ctrl_stat & 0xB2:
                errors = "\n"
                if ctrl_stat & 0x02:
                    errors += "\n  - STICKYORUN: Sticky Overrun"
                if ctrl_stat & 0x10:
                    errors += "\n  - STICKYCMP: Mismatch occur during a pushed-compare operation"
                if ctrl_stat & 0x20:
                    errors += "\n  - STICKYERR: Sticky Error - AP transaction failed"
                if ctrl_stat & 0x80:
                    errors += "\n  - WDATAERR: Write data error occur"
                logger.debug(f"Debug interface: Sticky error(s) detected:{errors}")

                # Clear The sticky errors
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
        except SPSDKError as e:
            try:
                logger.debug("Read sticky errors failed, sending ABORT request.")
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKError:
                pass
            else:
                raise SPSDKDebugProbeTransferError(
                    "Cannot reestablish the Debug probe communication - please reset the board."
                ) from e
        finally:
            self.last_accessed_ap = -1

    def _reinit_target(self) -> None:
        """Re-initialize the Probe connection.

        This is an obsolete method kept here just for backward compatibility reasons
        in debug probe plugins.
        """

    def _target_power_control(self, sys_power: bool = False, debug_power: bool = False) -> None:
        """Control power state of the target device.

        This method manages both system and debug power states of the target device
        through CoreSight debug port control/status register operations.

        :param sys_power: Enable or disable target system power state.
        :param debug_power: Enable or disable target debug power state.
        :raises SPSDKTimeoutError: Timeout on power enable operation.
        """
        logger.debug(
            f"Power Control the debug connection:\nSystem power: {sys_power}\nDebug power: {debug_power}"
        )
        # Request change of target power
        req = self.MASKLANE
        check_status = 0
        if sys_power:
            req |= self.CSYSPWRUPREQ
            check_status |= self.CSYSPWRUPACK
        if debug_power:
            req |= self.CDBGPWRUPREQ
            check_status |= self.CDBGPWRUPACK
        self.coresight_reg_write(access_port=False, addr=self.DP_CTRL_STAT_REG, data=req)

        # Check the state (check these statuses that are set)
        ret = 0
        timeout = Timeout(1, units="s")
        while (ret & (self.CDBGPWRUPACK | self.CSYSPWRUPACK)) != check_status:
            if timeout.overflow():
                self.debug_access_status["dp_power_domains_ok"] = False
                raise SPSDKTimeoutError(
                    "The Debug Mailbox power control operation ends on timeout."
                )
            ret = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
        if sys_power or debug_power:
            self.debug_access_status["dp_power_domains_ok"] = True
        self.last_accessed_ap = -1

    def power_up_target(self) -> None:
        """Power up the target for the Probe connection.

        This method enables both system and debug power to establish a proper
        connection with the target device through the debug probe.

        :raises SPSDKError: If power control operation fails.
        """
        logger.debug("Power up the debug connection")
        # Enable the whole power of target :-)
        self._target_power_control(sys_power=True, debug_power=True)

    def initialize_debug_port(self) -> None:
        """Initialize Debug Port after low-level SWD/JTAG connection.

        The method clears possible stale sticky DP errors and powers up system and debug
        domains together using the common CoreSight power-up sequence.

        :raises SPSDKError: If debug port power-up fails.
        """
        logger.debug("Initialize debug port")
        try:
            self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
        except SPSDKError as exc:
            logger.debug(f"DP sticky error clear before power-up failed: {exc}")
        self.power_up_target()
        self.last_accessed_ap = -1

    def power_down_target(self) -> None:
        """Power down the target for the Probe connection.

        This method performs a two-step power down sequence: first disabling system power
        while maintaining debug power, then disabling debug power completely to ensure
        proper target shutdown.
        """
        logger.debug("Power down the debug connection")
        # First of all power down system power
        self._target_power_control(sys_power=False, debug_power=True)
        # As a second step, power off also debug power
        self._target_power_control(sys_power=False, debug_power=False)

    def select_ap(self, addr: int) -> None:
        """Select the access port in Debug Port (DP).

        This method configures the Debug Port to access a specific Access Port by writing
        to the SELECT register. It includes caching optimization to avoid redundant writes
        when the same AP is already selected.

        :param addr: Requested AP access address containing AP selection and bank information.
        """
        if self.adi_version == 6:
            # ADIv6: SELECT holds the AP base address (bits [31:4]) plus DP bank
            # select (bits [3:0]). There is no APSEL index field. On DPs with an
            # address size > 32 bits the upper AP address bits [63:32] are carried
            # in the SELECT1 register.
            select = addr & self.SELECT_APADDR_MASK
            # Cache the full 64-bit address so a differing upper half is not masked out.
            if self.last_accessed_ap != addr or DISABLE_AP_SELECT_CACHING:
                self.last_accessed_ap = addr
                if self.adiv6_addr_size > self.ADIV6_ADDR_SIZE_32:
                    select_high = (addr >> 32) & 0xFFFFFFFF
                    self.coresight_reg_write_safe(
                        access_port=False, addr=self.ADIV6_SELECT1_REG, data=select_high
                    )
                    logger.debug(f"Selected AP SELECT1 (upper address): 0x{select_high:08X}")
                self.coresight_reg_write_safe(
                    access_port=False, addr=self.ADIV6_SELECT_REG, data=select
                )
                logger.debug(f"Selected AP address: 0x{select:08X}")
            return
        if self.last_accessed_ap != addr & self.APSEL_APBANKSEL or DISABLE_AP_SELECT_CACHING:
            addr = addr & self.APSEL_APBANKSEL
            self.last_accessed_ap = addr
            self.coresight_reg_write_safe(access_port=False, addr=0x08, data=addr)
            logger.debug(
                f"Selected AP: {(self.last_accessed_ap & self.APSEL)>>self.APSEL_SHIFT}, "
                f"Bank: {hex((self.last_accessed_ap & self.APBANKSEL) >> self.APBANK_SHIFT)}"
            )

    def read_dp_idr(self) -> int:
        """Read Debug port identification register.

        :return: Debug port identification register value.
        """
        try:
            idr = self.coresight_reg_read_safe(access_port=False, addr=self.DP_IDR_REG)
        except SPSDKError:
            self.debug_access_status["dp_idr_ok"] = False
            raise
        self.debug_access_status["dp_idr_ok"] = True
        return idr

    # Human-readable labels for the ARM CoreSight specific debug_access_status gates,
    # extending the base DebugProbe.DEBUG_ACCESS_STATUS_LABELS (probe_connected,
    # dp_idr_ok). Order reflects the expected evaluation sequence: Debug Port power
    # domains -> Access Port -> DBGEN/SPIDEN signals -> core PPB -> AHB system bus ->
    # Debug Mailbox AP (only relevant for DAT-capable families).
    #
    # Each label pairs the technical name with a short plain-language explanation in
    # parentheses, so the diagnostic table is useful to users who are not ARM
    # CoreSight experts (e.g. field engineers debugging a "read via debug probe
    # failed" issue like SPSDK-7081/SPSDK-6704).
    DEBUG_ACCESS_STATUS_LABELS: dict[str, str] = {
        **DebugProbe.DEBUG_ACCESS_STATUS_LABELS,
        "dp_power_domains_ok": (
            "DP power domains up / CDBGPWRUPACK+CSYSPWRUPACK "
            "(target power supply and clocks are on)"
        ),
        "ap_idr_ok": (
            "Access Port IDR readable / MEM-AP found (a memory access channel to the chip exists)"
        ),
        "ap_dbgswenable": (
            "AP CSW.DbgSwEnable (core debug is enabled - DBGEN signal asserted on the chip)"
        ),
        "sda_dbgenctrl_written": (
            "SDA-AP DBGENCTRL written / GDBGEN+CDBGEN "
            "(secure debug authentication unlocked the debug paths)"
        ),
        "core_dhcsr_ok": ("Core PPB access / DHCSR readable (CPU debug registers are reachable)"),
        "ahb_system_bus_ok": (
            "System bus (AHB) access (the debug probe can read/write chip RAM/registers)"
        ),
        "dbgmlbx_ap_idr_ok": (
            "Debug Mailbox AP IDR valid (secure debug authentication channel is available)"
        ),
    }

    def get_not_applicable_debug_access_gates(self) -> set[str]:
        """Get CoreSight gate keys that can never apply to this family.

        The SDA-AP secure-debug-unlock gate (``sda_dbgenctrl_written``) and the
        Debug Mailbox AP gate (``dbgmlbx_ap_idr_ok``) are mutually exclusive at the
        device-database level: a family either sets ``dat.sub_features: [sda]``
        (SDA-AP) or ``dat.dmbox_ap_ix`` (Debug Mailbox), never both. The gate that
        does not apply to the current family is entirely omitted from the
        diagnostic table instead of being shown as a misleading "NOT TESTED".

        :return: Set of gate keys to omit for this probe's family. Empty when the
            family is unknown (no filtering possible) so the table falls back to
            showing every gate, as before.
        """
        not_applicable: set[str] = set()
        if self.family is None:
            # Family unknown - DB-driven mutual exclusivity cannot be determined,
            # show every gate rather than guessing.
            return not_applicable
        if not self.enable_sda_debug_paths_after_connect:
            not_applicable.add("sda_dbgenctrl_written")
        if self.dbgmlbx_ap_ix < 0:
            not_applicable.add("dbgmlbx_ap_idr_ok")
        return not_applicable

    def get_never_tested_debug_access_gates(self) -> set[str]:
        """Get CoreSight gate keys that will never be exercised due to a DB shortcut.

        When the device database pins a fixed MEM-AP index (``debug_probe.mem_ap_index``),
        the AP-scan loop in the ``get_mem_ap`` decorator is skipped entirely for
        performance, so ``ap_idr_ok`` and ``ap_dbgswenable`` are never actually
        exercised for this family. Unlike :meth:`get_not_applicable_debug_access_gates`
        (gates that are architecturally impossible), these gates *could* be tested
        but simply are not, by design, on this DB-configured shortcut path — the
        diagnostic table renders them as "N/A" rather than "NOT TESTED" to avoid
        implying a real test was skipped/failed.

        :return: Set of gate keys that are never exercised due to a fixed MEM-AP
            index. Empty when the MEM-AP index is auto-detected (normal AP scan).
        """
        return {"ap_idr_ok", "ap_dbgswenable"} if self.mem_ap_fixed_from_db else set()

    def _detect_adi_version(self) -> None:
        """Detect ARM Debug Interface version (ADIv5 vs ADIv6) from DP_IDR.

        Reads the DP_IDR register and extracts the DP version field (bits [15:12]).
        Sets self.adi_version to 5 for ADIv5 or 6 for ADIv6 (when DPVER == 3).

        :raises SPSDKError: If DP_IDR read fails.
        :raises SPSDKDebugProbeError: The detected ADI version is not supported by this
            debug probe (see ``SUPPORTED_VERSIONS``).
        """
        try:
            dp_idr = self.read_dp_idr()
            dp_version = (dp_idr & self.DPVER_MASK) >> self.DPVER_SHIFT
            if dp_version == self.DPVER_ADIv6:
                self.adi_version = 6
                logger.debug(f"Detected ADIv6 (DPv3): DP_IDR=0x{dp_idr:08X}")
                self.trace_cs_event(f"ADI version detected: ADIv6 (DPv3) DP_IDR=0x{dp_idr:08X}")
                self._detect_adiv6_addr_size()
            else:
                self.adi_version = 5
                logger.debug(
                    f"Detected ADIv5 (DPv{dp_version}): DP_IDR=0x{dp_idr:08X}, DPVER={dp_version}"
                )
                self.trace_cs_event(
                    f"ADI version detected: ADIv5 (DPv{dp_version}) DP_IDR=0x{dp_idr:08X}"
                )
        except SPSDKError as exc:
            logger.warning(f"Failed to detect ADI version: {exc}, defaulting to ADIv5")
            self.trace_cs_event(f"ADI version detection FAILED ({exc}), defaulting to ADIv5")
            self.adi_version = 5

        # Raised outside the try/except above: SPSDKDebugProbeError is a subclass of
        # SPSDKError, so raising it inside the try block would be swallowed by the
        # "default to ADIv5" fallback instead of being reported to the caller.
        if self.adi_version not in self.SUPPORTED_VERSIONS:
            supported = ", ".join(f"ADIv{version}" for version in self.SUPPORTED_VERSIONS)
            raise SPSDKDebugProbeError(
                f"Debug probe '{self.NAME}' does not support ADIv{self.adi_version} "
                f"targets. Supported ADI versions: {supported}. "
                f"Use a different debug probe or update the firmware of this probe "
                f"to support ADIv{self.adi_version}."
            )

    def _detect_adiv6_addr_size(self) -> None:
        """Detect the ADIv6 AP address size from DPIDR1.ASIZE.

        DPIDR1 is located in DP bank 1, so DPBANKSEL (SELECT bits [3:0]) must be set
        to 1 before reading DPIDR1 at offset 0x00, and restored to 0 afterwards.
        The ASIZE field (bits [6:0]) reports the DP address bus width in bits; when
        it exceeds 32, the SELECT1 register carries the upper AP address bits and
        64-bit AP addresses are used. On any error the size falls back to 32 bits.
        """
        try:
            # Switch to DP bank 1 to expose DPIDR1, then restore bank 0.
            self.coresight_reg_write_safe(access_port=False, addr=self.ADIV6_SELECT_REG, data=0x1)
            try:
                dpidr1 = self.coresight_reg_read_safe(access_port=False, addr=self.ADIV6_DPIDR1_REG)
            finally:
                self.coresight_reg_write_safe(
                    access_port=False, addr=self.ADIV6_SELECT_REG, data=0x0
                )
                self.last_accessed_ap = -1
            asize = dpidr1 & self.ADIV6_DPIDR1_ASIZE_MASK
            if asize:
                self.adiv6_addr_size = asize
            select1_used = self.adiv6_addr_size > self.ADIV6_ADDR_SIZE_32
            logger.debug(
                f"ADIv6 DPIDR1=0x{dpidr1:08X}, AP address size={self.adiv6_addr_size} bits "
                f"(SELECT1 {'used' if select1_used else 'not used'})"
            )
            self.trace_cs_event(
                f"ADIv6 AP address size={self.adiv6_addr_size} bits, "
                f"SELECT1 {'used' if select1_used else 'not used'} (DPIDR1=0x{dpidr1:08X})"
            )
        except SPSDKError as exc:
            logger.debug(f"Failed to detect ADIv6 address size: {exc}, defaulting to 32 bits")
            self.trace_cs_event(
                f"ADIv6 AP address size detection FAILED ({exc}), defaulting to 32 bits"
            )
            self.adiv6_addr_size = 32

    def _ap_idr_reg(self) -> int:
        """Return the AP IDR register offset for the detected ADI version.

        :return: 0xDFC for ADIv6 (APv2 IDR) or 0xFC for ADIv5 (APv1 IDR).
        """
        return self.AP_IDR_REG_ADIv6 if self.adi_version == 6 else self.AP_IDR_REG

    def _dbgmlbx_idr_address(self, adiv5_idr_offset: int) -> int:
        """Return the debug mailbox IDR register offset for the detected ADI version.

        :param adiv5_idr_offset: IDR offset used on ADIv5 (typically 0xFC).
        :return: 0xDFC for ADIv6 (APv2 IDR) or the provided ADIv5 offset otherwise.
        """
        return self.AP_IDR_REG_ADIv6 if self.adi_version == 6 else adiv5_idr_offset

    def _ap_scan_candidates(self, adiv5_indices: list[int]) -> list[tuple[int, int]]:
        """Return the AP scan domain for the detected ADI version.

        Each returned item is a (candidate, idr) pair, where 'candidate' is an AP
        index (ADIv5) or an AP base address (ADIv6), and 'idr' is the already-known
        AP IDR value or 0 when the IDR is not known yet. For ADIv5 the IDR is always
        0 (unknown, the caller must read it). For ADIv6 the APs are discovered by
        walking the CoreSight ROM table hierarchy, which reads the IDR anyway, so it
        is returned alongside the address to avoid a redundant read in the caller.
        The ADIv6 enumeration can be overridden by the 'adiv6_ap_addresses' option
        (comma-separated hex or decimal values); overridden entries have an unknown
        (0) IDR.

        :param adiv5_indices: Candidate AP indices used for ADIv5 scanning.
        :return: List of (candidate, idr) pairs to probe.
        """
        if self.adi_version != 6:
            return [(index, 0) for index in adiv5_indices]
        override = self.options.get("adiv6_ap_addresses")
        if override:
            return [(value_to_int(part), 0) for part in str(override).split(",") if part.strip()]
        return self._enumerate_adiv6_aps()

    def _read_dp_baseptr(self) -> int:
        """Read and validate the 64-bit ADIv6 ROM table base pointer from the DP.

        BASEPTR0 and BASEPTR1 are DP bank-switched registers: BASEPTR0 lives at
        DP register offset 0x0 in DP bank 2 and BASEPTR1 at offset 0x0 in DP bank 3
        (the same scheme DPIDR1 uses in bank 1). DPBANKSEL (SELECT bits [3:0]) must
        therefore be programmed to the target bank before reading offset 0x0, and
        restored to bank 0 afterwards. Reading a fixed offset 0x08/0x0C in bank 0
        instead returns the SELECT/RDBUFF readback, not the base pointer.

        BASEPTR0 bit0 is the valid flag; the combined address is 4KB aligned.
        BASEPTR1 (bits [63:32]) is only relevant when the DP address size > 32 bits.

        :return: 4KB-aligned root ROM table address, or -1 if BASEPTR is not valid.
        :raises SPSDKDebugProbeError: If the DP BASEPTR registers cannot be read.
        """
        try:
            # Select DP bank 2 to expose BASEPTR0 at offset 0x0.
            self.coresight_reg_write_safe(
                access_port=False,
                addr=self.ADIV6_SELECT_REG,
                data=self.ADIV6_DP_BASEPTR0_BANK,
            )
            baseptr_low = self.coresight_reg_read_safe(
                access_port=False, addr=self.ADIV6_DP_BASEPTR_REG
            )
            # Read BASEPTR1 (upper 32 bits) only when the AP address space exceeds
            # 32 bits; otherwise the whole base pointer fits in BASEPTR0.
            baseptr_high = 0
            if self.adiv6_addr_size > self.ADIV6_ADDR_SIZE_32:
                self.coresight_reg_write_safe(
                    access_port=False,
                    addr=self.ADIV6_SELECT_REG,
                    data=self.ADIV6_DP_BASEPTR1_BANK,
                )
                baseptr_high = self.coresight_reg_read_safe(
                    access_port=False, addr=self.ADIV6_DP_BASEPTR_REG
                )
        except SPSDKError as exc:
            raise SPSDKDebugProbeError(f"Failed to read ADIv6 DP BASEPTR registers: {exc}") from exc
        finally:
            # Always restore DP bank 0 and invalidate the AP-select cache.
            self.coresight_reg_write_safe(access_port=False, addr=self.ADIV6_SELECT_REG, data=0x0)
            self.last_accessed_ap = -1

        if not baseptr_low & self.ADIV6_BASEPTR_VALID_MASK:
            logger.debug("ADIv6 DP BASEPTR is not valid, no ROM table available")
            return -1

        baseptr = ((baseptr_high << 32) | baseptr_low) & self.ADIV6_BASEPTR_ADDR_MASK
        logger.debug(f"ADIv6 root ROM table base address: 0x{baseptr:X}")
        return baseptr

    def _adiv6_component_read(self, base_address: int, offset: int) -> int:
        """Read a CoreSight component register directly in the ADIv6 AP address space.

        On ADIv6 (CoreSight SoC-600 / DPv3) the ROM tables and AP register banks are
        directly addressable: the absolute address (component base + register offset)
        is programmed into DP SELECT (bits [31:4] via select_ap) and the low word
        offset bits [3:2] are carried by the AP transaction itself. This is a plain
        AP read, NOT the ADIv5 MEM-AP CSW/TAR/DRW memory indirection used by
        _mem_reg_read - applying that indirection here returns the SELECT/RDBUFF
        readback instead of the real component register value.

        :param base_address: 4KB-aligned base address of the CoreSight component.
        :param offset: Register offset within the component (e.g. 0xFF4 for CIDR1).
        :return: The 32-bit register value.
        :raises SPSDKDebugProbeTransferError: If the AP read fails.
        """
        return self.coresight_reg_read_safe(access_port=True, addr=base_address | offset)

    def _enumerate_adiv6_aps(self) -> list[tuple[int, int]]:
        """Enumerate ADIv6 APs by walking the CoreSight ROM tables.

        Reads the DP BASEPTR to locate the root ROM table, then recursively walks the
        ROM table hierarchy. Each present entry is resolved to an absolute component
        address; ROM tables are descended into and AP components (MEM-AP and the NXP
        Debug Mailbox AP) are collected together with their already-read IDR value.

        :return: List of (ap_base_address, ap_idr) pairs (may be empty).
        """
        root = self._read_dp_baseptr()
        if root < 0:
            logger.warning("ADIv6 ROM table enumeration skipped, no valid BASEPTR")
            return []

        found_aps: list[tuple[int, int]] = []
        visited: set[int] = set()
        self._scan_coresight_component(root, found_aps, visited, depth=0)
        logger.debug(
            f"ADIv6 enumeration found {len(found_aps)} AP(s): "
            f"{[(hex(addr), hex(idr)) for addr, idr in found_aps]}"
        )
        return found_aps

    def _scan_coresight_component(
        self, address: int, found_aps: list[tuple[int, int]], visited: set[int], depth: int
    ) -> None:
        """Identify a single CoreSight component and recurse into ROM tables.

        Reads CIDR1 to classify the component. ROM tables (class 0x1) are walked
        recursively; CoreSight components (class 0x9) are checked via their AP IDR
        (Debug Mailbox) or DEVTYPE/DEVARCH (MEM-AP) and, when identified as an AP,
        appended to the result list as an (address, idr) pair.

        :param address: 4KB-aligned base address of the component to inspect.
        :param found_aps: Accumulator list for discovered (address, idr) AP pairs.
        :param visited: Set of already-visited component addresses (loop guard).
        :param depth: Current recursion depth (bounded by ADIV6_MAX_ROM_DEPTH).
        """
        if depth > self.ADIV6_MAX_ROM_DEPTH:
            logger.debug(f"ADIv6 ROM walk depth limit reached at 0x{address:X}")
            return
        if address in visited:
            return
        visited.add(address)

        try:
            cidr1 = self._adiv6_component_read(address, self.CIDR1_OFFSET)
        except SPSDKError as exc:
            logger.debug(f"Failed to read CIDR1 at 0x{address:X}: {exc}")
            return

        comp_class = cidr1 & self.CIDR1_CLASS_MASK
        if comp_class == self.CIDR1_CLASS_ROM:
            # Legacy Class 0x1 ROM table.
            logger.debug(f"Walking ADIv6 (Class 1) ROM table at 0x{address:X}")
            self._walk_rom_table(address, found_aps, visited, depth)
        elif comp_class == self.CIDR1_CLASS_CORESIGHT:
            # A Class 0x9 CoreSight component is either a CoreSight SoC-600 ROM
            # table (DEVARCH ARCHID == 0xAF7) or an actual component/AP. Read
            # DEVARCH first so a Class 9 ROM table is descended into rather than
            # being mistaken for a leaf component (which would find no APs).
            try:
                devarch = self._adiv6_component_read(address, self.DEVARCH_OFFSET)
            except SPSDKError as exc:
                logger.debug(f"Failed to read DEVARCH at 0x{address:X}: {exc}")
                devarch = 0
            if (devarch & self.DEVARCH_ARCHID_MASK) == self.DEVARCH_CLASS9_ROM:
                logger.debug(f"Walking ADIv6 (Class 9) ROM table at 0x{address:X}")
                self._walk_rom_table(address, found_aps, visited, depth)
                return
            # Read the APv2 IDR once here; the value is stored with the address so
            # the caller does not have to read it again.
            try:
                ap_idr = self._adiv6_component_read(address, self.AP_IDR_REG_ADIv6)
            except SPSDKError as exc:
                logger.debug(f"Failed to read AP IDR at 0x{address:X}: {exc}")
                ap_idr = 0
            # Check the NXP Debug Mailbox AP first: it is identified by its known
            # APv2 IDR value rather than by the generic DEVTYPE/DEVARCH signature.
            if ap_idr == self.DBGMLBX_IDR_VALUE:
                logger.debug(f"Identified Debug Mailbox AP at 0x{address:X}")
                found_aps.append((address, ap_idr))
                return
            try:
                devtype = self._adiv6_component_read(address, self.DEVTYPE_OFFSET)
            except SPSDKError as exc:
                logger.debug(f"Failed to read DEVTYPE at 0x{address:X}: {exc}")
                return
            if (
                devtype == self.DEVTYPE_MEM_AP
                or (devarch & self.DEVARCH_ARCHID_MASK) == self.DEVARCH_MEM_AP
            ):
                logger.debug(f"Identified MEM-AP at 0x{address:X}")
                found_aps.append((address, ap_idr))

    def _walk_rom_table(
        self, base_address: int, found_aps: list[tuple[int, int]], visited: set[int], depth: int
    ) -> None:
        """Iterate the entries of a single ADIv6 ROM table.

        Reads consecutive 32-bit ROM entries until a terminating (zero) entry is
        found. Present entries are resolved to absolute addresses using the
        sign-extended 4KB-aligned relative offset and scanned recursively.

        :param base_address: Base address of the ROM table being walked.
        :param found_aps: Accumulator list for discovered MEM-AP base addresses.
        :param visited: Set of already-visited component addresses (loop guard).
        :param depth: Current recursion depth of the enclosing component scan.
        """
        entry_offset = 0x0
        while True:
            try:
                rom_entry = self._adiv6_component_read(base_address, entry_offset)
            except SPSDKError as exc:

                logger.debug(
                    f"Failed to read ROM entry at 0x{base_address:X}+0x{entry_offset:X}: {exc}"
                )
                return

            # A zero entry terminates the ROM table.
            if rom_entry == 0x0:
                break

            if rom_entry & self.ROM_ENTRY_PRESENT_MASK:
                relative_offset = rom_entry & self.ROM_ENTRY_OFFSET_MASK
                # Sign-extend the 32-bit relative offset (offsets may be negative).
                if relative_offset & self.ROM_ENTRY_SIGN_BIT:
                    relative_offset -= self.ROM_ENTRY_SIGN_EXTEND
                component_address = (base_address + relative_offset) & self.ADIV6_BASEPTR_ADDR_MASK
                self._scan_coresight_component(component_address, found_aps, visited, depth + 1)

            entry_offset += 4

    def recover_debug_connection(self) -> bool:
        """Recover debug connection using progressive recovery strategy.

        Implements ARM CoreSight best practices by attempting multiple recovery levels
        in sequence: soft recovery, power cycle recovery, probe reconnect recovery,
        and hard reset recovery. Each level is progressively more invasive.

        :return: True if recovery successful, False otherwise.
        """
        recovery_steps = [
            self._level1_soft_recovery,
            self._level2_power_cycle_recovery,
            self._level3_probe_reconnect_recovery,
            self._level4_hard_reset_recovery,
        ]

        for step_num, recovery_step in enumerate(recovery_steps, 1):
            logger.debug(f"Attempting recovery level {step_num}")
            try:
                if recovery_step():
                    logger.debug(f"Recovery successful at level {step_num}")
                    return True
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Recovery level {step_num} failed: {e}")
                continue

        logger.debug("Error: All recovery attempts failed")
        return False

    def _level1_soft_recovery(self) -> bool:
        """Clear sticky errors and verify basic DP access.

        Performs level 1 soft recovery by clearing all sticky error flags in the Debug Port,
        waiting for errors to clear, and verifying that the DP is responsive. This is a
        gentle recovery method that doesn't reset the target system.

        :return: True if recovery was successful and DP is accessible without errors,
                 False otherwise.
        """
        try:
            # Step 1: Read current DP CTRL/STAT
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            logger.debug(f"Current DP CTRL/STAT: 0x{ctrl_stat:08x}")

            # Step 2: Clear all sticky error flags
            self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)

            # Step 3: Wait for errors to clear
            sleep(0.01)

            # Step 4: Verify DP is responsive
            dp_idr = self.read_dp_idr()
            if dp_idr == 0 or dp_idr == 0xFFFFFFFF:
                return False

            # Step 5: Reset AP selection cache
            self.last_accessed_ap = -1

            # Step 6: Test basic DP access and read possible errors
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            return (ctrl_stat & self.DP_CTRL_STAT_ERROR_MASK) == 0

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Level 1 debug power recovery failed: {exc}")
            return False

    def _level2_power_cycle_recovery(self) -> bool:
        """Perform level 2 power cycle recovery for debug and system domains.

        This recovery method performs a complete power cycle sequence of both debug and system
        power domains to recover from communication errors. It includes proper sequencing,
        error clearing, and verification of successful power restoration.

        :return: True if power cycle recovery was successful and no errors remain, False otherwise.
        """
        try:
            # Step 1: Power down in correct sequence
            self._target_power_control(sys_power=False, debug_power=True)
            sleep(0.1)
            self._target_power_control(sys_power=False, debug_power=False)
            sleep(0.1)

            # Step 2: Clear any residual errors
            try:
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKDebugProbeTransferError:
                pass  # May fail if DP is not accessible

            # Step 3: Power up in correct sequence
            self._target_power_control(sys_power=False, debug_power=True)
            sleep(0.05)
            self._target_power_control(sys_power=True, debug_power=True)
            sleep(0.05)

            # Step 4: Verify power up successful
            ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
            power_ok = (ctrl_stat & self.CDBGPWRUPACK) and (ctrl_stat & self.CSYSPWRUPACK)

            if power_ok:
                self.last_accessed_ap = -1
                # Step 5: Test basic DP access and read possible errors
                ctrl_stat = self.coresight_reg_read(access_port=False, addr=self.DP_CTRL_STAT_REG)
                return (ctrl_stat & self.DP_CTRL_STAT_ERROR_MASK) == 0

            return False

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Level 2 power cycle recovery failed: {exc}")
            return False

    def _level3_probe_reconnect_recovery(self) -> bool:
        """Perform level 3 probe reconnection recovery procedure.

        This method attempts to recover a debug probe connection by performing a complete
        reconnection sequence including closing the current connection, reopening the probe,
        re-establishing target connection, and verifying basic functionality through DP IDR read.

        :return: True if reconnection was successful and probe is functional, False otherwise.
        """
        try:
            # Step 1: Close current connection
            self.close()
            sleep(0.2)

            # Step 2: Re-open probe
            self.open()
            sleep(0.1)

            # Step 3: Re-establish target connection
            self.connect()

            # Step 4: Verify basic functionality
            dp_idr = self.read_dp_idr()
            return dp_idr != 0 and dp_idr != 0xFFFFFFFF

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Level 3 probe reconnect recovery failed: {exc}")
            return False

    def _level4_hard_reset_recovery(self) -> bool:
        """Perform level 4 hardware reset recovery sequence.

        This method performs a complete hardware reset of the target chip to recover from
        severe debug connection issues. The reset sequence includes asserting the reset line,
        clearing debug errors, releasing reset, and re-establishing the debug connection.
        All target state including registers, RAM contents, and execution context will be lost.

        :return: True if hardware reset recovery was successful and debug connection was
                 re-established, False otherwise.
        """
        # Check if recovery reset is enabled
        if not self.options.get("enable_recovery_reset", False):
            logger.debug("Hardware reset recovery disabled by user option")
            return False

        logger.warning(
            "Performing hardware reset recovery - this will restart the target chip "
            "and all current state (registers, RAM contents, execution context) will be lost"
        )
        try:
            # Step 1: Assert reset while maintaining debug power
            self._target_power_control(sys_power=True, debug_power=True)
            self.assert_reset_line(True)
            sleep(0.1)

            # Step 2: Clear errors while in reset
            try:
                self.coresight_reg_write(access_port=False, addr=self.DP_ABORT_REG, data=0x1F)
            except SPSDKDebugProbeTransferError:
                pass

            # Step 3: Release reset
            self.assert_reset_line(False)
            sleep(0.1)  # Allow target to boot

            # Step 4: Re-establish debug connection
            self._target_power_control(sys_power=True, debug_power=True)

            # Step 5: Verify connection
            dp_idr = self.read_dp_idr()
            if dp_idr != 0 and dp_idr != 0xFFFFFFFF:
                self.last_accessed_ap = -1
                return True

            return False

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Level 4 hard reset recovery failed: {exc}")
            return False

    @get_mem_ap
    def debug_halt(self) -> None:
        """Halt the CPU execution.

        This method stops the CPU by writing to the Debug Halting Control and Status Register
        (DHCSR) with the appropriate debug key, halt, and debug enable flags.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_HALT | self.DHCSR_C_DEBUGEN),
        )

    @get_mem_ap
    def debug_resume(self) -> None:
        """Resume the CPU execution.

        This method clears the debug halt bit in the Debug Halting Control and Status Register
        (DHCSR) to allow the CPU to continue execution from its current state.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY),
        )

    @get_mem_ap
    def debug_step(self) -> None:
        """Step the CPU execution by one instruction.

        This method performs a single-step operation on the target CPU by writing
        to the Debug Halting Control and Status Register (DHCSR) with appropriate
        control bits to enable debug mode and execute one instruction.

        :raises SPSDKError: If the memory register write operation fails.
        """
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DHCSR_REG,
            data=(self.DHCSR_DEBUGKEY | self.DHCSR_C_STEP | self.DHCSR_C_DEBUGEN),
        )

    @get_mem_ap
    def is_cpu_halted(self) -> bool:
        """Check if ARM Cortex CPU is halted by reading DHCSR."""
        try:
            dhcsr = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=self.DHCSR_REG)
        except SPSDKError:
            self.debug_access_status["core_dhcsr_ok"] = False
            raise
        self.debug_access_status["core_dhcsr_ok"] = True
        is_halted = bool(dhcsr & self.DHCSR_S_HALT)
        logger.debug(f"CPU state: {'HALTED' if is_halted else 'RUNNING'} (DHCSR: 0x{dhcsr:08X})")
        return is_halted

    @get_mem_ap
    def write_core_register(self, reg_num: int, value: int) -> None:
        """Write a value into an ARM core register via DCRSR/DCRDR.

        The core must be halted for this transfer to have a defined effect (per the ARM
        debug architecture); this method does not halt the core implicitly.

        :param reg_num: Core register number (DCRSR REGSEL field), e.g. ``CORE_REG_PC``,
            ``CORE_REG_SP``. Numbering is fixed by the ARM debug architecture and is the
            same for every ARMv6-M/v7-M/v8-M Cortex-M core.
        :param value: 32-bit value to write into the register.
        :raises SPSDKError: If the memory register write operation fails.
        :raises SPSDKTimeoutError: If the transfer does not complete (S_REGRDY) in time.
        """
        self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=self.DCRDR_REG, data=value)
        self._mem_reg_write(
            mem_ap_ix=self.mem_ap_ix,
            addr=self.DCRSR_REG,
            data=(reg_num & 0x1F) | self.DCRSR_REGWNR,
        )
        self._wait_for_reg_transfer_done()

    @get_mem_ap
    def read_core_register(self, reg_num: int) -> int:
        """Read the value of an ARM core register via DCRSR/DCRDR.

        The core must be halted for this transfer to have a defined effect.

        :param reg_num: Core register number (DCRSR REGSEL field), e.g. ``CORE_REG_PC``.
        :return: 32-bit value of the register.
        :raises SPSDKError: If the memory register access fails.
        :raises SPSDKTimeoutError: If the transfer does not complete (S_REGRDY) in time.
        """
        self._mem_reg_write(mem_ap_ix=self.mem_ap_ix, addr=self.DCRSR_REG, data=reg_num & 0x1F)
        self._wait_for_reg_transfer_done()
        return self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=self.DCRDR_REG)

    def _wait_for_reg_transfer_done(self) -> None:
        """Poll DHCSR.S_REGRDY until the pending DCRSR core-register transfer completes.

        :raises SPSDKTimeoutError: If the transfer does not complete within the timeout.
        """
        timeout = Timeout(100, units="ms")
        while True:
            dhcsr = self._mem_reg_read(mem_ap_ix=self.mem_ap_ix, addr=self.DHCSR_REG)
            if dhcsr & self.DHCSR_S_REGRDY:
                return
            if timeout.overflow():
                raise SPSDKTimeoutError(
                    "Timed out waiting for DCRSR core-register transfer to complete "
                    f"(DHCSR: 0x{dhcsr:08X})."
                )

    def set_registers_and_resume(self, pc: int, sp: int) -> None:
        """Set the Program Counter and Stack Pointer, then resume core execution.

        This provides the generic "load binary into RAM, then jump to it" primitive used
        by e.g. the ``nxpdebugmbox tool execute`` CLI command: after the target binary has
        been written into RAM via :meth:`mem_block_write`, this halts the core if it is not
        already halted, sets SP/PC to the requested values, and resumes execution from
        there. Works identically on any Cortex-M based device, since DHCSR/DCRSR/DCRDR
        addresses and register numbering are fixed by the ARM debug architecture.

        :param pc: Value to set into the Program Counter (R15) - the execution start address.
        :param sp: Value to set into the Stack Pointer (R13) - the initial stack top.
        :raises SPSDKError: If any of the underlying register accesses fail.
        """
        if not self.is_cpu_halted():
            self.debug_halt()
        self.write_core_register(self.CORE_REG_SP, sp)
        self.write_core_register(self.CORE_REG_PC, pc)
        self.debug_resume()

    def __del__(self) -> None:
        """Clean up resources when the debug probe object is destroyed.

        This destructor method ensures proper cleanup by attempting to close the debug probe
        connection when the object is being garbage collected. It safely handles cases where
        the close method is not implemented by catching NotImplementedError.

        :raises NotImplementedError: When the close method is not implemented (handled internally).
        """
        try:
            self.close()
        except NotImplementedError:
            pass

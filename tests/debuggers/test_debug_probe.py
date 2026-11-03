#!/usr/bin/env python
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Probe interface testing module.

This module contains unit tests for the debug probe functionality,
validating the behavior of debug probe interfaces and their methods
in the SPSDK debuggers package.
"""

import re
import subprocess
import sys

import colorama
import pytest

import spsdk.debuggers.debug_probe as DP
import spsdk.debuggers.debug_probe_arm as DP_ARM
from spsdk.debuggers.utils import render_debug_access_status_table
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.family import FamilyRevision


class DummyCoreSightProbe(DP_ARM.DebugProbeCoreSightOnly):
    """Dummy CoreSight-only probe for non-hardware tests."""

    def __init__(self, hardware_id: str, options: dict | None = None) -> None:
        """Initialize dummy probe."""
        super().__init__(hardware_id, options)
        self.writes: list[tuple[bool, int, int]] = []

    @classmethod
    def get_connected_probes(
        cls, hardware_id: str | None = None, options: dict | None = None
    ) -> DP.DebugProbes:
        """Get connected probes."""
        return DP.DebugProbes()

    def open(self) -> None:
        """Open probe."""

    def connect(self) -> None:
        """Connect probe."""

    def close(self) -> None:
        """Close probe."""

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Read CoreSight register."""
        if not access_port and addr == self.DP_CTRL_STAT_REG:
            return self.CSYSPWRUPACK | self.CDBGPWRUPACK
        return 0

    def coresight_reg_write(self, access_port: bool = True, addr: int = 0, data: int = 0) -> None:
        """Write CoreSight register."""
        self.writes.append((access_port, addr, data))

    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line."""

    def read_dp_idr(self) -> int:
        """Read DP IDR."""
        return 0


class DummyBaseProbe(DP.DebugProbe):
    """Dummy minimal (non-ARM) probe implementing only the base DebugProbe API."""

    @classmethod
    def get_connected_probes(
        cls, hardware_id: str | None = None, options: dict | None = None
    ) -> DP.DebugProbes:
        """Get connected probes."""
        return DP.DebugProbes()

    def open(self) -> None:
        """Open probe."""

    def connect(self) -> None:
        """Connect probe."""

    def connect_safe(self) -> None:
        """Connect probe in a safe manner."""

    def close(self) -> None:
        """Close probe."""

    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox register."""
        return 0

    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox register."""

    def mem_reg_read(self, addr: int = 0, space: DP.MemorySpace = DP.MemorySpace.DATA) -> int:
        """Read memory register."""
        return 0

    def mem_reg_write(
        self, addr: int = 0, data: int = 0, space: DP.MemorySpace = DP.MemorySpace.DATA
    ) -> None:
        """Write memory register."""

    def mem_block_read(
        self, addr: int, size: int, space: DP.MemorySpace = DP.MemorySpace.DATA
    ) -> bytes:
        """Read a block of memory."""
        return bytes(size)

    def mem_block_write(
        self, addr: int, data: bytes, space: DP.MemorySpace = DP.MemorySpace.DATA
    ) -> None:
        """Write a block of memory."""

    def assert_reset_line(self, assert_reset: bool = False) -> None:
        """Control reset line."""

    def debug_halt(self) -> None:
        """Halt the CPU."""

    def debug_resume(self) -> None:
        """Resume the CPU."""

    def debug_step(self) -> None:
        """Step the CPU."""

    def is_cpu_halted(self) -> bool:
        """Check if the CPU is halted."""
        return False

    def read_dp_idr(self) -> int:
        """Read DP IDR."""
        return 0


def test_probe_ap_address() -> None:
    """Test Debug Probe AP address calculation functionality.

    Validates that the get_coresight_ap_address method correctly calculates
    CoreSight Access Port addresses from AP index and address offset parameters.
    Also verifies proper error handling for invalid input values.

    :raises SPSDKError: When invalid AP index or address parameters are provided.
    :raises ValueError: When parameter values are out of valid range.
    """
    probe = DummyCoreSightProbe("dummy")
    assert probe.get_coresight_ap_address(8, 8) == 0x08000008
    with pytest.raises((SPSDKError, ValueError)):
        assert probe.get_coresight_ap_address(256, 8) == 0xFF000008


def test_initialize_debug_port_clears_sticky_errors_and_powers_up() -> None:
    """Test debug port initialization clears sticky errors before power-up."""
    probe = DummyCoreSightProbe("dummy")

    probe.initialize_debug_port()

    assert probe.writes == [
        (False, probe.DP_ABORT_REG, 0x1F),
        (False, probe.DP_CTRL_STAT_REG, probe.CSYSPWRUPREQ | probe.CDBGPWRUPREQ | probe.MASKLANE),
    ]
    assert probe.last_accessed_ap == -1


def test_probe_options_are_not_mutated() -> None:
    """Test debug probe initialization doesn't mutate input options."""
    options = {"family": "lpc55s69", "revision": "latest", "test_address": 0x20000000}

    DummyCoreSightProbe("dummy", options)

    assert options == {"family": "lpc55s69", "revision": "latest", "test_address": 0x20000000}


def test_probe_protocol_options() -> None:
    """Test generic debug probe protocol option handling."""
    probe = DummyCoreSightProbe("dummy")
    assert probe.protocol == DP.DebugProbeProtocol.SWD
    assert probe.get_debug_probe_protocol() == DP.DebugProbeProtocol.SWD

    probe = DummyCoreSightProbe("dummy", {"protocol": "swd"})
    assert probe.protocol == DP.DebugProbeProtocol.SWD
    assert probe.get_debug_probe_protocol() == DP.DebugProbeProtocol.SWD

    probe = DummyCoreSightProbe("dummy", {"use_jtag": "1"})
    assert probe.protocol == DP.DebugProbeProtocol.JTAG

    with pytest.raises(DP.SPSDKDebugProbeError, match="does not support JTAG"):
        probe.get_debug_probe_protocol()


def test_probe_protocol_invalid_option() -> None:
    """Test invalid debug probe protocol option handling."""
    with pytest.raises(DP.SPSDKDebugProbeError, match="Unsupported debug probe protocol"):
        DummyCoreSightProbe("dummy", {"protocol": "invalid"})


def test_clear_sticky_errors_uses_selected_jtag_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test JTAG sticky-error clear uses the selected protocol option."""
    monkeypatch.setattr(
        DummyCoreSightProbe,
        "SUPPORTED_PROTOCOLS",
        (DP.DebugProbeProtocol.SWD, DP.DebugProbeProtocol.JTAG),
    )
    probe = DummyCoreSightProbe("dummy", {"protocol": "jtag"})

    probe.clear_sticky_errors()

    assert (False, 4, 0x50000F20) in probe.writes


def test_mcxe31b_mem_ap_settings_are_database_driven() -> None:
    """Test MCXE31B enables explicit MEM-AP behavior flags from database."""
    probe = DummyCoreSightProbe("dummy", {"family": "mcxe31b"})

    assert probe.family is not None
    assert probe.family.revision == "latest"
    assert probe.mem_ap_ix == 4
    assert probe.enable_power_domains_after_connect is True
    assert probe.enable_sda_debug_paths_after_connect is True
    assert probe.preserve_csw_ro_bits is True
    assert probe.mem_ap_scan_write_before_read is True


def test_mcxe32b_mem_ap_settings_inherit_from_mcxe31b() -> None:
    """Test MCXE32B inherits mem_ap_index=4 (M7_0 AHB-AP) from mcxe31b.

    MCXE32B is a dual-core part additionally exposing AP5 as the AHB-AP for
    the secondary core M7_1, but SPSDK always targets the primary core
    M7_0, so the whole MCX E3 family uses AP4 uniformly (SPSDK-7144).
    """
    probe = DummyCoreSightProbe("dummy", {"family": "mcxe32b"})

    assert probe.family is not None
    assert probe.mem_ap_ix == 4
    assert probe.enable_power_domains_after_connect is True
    assert probe.enable_sda_debug_paths_after_connect is True
    assert probe.preserve_csw_ro_bits is True
    assert probe.mem_ap_scan_write_before_read is True


def test_mcxe327_mem_ap_settings_inherit_from_mcxe31b() -> None:
    """Test MCXE327 inherits mem_ap_index=4 (M7_0 AHB-AP) from mcxe31b, for the
    same reason as mcxe32b (SPSDK-7144)."""
    probe = DummyCoreSightProbe("dummy", {"family": "mcxe327"})

    assert probe.family is not None
    assert probe.mem_ap_ix == 4
    assert probe.enable_power_domains_after_connect is True
    assert probe.enable_sda_debug_paths_after_connect is True
    assert probe.preserve_csw_ro_bits is True
    assert probe.mem_ap_scan_write_before_read is True


def test_fixed_mem_ap_is_preserved_after_recovery() -> None:
    """Test recovery preserves fixed MEM-AP index loaded from the database."""
    probe = DummyCoreSightProbe("dummy", {"family": "mcxe31b"})
    probe._target_power_control = (  # type: ignore[method-assign]  # pylint: disable=protected-access
        lambda sys_power=False, debug_power=False: None
    )

    assert probe._level2_power_cycle_recovery() is True  # pylint: disable=protected-access

    assert probe.mem_ap_ix == 4


def test_mcxn947_mem_ap_settings_keep_standard_behavior() -> None:
    """Test MCXN947 fixed MEM-AP does not enable MCXE31B-specific behavior."""
    probe = DummyCoreSightProbe("dummy", {"family": "mcxn947"})

    assert probe.family is not None
    assert probe.family.revision == "latest"
    assert probe.mem_ap_ix == 0
    assert probe.enable_power_domains_after_connect is False
    assert probe.enable_sda_debug_paths_after_connect is False
    assert probe.preserve_csw_ro_bits is False
    assert probe.mem_ap_scan_write_before_read is False


def test_debug_probe_only_family_does_not_require_dat() -> None:
    """Test debug_probe-only families do not require DAT configuration."""
    probe = DummyCoreSightProbe("dummy", {"family": "mimxrt1166"})

    assert probe.family is not None
    assert probe.mem_ap_ix == 0
    assert probe.dbgmlbx_ap_ix == -1


@pytest.mark.parametrize("family", ["lpc55s36", "lpc55s69"])
def test_lpc55sxx_mem_ap_settings_keep_standard_behavior(family: str) -> None:
    """Test LPC55Sxx fixed MEM-AP does not enable MCXE31B-specific behavior."""
    probe = DummyCoreSightProbe("dummy", {"family": family})

    assert probe.family is not None
    assert probe.family.revision == "latest"
    assert probe.mem_ap_ix == 0
    assert probe.enable_power_domains_after_connect is False
    assert probe.enable_sda_debug_paths_after_connect is False
    assert probe.preserve_csw_ro_bits is False
    assert probe.mem_ap_scan_write_before_read is False


class DummyMemApScanProbe(DummyCoreSightProbe):
    """Dummy probe for testing MEM-AP scan DHCSR restore behavior."""

    def __init__(self, hardware_id: str, options: dict | None = None) -> None:
        """Initialize dummy MEM-AP scan probe."""
        super().__init__(hardware_id, options)
        self.mem_writes: list[tuple[int, int, int]] = []

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Return MEM-AP IDR on AP0 so get_mem_ap() scan can select it."""
        ap0_idr_addr = self.get_coresight_ap_address(access_port=0, address=self.AP_IDR_REG)
        if access_port and addr == ap0_idr_addr:
            return 0x00010001
        return super().coresight_reg_read(access_port=access_port, addr=addr)

    def _mem_reg_read(self, mem_ap_ix: int, addr: int = 0) -> int:
        """Provide deterministic values for DHCSR and memory-read test points."""
        if addr == self.DHCSR_REG:
            return 0x12345678
        return 0

    def _mem_reg_write(self, mem_ap_ix: int, addr: int = 0, data: int = 0) -> None:
        """Capture raw memory writes performed by MEM-AP scan."""
        self.mem_writes.append((mem_ap_ix, addr, data))


def test_get_mem_ap_restores_dhcsr_with_debug_key() -> None:
    """Test MEM-AP scan restores DHCSR using DEBUGKEY and original low control bits."""
    probe = DummyMemApScanProbe("dummy")

    probe.mem_reg_read(0x20000000)

    assert (
        0,
        probe.DHCSR_REG,
        probe.DHCSR_DEBUGKEY | probe.DHCSR_C_HALT | probe.DHCSR_C_DEBUGEN,
    ) in probe.mem_writes
    assert (0, probe.DHCSR_REG, probe.DHCSR_DEBUGKEY | 0x5678) in probe.mem_writes


class DummyCoreRegisterProbe(DummyCoreSightProbe):
    """Dummy probe with a fixed MEM-AP and simulated DHCSR/DCRSR/DCRDR registers.

    Used to unit-test the DCRSR/DCRDR core-register transfer sequence
    (:meth:`write_core_register`/:meth:`read_core_register`) and the higher-level
    :meth:`set_registers_and_resume` primitive without any real hardware.
    """

    def __init__(self, hardware_id: str = "dummy") -> None:
        """Initialize dummy probe with mem_ap_ix pinned and S_REGRDY always set."""
        super().__init__(hardware_id)
        self.mem_ap_ix = 0
        self.mem_ap_fixed_from_db = True
        self.dcrdr_value = 0
        self.mem_reg_writes: list[tuple[int, int]] = []

    def _mem_reg_read(self, mem_ap_ix: int, addr: int = 0) -> int:
        """Simulate DHCSR (always ready) and DCRDR reads."""
        if addr == self.DHCSR_REG:
            return self.DHCSR_S_REGRDY
        if addr == self.DCRDR_REG:
            return self.dcrdr_value
        return 0

    def _mem_reg_write(self, mem_ap_ix: int, addr: int = 0, data: int = 0) -> None:
        """Capture DCRSR/DCRDR writes and update simulated DCRDR value."""
        self.mem_reg_writes.append((addr, data))
        if addr == self.DCRDR_REG:
            self.dcrdr_value = data


def test_write_core_register_writes_dcrdr_then_dcrsr_with_regwnr() -> None:
    """Test write_core_register() writes value to DCRDR, then REGSEL|REGWnR to DCRSR."""
    probe = DummyCoreRegisterProbe()

    probe.write_core_register(probe.CORE_REG_PC, 0x2000_1000)

    assert (probe.DCRDR_REG, 0x2000_1000) in probe.mem_reg_writes
    assert (
        probe.DCRSR_REG,
        probe.CORE_REG_PC | probe.DCRSR_REGWNR,
    ) in probe.mem_reg_writes
    # DCRDR must be written before DCRSR (order matters per ARM debug architecture).
    assert probe.mem_reg_writes.index((probe.DCRDR_REG, 0x2000_1000)) < probe.mem_reg_writes.index(
        (probe.DCRSR_REG, probe.CORE_REG_PC | probe.DCRSR_REGWNR)
    )


def test_read_core_register_writes_dcrsr_without_regwnr_and_reads_dcrdr() -> None:
    """Test read_core_register() selects the register via DCRSR (REGWnR=0) then reads DCRDR."""
    probe = DummyCoreRegisterProbe()
    probe.dcrdr_value = 0xDEAD_BEEF

    value = probe.read_core_register(probe.CORE_REG_SP)

    assert value == 0xDEAD_BEEF
    assert (probe.DCRSR_REG, probe.CORE_REG_SP) in probe.mem_reg_writes
    # REGWnR bit must be clear for a read selector write.
    for addr, data in probe.mem_reg_writes:
        if addr == probe.DCRSR_REG:
            assert data & probe.DCRSR_REGWNR == 0


def test_write_core_register_times_out_if_s_regrdy_never_set() -> None:
    """Test write_core_register() raises SPSDKTimeoutError if S_REGRDY never becomes set."""

    class NeverReadyProbe(DummyCoreRegisterProbe):
        """Fake probe whose DHCSR read never reports S_REGRDY as set."""

        def _mem_reg_read(self, mem_ap_ix: int, addr: int = 0) -> int:
            if addr == self.DHCSR_REG:
                return 0  # S_REGRDY never set
            return 0

    probe = NeverReadyProbe()
    with pytest.raises(SPSDKTimeoutError):
        probe.write_core_register(probe.CORE_REG_PC, 0x1000)


def test_set_registers_and_resume_halts_sets_sp_pc_then_resumes() -> None:
    """Test set_registers_and_resume() halts (if running), sets SP/PC, then resumes."""
    probe = DummyCoreRegisterProbe()
    halt_calls = []
    resume_calls = []
    probe.debug_halt = lambda: halt_calls.append(True)  # type: ignore[method-assign]
    probe.debug_resume = lambda: resume_calls.append(True)  # type: ignore[method-assign]
    probe.is_cpu_halted = lambda: False  # type: ignore[method-assign]

    probe.set_registers_and_resume(pc=0x2000_0100, sp=0x2004_0000)

    assert halt_calls == [True]
    assert resume_calls == [True]
    assert (probe.DCRDR_REG, 0x2004_0000) in probe.mem_reg_writes
    assert (probe.DCRDR_REG, 0x2000_0100) in probe.mem_reg_writes
    assert (probe.DCRSR_REG, probe.CORE_REG_SP | probe.DCRSR_REGWNR) in probe.mem_reg_writes
    assert (probe.DCRSR_REG, probe.CORE_REG_PC | probe.DCRSR_REGWNR) in probe.mem_reg_writes


def test_set_registers_and_resume_skips_halt_if_already_halted() -> None:
    """Test set_registers_and_resume() does not call debug_halt() if core is already halted."""
    probe = DummyCoreRegisterProbe()
    halt_calls = []
    probe.debug_halt = lambda: halt_calls.append(True)  # type: ignore[method-assign]
    probe.debug_resume = lambda: None  # type: ignore[method-assign]
    probe.is_cpu_halted = lambda: True  # type: ignore[method-assign]

    probe.set_registers_and_resume(pc=0x2000_0100, sp=0x2004_0000)

    assert halt_calls == []


class DummyDebugMailboxApProbe(DummyCoreSightProbe):
    """Dummy probe for testing debug mailbox AP validation."""

    def __init__(self, idr: int) -> None:
        """Initialize dummy debug mailbox AP probe."""
        super().__init__("dummy")
        self.dbgmlbx_ap_ix = 2
        self.idr = idr
        self.idr_reads = 0

    def coresight_reg_read(self, access_port: bool = True, addr: int = 0) -> int:
        """Return configured IDR on debug mailbox AP."""
        ap2_idr_addr = self.get_coresight_ap_address(access_port=2, address=self.AP_IDR_REG)
        if access_port and addr == ap2_idr_addr:
            self.idr_reads += 1
            return self.idr
        return super().coresight_reg_read(access_port=access_port, addr=addr)


def test_dbgmlbx_ap_fixed_index_is_validated_once() -> None:
    """Test fixed debug mailbox AP index is validated once before use."""
    probe = DummyDebugMailboxApProbe(idr=0x002A0000)

    probe.dbgmlbx_reg_read(0)
    probe.dbgmlbx_reg_read(0)

    assert probe.dbgmlbx_ap_validated is True
    assert probe.idr_reads == 1


def test_dbgmlbx_ap_fixed_index_invalid_idr_raises() -> None:
    """Test fixed debug mailbox AP index rejects unexpected IDR."""
    probe = DummyDebugMailboxApProbe(idr=0xDEADBEEF)

    with pytest.raises(SPSDKError, match="doesn't match the expected value"):
        probe.dbgmlbx_reg_read(0)


def test_debug_access_status_dict_exists_on_base_probe() -> None:
    """Test debug_access_status dict exists even for a plain (non-ARM) probe."""
    probe = DummyBaseProbe("dummy")

    assert probe.debug_access_status == {
        "probe_opened": None,
        "probe_connected": None,
        "dp_idr_ok": None,
    }
    assert set(DP.DebugProbe.DEBUG_ACCESS_STATUS_LABELS) == {
        "probe_opened",
        "probe_connected",
        "dp_idr_ok",
    }


def test_debug_access_status_table_default_all_not_tested() -> None:
    """Test the debug-access status table renders 'NOT TESTED' for an untouched probe."""
    probe = DummyCoreSightProbe("dummy")

    table = render_debug_access_status_table(probe)

    assert "NOT TESTED" in table
    assert "PASSED" not in table
    assert "FAILED" not in table
    for label in DP_ARM.DebugProbeCoreSightOnly.DEBUG_ACCESS_STATUS_LABELS.values():
        assert label in table


def test_debug_access_status_table_reflects_mixed_gate_results() -> None:
    """Test the debug-access status table reflects True/False/None gate results."""
    probe = DummyCoreSightProbe("dummy")
    probe.debug_access_status["probe_opened"] = True
    probe.debug_access_status["probe_connected"] = True
    probe.debug_access_status["dp_idr_ok"] = True
    probe.debug_access_status["dp_power_domains_ok"] = False
    probe.debug_access_status["ahb_system_bus_ok"] = False
    # ap_idr_ok, ap_dbgswenable, sda_dbgenctrl_written, core_dhcsr_ok remain None (not tested)

    table = render_debug_access_status_table(probe)

    assert "Debug probe opened" in table
    assert "Probe attached to target" in table
    assert "Debug Port IDR readable" in table
    assert "PASSED" in table
    assert "FAILED" in table
    assert "NOT TESTED" in table
    # Every configured gate key must be represented via its human-readable label.
    for key, label in DP_ARM.DebugProbeCoreSightOnly.DEBUG_ACCESS_STATUS_LABELS.items():
        assert label in table
        result = probe.debug_access_status[key]
        line = next(row for row in table.splitlines() if label in row)
        if result is True:
            assert "PASSED" in line
        elif result is False:
            assert "FAILED" in line
        else:
            assert "NOT TESTED" in line


def test_debug_access_status_table_row_colour_matches_status() -> None:
    """Test the whole row (index, gate label, status) is coloured, not just the status word.

    Regression scenario reported from real hardware: only the status word (PASSED/
    FAILED/NOT TESTED) had colour while the gate description stayed plain, which
    visually looked like the colour was "shifted" relative to the text it describes.
    The entire row must share one colour, and every cell must carry its own
    RESET_ALL so the colour never bleeds into the next row/border.
    """
    probe = DummyCoreSightProbe("dummy")
    probe.debug_access_status["probe_opened"] = True
    probe.debug_access_status["probe_connected"] = False
    # dp_idr_ok, and everything else, remains None -> NOT TESTED.

    table = render_debug_access_status_table(probe)
    lines = table.splitlines()

    opened_line = next(row for row in lines if "Debug probe opened" in row)
    connected_line = next(row for row in lines if "Probe attached to target" in row)
    dp_idr_line = next(row for row in lines if "Debug Port IDR readable" in row)

    # Three cells (#, Gate, Status) -> three colour/reset pairs per row.
    assert opened_line.count(colorama.Style.RESET_ALL) == 3
    assert connected_line.count(colorama.Style.RESET_ALL) == 3
    assert dp_idr_line.count(colorama.Style.RESET_ALL) == 3

    # The gate label itself (not just the status word) must be coloured to match.
    assert re.search(
        re.escape(colorama.Fore.GREEN)
        + r"Debug probe opened"
        + r".*"
        + re.escape(colorama.Fore.GREEN)
        + r"PASSED",
        opened_line,
    )
    assert re.search(
        re.escape(colorama.Fore.RED)
        + r"Probe attached to target"
        + r".*"
        + re.escape(colorama.Fore.RED)
        + r"FAILED",
        connected_line,
    )
    assert re.search(
        re.escape(colorama.Fore.LIGHTBLACK_EX)
        + r"Debug Port IDR readable"
        + r".*"
        + re.escape(colorama.Fore.LIGHTBLACK_EX)
        + r"NOT TESTED",
        dp_idr_line,
    )


def test_debug_access_status_table_probe_opened_ok_but_connect_failed() -> None:
    """Test the table shows PC<->probe OK but probe<->MCU attach FAILED (SWD cable unplugged).

    Regression scenario reported from real hardware (P&E Multilink): the probe opens fine
    over USB, but the SWD attach to the target MCU fails. The two gates must be reported
    independently - probe_opened=PASSED, probe_connected=FAILED - rather than being
    conflated into a single "probe connected" gate.
    """
    probe = DummyCoreSightProbe("dummy")
    probe.debug_access_status["probe_opened"] = True
    probe.debug_access_status["probe_connected"] = False
    # Everything downstream of the failed SWD/JTAG attach remains untested.

    table = render_debug_access_status_table(probe)
    lines = table.splitlines()

    opened_line = next(row for row in lines if "Debug probe opened" in row)
    connected_line = next(row for row in lines if "Probe attached to target" in row)
    dp_idr_line = next(row for row in lines if "Debug Port IDR readable" in row)

    assert "PASSED" in opened_line
    assert "FAILED" in connected_line
    assert "NOT TESTED" in dp_idr_line


def test_debug_access_status_table_depth_limits_gates() -> None:
    """Test the depth parameter limits the table to the first N gates."""
    probe = DummyCoreSightProbe("dummy")
    probe.debug_access_status["probe_opened"] = True
    probe.debug_access_status["probe_connected"] = True
    probe.debug_access_status["dp_idr_ok"] = True
    probe.debug_access_status["ahb_system_bus_ok"] = False

    table = render_debug_access_status_table(probe, depth=3)

    assert "Debug probe opened" in table
    assert "Probe attached to target" in table
    assert "Debug Port IDR readable" in table
    assert "System bus (AHB) access" not in table


def test_debug_access_status_table_omits_mutually_exclusive_gate() -> None:
    """Test the table omits the gate that cannot apply to this family's DAT variant.

    Regression scenario reported from real hardware (lpc55s69): the SDA-AP gate and
    the Debug Mailbox AP gate are mutually exclusive per device database (a family
    has ``dat.sub_features: [sda]`` XOR ``dat.dmbox_ap_ix``, never both), yet the
    table used to always show both, with the inapplicable one permanently stuck at
    "NOT TESTED". The gate that cannot apply to this family must be omitted
    entirely instead.
    """
    # lpc55s69-like family: has a Debug Mailbox AP, no SDA-AP.
    dmbox_probe = DummyCoreSightProbe("dummy")
    dmbox_probe.family = FamilyRevision("lpc55s69")
    dmbox_probe.enable_sda_debug_paths_after_connect = False
    dmbox_probe.dbgmlbx_ap_ix = 2

    table = render_debug_access_status_table(dmbox_probe)

    assert "SDA-AP DBGENCTRL written" not in table
    assert "Debug Mailbox AP IDR valid" in table

    # mcxe31b-like family: has an SDA-AP, no Debug Mailbox AP.
    sda_probe = DummyCoreSightProbe("dummy")
    sda_probe.family = FamilyRevision("lpc55s69")
    sda_probe.enable_sda_debug_paths_after_connect = True
    sda_probe.dbgmlbx_ap_ix = -1

    table = render_debug_access_status_table(sda_probe)

    assert "SDA-AP DBGENCTRL written" in table
    assert "Debug Mailbox AP IDR valid" not in table


def test_debug_access_status_table_marks_skipped_ap_scan_gates_as_not_applicable() -> None:
    """Test AP-scan gates render as N/A (not NOT TESTED) when the DB pins a fixed MEM-AP.

    Regression scenario reported from real hardware (lpc55s69, ``mem_ap_index: 0`` in the
    device database): the AP-scan loop that would set ``ap_idr_ok``/``ap_dbgswenable`` is
    skipped entirely for performance, so those gates are never actually exercised for this
    family - not because a test failed or was never run for some other reason, but because
    the DB shortcut makes exercising them structurally impossible. "N/A" communicates that
    distinction, whereas "NOT TESTED" would misleadingly suggest the test could still run.
    """
    probe = DummyCoreSightProbe("dummy")
    probe.mem_ap_fixed_from_db = True
    probe.debug_access_status["probe_opened"] = True
    probe.debug_access_status["probe_connected"] = True
    # ap_idr_ok / ap_dbgswenable remain None: never exercised due to the DB shortcut.

    table = render_debug_access_status_table(probe)
    lines = table.splitlines()

    ap_idr_line = next(row for row in lines if "Access Port IDR readable" in row)
    dbgswenable_line = next(row for row in lines if "AP CSW.DbgSwEnable" in row)

    assert "N/A" in ap_idr_line
    assert "NOT TESTED" not in ap_idr_line
    assert "N/A" in dbgswenable_line
    assert "NOT TESTED" not in dbgswenable_line

    # A regular AP-scan family (no fixed MEM-AP) must still show "NOT TESTED" for the
    # same untouched gates - the N/A treatment only applies to the DB-shortcut case.
    scanning_probe = DummyCoreSightProbe("dummy")
    scanning_probe.mem_ap_fixed_from_db = False

    scanning_table = render_debug_access_status_table(scanning_probe)
    scanning_ap_idr_line = next(
        row for row in scanning_table.splitlines() if "Access Port IDR readable" in row
    )
    assert "NOT TESTED" in scanning_ap_idr_line
    assert "N/A" not in scanning_ap_idr_line


@pytest.mark.parametrize(
    "module_name",
    [
        "spsdk.debuggers.debug_probe_arm",
        "spsdk.debuggers.debug_probe_dsc",
    ],
)
def test_direct_import_of_concrete_probe_module_does_not_raise(module_name: str) -> None:
    """Regression test for SPSDK-7185.

    Importing ``debug_probe_arm`` or ``debug_probe_dsc`` as the *first* SPSDK
    debuggers module used to raise ``ImportError`` due to a circular import:
    ``debug_probe.py`` eagerly re-imported both submodules at the bottom of the
    file (for backward-compatible re-exports), while each submodule imports
    base names from ``debug_probe`` at its own top. Whichever module got
    imported first was left partially initialized when the cycle closed.

    This must run in a fresh subprocess: within the *current* test process the
    modules are already fully imported and cached in ``sys.modules``, so the
    failure mode (import order dependent) would not be reproduced here.
    """
    result = subprocess.run(
        [sys.executable, "-c", f"import {module_name}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), f"import {module_name} failed as the first debuggers import:\n{result.stderr}"

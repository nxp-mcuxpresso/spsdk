#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Probe interface testing module.

This module contains unit tests for the debug probe functionality,
validating the behavior of debug probe interfaces and their methods
in the SPSDK debuggers package.
"""

import pytest

import spsdk.debuggers.debug_probe as DP
from spsdk.exceptions import SPSDKError


class DummyCoreSightProbe(DP.DebugProbeCoreSightOnly):
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


def test_probe_ap_address() -> None:
    """Test Debug Probe AP address calculation functionality.

    Validates that the get_coresight_ap_address method correctly calculates
    CoreSight Access Port addresses from AP index and address offset parameters.
    Also verifies proper error handling for invalid input values.

    :raises SPSDKError: When invalid AP index or address parameters are provided.
    :raises ValueError: When parameter values are out of valid range.
    """
    assert DP.DebugProbe.get_coresight_ap_address(8, 8) == 0x08000008
    with pytest.raises((SPSDKError, ValueError)):
        assert DP.DebugProbe.get_coresight_ap_address(256, 8) == 0xFF000008


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


def test_mcxe31b_mem_ap_settings_are_database_driven() -> None:
    """Test MCXE31B enables explicit MEM-AP behavior flags from database."""
    probe = DummyCoreSightProbe("dummy", {"family": "mcxe31b"})

    assert probe.family is not None
    assert probe.family.revision == "latest"
    assert probe.mem_ap_ix == 5
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

    assert probe.mem_ap_ix == 5


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

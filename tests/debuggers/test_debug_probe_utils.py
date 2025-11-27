#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK debug probe utilities functionality.

This module contains comprehensive test cases for debug probe discovery,
selection, and management utilities in the SPSDK debuggers package.
The tests cover both interactive and non-interactive probe selection modes,
error handling for missing or multiple probes, and probe connection utilities.
"""

from unittest.mock import patch

import pytest

import spsdk.debuggers.debug_probe as DP
from spsdk.debuggers.debug_probe import (
    DebugProbes,
    ProbeDescription,
    SPSDKMultipleProbesError,
    SPSDKProbeNotFoundError,
)
from spsdk.debuggers.utils import get_connected_probes, select_probe
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_debugprobes_discovery() -> None:
    """Test debug probe discovery functionality.

    Validates the discovery mechanism for debug probes by testing virtual probe
    detection with different configurations. Verifies that probes are correctly
    identified and filtered based on provided parameters.

    :raises AssertionError: When probe discovery or filtering doesn't work as expected.
    """
    probe_list = get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL)

    assert probe_list.pop().description == "Special virtual debug probe used for product testing"

    probe_list = get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL, {"exc": None})
    assert len(probe_list) == 0


def test_debugprobes_get_probe() -> None:
    """Test debug probe utilities get_probe functionality.

    Validates that get_connected_probes returns a proper probe list for virtual debug probes,
    verifies that select_probe can retrieve a DebugProbeVirtual instance, and ensures that
    calling get_probe with invalid parameters raises the expected SPSDKDebugProbeError exception.

    :raises SPSDKDebugProbeError: When get_probe is called with invalid parameters.
    """
    probe_list = get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL)

    probe = select_probe(probe_list).get_probe()
    assert isinstance(probe, DebugProbeVirtual)

    with pytest.raises(DP.SPSDKDebugProbeError):
        assert select_probe(probe_list).get_probe({"exc": None}) is None


def test_debugprobes_select_probe() -> None:
    """Test the debug probe selection functionality.

    Verifies that the select_probe function correctly handles empty probe lists
    by raising SPSDKProbeNotFoundError, and successfully selects a probe when
    one is available in the list. Tests both silent and non-silent modes.

    :raises SPSDKProbeNotFoundError: When no probes are available for selection.
    """
    probe_list = DebugProbes()

    with pytest.raises(SPSDKProbeNotFoundError):
        select_probe(probe_list, silent=True)

    with pytest.raises(SPSDKProbeNotFoundError):
        select_probe(probe_list, silent=False)

    probe_description = ProbeDescription(
        "virtual", DebugProbeVirtual.UNIQUE_SERIAL, "Virtual Probe", DebugProbeVirtual
    )
    probe_list.append(probe_description)

    assert select_probe(probe_list, silent=True) == probe_description
    assert select_probe(probe_list, silent=False) == probe_description


@patch("spsdk.debuggers.utils.SPSDK_INTERACTIVE_DISABLED", True)
def test_debugprobes_select_from_multiple_probes_non_interactive() -> None:
    """Test selection from multiple probes in non-interactive mode.

    Verifies that when multiple debug probes are available and no specific probe
    is selected, the select_probe function raises SPSDKMultipleProbesError in
    non-interactive mode. This test creates two virtual probes and expects the
    selection to fail with the appropriate exception.

    :raises SPSDKMultipleProbesError: When multiple probes are available without selection.
    """
    probe_list = DebugProbes()
    probe_list.append(
        ProbeDescription("virtual", "ABCDE12345", "Virtual Probe 01", DebugProbeVirtual)
    )
    probe_list.append(
        ProbeDescription("virtual", "ABCDE12346", "Virtual Probe 02", DebugProbeVirtual)
    )
    with pytest.raises(SPSDKMultipleProbesError):
        select_probe(probe_list)


def test_debugprobes_select_from_multiple_probes_interactive() -> None:
    """Test interactive selection of debug probes from multiple available probes.

    This test verifies the interactive probe selection functionality when multiple
    debug probes are available. It tests valid selections (indices 0 and 1) and
    invalid selection (index 2) to ensure proper error handling.

    :raises SPSDKProbeNotFoundError: When an invalid probe index is selected.
    """
    probe_list = DebugProbes()
    probe1 = ProbeDescription("virtual", "ABCDE12345", "Virtual Probe 01", DebugProbeVirtual)
    probe2 = ProbeDescription("virtual", "ABCDE12346", "Virtual Probe 02", DebugProbeVirtual)
    probe_list.extend([probe1, probe2])
    selected = select_probe(probe_list, input_func=lambda: "0")
    assert selected == probe1
    selected = select_probe(probe_list, input_func=lambda: "1")
    assert selected == probe2
    with pytest.raises(SPSDKProbeNotFoundError):
        select_probe(probe_list, input_func=lambda: "2")

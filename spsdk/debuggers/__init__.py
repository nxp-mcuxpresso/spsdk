#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK debugger interface wrappers.

Overview
--------

SPSDK communicates with NXP target devices through **debug probes** — physical
hardware adapters that connect a host PC to the chip's debug port (SWD or JTAG).
This package provides a hardware-independent abstraction layer so that the rest
of SPSDK never has to care which physical probe is plugged in or which
architecture is being debugged.

Architecture support
--------------------

Two fundamentally different architectures are supported, each requiring a
different low-level protocol:

**ARM Cortex-M / CoreSight** (module :mod:`spsdk.debuggers.debug_probe_arm`)
    NXP's mainstream Cortex-M portfolio (LPC, MCX, i.MX RT, …) exposes the
    standard ARM **CoreSight** debug architecture over SWD or JTAG.  Access to
    the CPU and its tightly-coupled memory is made through a chain of
    *Access Ports* (APs): a **MEM-AP** provides 32-bit load/store access to the
    AHB/AXI bus fabric, and an optional **Debug Mailbox AP** enables secure
    debug credential injection and RoT-authenticated debug sessions.

**DSC56800EX** (module :mod:`spsdk.debuggers.debug_probe_dsc`)
    NXP's *Digital Signal Controller* (DSC) family uses an entirely different
    on-chip debug engine called **OnCE** (On-Chip Emulation) accessed over
    JTAG.  The DSC Harvard architecture exposes *two separate memory buses* —
    the **X: DATA bus** for operand data and the **P: PROGRAM bus** for
    instruction words.  Reading or writing program-space flash/RAM requires
    explicit P: addressing; naive DATA-space reads would return garbage from
    the wrong address space.  :class:`~spsdk.debuggers.debug_probe.MemorySpace`
    selects which bus to use on every memory operation.

Plugin system
-------------

Physical probe support (J-Link, PyOCD, PE Micro, Lauterbach, MCU-Link) is
deliberately kept *outside* the SPSDK core as optional packages so that the
base installation stays lean.  Each plugin registers itself via the
``spsdk.debug_probe`` setuptools entry-point and is auto-discovered at run
time.  Custom probes can be created by deriving from
:class:`~spsdk.debuggers.debug_probe_arm.DebugProbeCoreSightOnly` (for ARM
targets) or :class:`~spsdk.debuggers.debug_probe_dsc.DebugProbeDsc` (for DSC
targets) and distributing a package with the appropriate entry-point metadata.
See ``examples/plugins/README.md`` for a step-by-step guide and Cookiecutter
templates.
"""

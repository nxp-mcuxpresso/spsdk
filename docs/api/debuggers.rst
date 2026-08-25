Debuggers API
=============

Architecture overview
---------------------

The ``spsdk.debuggers`` package provides a hardware-independent debug-probe
abstraction that is used by the rest of SPSDK to communicate with NXP target
devices.  The application code always calls the same API — open a probe, read
or write memory, exchange debug-mailbox commands — and the concrete probe
implementation handles all low-level protocol details.

A **debug probe** is any physical adapter that connects a host PC to a target
chip's debug port.  SPSDK represents this concept with the abstract base class
:class:`~spsdk.debuggers.debug_probe.DebugProbe`.  All higher-level features
(firmware signing, secure provisioning, fuse programming, authenticated debug)
are built on top of this single interface.

Two chip architectures are supported natively; each requires a completely
different low-level protocol.

ARM CoreSight probes
~~~~~~~~~~~~~~~~~~~~

All NXP **Cortex-M** devices (LPC55, MCX, i.MX RT, MIMXRT, …) implement
the ARM `CoreSight`_ debug architecture.  The debug port (DP) is exposed over
**SWD** (two-wire) or **JTAG** (four-wire) and acts as a gateway to a chain of
*Access Ports* (APs).

.. _CoreSight: https://developer.arm.com/documentation/ihi0029

Two APs are relevant for SPSDK:

``MEM-AP (AHB-AP / AXI-AP)``
    Provides 32-bit read/write access to every address on the chip's AHB or
    AXI bus fabric — SRAM, flash, and peripheral registers.  SPSDK
    automatically locates the correct MEM-AP index for each device from the
    device database, and configures the CSW (Control/Status Word) to match the
    hardware capabilities of the specific part (including a
    ``preserve_csw_ro_bits`` flag needed for some MCX variants that have
    hardware-managed CSW bits).

``Debug Mailbox AP``
    An NXP-proprietary AP implemented on LPC, MCX, and related families.  It
    provides a command/response channel used to:

    * Inject a **debug credential** certificate signed with the device's
      debug-authentication key, enabling fully authenticated debug on
      RoT-locked production parts.
    * Trigger an **ISP mode** entry without physical reset pins.
    * Initiate a device-level reset independently of the power rail.

    SPSDK auto-detects the Debug Mailbox AP by scanning the AP IDR chain at
    connection time.

The ARM implementation also handles the complete **debug port power-up /
power-down** lifecycle and implements four progressive **sticky-error recovery
levels** — ranging from a soft ABORT to a full hardware reset — so that
transient bus faults do not permanently stall provisioning scripts.

ARM access is handled by
:class:`~spsdk.debuggers.debug_probe_arm.DebugProbeCoreSightOnly`.  Only
``MemorySpace.DATA`` is valid; passing ``MemorySpace.PROGRAM`` raises
:class:`~spsdk.exceptions.SPSDKError` immediately.

DSC56800EX probes
~~~~~~~~~~~~~~~~~

NXP's **Digital Signal Controller** (DSC) family (MC56F8xx, MC56F81xx, …)
is built around the **DSC56800EX** core — a Harvard-architecture dual-MAC DSP
with an on-chip debug engine called **OnCE** (*On-Chip Emulation*), accessed
over JTAG.

The key difference from ARM is the **dual memory bus** (Harvard) architecture:

``X: DATA bus``
    Holds variables, stack, and peripheral registers.  Accesses are made using
    OnCE's ``DMOVX`` instruction, which performs a direct load/store to an
    absolute X: address.  Both 16-bit and 32-bit (two consecutive 16-bit)
    transfers are supported.

``P: PROGRAM bus``
    Holds executable code and constants stored in program flash.  The P: bus
    **is not reachable** via the same ``DMOVX`` path used for X: space — the
    same numerical address refers to a completely different physical location.
    To access P: memory, OnCE requires a dedicated sequence:

    1. Load the P: target address into core register **R3** using a
       ``move.l #addr, R3`` instruction (three 16-bit words: opcode ``0xE41B``
       followed by the high and low 16-bit halves of the address).
    2. Execute a ``move.w P:(R3), Y0`` or ``move.w Y0, P:(R3)`` to read or
       write the P: word through the program bus.

    This sequence is generated automatically by
    :class:`~spsdk.debuggers.debug_probe_dsc.DebugProbeDsc`; callers simply
    pass ``space=MemorySpace.PROGRAM``.

.. warning::

   Verifying freshly-programmed DSC flash by reading back using X: (DATA)
   addresses always returns data from a *different* memory than was just
   written.  Always use ``MemorySpace.PROGRAM`` for P: flash readback.

DSC devices may appear in **JTAG TAP chains** alongside other TAPs (e.g. an
ARM companion core or an on-board FPGA).  The
:class:`~spsdk.debuggers.debug_probe_dsc.TapConfig` dataclass captures the
IR/DR lengths, IDCODE, and the TAP-selection IR value.  The device database
(``database.yaml`` per chip) stores these values so no manual JTAG
configuration is needed.

Memory space selection
~~~~~~~~~~~~~~~~~~~~~~

The ``space`` parameter on every memory method accepts a
:class:`~spsdk.debuggers.debug_probe.MemorySpace` value:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - ``MemorySpace``
     - ARM
     - DSC
   * - ``DATA`` (default)
     - AHB/AXI via MEM-AP
     - OnCE ``DMOVX`` direct X: access; 16- and 32-bit word transfers
   * - ``PROGRAM``
     - *raises* ``SPSDKError``
     - OnCE R3-indirect P: sequence; 16-bit word transfers only

Plugin architecture
~~~~~~~~~~~~~~~~~~~

Physical probe drivers (J-Link, PyOCD, PE Micro, Lauterbach, MCU-Link) are
distributed as **optional plugin packages** so that the SPSDK base installation
stays lean.  Each plugin:

1. Derives from :class:`~spsdk.debuggers.debug_probe_arm.DebugProbeCoreSightOnly`
   (ARM targets) or :class:`~spsdk.debuggers.debug_probe_dsc.DebugProbeDsc`
   (DSC targets).
2. Sets ``NAME`` and ``ARCHITECTURE`` class variables (``"arm_cortex"`` or
   ``"dsc56800ex"``).)
3. Registers itself via the ``spsdk.debug_probe`` setuptools entry-point.

At run time, :func:`~spsdk.debuggers.utils.get_connected_probes` iterates all
registered entry-points, instantiates each probe class, and filters by
``ARCHITECTURE`` when the caller requests a specific architecture.

NXP-maintained plugin packages are available at
https://github.com/nxp-mcuxpresso/spsdk_plugins

To create a custom probe plugin use the Cookiecutter template at
``examples/plugins/templates/cookiecutter-spsdk-debug-probe-plugin.zip``.

----

API Reference
-------------

Package
~~~~~~~

.. automodule:: spsdk.debuggers


Base interface and infrastructure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: spsdk.debuggers.debug_probe
   :members:
   :special-members: DebugProbe
   :undoc-members:
   :show-inheritance:


ARM CoreSight probe
~~~~~~~~~~~~~~~~~~~

.. automodule:: spsdk.debuggers.debug_probe_arm
   :members:
   :undoc-members:
   :show-inheritance:


DSC56800EX probe
~~~~~~~~~~~~~~~~

.. automodule:: spsdk.debuggers.debug_probe_dsc
   :members:
   :undoc-members:
   :show-inheritance:


Probe utilities
~~~~~~~~~~~~~~~

.. automodule:: spsdk.debuggers.utils
   :members:
   :undoc-members:
   :show-inheritance:

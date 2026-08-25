#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DSC debug probe implementation.

Background — DSC56800EX debug architecture
------------------------------------------

NXP's **Digital Signal Controller** (DSC) family (MC56F8xx, MC56F81xx, …)
is built around the **DSC56800EX** core — a Harvard-architecture dual-MAC DSP
with a dedicated on-chip debug engine called **OnCE** (*On-Chip Emulation*).
OnCE is accessed over a standard four-wire **JTAG** TAP (Test Access Port) and
provides instruction-level control of the DSP core as well as direct access to
its memory buses.

The Harvard memory map
----------------------

The DSC56800EX core has **two completely independent address spaces**:

``X: DATA bus``
    Holds variables, stack, and peripheral registers.  Addressed in **16-bit
    words**; SPSDK also supports 32-bit (long-word) transfers by issuing two
    consecutive 16-bit operations.  This is the "normal" memory you access when
    reading or writing RAM/peripheral registers.

``P: PROGRAM bus``
    Holds executable code and read-only constants stored in program flash.
    Addressed in **16-bit words** using a *different* address range — address 0
    in P-space is *not* the same chip location as address 0 in X-space.
    Crucially, the P-bus **cannot be accessed by the standard data-move
    instructions** that OnCE uses for X-space; a special **R3-register-indirect
    move sequence** must be used instead.

Why this matters in practice
----------------------------

A common mistake when porting a flash programmer to DSC is to read back
freshly-written program flash using DATA-space addresses.  The readback
returns data from the X: space at the same *numerical* address — an entirely
different location — giving a false "verify OK" result.  SPSDK avoids this
by making the bus selection **explicit** on every memory operation through the
``space`` parameter (:class:`~spsdk.debuggers.debug_probe.MemorySpace`).

How OnCE memory access works
-----------------------------

DATA space (X:)
    OnCE's ``DMOVX`` instruction performs a direct load or store to an
    absolute X: address.  The address and data are shifted into the OnCE
    data register via JTAG DR-scan.

PROGRAM space (P:)
    OnCE does not have a ``DMOVP`` direct instruction.  The correct sequence
    is:

    1. Load the P: target address into core register **R3** using a
       ``move.l #addr, R3`` instruction (three 16-bit JTAG words):
       ``0xE41B`` followed by the high and low 16-bit halves of the address.
    2. Execute a ``move.w P:(R3), Y0`` or ``move.w Y0, P:(R3)`` to transfer
       the data word through the P: bus.

    This sequence is generated automatically by :class:`DebugProbeDsc`; callers
    simply pass ``space=MemorySpace.PROGRAM``.

JTAG TAP chain
--------------

DSC devices may be daisy-chained with other JTAG TAPs (e.g. a companion ARM
core on a multi-core SoC or an on-board FPGA).  :class:`TapConfig` captures
the IR length, DR length, IDCODE, and the custom select-TAP IR value needed to
route scans to the correct TAP.  The device database (``database.yaml``) stores
these values per chip so no manual JTAG configuration is needed.

Plugin development
------------------

To add support for a new physical JTAG adapter targeting DSC devices, derive
from :class:`DebugProbeDsc` and implement the low-level JTAG primitives.
Register the class via the ``spsdk.debug_probe`` setuptools entry-point.
See ``examples/plugins/README.md`` for a Cookiecutter template.
"""

import functools
from abc import abstractmethod
from dataclasses import dataclass
from time import sleep
from typing import Any, no_type_check

from spsdk import get_logger
from spsdk.debuggers.debug_probe import (
    DebugProbe,
    MemorySpace,
    SPSDKDebugProbeError,
    SPSDKDebugProbeNotOpenError,
)
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import get_db

logger = get_logger(__name__)


@dataclass
class TapConfig:
    """JTAG TAP (Test Access Port) configuration.

    This dataclass encapsulates the configuration parameters for a JTAG TAP,
    including register lengths, identification codes, and selection instructions.
    """

    ir_length: int
    dr_length: int
    id: int
    id_ir: int
    select_tap_ir: int
    tlm_select_id: int
    dtmcs_ir: int | None = None

    @classmethod
    def from_dict(cls, config: dict) -> "TapConfig":
        """Create TapConfig from dictionary.

        :param config: Dictionary containing TAP configuration parameters
        :return: TapConfig instance
        """
        return cls(
            ir_length=config["ir_length"],
            dr_length=config["dr_length"],
            id=config["id"],
            id_ir=config["id_ir"],
            select_tap_ir=config["select_tap_ir"],
            tlm_select_id=config["tlm_select_id"],
            dtmcs_ir=config.get("dtmcs_ir"),
        )


class DebugProbeDsc(DebugProbe):
    """SPSDK Debug Probe with DSC interface support.

    This class provides a debug probe implementation for DSC (Digital Signal Controller)
    based MCUs, extending the base DebugProbe class with DSC-specific register definitions
    and memory access patterns.

    :cvar NAME: Debug probe identifier name.
    :cvar ONCE_IR_EONCE: Core-TAP IR instruction to enable EOnCE register access (0x06).
    :cvar CORE_IR_DEBUG_REQUEST: Core-TAP IR instruction to halt the CPU (0x07).
    :cvar IDCODE_IR_INSTRUCTION: JTAG IR instruction to read chip IDCode.
    """

    ARCHITECTURE = "dsc56800ex"
    NAME = "base-dsc"

    # Core-TAP JTAG IR instructions (4-bit IR, per MC56F85xxx RM Section 9.3.3)
    ONCE_IR_EONCE = 0x06  # ENABLE_EOnCE - enables OnCE register access via DR
    CORE_IR_DEBUG_REQUEST = 0x07  # DEBUG_REQUEST - request core to enter debug mode (halt)
    CORE_IR_DEBUGREQ_TLMSEL = 0x09  # DEBUG_REQUEST + TLM_SELECT combined
    IDCODE_IR_INSTRUCTION = 0x02  # IDCode read instruction

    # TLM (Target Link Module) constants
    TLM_DR_LENGTH = 4  # TLM select data register is always 4 bits

    # OnCE command byte (shifted via DR when IR = ONCE_IR_EONCE)
    # OCMDR format per HAWKV2 Figure 11-4: [R/W(7)][GO(6)][EX(5)][RS4:RS0(4:0)]
    ONCE_CMD_NOP = 0x1F  # NOP - No register selected (RS=11111) for OSR polling
    ONCE_CMD_DR_LENGTH = 8  # OnCE command register DR width in bits
    ONCE_DATA_DR_LENGTH = 32  # OnCE data register DR width in bits

    # OnCE Status Register (OSR) bits - returned on TDO during OCMDR 8-bit shift
    ONCE_OSCR_DEBUG = 1 << 5  # Core is in debug (halted) mode (OS1:OS0 = 11)
    ONCE_OSCR_BUSY = 1 << 3  # Core is busy executing

    # OnCE Register Select addresses (RS field, bits [4:0] of command byte)
    # Per HAWKV2 Core User Guide Table 11-1
    # OCMDR format: [R/W(7)][GO(6)][EX(5)][RS4:RS0(4:0)]
    ONCE_RS_OCR = 1  # Control Register (8-bit)
    ONCE_RS_OSCNTR = 2  # Instruction Step Counter (24-bit)
    ONCE_RS_OSR = 3  # Status Register (16-bit, read-only)
    ONCE_RS_OPDBR = 4  # Program Data Bus Register (debug mode only, write)
    ONCE_RS_OBASE = 5  # Peripheral Base Address (8-bit, read-only)
    ONCE_RS_OTXRXSR = 6  # TX/RX Status and Control Register (8-bit)
    ONCE_RS_OTX = 7  # Transmit Register (32-bit, read by host)
    ONCE_RS_OTX1 = 9  # Transmit Register Upper Word (16-bit, read by host)
    ONCE_RS_ORX = 11  # Receive Register (32-bit, write by host)
    ONCE_RS_ORX1 = 13  # Receive Register Upper Word (16-bit, write by host)
    ONCE_RS_NOP = 31  # No Register Selected

    # OPDBR (Program Data Bus Register) width for single-word instruction injection
    ONCE_OPDBR_DR_LENGTH = 16  # 16 bits per instruction word (max 3 words = 48 bits)

    # OnCE command control flags (OCMDR bit positions per HAWKV2 Figure 11-4)
    ONCE_RW = 0x80  # Bit 7: R/W - 1=Read, 0=Write
    ONCE_GO = 0x40  # Bit 6: Execute instruction in OPDBR after register access
    ONCE_EX = 0x20  # Bit 5: Exit debug mode (when all RS bits also set)

    # DSC core instructions for OnCE memory access via OPDBR injection.
    # These are 16-bit instruction words injected into the core pipeline.
    DSC_NOP = 0xE9C0  # NOP - pipeline flush
    DSC_MOVE_ORX_R0 = 0xE78D  # MOVE.L OTXRX, R0 - OnCE RX -> R0 (32-bit)
    DSC_MOVE_ORX_Y0 = 0xE79D  # MOVE.L OTXRX, Y0 - OnCE RX -> Y0 (32-bit)
    DSC_MOVE_Y0_OTX = 0xE79E  # MOVE.L Y0, OTXRX - Y0 -> OnCE TX (32-bit)
    DSC_MOVE_L_XR0_Y0 = 0xF9A0  # MOVE.L X:(R0), Y0 - memory read: Y0 = mem[R0]
    DSC_MOVE_L_Y0_XR0 = 0xD9A0  # MOVE.L Y0, X:(R0) - memory write: mem[R0] = Y0
    DSC_MOVE_L_XR0P_Y0 = 0xF1A0  # MOVE.L X:(R0)+, Y0 - read with post-increment
    DSC_MOVE_L_Y0_XR0P = 0xD1A0  # MOVE.L Y0, X:(R0)+ - write with post-increment

    # DSC program bus (P: space) access instructions.
    # These use R3 as the address register and X0 as the data register.
    # References: coreTAP_EONCE_read_PMEM_memory_word / write_PMEM_memory_word in JTAG_Driver.c
    DSC_MOVE_L_IMM_R3 = 0xE41B  # MOVE.L #imm24, R3 — 3-word: (imm>>16, imm&0xFFFF, 0xE41B)
    DSC_MOVE_W_IMM_X0 = 0x8744  # MOVE.W #imm16, X0 — 2-word: (imm16, 0x8744)
    DSC_MOVE_W_PR3P_X0 = 0x846B  # MOVE.W P:(R3)+, X0 — program bus read (1-word)
    DSC_MOVE_W_X0_PR3P = 0x8463  # MOVE.W X0, P:(R3)+ — program bus write (1-word)
    # Save/restore helpers — 3-word instruction constants (H, M, L) for _once_exec_3word
    # MOVE.L R3, X:OTX  (save R3 to 32-bit OTX)   → _once_exec_3word(0xFFFF, 0xDB7D, 0xE37F)
    # MOVE.W X0, X:OTX1 (save X0 to 16-bit OTX1)  → _once_exec_3word(0xFFFF, 0xD47C, 0xE77F)
    DSC_SAVE_R3_H = 0xFFFF  # MSB extension for MOVE.L R3, X:OTX
    DSC_SAVE_R3_M = 0xDB7D  # Mid word for MOVE.L R3, X:OTX
    DSC_SAVE_R3_L = 0xE37F  # Opcode for MOVE.L R3, X:OTX
    DSC_SAVE_X0_H = 0xFFFF  # MSB extension for MOVE.W X0, X:OTX1
    DSC_SAVE_X0_M = 0xD47C  # Mid word for MOVE.W X0, X:OTX1
    DSC_SAVE_X0_L = 0xE77F  # Opcode for MOVE.W X0, X:OTX1

    # CHIP-TAG JTAG register lengths (used for IDCode read via CHIP-TAG)
    CHIP_TAP_IR_LENGTH = 8  # CHIP-TAG Instruction Register length in bits
    CHIP_TAP_DR_LENGTH = 32  # CHIP-TAG Data Register length in bits (IDCode)

    # DM-TAP (Debug Mailbox TAP) constants
    DMTAP_IR_LENGTH = 5  # DM-TAP Instruction Register length
    DMTAP_DMI_IR = 0x11  # DMI access instruction

    # DTMCS (Debug Transport Module Control and Status) register bits
    DTMCS_DMIRESET = 1 << 16  # DMI reset bit
    DTMCS_DMIHARDRESET = 1 << 17  # DMI hard reset bit
    DTMCS_RESET_MASK = DTMCS_DMIRESET | DTMCS_DMIHARDRESET  # Combined reset mask

    # DMI (Debug Module Interface) constants
    DMI_DR_LENGTH = 42  # 8-bit address + 32-bit data + 2-bit op
    DMI_OP_NOP = 0x0
    DMI_OP_READ = 0x1
    DMI_OP_WRITE = 0x2

    # Debug Mailbox register addresses (used in DMI)
    DM_CSW_REG = 0x00
    DM_REQUEST_REG = 0x04
    DM_RETURN_REG = 0x08
    DM_IDR_REG = 0xFC

    DEFAULT_TAP = "CHIP-TAG"

    # Default TAP configurations
    DEFAULT_TAPS = {
        "CHIP-TAG": TapConfig(
            ir_length=8,
            dr_length=4,
            id=0x86B5402B,
            id_ir=0x02,
            select_tap_ir=0x05,
            tlm_select_id=0x01,
        ),
        "DM-TAP": TapConfig(
            ir_length=5,
            dr_length=32,
            id=0x0838101D,
            id_ir=0x01,
            select_tap_ir=0x05,
            dtmcs_ir=0x10,
            tlm_select_id=0x08,
        ),
        "CORE0-TAP": TapConfig(
            ir_length=4,
            dr_length=32,
            id=0x61C0301D,
            id_ir=0x02,
            select_tap_ir=0x08,
            tlm_select_id=0x02,
        ),
        "CORE1-TAP": TapConfig(
            ir_length=4,
            dr_length=32,
            id=0x61C1301D,
            id_ir=0x02,
            select_tap_ir=0x08,
            tlm_select_id=0x04,
        ),
    }

    def __init__(self, hardware_id: str, options: dict | None = None) -> None:
        """Initialize debug probe with hardware ID and options.

        :param hardware_id: Hardware ID of the debug probe to open
        :param options: Optional dictionary with probe-specific configuration options
        """
        super().__init__(hardware_id, options)
        self.dbgmlbx_ap_ix = -1  # Debug mailbox AP index (-1 means not initialized)
        self.last_accessed_tap = "Unknown"
        self.dmi_selected = False  # Track if DMI IR is already selected

        self.taps: dict[str, TapConfig] = {}
        self._load_tap_configs()

    def _load_tap_configs(self) -> None:
        """Load TAP configurations from database or use defaults.

        This method attempts to load TAP configurations from the device database.
        If the family is not specified or database doesn't contain TAP configs,
        it falls back to the default configurations.
        """
        # Start with default configurations
        self.taps = self.DEFAULT_TAPS.copy()

        # Try to load from database if family is specified
        if self.family:
            try:
                db = get_db(self.family)
                # Try to get TAP configurations from database
                # The database path might be something like: debuggers.dsc.taps
                tap_configs = db.get_dict(DatabaseManager.DAT, "dsc_taps", default={})

                if tap_configs:
                    logger.debug(f"Loading TAP configurations from database for {self.family}")
                    for tap_name, tap_dict in tap_configs.items():
                        self.taps[tap_name] = TapConfig.from_dict(tap_dict)
                else:
                    logger.debug(
                        f"No TAP configurations in database for {self.family}, using defaults"
                    )

            except Exception as e:
                logger.debug(f"Could not load TAP configs from database: {e}, using defaults")

    @abstractmethod
    def write_ir(self, instruction: int, length: int) -> None:
        """Write to JTAG Instruction Register.

        This method writes an instruction value to the JTAG Instruction Register (IR)
        with the specified bit length.

        :param instruction: Instruction value to write to IR.
        :param length: Bit length of the instruction.
        :raises SPSDKDebugProbeError: If the IR write operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """

    @abstractmethod
    def write_dr(self, bitlength: int, data: bytearray) -> bytearray:
        """Write to and read from JTAG Data Register.

        This method writes data to the JTAG Data Register (DR) and returns the
        data shifted out during the operation.

        :param bitlength: Number of bits to shift through DR.
        :param data: Data buffer to write to DR.
        :return: Data read from DR during the shift operation.
        :raises SPSDKDebugProbeError: If the DR operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """

    @abstractmethod
    def jtag_init(self) -> None:
        """Get JTAG TAP controller into known state."""

    def connect_safe(self) -> None:
        """Debug probe connect in safe manner.

        Establishes communication with the DSC debug probe hardware in a safe manner
        with error recovery capabilities.

        :raises SPSDKError: When connection to debug probe fails.
        :raises SPSDKTimeoutError: When connection timeout occurs.
        """
        self.connect()

    @no_type_check
    # pylint: disable=no-self-argument
    def select_coretap(func: Any):
        """Decorator that ensures CORE0-TAP is selected before OnCE operations.

        For DSC architecture, this decorator switches the JTAG chain to CORE0-TAP
        via TLM before performing OnCE (On-Chip Emulation) operations like
        halt, resume, step, and status read.

        :param func: The function to be decorated that requires CORE0-TAP access.
        :raises SPSDKDebugProbeError: When CORE0-TAP cannot be accessed.
        :return: Decorated function wrapper.
        """

        @functools.wraps(func)
        def wrapper(self: "DebugProbeDsc", *args, **kwargs):
            self._select_tap(tap="CORE0-TAP")
            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    def _once_command(self, command: int) -> int:
        """Send an OnCE command via CORE0-TAP and return the OSCR status.

        Writes ENABLE_EOnCE IR instruction (0x06) to select EOnCE register
        interface, then shifts the 8-bit command byte into DR. The TDO output
        during the DR shift contains the OnCE OSCR value from previous state.

        :param command: OnCE command byte [EX][GO][RS4:0][RW].
        :return: OSCR value shifted out on TDO during the DR operation.
        :raises SPSDKDebugProbeError: If the OnCE command fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        core_tap = self.taps["CORE0-TAP"]
        self.write_ir(instruction=self.ONCE_IR_EONCE, length=core_tap.ir_length)
        cmd_data = self._int_to_bytearray(command, 1)
        response = self.write_dr(bitlength=self.ONCE_CMD_DR_LENGTH, data=cmd_data)
        return self._bytearray_to_int(response)

    def _once_write_reg(self, rs: int, data: int, go: bool = False, ex: bool = False) -> int:
        """Write 32-bit data to an OnCE register via two-phase DR protocol.

        The EOnCE uses a two-phase protocol with separate DR scans:
        Phase 1 (command): 8-bit DR scan sends command byte, TDO returns OSCR.
                           The OnCE controller latches the command at Update-DR.
        Phase 2 (data):    32-bit DR scan sends data to the addressed register.

        :param rs: OnCE register select value (ONCE_RS_* constant).
        :param data: 32-bit value to write into the register.
        :param go: If True, execute instruction in OPDBR after the write completes.
        :param ex: If True, exit debug mode after execution.
        :return: OSCR value captured during the command phase.
        :raises SPSDKDebugProbeError: If the OnCE register write fails.
        """
        cmd = rs | 0x00  # R/W=0 (write), RS in bits [4:0]
        if go:
            cmd |= self.ONCE_GO
        if ex:
            cmd |= self.ONCE_EX
        oscr = self._once_command(cmd)
        # Data phase: shift 32-bit data into the selected register (IR stays at ENABLE_EOnCE)
        self.write_dr(bitlength=self.ONCE_DATA_DR_LENGTH, data=self._int_to_bytearray(data, 4))
        return oscr

    def _once_read_reg(self, rs: int) -> tuple[int, int]:
        """Read 32-bit data from an OnCE register via two-phase DR protocol.

        The EOnCE uses a two-phase protocol with separate DR scans:
        Phase 1 (command): 8-bit DR scan sends command byte with RW=1 (read).
                           The OnCE controller latches the command at Update-DR
                           and captures the register value at next Capture-DR.
        Phase 2 (data):    32-bit DR scan reads data from the addressed register.

        :param rs: OnCE register select value (ONCE_RS_* constant).
        :return: Tuple of (oscr, data) where data is the 32-bit register value.
        :raises SPSDKDebugProbeError: If the OnCE register read fails.
        """
        cmd = rs | self.ONCE_RW  # R/W=1 (read), RS in bits [4:0]
        oscr = self._once_command(cmd)
        # Data phase: shift out 32-bit data from the selected register (IR stays at ENABLE_EOnCE)
        response = self.write_dr(bitlength=self.ONCE_DATA_DR_LENGTH, data=bytearray(4))
        return oscr, self._bytearray_to_int(response)

    def _once_exec(self, instruction: int) -> int:
        """Inject and execute a DSC instruction via OnCE OPDBR with GO flag.

        Writes a single 16-bit instruction word to the OPDBR register (RS=4)
        with GO bit set, causing the halted core to execute the instruction
        from the debug pipeline. Uses 16-bit DR shift per OPDBR specification.

        :param instruction: DSC machine code instruction word (16-bit).
        :return: OSCR value captured during the command phase.
        :raises SPSDKDebugProbeError: If the instruction injection fails.
        """
        cmd = self.ONCE_RS_OPDBR | self.ONCE_GO  # RS=4, GO=1, R/W=0 (write) → 0x44
        oscr = self._once_command(cmd)
        # Data phase: shift 16-bit instruction into OPDBR
        self.write_dr(
            bitlength=self.ONCE_OPDBR_DR_LENGTH,
            data=self._int_to_bytearray(instruction, 2),
        )
        return oscr

    def _once_write_opdbr_no_go(self, word: int) -> int:
        """Write a 16-bit word to OPDBR without GO flag (for multi-word instructions).

        Used to load extension words of multi-word DSC instructions into the
        pipeline before the final word triggers execution with GO.

        :param word: 16-bit instruction word to load into OPDBR.
        :return: OSCR value captured during the command phase.
        """
        cmd = self.ONCE_RS_OPDBR  # RS=4, GO=0, R/W=0 (write) → 0x04
        oscr = self._once_command(cmd)
        self.write_dr(
            bitlength=self.ONCE_OPDBR_DR_LENGTH,
            data=self._int_to_bytearray(word, 2),
        )
        return oscr

    def _once_exec_2word(self, h: int, lo: int) -> int:
        """Execute a 2-word DSC instruction via OPDBR.

        Loads words in program order: lo (opcode) first without GO,
        then h (extension word) with GO to trigger execution.

        Matches reference: coreTAP_EONCE_execute_2Word_instruction(H, L).
        Example: move.w #imm16, D1 → _once_exec_2word(imm16, 0x8753)

        :param h: Second instruction word (extension), loaded last WITH GO.
        :param lo: First instruction word (opcode), loaded first WITHOUT GO.
        :return: OSCR value from the final command phase.
        """
        self._once_write_opdbr_no_go(lo)
        return self._once_exec(h)

    def _once_exec_3word(self, h: int, m: int, lo: int) -> int:
        """Execute a 3-word DSC instruction via OPDBR.

        Loads words in program order: lo (opcode) first without GO,
        m (extension 1) second without GO, h (extension 2) last with GO.

        Matches reference: coreTAP_EONCE_execute_3Word_instruction(H, M, L).
        Example: move.w D1, x:0xFFFFFF → _once_exec_3word(0xFFFF, 0xD37C, 0xE77F)

        :param h: Third instruction word (last extension), loaded last WITH GO.
        :param m: Second instruction word (extension 1), loaded second WITHOUT GO.
        :param lo: First instruction word (opcode), loaded first WITHOUT GO.
        :return: OSCR value from the final command phase.
        """
        self._once_write_opdbr_no_go(lo)
        self._once_write_opdbr_no_go(m)
        return self._once_exec(h)

    def _once_read_reg_16(self, rs: int) -> tuple[int, int]:
        """Read 16-bit data from an OnCE register via two-phase DR protocol.

        Same as _once_read_reg but uses 16-bit data phase for registers like
        OTX1 (16-bit) and OSR (16-bit).

        :param rs: OnCE register select value (ONCE_RS_* constant).
        :return: Tuple of (oscr, data) where data is the 16-bit register value.
        """
        cmd = rs | self.ONCE_RW  # R/W=1 (read)
        oscr = self._once_command(cmd)
        response = self.write_dr(bitlength=16, data=bytearray(2))
        return oscr, self._bytearray_to_int(response) & 0xFFFF

    @staticmethod
    def _encode_move_xaddr_opcode(addr: int) -> int:
        """Encode upper address bits into opcode word for move.w x:<addr>,D1.

        DSC56800EX uses 24-bit data memory addressing. The upper 8 bits of
        the address are encoded into the first instruction word.
        Format: 1110_0BBB_0B11_AAAA where BBBBAAAA = addr[23:16].

        Based on reference JTAG_Driver.c encoding algorithm.

        :param addr: 24-bit data memory address (word-addressed).
        :return: 16-bit opcode word with encoded upper address bits.
        """
        upper = (addr >> 16) & 0xFF
        tmp_l = upper & 0x0F
        tmp_h = (upper & 0xF0) << 3
        if tmp_h & 0x0080:
            tmp_h |= 0x40
            tmp_h &= ~0x80
        return tmp_h | 0xE030 | tmp_l

    @select_coretap
    def debug_halt(self) -> None:
        """Halt the DSC CPU execution via Core-TAP DEBUGREQ_TLMSEL.

        Uses DEBUGREQ_TLMSEL (IR=0x09) which combines DEBUG_REQUEST with
        TLM_SELECT, ensuring the debug request is asserted during the full
        DR scan phase. The TLM DR value re-selects Core0-TAP to maintain
        the current TAP selection while the debug request is latched.

        :raises SPSDKDebugProbeError: If the halt operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        core_tap = self.taps["CORE0-TAP"]
        self.write_ir(instruction=self.CORE_IR_DEBUGREQ_TLMSEL, length=core_tap.ir_length)
        tlm_data = bytearray([core_tap.tlm_select_id])
        self.write_dr(bitlength=self.TLM_DR_LENGTH, data=tlm_data)
        sleep(0.01)

    @select_coretap
    def debug_resume(self) -> None:
        """Resume the DSC CPU execution via OnCE EX flag.

        Switches to CORE0-TAP and sends an OnCE NOP command with the EX (exit)
        flag set, which causes the core to leave debug mode and resume execution.

        :raises SPSDKDebugProbeError: If the resume operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        self._once_command(self.ONCE_EX | self.ONCE_CMD_NOP)
        sleep(0.01)

    @select_coretap
    def debug_step(self) -> None:
        """Step the DSC CPU by one instruction via OnCE.

        Switches to CORE0-TAP and sends an OnCE NOP command with EX and GO
        flags set, causing the core to execute one instruction and re-enter
        debug mode.

        :raises SPSDKDebugProbeError: When the debug step operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        self._once_command(self.ONCE_EX | self.ONCE_GO | self.ONCE_CMD_NOP)
        sleep(0.01)

    @select_coretap
    def is_cpu_halted(self) -> bool:
        """Check if DSC CPU is halted by reading OnCE status.

        Sends a NOP OnCE command and reads the OSCR value shifted out on TDO.
        The OSCR[DEBUG] bit indicates whether the core is in debug (halted) mode.

        :return: True if CPU is halted (in debug mode), False if running.
        :raises SPSDKDebugProbeError: If the status read fails.
        """
        oscr = self._once_command(self.ONCE_CMD_NOP)
        return bool(oscr & self.ONCE_OSCR_DEBUG)

    def read_dp_idr(self) -> int:
        """Read Debug port identification register.

        For DSC architecture, this reads the chip IDCode through the JTAG interface
        by writing instruction register (IR) value 2 with 8-bit length, then reading
        the 32-bit data register (DR) to retrieve the chip identification code.

        :return: Debug port identification register value (chip IDCode).
        :raises SPSDKDebugProbeError: If the IDCode read operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        try:
            # Write IR with IDCODE instruction (CHIP-TAG: 8-bit IR)
            self.write_ir(instruction=self.IDCODE_IR_INSTRUCTION, length=self.CHIP_TAP_IR_LENGTH)

            # Read DR with 32-bit length to get the chip IDCode
            data_buffer = bytearray(4)
            data_list = self.write_dr(bitlength=self.CHIP_TAP_DR_LENGTH, data=data_buffer)

            # Convert the returned data to integer (little-endian)
            value = int.from_bytes(data_list, "little")

            return value

        except AttributeError as exc:
            raise SPSDKDebugProbeNotOpenError(
                "Debug probe is not opened or write_ir/write_dr methods are not available"
            ) from exc
        except Exception as exc:
            raise SPSDKDebugProbeError(f"Failed to read DSC chip IDCode: {str(exc)}") from exc

    def _once_read_word(self, addr: int) -> int:
        """Read a single 16-bit word from DSC data memory.

        Uses move.w x:<addr>, D1 (3-word instruction with absolute addressing)
        followed by move.w D1, x:0xFFFFFF (write D1 to OTX1), then reads OTX1
        via JTAG. Caller must ensure D1 is saved/restored externally.

        Based on reference JTAG_Driver.c coreTAP_EONCE_read_memory_word().

        :param addr: 24-bit DSC data memory word address.
        :return: 16-bit word value.
        """
        opcode = self._encode_move_xaddr_opcode(addr)
        # move.w x:<addr>, D1 — read memory into D1
        self._once_exec_3word(addr & 0xFFFF, 0xF3FC, opcode)
        # move.w D1, x:0xFFFFFF — D1 → OTX1
        self._once_exec_3word(0xFFFF, 0xD37C, 0xE77F)
        # Read OTX1 via JTAG
        _, value = self._once_read_reg_16(self.ONCE_RS_OTX1)
        return value

    def _once_write_word(self, addr: int, data: int) -> None:
        """Write a single 16-bit word to DSC data memory.

        Uses move.w #imm16, D1 (2-word) to load the data, then
        move.w D1, x:<addr> (3-word) to write to memory.
        Caller must ensure D1 is saved/restored externally.

        Based on reference JTAG_Driver.c coreTAP_EONCE_write_memory_word().

        :param addr: 24-bit DSC data memory word address.
        :param data: 16-bit word value to write.
        """
        # move.w #data, D1 — load immediate into D1
        self._once_exec_2word(data & 0xFFFF, 0x8753)
        opcode = self._encode_move_xaddr_opcode(addr)
        # move.w D1, x:<addr> — D1 → memory
        self._once_exec_3word(addr & 0xFFFF, 0xD37C, opcode)

    def _once_read_pmem_word(self, addr: int) -> int:
        """Read a single 16-bit word from DSC program memory (P: space).

        Uses R3 as the address register and X0 as the data register:
          1. MOVE.L #addr, R3   — load 24-bit address into R3 (3-word instruction)
          2. MOVE.W P:(R3)+, X0 — read program bus word into X0 (1-word, post-increment unused)
          3. MOVE.W X0, X:OTX1  — transfer X0 to OTX1 for host read (3-word instruction)
          4. Read OTX1 via JTAG

        Caller must save/restore R3 and X0 externally before and after the loop.

        Based on reference JTAG_Driver.c coreTAP_EONCE_read_PMEM_memory_word().

        :param addr: 24-bit DSC program memory word address.
        :return: 16-bit word value read from program space.
        """
        # MOVE.L #addr, R3
        self._once_exec_3word(addr >> 16, addr & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
        # MOVE.W P:(R3)+, X0 — read program bus
        self._once_exec(self.DSC_MOVE_W_PR3P_X0)
        # MOVE.W X0, X:OTX1 — X0 → OTX1
        self._once_exec_3word(self.DSC_SAVE_X0_H, self.DSC_SAVE_X0_M, self.DSC_SAVE_X0_L)
        # Read OTX1 via JTAG
        _, value = self._once_read_reg_16(self.ONCE_RS_OTX1)
        return value

    def _once_write_pmem_word(self, addr: int, data: int) -> None:
        """Write a single 16-bit word to DSC program memory (P: space).

        Uses R3 as the address register and X0 as the data register:
          1. MOVE.W #data, X0   — load immediate 16-bit value into X0 (2-word instruction)
          2. MOVE.L #addr, R3   — load 24-bit address into R3 (3-word instruction)
          3. MOVE.W X0, P:(R3)+ — write X0 to program bus word address (1-word)

        Caller must save/restore R3 and X0 externally before and after the loop.

        Based on reference JTAG_Driver.c coreTAP_EONCE_write_PMEM_memory_word().

        :param addr: 24-bit DSC program memory word address.
        :param data: 16-bit word value to write.
        """
        # MOVE.W #data, X0 — load immediate into X0
        self._once_exec_2word(data & 0xFFFF, self.DSC_MOVE_W_IMM_X0)
        # MOVE.L #addr, R3
        self._once_exec_3word(addr >> 16, addr & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
        # MOVE.W X0, P:(R3)+ — write to program bus
        self._once_exec(self.DSC_MOVE_W_X0_PR3P)

    @select_coretap
    def mem_reg_read(self, addr: int = 0, space: MemorySpace = MemorySpace.DATA) -> int:
        """Read a value from DSC memory via OnCE instruction injection.

        Supports both DATA bus (X: space, 32-bit read as two 16-bit words) and
        PROGRAM bus (P: space, 16-bit read only — upper 16 bits of the return value
        are always zero for program space reads).

        DSC memory is 16-bit word-addressed. The address is used directly
        as a DSC word address (not byte-addressed).

        DATA space — uses the proven JTAG_Driver.c approach with D1 register and
        absolute addressing. Reads two consecutive 16-bit words at addr (low) and
        addr+1 (high). Instruction sequence:

          1. Save D1:        move.w D1, x:0xFFFFFF  →  read OTX1 via JTAG
          2. Read low word:  move.w x:<addr>, D1    →  move.w D1, x:0xFFFFFF  →  read OTX1
          3. Read high word: move.w x:<addr+1>, D1  →  move.w D1, x:0xFFFFFF  →  read OTX1
          4. Restore D1:     move.w #saved, D1

        PROGRAM space — uses R3-register-indirect addressing (16-bit word only):

          1. Save R3:  move.l R3, x:0xFFFFFF  →  read OTX via JTAG
          2. Save X0:  move.w X0, x:0xFFFFFF  →  read OTX1 via JTAG
          3. Load address:  move.l #addr, R3
          4. Read word:     move.w p:(R3+), X0  →  move.w X0, x:0xFFFFFF  →  read OTX1
          5. Restore R3 and X0

        :param addr: DSC memory word address (24-bit).
        :param space: Memory bus to access. Defaults to DATA for full backward compatibility.
        :return: The value read from memory (32-bit for DATA space, 16-bit for PROGRAM space).
        :raises SPSDKDebugProbeError: If the memory read operation fails.
        """
        if not self.is_cpu_halted():
            self.debug_halt()
            if not self.is_cpu_halted():
                raise SPSDKDebugProbeError("Failed to halt DSC CPU for memory read")

        if space == MemorySpace.DATA:
            # Save D1: move.w D1, x:0xFFFFFF (D1 → OTX1)
            self._once_exec_3word(0xFFFF, 0xD37C, 0xE77F)
            _, saved_d1 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            low_word = self._once_read_word(addr)
            high_word = self._once_read_word((addr + 1) & 0xFFFFFF)

            # Restore D1: move.w #saved_d1, D1
            self._once_exec_2word(saved_d1, 0x8753)

            result = (high_word << 16) | low_word
        else:
            # PROGRAM space: 16-bit access only; save R3 and X0
            self._once_exec_3word(self.DSC_SAVE_R3_H, self.DSC_SAVE_R3_M, self.DSC_SAVE_R3_L)
            _, saved_r3 = self._once_read_reg(self.ONCE_RS_OTX)
            self._once_exec_3word(self.DSC_SAVE_X0_H, self.DSC_SAVE_X0_M, self.DSC_SAVE_X0_L)
            _, saved_x0 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            result = self._once_read_pmem_word(addr)

            # Restore R3 and X0
            self._once_exec_3word(saved_r3 >> 16, saved_r3 & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
            self._once_exec_2word(saved_x0, self.DSC_MOVE_W_IMM_X0)

        logger.debug(f"Memory read [{space.label}]: addr=0x{addr:06X}, value=0x{result:08X}")
        return result

    @select_coretap
    def mem_reg_write(
        self, addr: int = 0, data: int = 0, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write a value to DSC memory via OnCE instruction injection.

        Supports both DATA bus (X: space, 32-bit write as two 16-bit words) and
        PROGRAM bus (P: space, 16-bit write only — only the lower 16 bits of data
        are written; upper bits are silently ignored for program space).

        DATA space — uses the proven JTAG_Driver.c approach with D1 register and
        absolute addressing. Writes two consecutive 16-bit words at addr (low) and
        addr+1 (high). Instruction sequence:

          1. Save D1:         move.w D1, x:0xFFFFFF  →  read OTX1 via JTAG  →  saved value
          2. Load low word:   move.w #low, D1
          3. Write low word:  move.w D1, x:<addr>
          4. Load high word:  move.w #high, D1
          5. Write high word: move.w D1, x:<addr+1>
          6. Restore D1:      move.w #saved, D1

        PROGRAM space — uses R3-register-indirect addressing (16-bit word only):

          1. Save R3:   move.l R3, x:0xFFFFFF  →  read OTX via JTAG
          2. Save X0:   move.w X0, x:0xFFFFFF  →  read OTX1 via JTAG
          3. Load address:  move.l #addr, R3
          4. Load word:     move.w #data, X0
          5. Write word:    move.w X0, p:(R3+)
          6. Restore R3 and X0

        :param addr: DSC memory word address (24-bit).
        :param data: Value to write (32-bit for DATA space; only lower 16 bits used for PROGRAM space).
        :param space: Memory bus to access. Defaults to DATA for full backward compatibility.
        :raises SPSDKDebugProbeError: If the memory write operation fails.
        """
        if not self.is_cpu_halted():
            self.debug_halt()
            if not self.is_cpu_halted():
                raise SPSDKDebugProbeError("Failed to halt DSC CPU for memory write")

        if space == MemorySpace.DATA:
            # Save D1: move.w D1, x:0xFFFFFF (D1 → OTX1)
            self._once_exec_3word(0xFFFF, 0xD37C, 0xE77F)
            _, saved_d1 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            self._once_write_word(addr, data & 0xFFFF)
            self._once_write_word((addr + 1) & 0xFFFFFF, (data >> 16) & 0xFFFF)

            # Restore D1: move.w #saved_d1, D1
            self._once_exec_2word(saved_d1, 0x8753)
        else:
            # PROGRAM space: 16-bit access only; upper bits of data are ignored
            if data & 0xFFFF0000:
                logger.warning(
                    f"mem_reg_write [program]: addr=0x{addr:06X} — upper 16 bits "
                    f"0x{(data >> 16) & 0xFFFF:04X} ignored (P: space is 16-bit only)"
                )
            # Save R3 and X0
            self._once_exec_3word(self.DSC_SAVE_R3_H, self.DSC_SAVE_R3_M, self.DSC_SAVE_R3_L)
            _, saved_r3 = self._once_read_reg(self.ONCE_RS_OTX)
            self._once_exec_3word(self.DSC_SAVE_X0_H, self.DSC_SAVE_X0_M, self.DSC_SAVE_X0_L)
            _, saved_x0 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            self._once_write_pmem_word(addr, data & 0xFFFF)

            # Restore R3 and X0
            self._once_exec_3word(saved_r3 >> 16, saved_r3 & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
            self._once_exec_2word(saved_x0, self.DSC_MOVE_W_IMM_X0)

        logger.debug(f"Memory write [{space.label}]: addr=0x{addr:06X}, data=0x{data:08X}")

    @select_coretap
    def mem_block_read(self, addr: int, size: int, space: MemorySpace = MemorySpace.DATA) -> bytes:
        """Read a block of memory from DSC memory via OnCE.

        Reads consecutive 16-bit words from the selected memory space.
        For DATA space (default) uses absolute D1 addressing.
        For PROGRAM space uses R3-indirect addressing (16-bit words only).

        :param addr: Starting DSC word address (24-bit).
        :param size: Number of bytes to read.
        :param space: Memory bus to access. Defaults to DATA for full backward compatibility.
        :return: The read data as a bytes object.
        :raises SPSDKDebugProbeError: If there's an error during the read operation.
        """
        if size == 0:
            return b""

        if not self.is_cpu_halted():
            self.debug_halt()
            if not self.is_cpu_halted():
                raise SPSDKDebugProbeError("Failed to halt DSC CPU for block read")

        # DSC: 1 word = 2 bytes
        num_words = (size + 1) // 2
        result = bytearray()

        if space == MemorySpace.DATA:
            # Save D1: move.w D1, x:0xFFFFFF (D1 → OTX1)
            self._once_exec_3word(0xFFFF, 0xD37C, 0xE77F)
            _, saved_d1 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            for i in range(num_words):
                word_addr = (addr + i) & 0xFFFFFF
                result.extend(self._once_read_word(word_addr).to_bytes(2, "little"))

            # Restore D1: move.w #saved_d1, D1
            self._once_exec_2word(saved_d1, 0x8753)
        else:
            # PROGRAM space: save R3 and X0 once, then loop
            self._once_exec_3word(self.DSC_SAVE_R3_H, self.DSC_SAVE_R3_M, self.DSC_SAVE_R3_L)
            _, saved_r3 = self._once_read_reg(self.ONCE_RS_OTX)
            self._once_exec_3word(self.DSC_SAVE_X0_H, self.DSC_SAVE_X0_M, self.DSC_SAVE_X0_L)
            _, saved_x0 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            for i in range(num_words):
                word_addr = (addr + i) & 0xFFFFFF
                result.extend(self._once_read_pmem_word(word_addr).to_bytes(2, "little"))

            # Restore R3 and X0
            self._once_exec_3word(saved_r3 >> 16, saved_r3 & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
            self._once_exec_2word(saved_x0, self.DSC_MOVE_W_IMM_X0)

        logger.debug(f"Block read [{space.label}]: addr=0x{addr:06X}, size={size}")
        return bytes(result[:size])

    @select_coretap
    def mem_block_write(
        self, addr: int, data: bytes, space: MemorySpace = MemorySpace.DATA
    ) -> None:
        """Write a block of memory to DSC memory via OnCE.

        Writes consecutive 16-bit words to the selected memory space.
        For DATA space (default) uses absolute D1 addressing.
        For PROGRAM space uses R3-indirect addressing (16-bit words only).

        :param addr: Starting DSC word address (24-bit).
        :param data: The data to be written, as a bytes object.
        :param space: Memory bus to access. Defaults to DATA for full backward compatibility.
        :raises SPSDKDebugProbeError: If there's an error during the write operation.
        """
        if len(data) == 0:
            return

        if not self.is_cpu_halted():
            self.debug_halt()
            if not self.is_cpu_halted():
                raise SPSDKDebugProbeError("Failed to halt DSC CPU for block write")

        # DSC: 1 word = 2 bytes; pad to word boundary if needed
        num_words = (len(data) + 1) // 2
        padded = bytearray(data)
        if len(padded) % 2:
            padded.append(0)

        if space == MemorySpace.DATA:
            # Save D1: move.w D1, x:0xFFFFFF (D1 → OTX1)
            self._once_exec_3word(0xFFFF, 0xD37C, 0xE77F)
            _, saved_d1 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            for i in range(num_words):
                word_addr = (addr + i) & 0xFFFFFF
                word = int.from_bytes(padded[i * 2 : i * 2 + 2], "little")
                self._once_write_word(word_addr, word)

            # Restore D1: move.w #saved_d1, D1
            self._once_exec_2word(saved_d1, 0x8753)
        else:
            # PROGRAM space: save R3 and X0 once, then loop
            self._once_exec_3word(self.DSC_SAVE_R3_H, self.DSC_SAVE_R3_M, self.DSC_SAVE_R3_L)
            _, saved_r3 = self._once_read_reg(self.ONCE_RS_OTX)
            self._once_exec_3word(self.DSC_SAVE_X0_H, self.DSC_SAVE_X0_M, self.DSC_SAVE_X0_L)
            _, saved_x0 = self._once_read_reg_16(self.ONCE_RS_OTX1)

            for i in range(num_words):
                word_addr = (addr + i) & 0xFFFFFF
                word = int.from_bytes(padded[i * 2 : i * 2 + 2], "little")
                self._once_write_pmem_word(word_addr, word)

            # Restore R3 and X0
            self._once_exec_3word(saved_r3 >> 16, saved_r3 & 0xFFFF, self.DSC_MOVE_L_IMM_R3)
            self._once_exec_2word(saved_x0, self.DSC_MOVE_W_IMM_X0)

        logger.debug(
            f"Block write [{space.label}]: addr=0x{addr:06X}, size={len(data)}, words={num_words}"
        )

    @abstractmethod
    def jtag_idle(self, num_cycles: int = 1) -> None:
        """Perform JTAG idle cycles.

        This method should be implemented by concrete probe classes to perform
        the specified number of JTAG idle (Run-Test/Idle) cycles.

        :param num_cycles: Number of idle cycles to perform
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """

    def _create_dmi_value(self, address: int, data: int, op: int) -> int:
        """Create a 42-bit DMI register value.

        DMI format: [address(8 bits)][data(32 bits)][op(2 bits)]

        :param address: 8-bit register address
        :param data: 32-bit data value
        :param op: 2-bit operation code (0=NOP, 1=READ, 2=WRITE)
        :return: 42-bit DMI value as integer
        """
        return ((address & 0xFF) << 34) | ((data & 0xFFFFFFFF) << 2) | (op & 0x3)

    def _parse_dmi_value(self, dmi_value: int) -> tuple[int, int, int]:
        """Parse a 42-bit DMI register value.

        :param dmi_value: 42-bit DMI value
        :return: Tuple of (address, data, op)
        """
        op = dmi_value & 0x3
        data = (dmi_value >> 2) & 0xFFFFFFFF
        address = (dmi_value >> 34) & 0xFF
        return address, data, op

    def _int_to_bytearray(self, value: int, num_bytes: int) -> bytearray:
        """Convert integer to little-endian bytearray.

        :param value: Integer value to convert
        :param num_bytes: Number of bytes in output
        :return: Little-endian bytearray
        """
        result = bytearray(num_bytes)
        for i in range(num_bytes):
            result[i] = (value >> (i * 8)) & 0xFF
        return result

    def _bytearray_to_int(self, data: bytearray) -> int:
        """Convert little-endian bytearray to integer.

        :param data: Bytearray to convert
        :return: Integer value
        """
        result = 0
        for i in range(len(data)):
            result |= data[i] << (i * 8)
        return result

    def _write_dmi(self, address: int, data: int, op: int) -> int:
        """Write to DMI register and return the data field.

        :param address: 8-bit register address
        :param data: 32-bit data to write
        :param op: Operation code (DMI_OP_READ, DMI_OP_WRITE, DMI_OP_NOP)
        :param select_ir: If True, select DMI IR first; if False, assume already selected
        :return: 32-bit data field from the DMI response
        :raises SPSDKDebugProbeError: If DMI operation fails
        """
        try:
            # Select DMI IR if needed
            if not self.dmi_selected:
                self.write_ir(instruction=self.DMTAP_DMI_IR, length=self.DMTAP_IR_LENGTH)
                self.dmi_selected = True

            # Create 42-bit DMI value
            dmi_input = self._create_dmi_value(address, data, op)

            # Convert to bytearray (6 bytes for 42 bits, little-endian)
            dmi_bytes = self._int_to_bytearray(dmi_input, 6)

            # Write DR and get response
            dmi_response_bytes = self.write_dr(bitlength=self.DMI_DR_LENGTH, data=dmi_bytes)

            # Convert response back to integer
            dmi_output = self._bytearray_to_int(dmi_response_bytes)

            # Parse and return data field
            _, response_data, op = self._parse_dmi_value(dmi_output)

            if op in (0x02, 0x03):
                logger.error(f"DMI operation error: OP=0x{op:02X}")
                self._recover_dmi(op)

            return response_data

        except Exception as exc:
            self.dmi_selected = False
            raise SPSDKDebugProbeError(f"DMI operation failed: {str(exc)}") from exc

    def _reset_dmi(self) -> None:
        """Reset DMI (Debug Module Interface) for debug mailbox access.

        This method resets the DMI by setting the DTMCS[dmireset] and DTMCS[dmihardreset] bits.
        This is required before accessing debug mailbox registers to ensure clean state.

        :raises SPSDKDebugProbeError: If DMI reset operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        self.dmi_selected = False
        try:
            # Get DM-TAP configuration
            dm_tap_config = self.taps["DM-TAP"]

            # Only reset if DTMCS IR is configured
            if dm_tap_config.dtmcs_ir is not None:
                # Shift DTMCS IR instruction
                self.write_ir(instruction=dm_tap_config.dtmcs_ir, length=dm_tap_config.ir_length)
                # Shift reset bits into DR (bit 16: dmireset, bit 17: dmihardreset)
                dr_data = self._int_to_bytearray(self.DTMCS_RESET_MASK, 4)
                self.write_dr(bitlength=dm_tap_config.dr_length, data=dr_data)

                logger.debug("DMI reset completed")
        except AttributeError as exc:
            raise SPSDKDebugProbeNotOpenError(
                "Debug probe is not opened or JTAG methods are not available"
            ) from exc
        except Exception as exc:
            raise SPSDKDebugProbeError(f"Failed to reset DMI: {str(exc)}") from exc

    def _recover_dmi(self, op: int) -> None:
        """Recover DMI from error state based on the OP code.

        Recovery strategy based on debug mailbox DTM behavior spec:

        OP=0x03 (stalled/busy):
          Caused by debugger reading RETURN before core writes it, or by
          CSW[RESYNCH_REQ] putting APB interface into reset state.
          Recovery: write 0x30000 to DTMCS register (dmireset + dmihardreset).

        OP=0x02 (overrun error):
          Caused by debugger writing REQUEST before core reads previous one
          (CSW[DBG_OR_ERR]), or core writing RETURN before debugger reads
          previous one (CSW[AHB_OR_ERR]).
          Recovery at DMI level: reset DMI via DTMCS. The DM-level recovery
          (CSW register manipulation) must be handled by the debug_mailbox layer.

        :param op: The DMI OP code that indicates the error type (0x02 or 0x03).
        :raises SPSDKDebugProbeError: If DMI recovery fails or OP=0x02 overrun detected.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        try:
            if op == 0x03:
                # OP=3: stalled read or RESYNCH_REQ caused APB reset
                # Clear by writing 0x30000 to DTMCS (dmireset + dmihardreset)
                logger.warning("DMI OP=0x03 (stalled). Resetting DMI via DTMCS.")
                self._reset_dmi()

            elif op == 0x02:
                # OP=2: overrun error (DBG_OR_ERR or AHB_OR_ERR)
                # Reset DMI transport layer only; DM-level recovery is not
                # the responsibility of the debug probe layer.
                logger.error("DMI OP=0x02 (overrun error). Resetting DMI via DTMCS.")
                self._reset_dmi()
                raise SPSDKDebugProbeError(
                    "DMI overrun error (OP=0x02). "
                    "DM-level recovery (CSW reset) must be handled by the caller."
                )

        except SPSDKDebugProbeError:
            raise
        except Exception as exc:
            raise SPSDKDebugProbeError(f"DMI recovery failed for OP=0x{op:02X}: {exc}") from exc

    def _select_tap(self, tap: str) -> bool:
        """Select DM-TAP (Debug Mailbox TAP) via TLM.

        This method switches the JTAG chain to access the Debug Mailbox TAP
        by writing to the TLM (Target Link Module). It uses caching to avoid
        redundant switching operations.

        :raises SPSDKDebugProbeError: If TLM switching fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        # Check if already switched to DM-TAP
        if self.last_accessed_tap == tap:
            logger.debug(f"Already switched to {tap}, skipping TLM switch")
            return False

        try:
            logger.debug(f"Switching TLM to {tap}")

            self.jtag_init()  # get the TAP into a known state

            # Write TLM IR instruction to select TLM access
            self.write_ir(
                instruction=self.taps[self.DEFAULT_TAP].select_tap_ir,
                length=self.taps[self.DEFAULT_TAP].ir_length,
            )

            # Write TLM DR to select DM-TAP (value = 0x08, 4 bits)
            tlm_data = bytearray([self.taps[tap].tlm_select_id])
            self.write_dr(bitlength=self.taps[self.DEFAULT_TAP].dr_length, data=tlm_data)

            # Read DM-TAP IDCODE to verify the switch was successful
            self.write_ir(instruction=self.taps[tap].id_ir, length=self.taps[tap].ir_length)

            # Read DR to get the IDCODE (32 bits)
            idcode_buffer = bytearray(4)
            idcode_data = self.write_dr(bitlength=self.taps[tap].dr_length, data=idcode_buffer)

            idcode_value = self._bytearray_to_int(idcode_data[:4])
            logger.debug(f"{tap} IDCODE: 0x{idcode_value:08X}")

            if idcode_value != self.taps[tap].id:
                raise SPSDKDebugProbeError(
                    f"Invalid {tap} IDCODE: 0x{idcode_value:08X}. "
                    f"TLM switch to {tap} may have failed."
                )

            self.last_accessed_tap = tap
            self.dmi_selected = False  # Reset DMI selection state
            logger.debug(f"Successfully switched to {tap}")
            return True

        except SPSDKDebugProbeError:
            self.last_accessed_tap = "Unknown"
            self.dmi_selected = False
            raise
        except Exception as exc:
            self.last_accessed_tap = "Unknown"
            self.dmi_selected = False
            raise SPSDKDebugProbeError(f"Failed to select DM-TAP: {str(exc)}") from exc

    @no_type_check
    # pylint: disable=no-self-argument
    def select_dmtap(func: Any):
        """Decorator function that secures getting the correct DEBUG MAILBOX AP for DSC.

        For DSC architecture, this decorator ensures that the DM-TAP (Debug Mailbox TAP)
        is properly selected and accessible before performing debug mailbox operations.

        :param func: The function to be decorated that requires debug mailbox access.
        :raises SPSDKError: When debug mailbox TAP cannot be accessed.
        :return: Decorated function wrapper.
        """

        @functools.wraps(func)
        def wrapper(self: "DebugProbeDsc", *args, **kwargs):
            """Wrapper function to ensure DM-TAP is accessible before execution.

            This decorator automatically verifies DM-TAP accessibility on first use
            by attempting to read the DM-TAP IDCode register.

            :param self: DebugProbeDsc instance
            :param args: Positional arguments passed to the wrapped function
            :param kwargs: Keyword arguments passed to the wrapped function
            :raises SPSDKDebugProbeError: When DM-TAP cannot be accessed
            :return: Result of the wrapped function execution
            """
            # Try to select DM-TAP connection, in case of fail method raise exception
            if self._select_tap(tap="DM-TAP"):

                # Reset DMI for debug mailbox access by setting DTMCS[dmihardreset] and DTMCS[dmireset] bits
                self._reset_dmi()

            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    @select_dmtap
    def dbgmlbx_reg_read(self, addr: int = 0) -> int:
        """Read debug mailbox access port register.

        This function reads a debug mailbox register through the DSC JTAG interface
        by accessing the DM-TAP (Debug Mailbox TAP) via DMI protocol.

        :param addr: The register address to read from (0x00=CSW, 0x04=REQUEST, 0x08=RETURN, 0xFC=ID)
        :return: The read value of addressed register (4 bytes).
        :raises SPSDKDebugProbeError: If the read operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        try:
            # Step 1: Issue read command to DMI
            self._write_dmi(address=addr, data=0, op=self.DMI_OP_READ)

            # Step 2: Required idle cycles
            self.jtag_idle(3)

            # Step 3: Read the result with NOP operation
            value = self._write_dmi(address=0, data=0, op=self.DMI_OP_NOP)

            logger.debug(f"Debug mailbox read: addr=0x{addr:02X}, value=0x{value:08X}")
            return value

        except AttributeError as exc:
            raise SPSDKDebugProbeNotOpenError(
                "Debug probe is not opened or JTAG methods are not available"
            ) from exc
        except SPSDKDebugProbeError:
            raise
        except Exception as exc:
            raise SPSDKDebugProbeError(
                f"Failed to read debug mailbox register at 0x{addr:02X}: {str(exc)}"
            ) from exc

    @select_dmtap
    def dbgmlbx_reg_write(self, addr: int = 0, data: int = 0) -> None:
        """Write debug mailbox access port register.

        Writes data to a specified register address in the debug mailbox through
        the DSC JTAG interface by accessing the DM-TAP via DMI protocol.

        :param addr: Register address to write to (0x00=CSW, 0x04=REQUEST, 0x08=RETURN, 0xFC=ID)
        :param data: Data value to write into the register.
        :raises SPSDKDebugProbeError: If the write operation fails.
        :raises SPSDKDebugProbeNotOpenError: If the debug probe is not opened.
        """
        try:
            # Issue write command to DMI
            self._write_dmi(address=addr, data=data, op=self.DMI_OP_WRITE)

            # Required idle cycles
            self.jtag_idle(3)

            logger.debug(f"Debug mailbox write: addr=0x{addr:02X}, data=0x{data:08X}")

        except AttributeError as exc:
            raise SPSDKDebugProbeNotOpenError(
                "Debug probe is not opened or JTAG methods are not available"
            ) from exc
        except SPSDKDebugProbeError:
            raise
        except Exception as exc:
            raise SPSDKDebugProbeError(
                f"Failed to write debug mailbox register at 0x{addr:02X}: {str(exc)}"
            ) from exc

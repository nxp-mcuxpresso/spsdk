#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""LPCProg Error codes."""
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# LPCProg Status Codes (Errors)
########################################################################################################################

# cspell:ignore EFRO EFRONoPower FAIM FAIMNoClock FAIMNoPower PDRUNCFG AHBCLKCTRL


class StatusCode(SpsdkEnum):
    """LPCProg status codes."""

    SUCCESS = (0x0, "Success", "Success")
    INVALID_COMMAND = (0x1, "InvalidCommand", "Invalid Command Error")
    SRC_ADDR_ERROR = (0x2, "SrcAddrError", "Source Address Error")
    DST_ADDR_ERROR = (0x3, "DstAddrError", "Destination Address Error")
    SRC_ADDR_NOT_MAPPED = (0x4, "SrcAddrNotMapped", "Source Address Not Mapped Error")
    DST_ADDR_NOT_MAPPED = (0x5, "DstAddrNotMapped", "Destination Address Not Mapped Error")
    COUNT_ERROR = (0x6, "CountError", "Count Error")
    INVALID_SECTOR_INVALID_PAGE = (0x7, "InvalidSectorInvalidPage", "Invalid Sector/Page Error")
    SECTOR_NOT_BLANK = (0x8, "SectorNotBlank", "Sector Not Blank Error")
    SECTOR_NOT_PREPARED_FOR_WRITE_OPERATION = (
        0x9,
        "SectorNotPreparedForWriteOperation",
        "Sector Not Prepared For Write Operation Error",
    )
    COMPARE_ERROR = (0xA, "CompareError", "Compare Error")
    BUSY = (0xB, "Busy", "Busy Error")
    PARAM_ERROR = (0xC, "ParamError", "Parameter Error")
    ADDR_ERROR = (0xD, "AddrError", "Address Error")
    ADDR_NOT_MAPPED = (0xE, "AddrNotMapped", "Address Not Mapped Error")
    CMD_LOCKED = (0xF, "CmdLocked", "Command Locked Error")
    INVALID_CODE = (0x10, "InvalidCode", "Invalid Code Error")
    INVALID_BAUD_RATE = (0x11, "InvalidBaudRate", "Invalid Baud Rate Error")
    INVALID_STOP_BIT = (0x12, "InvalidStopBit", "Invalid Stop Bit Error")
    CODE_READ_PROTECTION_ENABLED = (
        0x13,
        "CodeReadProtectionEnabled",
        "Code Read Protection Enabled Error",
    )
    RESERVED_1 = (0x14, "RESERVED1", "Reserved")
    USER_CODE_CHECKSUM = (0x15, "UserCodeChecksum", "User Code Checksum Error")
    RESERVED_2 = (0x16, "RESERVED2", "Reserved")
    EFRO_NO_POWER = (0x17, "EFRONoPower", "FRO not turned on in the PDRUNCFG register.")
    FLASH_NO_POWER = (0x18, "FlashNoPower", "Flash not turned on in the PDRUNCFG register.")
    RESERVED_3 = (0x19, "RESERVED3", "Reserved")
    RESERVED_4 = (0x1A, "RESERVED4", "Reserved")
    FLASH_NO_CLOCK = (0x1B, "FlashNoClock", "Flash clock disabled in the AHBCLKCTRL register.")
    REINVOKE_ISP_CONFIG = (0x1C, "ReinvokeISPConfig", "Re-invoke ISP Configuration Error")
    NO_VALID_IMAGE = (0x1D, "NoValidImage", "No Valid Image Error")
    FAIM_NO_POWER = (0x1E, "FAIMNoPower", "FAIM No Power Error")
    FAIM_NO_CLOCK = (0x1F, "FAIMNoClock", "FAIM No Clock Error")

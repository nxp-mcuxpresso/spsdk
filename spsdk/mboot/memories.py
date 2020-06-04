#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Various types of memory identifiers used in the MBoot module."""

from spsdk.utils.easy_enum import Enum


########################################################################################################################
# McuBoot External Memory ID
########################################################################################################################

class ExtMemId(Enum):
    """McuBoot External Memory Property Tags."""

    QUAD_SPI0 = (1, 'QSPI', 'Quad SPI Memory 0')
    IFR0 = (4, 'Nonvolatile information register 0 (only used by SB loader)')
    SEMC_NOR = (8, 'SEMC-NOR', 'SEMC NOR Memory')
    FLEX_SPI_NOR = (9, 'FLEX-SPI-NOR', 'Flex SPI NOR Memory')
    SPIFI_NOR = (10, 'SPIFI-NOR', 'SPIFI NOR Memory')
    FLASH_EXEC_ONLY = (16, 'FLASH-EXEC', 'Execute-Only region on internal Flash')
    SEMC_NAND = (256, 'SEMC-NAND', 'SEMC NAND Memory')
    SPI_NAND = (257, 'SPI-NAND', 'SPI NAND Memory')
    SPI_NOR_EEPROM = (272, 'SPI-MEM', 'SPI NOR/EEPROM Memory')
    I2C_NOR_EEPROM = (273, 'I2C-MEM', 'I2C NOR/EEPROM Memory')
    SD_CARD = (288, 'SD', 'eSD/SD/SDHC/SDXC Memory Card')
    MMC_CARD = (289, 'MMC', 'MMC/eMMC Memory Card')


########################################################################################################################
# McuBoot External Memory Property Tags
########################################################################################################################

class ExtMemPropTags(Enum):
    """McuBoot External Memory Property Tags."""

    INIT_STATUS = 0x00000000
    START_ADDRESS = 0x00000001
    SIZE_IN_KBYTES = 0x00000002
    PAGE_SIZE = 0x00000004
    SECTOR_SIZE = 0x00000008
    BLOCK_SIZE = 0x00000010

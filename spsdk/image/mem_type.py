#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP image memory type enum."""
from spsdk.utils.spsdk_enum import SpsdkEnum


class MemoryType(SpsdkEnum):
    """Bootable Image Memory Types."""

    FLEXSPI_RAM = (0, "flexspi_ram", "FlexSPI RAM")
    SEMC_SDRAM = (1, "semc_sdram", "SEMC SDRAM")
    INTERNAL = (2, "internal", "Internal memory")
    FLEXSPI_NAND = (3, "flexspi_nand", "Flexspi NAND")
    FLEXSPI_NOR = (4, "flexspi_nor", "Flexspi NOR")
    XSPI_NOR = (5, "xspi_nor", "XSPI NOR")
    SEMC_NOR = (6, "semc_nor", "SEMC NOR")
    SEMC_NAND = (7, "semc_nand", "SEMC NAND")
    SD = (8, "sd", "SD card")
    MMC = (9, "mmc", "MultiMediaCard")
    EMMC = (10, "emmc", "embedded MultiMediaCard")
    RECOVERY_SPI = (11, "recovery_spi", "Recovery SPI")
    RECOVERY_SPI_SB21 = (12, "recovery_spi_sb21", "Recovery SPI with SB21")
    RECOVERY_SPI_SB31 = (13, "recovery_spi_sb31", "Recovery SPI with SB31")
    RECOVERY_SPI_HAB = (14, "recovery_spi_hab", "Recovery SPI with HAB")
    RECOVERY_SPI_MBI = (15, "recovery_spi_mbi", "Recovery SPI with MBI")
    SERIAL_DOWNLOADER = (16, "serial_downloader", "Serial downloader")
    XSPI_RAM = (17, "xspi_ram", "XSPI RAM")

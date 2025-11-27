#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK LPC device management and configuration utilities.

This module provides the LPCDevice class for handling LPC microcontroller
device information, capabilities, and configuration within the SPSDK framework.
"""

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families


class LPCDevice:
    """LPC device representation for programming operations.

    This class provides an interface to LPC microcontroller devices, managing
    device-specific parameters such as flash memory layout, buffer configurations,
    and communication settings. It supports device identification through part IDs
    and retrieves configuration data from the SPSDK database.
    """

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize LPC device with specified family revision.

        :param family: Family revision of the LPC device to initialize.
        :raises SPSDKError: If the device family is not supported or database cannot be loaded.
        """
        self.features = get_db(family)

    @classmethod
    def from_part_id(cls, part_id: str) -> Self:
        """Create LPC device class from part ID.

        The method searches through all available LPC device families in the database
        to find a matching part ID and returns the corresponding device instance.

        :param part_id: Part ID string read from the ISP device.
        :raises SPSDKError: If the device with given part ID cannot be found in the database.
        :return: LPC device instance corresponding to the part ID.
        """
        devices = get_families(DatabaseManager.LPCPROG)
        for device in devices:
            part_ids = get_db(device).get_dict(DatabaseManager.LPCPROG, "part_ids")
            decoded_part_id = part_ids.get(part_id)
            if decoded_part_id:
                return cls(device)
        raise SPSDKError("Cannot find device from part ID")

    @property
    def buffer_address(self) -> int:
        """Get address of buffer for ISP communication.

        The method retrieves the buffer address from device features database,
        with a default fallback value if not specified in the database.

        :return: Buffer address for ISP communication operations.
        """
        return self.features.get_int(DatabaseManager.LPCPROG, "buffer_address", 0x1000_0800)

    @property
    def buffer_size(self) -> int:
        """Get the buffer size for ISP communication.

        The buffer size is retrieved from the device database configuration and defaults
        to 0x400 bytes if not specified.

        :return: Buffer size in bytes for ISP communication.
        """
        return self.features.get_int(DatabaseManager.LPCPROG, "buffer_size", 0x400)

    @property
    def sector_size(self) -> int:
        """Get the size of the flash sector.

        Retrieves the flash sector size from the device features database,
        with a default value of 0x400 bytes if not specified.

        :return: Flash sector size in bytes.
        """
        return self.features.get_int(DatabaseManager.LPCPROG, "sector_size", 0x400)

    @property
    def sector_count(self) -> int:
        """Get count of sectors in flash memory.

        Calculates the total number of sectors by dividing flash size by sector size.

        :return: Number of sectors in the flash memory.
        """
        return self.flash_size // self.sector_size

    @property
    def page_size(self) -> int:
        """Get the size of the flash page.

        The method retrieves the flash page size from the device features database,
        with a default value of 0x40 bytes if not specified.

        :return: Flash page size in bytes.
        """
        return self.features.get_int(DatabaseManager.LPCPROG, "page_size", 0x40)

    @property
    def ram_address(self) -> int:
        """Get the base address of RAM memory block.

        Retrieves the base address of the first RAM memory block instance from the device's
        memory map configuration.

        :return: Base address of the RAM memory block.
        """
        return self.features.device.info.memory_map.get_memory(
            block_name="ram", instance=0
        ).base_address

    @property
    def ram_size(self) -> int:
        """Get the size of RAM memory in bytes.

        :return: Size of RAM memory in bytes.
        """
        return self.features.device.info.memory_map.get_memory(block_name="ram", instance=0).size

    @property
    def flash_address(self) -> int:
        """Get base address of internal flash memory.

        :return: Base address of the internal flash memory block.
        :raises SPSDKError: If internal flash memory block is not found in memory map.
        """
        return self.features.device.info.memory_map.get_memory(
            block_name="internal-flash"
        ).base_address

    @property
    def flash_size(self) -> int:
        """Get the size of the flash memory.

        :return: Size of the flash memory in bytes.
        """
        return self.features.device.info.memory_map.get_memory(block_name="internal-flash").size

    def is_valid_address(self, address: int, size: int) -> bool:
        """Check if the given address and size lies within RAM or flash boundaries.

        The method validates whether a memory region defined by address and size
        falls completely within either the device's RAM or flash memory boundaries.

        :param address: Starting address of the memory region to validate.
        :param size: Size of the memory region in bytes.
        :return: True if the address range is valid (within RAM or flash), False otherwise.
        """
        return (
            address >= self.ram_address and (address + size) <= (self.ram_address + self.ram_size)
        ) or (
            address >= self.flash_address and address + size <= self.flash_address + self.flash_size
        )

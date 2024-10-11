#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""LPC device description."""

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_families


class LPCDevice:
    """Class representing LPC device."""

    def __init__(self, family: str = "lpc864", revision: str = "latest") -> None:
        """Constructor.

        :param family: family of LPC device, defaults to "lpc864"
        :param revision: revision of LPC device, defaults to "latest"
        """
        self.features = get_db(family, revision)

    @classmethod
    def from_part_id(cls, part_id: str) -> Self:
        """Create LPC device class from part ID.

        :param part_id: part ID read from the ISP
        :raises SPSDKError: If the device with given part ID cannot be found in the database
        :return: Self
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
        """Address of buffer for ISP communication."""
        return self.features.get_int(DatabaseManager.LPCPROG, "buffer_address", 0x1000_0800)

    @property
    def buffer_size(self) -> int:
        """Size of the buffer for ISP communication."""
        return self.features.get_int(DatabaseManager.LPCPROG, "buffer_size", 0x400)

    @property
    def sector_size(self) -> int:
        """Size of the flash sector."""
        return self.features.get_int(DatabaseManager.LPCPROG, "sector_size", 0x400)

    @property
    def sector_count(self) -> int:
        """Get count of sectors."""
        return self.flash_size // self.sector_size

    @property
    def page_size(self) -> int:
        """Size of the flash page."""
        return self.features.get_int(DatabaseManager.LPCPROG, "page_size", 0x40)

    @property
    def ram_address(self) -> int:
        """Base address of RAM."""
        return self.features.device.info.memory_map.get_memory(
            block_name="ram", instance=0
        ).base_address

    @property
    def ram_size(self) -> int:
        """Size of RAM."""
        return self.features.device.info.memory_map.get_memory(block_name="ram", instance=0).size

    @property
    def flash_address(self) -> int:
        """Base address of internal flash memory."""
        return self.features.device.info.memory_map.get_memory(
            block_name="internal-flash"
        ).base_address

    @property
    def flash_size(self) -> int:
        """Size of the flash memory."""
        return self.features.device.info.memory_map.get_memory(block_name="internal-flash").size

    def is_valid_address(self, address: int, size: int) -> bool:
        """Check if the given address and size lies within RAM or flash boundaries."""
        return (
            address >= self.ram_address and (address + size) <= (self.ram_address + self.ram_size)
        ) or (
            address >= self.flash_address and address + size <= self.flash_address + self.flash_size
        )

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module for blhost application."""

import math
from typing import List, NamedTuple

import bincopy

from spsdk import SPSDKError
from spsdk.mboot.commands import KeyProvUserKeyType

PROPERTIES_NAMES = {
    "list-properties": 0,
    "current-version": 1,
    "available-peripherals": 2,
    "flash-start-address": 3,
    "flash-size-in-bytes": 4,
    "flash-sector-size": 5,
    "flash-block-count": 6,
    "available-commands": 7,
    "check-status": 8,
    "reserved": 9,
    "verify-writes": 10,
    "max-packet-size": 11,
    "reserved-regions": 12,
    "reserved": 13,
    "ram-start-address": 14,
    "ram-size-in-bytes": 15,
    "system-device-id": 16,
    "security-state": 17,
    "unique-device-id": 18,
    "flash-fac-support": 19,
    "flash-access-segment-size": 20,
    "flash-access-segment-count": 21,
    "flash-read-margin": 22,
    "qspi/otfad-init-status": 23,
    "target-version": 24,
    "external-memory-attributes": 25,
    "reliable-update-status": 26,
    "flash-page-size": 27,
    "irq-notify-pin": 28,
    "pfr-keystore_update-opt": 29,
}


def parse_property_tag(property_tag: str) -> int:
    """Convert the property as name or stringified number into integer.

    :param property_tag: Name or number of the property tag
    :return: Property integer tag
    """
    try:
        return int(property_tag, 0)
    except:
        return PROPERTIES_NAMES.get(property_tag, 0xFF)


def parse_key_prov_key_type(key_type: str) -> int:
    """Convert the key type as name or stringified number into integer.

    :param key_type: Name or number of the Key type
    :return: key type number
    """
    try:
        return int(key_type, 0)
    except:
        key_type = key_type.upper()
        key_type_int = KeyProvUserKeyType.get(key_type, 0xFF)
        assert isinstance(key_type_int, int)
        return key_type_int

class SegmentInfo():
    """SegmentInfo class containing: start, length and data of segment."""
    ALIGNMENT = 1024

    def __init__(self, start: int, length: int, data_bin: bytes) -> None:
        """Initialize the SegmentInfo object.

        :param start: start address of segment
        :param length: length of segment
        :param data_bin: binary data in segment
        """
        self.start = start
        self.length = length
        self.data_bin = data_bin

    @property
    def aligned_start(self) -> int:
        """Returns aligned start address for erasing purposes."""
        return math.floor(self.start / self.ALIGNMENT) * self.ALIGNMENT

    @property
    def aligned_length(self) -> int:
        """Returns aligned length for erasing purposes."""
        end_address = self.start + self.length
        aligned_end = math.ceil(end_address / self.ALIGNMENT) * self.ALIGNMENT
        aligned_len = aligned_end - self.aligned_start
        return aligned_len


def parse_image_file(file_path: str) -> List[SegmentInfo]:
    """Parse image.

    :param file_path: path, where the image is stored
    :raises SPSDKError: when elf/axf files are used
    :raises SPSDKError: when binary file is used
    :raises SPSDKError: when unsupported file is used
    :return: SegmentInfo object
    """
    with open(file_path, "rb") as f:
        data = f.read(4)
    if data == b'\x7fELF':
        raise SPSDKError("Elf file is not supported")
    try:
        binfile = bincopy.BinFile(file_path)
        return [
            SegmentInfo(start=segment.address, length=len(segment.data), data_bin=segment.data)
            for segment in binfile.segments
        ]
    except UnicodeDecodeError as e:
        raise SPSDKError('Error: please use write-memory command for binary file downloading.') from e
    except Exception as e:
        raise SPSDKError("Error loading file") from e

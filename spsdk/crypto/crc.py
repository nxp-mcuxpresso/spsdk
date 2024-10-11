#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for Cyclic redundancy check computation."""

from dataclasses import dataclass
from typing import Union

import crcmod

from spsdk.exceptions import SPSDKKeyError
from spsdk.utils.spsdk_enum import SpsdkEnum


class CrcAlg(SpsdkEnum):
    """Available predefined CRC algorithms enum."""

    CRC32 = (0, "crc32", "Crc32 algorithm")
    CRC32_MPEG = (1, "crc32-mpeg", "Crc32 Mpeg algorithm")
    CRC16_XMODEM = (1, "crc16-xmodem", "Crc16 Xmodem algorithm")


@dataclass
class CrcConfig:
    """CRC configuration."""

    polynomial: int
    initial_value: int
    final_xor: int
    reverse: bool


class Crc:
    """SPSDK Cyclic redundancy check."""

    def __init__(self, config: CrcConfig):
        """CRC initialization."""
        self.polynomial = config.polynomial
        self.initial_value = config.initial_value
        self.final_xor = config.final_xor
        self.reverse = config.reverse

    def verify(self, data: bytes, crc: int) -> bool:
        """Verify if the given CRC matches the data.

        :param data: Data for CRC calculation
        :param crc: CRC checksum
        :return: True if data match the checksum
        """
        return self.calculate(data) == crc

    def calculate(self, data: bytes) -> int:
        """Calculate CRC form given data.

        :param data: Data for CRC calculation
        :return: CRC checksum
        """
        crc_func = crcmod.mkCrcFun(
            poly=self.polynomial,
            initCrc=self.initial_value,
            rev=self.reverse,
            xorOut=self.final_xor,
        )
        return crc_func(data)


CRC_ALGORITHMS = {
    CrcAlg.CRC32: CrcConfig(
        polynomial=0x104C11DB7,
        initial_value=0x00000000,
        final_xor=0xFFFFFFFF,
        reverse=True,
    ),
    CrcAlg.CRC32_MPEG: CrcConfig(
        polynomial=0x104C11DB7,
        initial_value=0xFFFFFFFF,
        final_xor=0x00000000,
        reverse=False,
    ),
    CrcAlg.CRC16_XMODEM: CrcConfig(
        polynomial=0x11021,
        initial_value=0x0000,
        final_xor=0x0000,
        reverse=False,
    ),
}


def from_crc_algorithm(crc_alg: Union[CrcAlg, str]) -> Crc:
    """Get CRC object from algorithm enum."""
    if isinstance(crc_alg, str):
        crc_alg = CrcAlg.from_label(crc_alg.lower())
    if crc_alg not in CRC_ALGORITHMS:
        raise SPSDKKeyError(f"Unknown CRC algorithm name: {crc_alg}")
    alg = CRC_ALGORITHMS[crc_alg]
    return Crc(alg)

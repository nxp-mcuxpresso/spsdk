#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Cyclic Redundancy Check (CRC) computation utilities.

This module provides comprehensive CRC calculation functionality with support for
multiple CRC algorithms. It includes CRC algorithm enumeration, configuration
management, and computation capabilities for data integrity verification.
"""

from dataclasses import dataclass
from typing import Union

import crcmod

from spsdk.exceptions import SPSDKKeyError
from spsdk.utils.spsdk_enum import SpsdkEnum


class CrcAlg(SpsdkEnum):
    """Enumeration of available predefined CRC algorithms.

    This enum provides standardized CRC algorithm identifiers used throughout SPSDK
    for data integrity verification and checksum calculations.
    """

    CRC32 = (0, "crc32", "Crc32 algorithm")
    CRC32_MPEG = (1, "crc32-mpeg", "Crc32 Mpeg algorithm")
    CRC16_XMODEM = (1, "crc16-xmodem", "Crc16 Xmodem algorithm")


@dataclass
class CrcConfig:
    """CRC configuration container for cryptographic operations.

    This class defines the parameters needed to configure CRC (Cyclic Redundancy Check)
    calculations, including polynomial, initial value, final XOR value, and bit reversal
    settings used across SPSDK cryptographic operations.
    """

    polynomial: int
    initial_value: int
    final_xor: int
    reverse: bool


class Crc:
    """SPSDK Cyclic Redundancy Check calculator.

    This class provides CRC calculation and verification functionality with configurable
    parameters including polynomial, initial value, final XOR, and bit reversal settings.
    It supports various CRC algorithms through flexible configuration options.
    """

    def __init__(self, config: CrcConfig):
        """Initialize CRC calculator with specified configuration.

        :param config: CRC configuration containing polynomial, initial value, final XOR value, and reverse flag.
        """
        self.polynomial = config.polynomial
        self.initial_value = config.initial_value
        self.final_xor = config.final_xor
        self.reverse = config.reverse

    def verify(self, data: bytes, crc: int) -> bool:
        """Verify if the given CRC matches the data.

        :param data: Data for CRC calculation.
        :param crc: CRC checksum to verify against.
        :return: True if calculated CRC matches the provided checksum, False otherwise.
        """
        return self.calculate(data) == crc

    def calculate(self, data: bytes) -> int:
        """Calculate CRC from given data.

        :param data: Input data bytes for CRC calculation.
        :return: Calculated CRC checksum value.
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
    """Get CRC object from algorithm enum.

    Creates a CRC calculator instance based on the specified algorithm identifier.
    The method accepts both CrcAlg enum values and string representations of
    algorithm names.

    :param crc_alg: CRC algorithm enum or string name of the algorithm.
    :raises SPSDKKeyError: Unknown CRC algorithm name provided.
    :return: CRC calculator object configured with the specified algorithm.
    """
    if isinstance(crc_alg, str):
        crc_alg = CrcAlg.from_label(crc_alg.lower())
    if crc_alg not in CRC_ALGORITHMS:
        raise SPSDKKeyError(f"Unknown CRC algorithm name: {crc_alg}")
    alg = CRC_ALGORITHMS[crc_alg]
    return Crc(alg)

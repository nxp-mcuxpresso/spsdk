#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Various utilities used throughout the DICE module."""

import logging
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from spsdk.dice.exceptions import SPSDKDICEError
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.registers import Register, Registers, RegsBitField

logger = logging.getLogger(__name__)


def get_supported_devices() -> list[str]:
    """List devices supported by DICE."""
    return get_families(DatabaseManager.DICE)


def reconstruct_ecc_key(puk_data: Union[str, bytes]) -> ec.EllipticCurvePublicKey:
    """Convert raw X,Y ECC coordinates into a key."""
    if isinstance(puk_data, str):
        puk_bytes = bytes.fromhex(puk_data)
    else:
        puk_bytes = puk_data
    x = int.from_bytes(puk_bytes[:32], byteorder="big")
    y = int.from_bytes(puk_bytes[32:], byteorder="big")
    numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return numbers.public_key()


def serialize_ecc_key(key: ec.EllipticCurvePublicKey) -> str:
    """Serialize public key into PEM-formatted string."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


HADDifferences = list[Union[tuple[RegsBitField, RegsBitField], tuple[Register, Register]]]


class HADDiff:
    """Helper class to parse differences in HAD values."""

    def __init__(self, family: str) -> None:
        """Initialize the HADDiff instance.

        :param family: Selected family for HAD data parsing
        :raises SPSDKDICEError: Unsupported family
        """
        self.family = family
        database = get_db(device=self.family)
        self.had_length = database.get_int(DatabaseManager.DICE, "had_length")
        self.critical_registers = database.get_list(DatabaseManager.DICE, "critical_had_members")

    def get_diff(
        self, expected: Union[str, bytes], actual: Union[str, bytes], critical_only: bool = False
    ) -> HADDifferences:
        """Compare provided HAD data and return registers/bitfields containing different values.

        :param expected: Expected HAD data
        :param actual: Actual HAD data
        :param critical_only: Return only set of differences of critical HAD register
        :raises SPSDKDICEError: Invalid data length
        :return: List of registers/bitfields with mismatching values
        """
        expected_data = bytes.fromhex(expected) if isinstance(expected, str) else expected
        actual_data = bytes.fromhex(actual) if isinstance(actual, str) else actual

        if len(expected_data) != self.had_length:
            raise SPSDKDICEError(
                f"Expected HAD length must be {self.had_length}; got {len(expected_data)}"
            )
        if len(actual_data) != self.had_length:
            raise SPSDKDICEError(
                f"Actual HAD length must be {self.had_length}; got {len(actual_data)}"
            )

        expected_regs = self._setup_regs(data=expected_data)
        actual_regs = self._setup_regs(data=actual_data)

        differences = expected_regs.get_diff(actual_regs)
        if not critical_only:
            return differences

        critical_differences: HADDifferences = []
        for d1, d2 in differences:
            if isinstance(d1, Register) and isinstance(d2, Register):
                if d1.name in self.critical_registers:
                    critical_differences.append((d1, d2))
            else:
                assert isinstance(d1, RegsBitField) and isinstance(d2, RegsBitField)
                if d1.parent.name in self.critical_registers:
                    critical_differences.append((d1, d2))
        return critical_differences

    def _setup_regs(self, data: bytes) -> Registers:
        registers = Registers(family=self.family, feature="dice")
        registers.parse(binary=data)
        return registers

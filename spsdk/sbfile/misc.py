#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions in SBFile module."""

from typing import Any, Sequence, Union

from spsdk.utils import misc


class SecBootBlckSize:
    """Helper methods allowing to convert size to number of blocks and back.

    Note: The class is not intended to be instantiated
    """

    # Size of cipher block in bytes
    BLOCK_SIZE = 16

    @staticmethod
    def is_aligned(size: int) -> bool:
        """Whether size is aligned to cipher block size.

        :param size: given size in bytes
        :return: True if yes, False otherwise
        """
        return size % SecBootBlckSize.BLOCK_SIZE == 0

    @staticmethod
    def align(size: int) -> int:
        """Align given size to block size.

        :param size: in bytes
        :return: size aligned up to block size
        """
        return misc.align(size, SecBootBlckSize.BLOCK_SIZE)

    @staticmethod
    def to_num_blocks(size: int) -> int:
        """Converts size to number of cipher blocks.

        :param size: to be converted, the size must be aligned to block boundary
        :return: corresponding number of cipher blocks
        :raise ValueError: is size not aligned to block boundary
        """
        if not SecBootBlckSize.is_aligned(size):
            raise ValueError(f'Invalid size {size}, expected number aligned to BLOCK size {SecBootBlckSize.BLOCK_SIZE}')
        return size // SecBootBlckSize.BLOCK_SIZE

    @staticmethod
    def align_block_fill_random(data: bytes) -> bytes:
        """Align block size to cipher block size.

        :param data: to be aligned
        :return: data aligned to cipher block size, filled with random values
        """
        return misc.align_block_fill_random(data, SecBootBlckSize.BLOCK_SIZE)


# the type represents input formats for BcdVersion3 value, see BcdVersion3.to_version
BcdVersion3Format = Union['BcdVersion3', str]


class BcdVersion3:
    """Version in format #.#.#, where # is BCD number (1-4 digits)."""

    # default value
    DEFAULT = '999.999.999'

    @staticmethod
    def _check_number(num: int) -> bool:
        """Check given number is a valid version number.

        :param num: to be checked
        :return: True if number format is valid
        :raise ValueError: if number format is not valid
        """
        if not 0 <= num <= 0x9999:
            raise ValueError('Invalid number range')
        for index in range(4):
            if (num >> 4 * index) & 0xF > 0x9:
                raise ValueError('Invalid number, contains digit > 9')
        return True

    @staticmethod
    def _num_from_str(text: str) -> int:
        """Converts BCD number from text to int.

        :param text: given string to be converted to a version number
        :return: version number
        :raise ValueError: if format is not valid
        """
        assert 0 <= len(text) <= 4
        result = int(text, 16)
        BcdVersion3._check_number(result)
        return result

    @staticmethod
    def from_str(text: str) -> 'BcdVersion3':
        """Convert string to BcdVersion instance.

        :param text: version in format #.#.#, where # is 1-4 decimal digits
        :return: BcdVersion3 instance
        :raise: ValueError: if format is not valid
        """
        parts = text.split('.')
        assert len(parts) == 3
        major = BcdVersion3._num_from_str(parts[0])
        minor = BcdVersion3._num_from_str(parts[1])
        service = BcdVersion3._num_from_str(parts[2])
        return BcdVersion3(major, minor, service)

    @staticmethod
    def to_version(input_version: BcdVersion3Format) -> 'BcdVersion3':
        """Convert different input formats into BcdVersion3 instance.

        :param input_version: either directly BcdVersion3 or string
        :raise ValueError: raises when the format is unsupported
        :return: BcdVersion3 instance
        """
        if isinstance(input_version, BcdVersion3):
            return input_version
        if isinstance(input_version, str):
            return BcdVersion3.from_str(input_version)
        raise ValueError('unsupported format')

    def __init__(self, major: int = 1, minor: int = 0, service: int = 0):
        """Initialize BcdVersion3.

        :param major: number in BCD format, 1-4 decimal digits
        :param minor: number in BCD format, 1-4 decimal digits
        :param service: number in BCD format, 1-4 decimal digits
        """
        assert all([BcdVersion3._check_number(major), BcdVersion3._check_number(minor),
                    BcdVersion3._check_number(service)])
        self.major = major
        self.minor = minor
        self.service = service

    def __str__(self) -> str:
        return f'{self.major:X}.{self.minor:X}.{self.service:X}'

    def __repr__(self) -> str:
        return self.__class__.__name__ + ': ' + self.__str__()

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, BcdVersion3) and
                (self.major == other.major) and
                (self.minor == other.minor) and
                (self.service == other.service))

    @property
    def nums(self) -> Sequence[int]:
        """Return array of version numbers: [major, minor, service]."""
        return [self.major, self.minor, self.service]

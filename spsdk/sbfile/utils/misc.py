#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SBFile miscellaneous utilities and helper functions.

This module provides utility functions and classes for SBFile operations,
including timestamp handling, version management, and block size definitions.
"""

from datetime import datetime, timezone
from typing import Any, Sequence, Union

from spsdk.exceptions import SPSDKError
from spsdk.utils import misc


class SecBootBlckSize:
    """Secure Binary cipher block size utility for size and block conversions.

    This utility class provides static methods for working with cipher block sizes
    in secure boot operations, including size alignment, block counting, and data
    padding operations.

    :cvar BLOCK_SIZE: Size of cipher block in bytes (16).
    """

    # Size of cipher block in bytes
    BLOCK_SIZE = 16

    @staticmethod
    def is_aligned(size: int) -> bool:
        """Check if size is aligned to cipher block size.

        :param size: Size value in bytes to check for alignment.
        :return: True if size is aligned to cipher block size, False otherwise.
        """
        return size % SecBootBlckSize.BLOCK_SIZE == 0

    @staticmethod
    def align(size: int) -> int:
        """Align given size to block size.

        :param size: Size in bytes to be aligned.
        :return: Size aligned up to block size.
        """
        return misc.align(size, SecBootBlckSize.BLOCK_SIZE)

    @staticmethod
    def to_num_blocks(size: int) -> int:
        """Convert size in bytes to number of cipher blocks.

        The size must be aligned to the cipher block boundary before conversion.

        :param size: Size in bytes to be converted, must be aligned to block boundary.
        :raises SPSDKError: When size is not aligned to block boundary.
        :return: Number of cipher blocks corresponding to the given size.
        """
        if not SecBootBlckSize.is_aligned(size):
            raise SPSDKError(
                f"Invalid size {size}, expected number aligned to BLOCK size {SecBootBlckSize.BLOCK_SIZE}"
            )
        return size // SecBootBlckSize.BLOCK_SIZE

    @staticmethod
    def align_block_fill_random(data: bytes) -> bytes:
        """Align block size to cipher block size.

        The method aligns input data to the cipher block size by padding it with random values
        to ensure proper encryption block alignment.

        :param data: Input data bytes to be aligned to cipher block size.
        :return: Data aligned to cipher block size, padded with random values if necessary.
        """
        return misc.align_block_fill_random(data, SecBootBlckSize.BLOCK_SIZE)

    @staticmethod
    def align_block_fill_zeros(data: bytes) -> bytes:
        """Align block size to cipher block size.

        :param data: Binary data to be aligned to cipher block size.
        :return: Data aligned to cipher block size, filled with zeros.
        """
        return misc.align_block(
            data, SecBootBlckSize.BLOCK_SIZE, padding=misc.BinaryPattern("zeros")
        )


# the type represents input formats for BcdVersion3 value, see BcdVersion3.to_version
BcdVersion3Format = Union["BcdVersion3", str]


class BcdVersion3:
    """BCD version representation for three-component version numbers.

    This class handles version numbers in the format major.minor.service where each
    component is a BCD (Binary Coded Decimal) number with 1-4 digits. It provides
    validation, parsing, and conversion functionality for version strings used in
    SPSDK operations.

    :cvar DEFAULT: Default version string template.
    """

    # default value
    DEFAULT = "999.999.999"

    @staticmethod
    def _check_number(num: int) -> bool:
        """Check given number is a valid version number.

        The method validates that the number is within valid range (0-0x9999) and contains only
        valid decimal digits (0-9) when interpreted as BCD (Binary Coded Decimal).

        :param num: Number to be checked for validity.
        :raises SPSDKError: If number is out of range or contains invalid BCD digits.
        :return: True if number format is valid.
        """
        if num < 0 or num > 0x9999:
            raise SPSDKError("Invalid number range")
        for index in range(4):
            if (num >> 4 * index) & 0xF > 0x9:
                raise SPSDKError("Invalid number, contains digit > 9")
        return True

    @staticmethod
    def _num_from_str(text: str) -> int:
        """Convert BCD number from text to integer.

        The method validates the input text length and converts hexadecimal string
        representation to integer, then validates the BCD format.

        :param text: Hexadecimal string to be converted to BCD version number.
        :return: Converted BCD version number as integer.
        :raises SPSDKError: If text length is invalid or BCD format is not valid.
        """
        if len(text) < 0 or len(text) > 4:
            raise SPSDKError("Invalid text length")
        result = int(text, 16)
        BcdVersion3._check_number(result)
        return result

    @staticmethod
    def from_str(text: str) -> "BcdVersion3":
        """Convert string to BcdVersion3 instance.

        Parses a version string in the format major.minor.service where each component
        is a 1-4 decimal digit number and creates a corresponding BcdVersion3 object.

        :param text: Version string in format #.#.#, where # is 1-4 decimal digits.
        :return: BcdVersion3 instance created from the parsed version string.
        :raises SPSDKError: If the format is not valid or contains invalid components.
        """
        parts = text.split(".")
        if len(parts) != 3:
            raise SPSDKError("Invalid length")
        major = BcdVersion3._num_from_str(parts[0])
        minor = BcdVersion3._num_from_str(parts[1])
        service = BcdVersion3._num_from_str(parts[2])
        return BcdVersion3(major, minor, service)

    @staticmethod
    def to_version(input_version: BcdVersion3Format) -> "BcdVersion3":
        """Convert different input formats into BcdVersion3 instance.

        The method accepts either a BcdVersion3 object directly or a string representation
        and converts it to a BcdVersion3 instance.

        :param input_version: Either a BcdVersion3 object or string representation of version
        :raises SPSDKError: When the input format is unsupported
        :return: BcdVersion3 instance
        """
        if isinstance(input_version, BcdVersion3):
            return input_version
        if isinstance(input_version, str):
            return BcdVersion3.from_str(input_version)
        raise SPSDKError("unsupported format")

    def __init__(self, major: int = 1, minor: int = 0, service: int = 0):
        """Initialize BcdVersion3.

        :param major: Major version number in BCD format, 1-4 decimal digits.
        :param minor: Minor version number in BCD format, 1-4 decimal digits.
        :param service: Service version number in BCD format, 1-4 decimal digits.
        :raises SPSDKError: Invalid version number provided.
        """
        if not all(
            [
                BcdVersion3._check_number(major),
                BcdVersion3._check_number(minor),
                BcdVersion3._check_number(service),
            ]
        ):
            raise SPSDKError("Invalid version")
        self.major = major
        self.minor = minor
        self.service = service

    def __str__(self) -> str:
        """Return string representation of version in hexadecimal format.

        The version is formatted as "MAJOR.MINOR.SERVICE" where each component
        is displayed as a hexadecimal number.

        :return: Version string in format "X.X.X" where X represents hexadecimal values.
        """
        return f"{self.major:X}.{self.minor:X}.{self.service:X}"

    def __repr__(self) -> str:
        """Get string representation of the object.

        Returns the class name followed by the string representation of the object.

        :return: String representation in format "ClassName: object_string".
        """
        return self.__class__.__name__ + ": " + self.__str__()

    def __eq__(self, other: Any) -> bool:
        """Check equality with another BcdVersion3 object.

        Compares major, minor, and service version components to determine if two
        BcdVersion3 instances represent the same version.

        :param other: Object to compare with this BcdVersion3 instance.
        :return: True if both objects are BcdVersion3 instances with identical version
                 components, False otherwise.
        """
        return (
            isinstance(other, BcdVersion3)
            and (self.major == other.major)
            and (self.minor == other.minor)
            and (self.service == other.service)
        )

    @property
    def nums(self) -> Sequence[int]:
        """Get version numbers as a sequence.

        :return: Array of version numbers in format [major, minor, service].
        """
        return [self.major, self.minor, self.service]


def pack_timestamp(value: datetime) -> int:
    """Convert datetime to microseconds since 1.1.2000.

    The method converts a datetime object to the number of microseconds that have
    elapsed since January 1, 2000, 00:00:00 UTC, returned as a 64-bit integer.

    :param value: Datetime object to be converted.
    :raises SPSDKError: When the conversion result is out of valid range.
    :return: Number of microseconds since 1.1.2000 00:00:00 UTC as 64-bit integer.
    """
    assert isinstance(value, datetime)
    start = datetime(2000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    result = int((value.timestamp() - start) * 1000000)
    if result < 0 or result > 0xFFFFFFFFFFFFFFFF:
        raise SPSDKError("Incorrect result of conversion")
    return result


def unpack_timestamp(value: int) -> datetime:
    """Convert timestamp in milliseconds to datetime object.

    Converts a timestamp value representing milliseconds since January 1, 2000 00:00:00 UTC
    into a corresponding datetime object.

    :param value: Number of milliseconds since 1.1.2000 00:00:00 UTC as 64-bit integer.
    :return: Corresponding datetime object.
    :raises SPSDKError: When the timestamp value is out of valid range.
    """
    assert isinstance(value, int)
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise SPSDKError("Incorrect result of conversion")
    start = int(datetime(2000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc).timestamp() * 1000000)
    return datetime.fromtimestamp((start + value) / 1000000)

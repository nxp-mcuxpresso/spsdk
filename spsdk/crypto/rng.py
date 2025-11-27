#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic random number generation utilities.

This module provides secure random number and byte generation functions
for cryptographic operations within SPSDK. It offers convenient wrappers
around Python's secrets module for generating random bytes, hexadecimal
strings, and bounded random integers.
"""

# Used security modules


from secrets import randbelow, token_bytes, token_hex


def random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    This function provides a secure source of randomness suitable for cryptographic
    operations and security-sensitive applications.

    :param length: The number of random bytes to generate.
    :raises ValueError: If length is negative.
    :return: Cryptographically secure random bytes of specified length.
    """
    return token_bytes(length)


def random_hex(length: int) -> str:
    """Generate random hexadecimal string of specified byte length.

    The method creates a cryptographically secure random hexadecimal string
    using the underlying token_hex function.

    :param length: The length in bytes of the random data to generate.
    :return: Random hexadecimal string representation (twice the byte length).
    """
    return token_hex(length)


def rand_below(upper_bound: int) -> int:
    """Generate a random integer in the specified range.

    Returns a cryptographically secure random number in the range [0, upper_bound]
    using the underlying randbelow function.

    :param upper_bound: The upper bound for the random number generation (inclusive).
    :return: Random integer between 0 and upper_bound (inclusive).
    """
    return randbelow(upper_bound)

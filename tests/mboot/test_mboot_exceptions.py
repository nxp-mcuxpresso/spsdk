#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for MBoot exception handling and inheritance.

This module contains unit tests for validating the proper behavior of
MBoot-related exceptions in SPSDK, including inheritance relationships,
error handling, and string representations.
"""

from typing import Type

from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootCommandError, McuBootConnectionError, McuBootError


def raise_and_catch(raising_exc: Exception, catching_exc: Type[Exception]) -> bool:
    """Test if an exception can be caught by a specific exception type.

    This utility function raises a given exception and attempts to catch it
    with a specified exception type to verify exception hierarchy relationships.

    :param raising_exc: The exception instance to be raised and tested.
    :param catching_exc: The exception type that should catch the raised exception.
    :return: True if catching_exc successfully catches raising_exc, False otherwise.
    """
    try:
        raise raising_exc
    except catching_exc:
        return True
    except Exception:
        return False


def test_base_inheritance() -> None:
    """Test whether all mboot exceptions inherit from SPSDKError base class.

    Validates that McuBootError, McuBootCommandError, and McuBootConnectionError
    all properly inherit from the SPSDKError base exception class by raising
    and catching each exception type.

    :raises AssertionError: If any mboot exception does not inherit from SPSDKError.
    """
    assert raise_and_catch(McuBootError(), SPSDKError)
    assert raise_and_catch(McuBootCommandError("cmd", 0), SPSDKError)
    assert raise_and_catch(McuBootConnectionError("description"), SPSDKError)


def test_sdp_inheritance() -> None:
    """Test whether McuBootError is base for all SDP Exceptions.

    Verifies the inheritance hierarchy by testing that McuBootError serves as the
    base exception class for all SDP-related exceptions including McuBootCommandError
    and McuBootConnectionError.

    :raises AssertionError: If any of the inheritance tests fail.
    """
    assert raise_and_catch(McuBootError(), McuBootError)
    assert raise_and_catch(McuBootCommandError("cmd", 0), McuBootError)
    assert raise_and_catch(McuBootConnectionError("description"), McuBootError)


def test_expect_fail() -> None:
    """Test failure conditions for exception hierarchy.

    Verifies that parent exceptions cannot be caught when child exceptions are raised,
    ensuring proper exception inheritance behavior in the mboot module.
    """
    assert not raise_and_catch(SPSDKError(), McuBootError)
    assert not raise_and_catch(McuBootError(), McuBootConnectionError)


def test_stringification() -> None:
    """Test stringified error messages from exceptions.

    Verifies that exception classes properly include relevant information
    in their string representations for debugging and error reporting.

    :raises AssertionError: If any exception string representation doesn't contain expected content.
    """
    assert "random-description" in str(McuBootError("random-description"))
    assert "random-description" in str(McuBootConnectionError("random-description"))
    assert "random-command" in str(McuBootCommandError("random-command", 0))
    assert "Unknown Error" in str(McuBootCommandError("random-command", -1))

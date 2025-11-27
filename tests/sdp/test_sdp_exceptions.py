#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDP exceptions testing module.

This module contains unit tests for SDP (Serial Download Protocol) exception
classes, verifying proper inheritance hierarchy and exception handling behavior.
"""

from typing import Type

from spsdk.exceptions import SPSDKError
from spsdk.sdp.sdp import SdpCommandError, SdpConnectionError, SdpError


def raise_and_catch(raising_exc: Exception, catching_exc: Type[Exception]) -> bool:
    """Test if an exception can be caught by a specific exception type.

    This utility function raises the provided exception and attempts to catch it
    with the specified exception type to verify exception hierarchy compatibility.

    :param raising_exc: The exception instance to be raised and tested.
    :param catching_exc: The exception type/class used to attempt catching the raised exception.
    :return: True if the raising_exc can be caught by catching_exc, False otherwise.
    """
    try:
        raise raising_exc
    except catching_exc:
        return True
    except Exception:
        return False


def test_base_inheritance() -> None:
    """Test whether SPSDKError is base for all SDP exceptions.

    Validates that all SDP-specific exception classes (SdpError, SdpCommandError,
    and SdpConnectionError) properly inherit from the base SPSDKError class.
    """
    assert raise_and_catch(SdpError(), SPSDKError)
    assert raise_and_catch(SdpCommandError("cmd", 0), SPSDKError)
    assert raise_and_catch(SdpConnectionError("description"), SPSDKError)


def test_sdp_inheritance() -> None:
    """Test whether SDPError is base for all SDP Exceptions.

    This test verifies that all SDP-specific exception classes properly inherit
    from the base SdpError class, ensuring consistent exception hierarchy.
    """
    assert raise_and_catch(SdpError(), SdpError)
    assert raise_and_catch(SdpCommandError("cmd", 0), SdpError)
    assert raise_and_catch(SdpConnectionError("description"), SdpError)


def test_expect_fail() -> None:
    """Test failure conditions for exception hierarchy.

    Verifies that parent exceptions cannot be caught when child exceptions are raised,
    ensuring proper exception inheritance behavior in the SDP module.
    """
    assert not raise_and_catch(SPSDKError(), SdpError)
    assert not raise_and_catch(SdpError(), SdpConnectionError)

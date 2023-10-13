#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootCommandError, McuBootConnectionError, McuBootError


def raise_and_catch(raising_exc, catching_exc) -> bool:
    """Raise exception 'raising_exc' and try to catch it with 'catching_exc.

    :return: True if we're able to catch raising_exc using catching_exc.
    """
    try:
        raise raising_exc
    except catching_exc:
        return True
    except Exception:
        return False


def test_base_inheritance():
    """Test whether BootSdkError is base for all exceptions."""
    assert raise_and_catch(McuBootError(), SPSDKError)
    assert raise_and_catch(McuBootCommandError("cmd", 0), SPSDKError)
    assert raise_and_catch(McuBootConnectionError("description"), SPSDKError)


def test_sdp_inheritance():
    """Test whether McuBootError is base for all SDP Exceptions."""
    assert raise_and_catch(McuBootError(), McuBootError)
    assert raise_and_catch(McuBootCommandError("cmd", 0), McuBootError)
    assert raise_and_catch(McuBootConnectionError("description"), McuBootError)


def test_expect_fail():
    """Test Fail conditions, e.i.: can't fetch parent exc using child exception."""
    assert False == raise_and_catch(SPSDKError(), McuBootError)
    assert False == raise_and_catch(McuBootError(), McuBootConnectionError)


def test_stringification():
    """Test stringified error messages from exceptions."""
    assert "random-description" in str(McuBootError("random-description"))
    assert "random-description" in str(McuBootConnectionError("random-description"))
    assert "random-command" in str(McuBootCommandError("random-command", 0))
    assert "Unknown Error" in str(McuBootCommandError("random-command", -1))

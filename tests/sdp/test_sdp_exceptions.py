#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.exceptions import SPSDKError
from spsdk.sdp.sdp import SdpCommandError, SdpConnectionError, SdpError


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
    assert raise_and_catch(SdpError(), SPSDKError)
    assert raise_and_catch(SdpCommandError("cmd", 0), SPSDKError)
    assert raise_and_catch(SdpConnectionError("description"), SPSDKError)


def test_sdp_inheritance():
    """Test whether SDPError is base for all SDP Exceptions."""
    assert raise_and_catch(SdpError(), SdpError)
    assert raise_and_catch(SdpCommandError("cmd", 0), SdpError)
    assert raise_and_catch(SdpConnectionError("description"), SdpError)


def test_expect_fail():
    """Test Fail conditions, e.i.: can't fetch parent exc using child exception."""
    assert False == raise_and_catch(SPSDKError(), SdpError)
    assert False == raise_and_catch(SdpError(), SdpConnectionError)

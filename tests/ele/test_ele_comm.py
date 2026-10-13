#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for ELE communication handlers."""

from struct import pack
from unittest.mock import MagicMock

import pytest

from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.ele.ele_comm import EleMessageHandlerMBoot, SPSDKEleMessageError
from spsdk.ele.ele_constants import ResponseIndication, ResponseStatus
from spsdk.ele.ele_message import EleMessage, EleMessagePing, EleMessageReset
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT16


def _get_mboot_handler() -> tuple[EleMessageHandlerMBoot, MagicMock]:
    """Create an mBoot ELE handler with a mocked McuBoot device."""
    device = MagicMock(spec=McuBoot)
    handler = EleMessageHandlerMBoot(device=device, family=FamilyRevision("mimxrt1189"))
    return handler, device


def _make_response(cmd: int, size: int, status: int, indication: int = 0, abort: int = 0) -> bytes:
    """Build a minimal valid ELE response carrying the given status word."""
    header = pack(
        LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8,
        EleMessage.VERSION,
        size,
        cmd,
        EleMessage.RSP_TAG,
    )
    status_word = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, status, indication, abort)
    return header + status_word


def test_mboot_reset_tolerates_missing_response() -> None:
    """Reset command must not fail when the chip resets before answering."""
    handler, device = _get_mboot_handler()
    device.ele_message.side_effect = SPSDKError("No response packet from target device")

    # Must NOT raise - chip reset is the expected behavior for EleMessageReset.
    handler.send_message(EleMessageReset())


def test_mboot_non_reset_still_raises_on_missing_response() -> None:
    """Non-reset commands must still propagate the communication failure."""
    handler, device = _get_mboot_handler()
    device.ele_message.side_effect = SPSDKError("No response packet from target device")

    with pytest.raises(SPSDKError):
        handler.send_message(EleMessagePing())


def test_mboot_reset_still_raises_on_write_failure() -> None:
    """A failed write means the board does not respond at all - must always raise."""
    handler, device = _get_mboot_handler()
    device.write_memory.side_effect = SPSDKError("No response packet from target device")

    with pytest.raises(SPSDKError):
        handler.send_message(EleMessageReset())


def test_mboot_message_failure_raises_ele_message_error() -> None:
    """A non-success ELE status must raise SPSDKEleMessageError carrying the indication."""
    handler, device = _get_mboot_handler()
    msg = EleMessagePing()
    device.read_memory.return_value = _make_response(
        cmd=msg.CMD,
        size=msg.RESPONSE_HEADER_WORDS_COUNT,
        status=ResponseStatus.ELE_FAILURE_IND.tag,
        indication=ResponseIndication.ELE_BAD_SIGNATURE_FAILURE_IND.tag,
    )

    with pytest.raises(SPSDKEleMessageError) as exc_info:
        handler.send_message(msg)

    assert exc_info.value.status == ResponseStatus.ELE_FAILURE_IND.tag
    assert exc_info.value.indication == ResponseIndication.ELE_BAD_SIGNATURE_FAILURE_IND.tag


def test_ele_message_error_is_spsdk_error() -> None:
    """SPSDKEleMessageError must map to the SPSDKAppError exit-code mechanism.

    It stays a SPSDKError subclass for backwards compatibility and exposes the ELE
    indication as the SPSDKAppError ``error_code`` so ``catch_spsdk_error`` uses it.
    """
    assert issubclass(SPSDKEleMessageError, SPSDKError)
    assert issubclass(SPSDKEleMessageError, SPSDKAppError)
    exc = SPSDKEleMessageError(
        "boom",
        status=ResponseStatus.ELE_FAILURE_IND.tag,
        indication=ResponseIndication.ELE_BAD_SIGNATURE_FAILURE_IND.tag,
    )
    assert exc.error_code == ResponseIndication.ELE_BAD_SIGNATURE_FAILURE_IND.tag

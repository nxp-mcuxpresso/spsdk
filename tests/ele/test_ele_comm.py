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
from spsdk.ele.ele_comm import EleMessageHandlerMBoot, EleMessageHandlerUBoot, SPSDKEleMessageError
from spsdk.ele.ele_constants import ResponseIndication, ResponseStatus
from spsdk.ele.ele_message import (
    EleMessage,
    EleMessageDumpDebugBuffer,
    EleMessagePing,
    EleMessageReset,
)
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.uboot.uboot import UbootSerial
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
    assert str(exc_info.value).startswith(
        "ELE Message failed: ELE_BAD_SIGNATURE_FAILURE_IND (0xF0): "
    )


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


# Response of the ELE dump debug buffer command (13 words incl. CRC) as printed by U-Boot
DUMP_DEBUG_BUFFER_RSP = (
    "060d21e1d60000005b000000c104000000000000f502000003000000"
    "d404000001000000a5d1000006012117a6d100006c0e00f6"
)


def _get_uboot_handler(output: str) -> EleMessageHandlerUBoot:
    """Create a U-Boot ELE handler with a mocked serial device returning given output."""
    device = MagicMock(spec=UbootSerial)
    device.read_output.return_value = output
    return EleMessageHandlerUBoot(device=device, family=FamilyRevision("mimx9352"))


@pytest.mark.parametrize(
    "output",
    [
        DUMP_DEBUG_BUFFER_RSP,
        f"{DUMP_DEBUG_BUFFER_RSP}(NULL device *): request 00000000fdee5940 was not queued to"
        " ep1in-bulk",
        f"ele_message 0x0 0x0 0017e106\n{DUMP_DEBUG_BUFFER_RSP}Detected boot\nu-boot=> ",
    ],
)
def test_uboot_dump_debug_buffer_with_console_noise(output: str) -> None:
    """Response must be parsed even when U-Boot appends unrelated console messages."""
    handler = _get_uboot_handler(output)
    msg = EleMessageDumpDebugBuffer()
    handler.send_message(msg)

    assert msg.nb_logs == 10
    assert not msg.has_more_logs
    assert msg.debug_words[0] == 0x5B
    assert msg.debug_words[-1] == 0xD1A6


def test_uboot_ping_response_with_console_noise() -> None:
    """Short response followed by a console message must be cut by the header size."""
    msg = EleMessagePing()
    response = _make_response(cmd=msg.CMD, size=2, status=ResponseStatus.ELE_SUCCESS_IND.tag)
    handler = _get_uboot_handler(response.hex() + "deadbeef(NULL device *): request")
    handler.send_message(msg)

    assert msg.status == ResponseStatus.ELE_SUCCESS_IND.tag


def test_uboot_no_response_line_raises() -> None:
    """Missing response line must raise SPSDKError."""
    handler = _get_uboot_handler("u-boot=> ")
    with pytest.raises(SPSDKError):
        handler.send_message(EleMessagePing())

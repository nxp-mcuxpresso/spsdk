#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ELE message functionality tests.

This module contains unit tests for ELE (EdgeLock Enclave) message classes
and their functionality in SPSDK context. Tests cover message creation,
serialization, and communication with ELE hardware.
"""

from struct import pack

import pytest

from spsdk.ele.ele_constants import (
    EleInfo2Commit,
    KeyBlobEncryptionAlgorithm,
    KeyBlobEncryptionIeeCtrModes,
    LifeCycleToSwitch,
    ResponseStatus,
)
from spsdk.ele.ele_message import (
    EleMessage,
    EleMessageCommit,
    EleMessageDeriveKey,
    EleMessageDumpDebugBuffer,
    EleMessageEleFwAuthenticate,
    EleMessageEnableApc,
    EleMessageEnableRtc,
    EleMessageForwardLifeCycleUpdate,
    EleMessageGenerateKeyBlobDek,
    EleMessageGenerateKeyBlobIee,
    EleMessageGenerateKeyBLobOtfad,
    EleMessageGetEvents,
    EleMessageGetFwStatus,
    EleMessageGetFwVersion,
    EleMessageGetInfo,
    EleMessageGetTrngState,
    EleMessageKeyStoreClose,
    EleMessageKeyStoreOpen,
    EleMessageLoadKeyBLob,
    EleMessageOemContainerAuthenticate,
    EleMessagePing,
    EleMessagePublicKeyExport,
    EleMessageReadCommonFuse,
    EleMessageReadShadowFuse,
    EleMessageReleaseContainer,
    EleMessageReset,
    EleMessageResetApcContext,
    EleMessageSabInit,
    EleMessageSessionClose,
    EleMessageSessionOpen,
    EleMessageStartTrng,
    EleMessageVerifyImage,
    EleMessageWriteFuse,
    EleMessageWriteShadowFuse,
)
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT16, UINT32, value_to_bytes, value_to_int


def test_ele_write_fuse() -> None:
    """Test ELE write fuse message functionality.

    This test verifies the EleMessageWriteFuse class by creating a message with
    specific parameters, validating the exported message format, decoding a
    response, and asserting the correct status and response values.

    :raises AssertionError: If any of the message properties don't match expected values.
    """
    msg = EleMessageWriteFuse(128 * 32, 32, False, 0x4E219CB1)
    assert msg.bit_length == 32
    assert msg.bit_position == 4096
    assert value_to_int(msg.export()) == 0x0603D61700102000B19C214E
    msg.decode_response(value_to_bytes(0x0603D6E1D600000080000000))
    assert msg.status == 0xD6
    assert msg.indication == 0
    assert msg.abort_code == 0
    assert msg.processed_idx == 128


def test_ele_read_fuse() -> None:
    """Test ELE read fuse message functionality.

    This test verifies the EleMessageReadCommonFuse class by creating a message
    with fuse ID 128, validating the exported message format, decoding a response,
    and asserting the correct indication, status, and abort code values.
    """
    msg = EleMessageReadCommonFuse(128)
    assert value_to_int(msg.export()) == 0x0602971780000000
    msg.decode_response(value_to_bytes(0x060397E1D6000000B19C214E))
    assert msg.indication == 0
    assert msg.status == 214
    assert msg.abort_code == 0


def test_ele_get_info() -> None:
    """Test ELE get info message functionality.

    Validates the EleMessageGetInfo class by decoding a real response from MX93
    and verifying that the parsed information fields match expected values.
    """
    msg = EleMessageGetInfo()
    # Real response from MX93
    response_data = b"""\xda\x01\\\x00\x00\x93\x00\xa0\x10\x00\x04\x00\xf2\xa6\x01v\xff0DG\
        x9b\xf0g\x99s\xc6\x97\x91\x05c\xdbm\xf68\x8e\xc7\xf5\xb2\xbb\xa5!\
            x10\xbe\xbd\xfa\x03\x02\xb6\xe3\xa3\x94\x93\xe0<|\x9b\xe7\
                xab\x86\x86\xa5Bc\x13}\x893\xfa\xe8\x02\xab\x15}uZ\x84(\xef\xe1\xfaT\x7f\tM\xd5*{\xf7v=\
                    xa1\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                        x00\x00\x10\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                            x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                            x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                    x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                        x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"""
    msg.decode_response_data(response_data)
    assert msg.info_cmd == 0xDA
    assert msg.info_version == 1
    assert msg.info_length == 92
    assert msg.info_soc_id == 0x9300


# Helpers

VERSION = EleMessage.VERSION  # 0x06
RSP_TAG = EleMessage.RSP_TAG  # 0xE1
TAG = EleMessage.TAG  # 0x17
VERSION_HSM = 0x07  # HSM API version


def make_response(
    cmd: int,
    size: int,
    status: int = 0xD6,
    indication: int = 0,
    abort: int = 0,
    payload: bytes = b"",
    version: int = VERSION,
) -> bytes:
    """Build a minimal valid response bytes object."""
    header = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8, version, size, cmd, RSP_TAG)
    status_word = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, status, indication, abort)
    return header + status_word + payload


# EleMessage base class


class TestEleMessageBase:
    """Tests for the EleMessage base class."""

    def test_export_returns_header(self) -> None:
        """EleMessage.export() should return a 4-byte header."""
        msg = EleMessage()
        data = msg.export()
        assert len(data) == 4
        assert data[3] == TAG  # tag byte

    def test_header_export_fields(self) -> None:
        """Header fields are correctly set."""
        msg = EleMessage()
        data = msg.header_export()
        version, _words, cmd, tag = data[0], data[1], data[2], data[3]
        assert version == VERSION
        assert tag == TAG
        assert cmd == 0x00

    def test_get_msg_crc_simple(self) -> None:
        """CRC of 4-byte aligned payload is XOR of 32-bit words."""
        payload = b"\x01\x00\x00\x00" b"\x02\x00\x00\x00"
        crc = EleMessage.get_msg_crc(payload)
        expected = (1 ^ 2).to_bytes(4, "little")
        assert crc == expected

    def test_get_msg_crc_not_aligned_raises(self) -> None:
        """CRC raises when payload is not 4-byte aligned."""
        with pytest.raises(SPSDKValueError):
            EleMessage.get_msg_crc(b"\x01\x02\x03")

    def test_decode_response_bad_tag(self) -> None:
        """decode_response raises on wrong tag."""
        msg = EleMessagePing()
        bad = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8, VERSION, 2, msg.CMD, 0xFF)
        bad += pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, 0xD6, 0, 0)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response(bad)

    def test_decode_response_bad_command(self) -> None:
        """decode_response raises on wrong command."""
        msg = EleMessagePing()
        bad = make_response(cmd=0xFF, size=2)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response(bad)

    def test_decode_response_bad_version(self) -> None:
        """decode_response raises on wrong version."""
        msg = EleMessagePing()
        bad = make_response(cmd=msg.CMD, size=2, version=0x99)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response(bad)

    def test_decode_response_bad_size(self) -> None:
        """decode_response raises on wrong size (0 is below expected range)."""
        msg = EleMessagePing()
        bad = make_response(cmd=msg.CMD, size=0)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response(bad)

    def test_set_buffer_params_too_small(self) -> None:
        """set_buffer_params raises when buffer is too small."""
        msg = EleMessageGetFwVersion()
        with pytest.raises(SPSDKValueError):
            msg.set_buffer_params(0x1000, 4)  # too small for response

    def test_equality(self) -> None:
        """Two Ping messages are equal."""
        assert EleMessagePing() == EleMessagePing()

    def test_inequality_different_type(self) -> None:
        """Ping and Reset messages are not equal."""
        assert not (EleMessagePing() == EleMessageReset())

    def test_inequality_non_message(self) -> None:
        """EleMessage is not equal to a non-EleMessage object."""
        assert not (EleMessagePing() == "not a message")

    def test_status_string_success(self) -> None:
        """status_string returns 'Succeeded' on success status."""
        msg = EleMessagePing()
        msg.status = ResponseStatus.ELE_SUCCESS_IND.tag
        assert msg.status_string == "Succeeded"

    def test_status_string_invalid(self) -> None:
        """status_string returns 'Invalid status!' on unknown status."""
        msg = EleMessagePing()
        msg.status = 0x00
        assert "Invalid" in msg.status_string

    def test_info_returns_string(self) -> None:
        """info() returns a non-empty string."""
        msg = EleMessagePing()
        msg.status = 0xD6  # set valid status to avoid SPSDKKeyError in response_status()
        assert len(msg.info()) > 0

    def test_command_data_is_empty_by_default(self) -> None:
        """Base command_data returns empty bytes."""
        msg = EleMessage()
        assert msg.command_data == b""

    def test_has_command_data_false(self) -> None:
        """has_command_data is False when command_data is empty."""
        msg = EleMessage()
        assert msg.has_command_data is False

    def test_has_response_data_false(self) -> None:
        """has_response_data is False when response_data_size is 0."""
        msg = EleMessagePing()
        assert msg.has_response_data is False


# EleMessagePing


class TestEleMessagePing:
    """Tests for EleMessagePing."""

    def test_export_length(self) -> None:
        """Ping export is 4 bytes (header only)."""
        msg = EleMessagePing()
        assert len(msg.export()) == 4

    def test_decode_response_success(self) -> None:
        """Ping decodes a valid success response."""
        msg = EleMessagePing()
        response = make_response(cmd=msg.CMD, size=msg.RESPONSE_HEADER_WORDS_COUNT)
        msg.decode_response(response)
        assert msg.status == 0xD6

    def test_command_value(self) -> None:
        """Ping CMD is 0x01."""
        assert EleMessagePing.CMD == 0x01


# EleMessageReset


class TestEleMessageReset:
    """Tests for EleMessageReset."""

    def test_export_is_header(self) -> None:
        """Reset export produces 4-byte header."""
        msg = EleMessageReset()
        assert len(msg.export()) == 4

    def test_response_header_words_zero(self) -> None:
        """Reset has RESPONSE_HEADER_WORDS_COUNT = 0."""
        assert EleMessageReset.RESPONSE_HEADER_WORDS_COUNT == 0


# EleMessageEleFwAuthenticate


class TestEleMessageEleFwAuthenticate:
    """Tests for EleMessageEleFwAuthenticate."""

    def test_export_length(self) -> None:
        """FW authenticate export is 4 + 12 = 16 bytes."""
        msg = EleMessageEleFwAuthenticate(ele_fw_address=0x1234_5678)
        data = msg.export()
        assert len(data) == 16

    def test_export_contains_address(self) -> None:
        """Export contains fw address (appears twice in payload)."""
        addr = 0xDEAD_BEEF
        msg = EleMessageEleFwAuthenticate(ele_fw_address=addr)
        data = msg.export()
        assert addr.to_bytes(4, "little") in data


# EleMessageOemContainerAuthenticate


class TestEleMessageOemContainerAuthenticate:
    """Tests for EleMessageOemContainerAuthenticate."""

    def test_export_length(self) -> None:
        """OEM container export is 4 + 8 = 12 bytes."""
        msg = EleMessageOemContainerAuthenticate(oem_cntn_addr=0x8000_0000)
        data = msg.export()
        assert len(data) == 12

    def test_export_contains_address(self) -> None:
        """Export contains OEM container address."""
        addr = 0x8000_0000
        msg = EleMessageOemContainerAuthenticate(oem_cntn_addr=addr)
        data = msg.export()
        assert addr.to_bytes(4, "little") in data


# EleMessageVerifyImage


class TestEleMessageVerifyImage:
    """Tests for EleMessageVerifyImage."""

    def test_export_length(self) -> None:
        """VerifyImage export is 4 + 4 = 8 bytes."""
        msg = EleMessageVerifyImage(image_mask=0x03)
        assert len(msg.export()) == 8

    def test_decode_response(self) -> None:
        """decode_response extracts valid/invalid image masks."""
        msg = EleMessageVerifyImage(image_mask=0x03)
        valid_mask = (0x01).to_bytes(4, "little")
        invalid_mask = (0x02).to_bytes(4, "little")
        payload = valid_mask + invalid_mask
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.valid_image_mask == 0x01
        assert msg.invalid_image_mask == 0x02

    def test_response_info(self) -> None:
        """response_info returns formatted string."""
        msg = EleMessageVerifyImage()
        msg.valid_image_mask = 0x01
        msg.invalid_image_mask = 0x00
        info = msg.response_info()
        assert "Valid" in info


# EleMessageReleaseContainer


class TestEleMessageReleaseContainer:
    """Tests for EleMessageReleaseContainer."""

    def test_export_is_header(self) -> None:
        """ReleaseContainer export is 4 bytes."""
        msg = EleMessageReleaseContainer()
        assert len(msg.export()) == 4


# EleMessageForwardLifeCycleUpdate


class TestEleMessageForwardLifeCycleUpdate:
    """Tests for EleMessageForwardLifeCycleUpdate."""

    def test_export_length(self) -> None:
        """ForwardLifeCycleUpdate export is 4 + 4 = 8 bytes."""
        msg = EleMessageForwardLifeCycleUpdate(LifeCycleToSwitch.OEM_CLOSED)
        assert len(msg.export()) == 8

    def test_export_contains_lifecycle(self) -> None:
        """Export bytes contain the lifecycle tag."""
        msg = EleMessageForwardLifeCycleUpdate(LifeCycleToSwitch.OEM_CLOSED)
        data = msg.export()
        # lifecycle OEM_CLOSED = 0x08, packed as UINT16 little-endian at offset 4
        assert data[4] == 0x08
        assert data[5] == 0x00


# EleMessageGetEvents


class TestEleMessageGetEvents:
    """Tests for EleMessageGetEvents."""

    def _build_events_response(self) -> bytes:
        """Build a minimal GetEvents response."""
        msg = EleMessageGetEvents()
        cmd = msg.CMD
        # Build 40-byte response:  header(4) + status(4) + 2+2+8*4+4=40 bytes payload
        event_cnt = 2
        max_events = 8
        events = [0xAABBCCDD, 0x11223344] + [0] * 6
        payload = pack(LITTLE_ENDIAN + UINT16 + UINT16 + "8L", event_cnt, max_events, *events)
        # CRC is over first 44 bytes; here we just mock it with 4 zeros
        crc = b"\x00\x00\x00\x00"
        full_payload = payload + crc
        # size = (4 + 4 + len(full_payload)) // 4
        total_words = (4 + 4 + len(full_payload)) // 4
        response = make_response(cmd=cmd, size=total_words, payload=full_payload)
        return response

    def test_decode_response_events(self) -> None:
        """GetEvents decode extracts event count."""
        msg = EleMessageGetEvents()
        response = self._build_events_response()
        msg.decode_response(response)
        assert msg.event_cnt == 2

    def test_response_info(self) -> None:
        """response_info returns formatted string with events."""
        msg = EleMessageGetEvents()
        msg.event_cnt = 1
        # Use valid status byte 0xD6 (success) in the lower 8 bits
        msg.events[0] = 0x010297D6
        msg.status = 0xD6
        info = msg.response_info()
        assert "Event count" in info

    def test_get_ipc_id(self) -> None:
        """get_ipc_id extracts MU id from event."""
        event = 0x01000000  # ipc_id=0x01 (RTD_MU)
        result = EleMessageGetEvents.get_ipc_id(event)
        assert isinstance(result, str)

    def test_get_cmd(self) -> None:
        """get_cmd extracts command from event."""
        event = 0x00010000  # cmd=0x01 (PING_REQ)
        result = EleMessageGetEvents.get_cmd(event)
        assert isinstance(result, str)

    def test_get_ind(self) -> None:
        """get_ind extracts indication from event."""
        event = 0x00000A00  # ind=0x0A
        result = EleMessageGetEvents.get_ind(event)
        assert isinstance(result, str)

    def test_get_sts(self) -> None:
        """get_sts extracts status from event."""
        event = 0x000000D6  # sts=0xD6 (success)
        result = EleMessageGetEvents.get_sts(event)
        assert "successful" in result.lower()


# EleMessageStartTrng


class TestEleMessageStartTrng:
    """Tests for EleMessageStartTrng."""

    def test_export_is_header(self) -> None:
        """StartTrng export is 4 bytes."""
        msg = EleMessageStartTrng()
        assert len(msg.export()) == 4


# EleMessageGetTrngState


class TestEleMessageGetTrngState:
    """Tests for EleMessageGetTrngState."""

    def test_export_length(self) -> None:
        """GetTrngState export is 4 bytes (header only)."""
        msg = EleMessageGetTrngState()
        assert len(msg.export()) == 4

    def test_decode_response(self) -> None:
        """GetTrngState decodes TRNG and CSAL states."""
        msg = EleMessageGetTrngState()
        # payload: 4 bytes trng_state, csal_state, 2 reserved
        trng = 0x03  # ELE_TRNG_READY
        csal = 0x01  # some csal state
        payload = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, trng, csal, 0)
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.ele_trng_state == trng
        assert msg.ele_csal_state == csal

    def test_response_info(self) -> None:
        """response_info returns formatted string."""
        msg = EleMessageGetTrngState()
        assert "TRNG" in msg.response_info()


# EleMessageCommit


class TestEleMessageCommit:
    """Tests for EleMessageCommit."""

    def test_export_length(self) -> None:
        """Commit export is 4 + 4 = 8 bytes."""
        msg = EleMessageCommit([EleInfo2Commit.OEM_FW_FUSE])
        assert len(msg.export()) == 8

    def test_info2commit_mask(self) -> None:
        """info2commit_mask combines all commit types."""
        msg = EleMessageCommit([EleInfo2Commit.NXP_SRK_REVOCATION, EleInfo2Commit.OEM_FW_FUSE])
        expected = EleInfo2Commit.NXP_SRK_REVOCATION.tag | EleInfo2Commit.OEM_FW_FUSE.tag
        assert msg.info2commit_mask == expected

    def test_decode_response(self) -> None:
        """Commit decode_response succeeds on matching mask."""
        commit_items = [EleInfo2Commit.OEM_FW_FUSE]
        msg = EleMessageCommit(commit_items)
        mask = msg.info2commit_mask
        payload = mask.to_bytes(4, "little")
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.status == 0xD6


# EleMessageGetFwStatus


class TestEleMessageGetFwStatus:
    """Tests for EleMessageGetFwStatus."""

    def test_export_is_header(self) -> None:
        """GetFwStatus export is 4 bytes."""
        msg = EleMessageGetFwStatus()
        assert len(msg.export()) == 4

    def test_decode_response(self) -> None:
        """GetFwStatus decodes firmware status."""
        msg = EleMessageGetFwStatus()
        fw_status = 0x01
        payload = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, fw_status, 0, 0)
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.ele_fw_status == fw_status

    def test_response_info(self) -> None:
        """response_info returns formatted string."""
        msg = EleMessageGetFwStatus()
        assert "firmware" in msg.response_info().lower()


# EleMessageGetFwVersion


class TestEleMessageGetFwVersion:
    """Tests for EleMessageGetFwVersion."""

    def test_export_is_header(self) -> None:
        """GetFwVersion export is 4 bytes."""
        msg = EleMessageGetFwVersion()
        assert len(msg.export()) == 4

    def test_decode_response(self) -> None:
        """GetFwVersion decodes version and sha1."""
        msg = EleMessageGetFwVersion()
        ver = 0x0001_0001
        sha1 = 0xDEAD_BEEF
        payload = ver.to_bytes(4, "little") + sha1.to_bytes(4, "little")
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.ele_fw_version_raw == ver
        assert msg.ele_fw_version_sha1 == sha1

    def test_response_info(self) -> None:
        """response_info returns formatted version string."""
        msg = EleMessageGetFwVersion()
        msg.ele_fw_version_raw = 0x8001_0001  # dirty build bit set
        msg.ele_fw_version_sha1 = 0xABCD1234
        info = msg.response_info()
        assert "Dirty" in info


# EleMessageReadCommonFuse


class TestEleMessageReadCommonFuse:
    """Tests for EleMessageReadCommonFuse."""

    def test_export_length(self) -> None:
        """ReadCommonFuse export is 8 bytes."""
        msg = EleMessageReadCommonFuse(128)
        assert len(msg.export()) == 8

    def test_decode_response(self) -> None:
        """ReadCommonFuse decodes fuse value."""
        msg = EleMessageReadCommonFuse(128)
        fuse_val = 0xCAFE_BABE
        payload = fuse_val.to_bytes(4, "little")
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.fuse_value == fuse_val

    def test_response_info(self) -> None:
        """response_info includes fuse ID."""
        msg = EleMessageReadCommonFuse(42)
        msg.fuse_value = 0x1234
        assert "42" in msg.response_info()


# EleMessageReadShadowFuse


class TestEleMessageReadShadowFuse:
    """Tests for EleMessageReadShadowFuse."""

    def test_export_length(self) -> None:
        """ReadShadowFuse export is 8 bytes (header + 4-byte index)."""
        msg = EleMessageReadShadowFuse(10)
        assert len(msg.export()) == 8

    def test_export_different_from_common(self) -> None:
        """ReadShadowFuse packs index as UINT32 (not UINT16+UINT16)."""
        idx = 10
        msg = EleMessageReadShadowFuse(idx)
        data = msg.export()
        # bytes 4-8 should be idx packed as 32-bit LE
        assert int.from_bytes(data[4:8], "little") == idx


# EleMessageGetInfo


class TestEleMessageGetInfo:
    """Tests for EleMessageGetInfo."""

    def test_export_length(self) -> None:
        """GetInfo export is 4 + 12 = 16 bytes."""
        msg = EleMessageGetInfo()
        assert len(msg.export()) == 16

    def test_decode_response_data(self) -> None:
        """GetInfo decode_response_data populates fields."""
        msg = EleMessageGetInfo()
        # Build 160-byte response data
        word0 = (92 << 16) | (0x01 << 8) | 0xDA  # length=92, version=1, cmd=0xDA
        word1 = (0x1000 << 16) | 0x9300  # soc_rev=0x1000, soc_id=0x9300
        word2 = (0x10 << 24) | (0x00 << 16) | 0x0020  # attest=0x10, sssm=0, lc=0x0020
        data = (
            word0.to_bytes(4, "little")
            + word1.to_bytes(4, "little")
            + word2.to_bytes(4, "little")
            + b"\xaa" * 16  # uuid
            + b"\xbb" * 32  # sha256_rom_patch
            + b"\xcc" * 32  # sha256_fw
            + b"\xdd" * 64  # oem_srkh
            + (0x00_03_02_01).to_bytes(4, "little")  # word39: trng=0x01, csal=0x02, imem=0x03
        )
        msg.decode_response_data(data)
        assert msg.info_cmd == 0xDA
        assert msg.info_version == 0x01
        assert msg.info_length == 92
        assert msg.info_soc_id == 0x9300

    def test_get_attribute_valid(self) -> None:
        """get_attribute returns a string for valid attribute names."""
        msg = EleMessageGetInfo()
        msg.info_soc_id = 0x9300
        result = msg.get_attribute("soc_id")
        assert result is not None
        assert "0x9300" in result

    def test_get_attribute_invalid(self) -> None:
        """get_attribute raises on invalid attribute name."""
        msg = EleMessageGetInfo()
        with pytest.raises(SPSDKValueError):
            msg.get_attribute("nonexistent")

    def test_get_available_attributes(self) -> None:
        """get_available_attributes returns a non-empty tuple."""
        attrs = EleMessageGetInfo.get_available_attributes()
        assert len(attrs) > 0
        assert "soc_id" in attrs

    def test_decode_response_data_with_pqc_srkh(self) -> None:
        """GetInfo decode_response_data handles PQC SRKH field (>160 bytes)."""
        msg = EleMessageGetInfo()
        word0 = (92 << 16) | (0x03 << 8) | 0xDA  # version=3
        word1 = 0
        word2 = 0
        data = (
            word0.to_bytes(4, "little")
            + word1.to_bytes(4, "little")
            + word2.to_bytes(4, "little")
            + b"\x00" * 16  # uuid
            + b"\x00" * 32  # sha256_rom_patch
            + b"\x00" * 32  # sha256_fw
            + b"\x00" * 64  # oem_srkh
            + b"\x00" * 4  # word39
            + b"\xee" * 64  # oem_pqc_srkh
        )
        msg.decode_response_data(data)
        assert msg.info_oem_pqc_srkh == b"\xee" * 64

    def test_response_info(self) -> None:
        """response_info returns formatted string."""
        msg = EleMessageGetInfo()
        info = msg.response_info()
        assert "Life Cycle" in info


# EleMessageDeriveKey


class TestEleMessageDeriveKey:
    """Tests for EleMessageDeriveKey."""

    def test_export_has_crc(self) -> None:
        """DeriveKey export includes CRC (last 4 bytes)."""
        msg = EleMessageDeriveKey(key_size=16, context=None)
        msg.set_buffer_params(0x1000, 0x400)
        data = msg.export()
        # header(4) + payload(20: 4*UINT32 + 2*UINT16) + crc(4) = 28 bytes
        assert len(data) == 28

    def test_invalid_key_size(self) -> None:
        """DeriveKey raises on unsupported key size."""
        with pytest.raises(SPSDKValueError):
            EleMessageDeriveKey(key_size=24, context=None)

    def test_with_context(self) -> None:
        """DeriveKey accepts context bytes."""
        ctx = b"\xaa" * 32
        msg = EleMessageDeriveKey(key_size=32, context=ctx)
        msg.set_buffer_params(0x1000, 0x800)
        assert msg.command_data == ctx

    def test_decode_response_data(self) -> None:
        """DeriveKey decode_response_data extracts key bytes."""
        msg = EleMessageDeriveKey(key_size=16, context=None)
        key_bytes = b"\x01" * 16 + b"\xff" * 16  # extra bytes after key
        msg.decode_response_data(key_bytes)
        assert msg.derived_key == b"\x01" * 16

    def test_get_key(self) -> None:
        """get_key returns derived key after decode."""
        msg = EleMessageDeriveKey(key_size=16, context=None)
        msg.derived_key = b"\xab" * 16
        assert msg.get_key() == b"\xab" * 16


# EleMessageGenerateKeyBlobDek


class TestEleMessageGenerateKeyBlobDek:
    """Tests for EleMessageGenerateKeyBlobDek (DEK keyblob)."""

    def test_export_length(self) -> None:
        """DEK keyblob export has correct length (header + payload + crc)."""
        key = b"\x00" * 16  # 128-bit AES
        msg = EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, key)
        msg.set_buffer_params(0x1000, 0x1000)
        data = msg.export()
        # In base export: payload = UINT32*5 + UINT16*2 = 24 bytes
        # then payload = header(4) + payload(24) = 28 bytes
        # return payload + crc(4) = 32 bytes
        assert len(data) == 32

    def test_command_data_structure(self) -> None:
        """DEK keyblob command_data has proper header and key."""
        key = b"\xaa" * 16
        msg = EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, key)
        data = msg.command_data
        assert data[3] == 0x81  # KEYBLOB_TAG
        assert key in data

    def test_invalid_algorithm(self) -> None:
        """DEK keyblob raises on unsupported algorithm."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CTR, b"\x00" * 16)

    def test_invalid_key_size(self) -> None:
        """DEK keyblob raises on unsupported key size."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, b"\x00" * 8)

    def test_decode_response_data_valid(self) -> None:
        """DEK keyblob decode_response_data extracts key_blob."""
        key = b"\x00" * 16
        msg = EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, key)
        # Build a minimal valid response_data
        blob_len = 24
        response_data = pack(
            LITTLE_ENDIAN + UINT8 + UINT16 + UINT8,
            0x00,  # version
            blob_len,  # length
            0x81,  # tag
        ) + b"\x00" * (blob_len - 4)
        msg.decode_response_data(response_data)
        assert len(msg.key_blob) == blob_len

    def test_decode_response_data_bad_tag(self) -> None:
        """DEK keyblob decode_response_data raises on bad tag."""
        key = b"\x00" * 16
        msg = EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, key)
        response_data = pack(LITTLE_ENDIAN + UINT8 + UINT16 + UINT8, 0x00, 10, 0xFF)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response_data(response_data)

    def test_info_method(self) -> None:
        """DEK keyblob info() returns formatted string."""
        key = b"\x00" * 16
        msg = EleMessageGenerateKeyBlobDek(0x01, KeyBlobEncryptionAlgorithm.AES_CBC, key)
        msg.status = 0xD6
        info = msg.info()
        assert "DEK" in info


# EleMessageGenerateKeyBLobOtfad


class TestEleMessageGenerateKeyBlobOtfad:
    """Tests for EleMessageGenerateKeyBLobOtfad (OTFAD keyblob)."""

    def _make_valid_otfad(self) -> EleMessageGenerateKeyBLobOtfad:
        return EleMessageGenerateKeyBLobOtfad(
            key_identifier=0x0102,  # peripheral_index=1, struct_index=2
            key=b"\xaa" * 16,
            aes_counter=b"\xbb" * 8,
            start_address=0x0000,
            end_address=0x0400,  # 1024-byte aligned
        )

    def test_command_data_length(self) -> None:
        """OTFAD command_data has expected length (0x30 + crc bytes etc.)."""
        msg = self._make_valid_otfad()
        data = msg.command_data
        assert len(data) > 0

    def test_invalid_struct_index(self) -> None:
        """OTFAD raises on struct_index > 3."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBLobOtfad(
                key_identifier=0x0104,  # struct_index=4 > 3
                key=b"\xaa" * 16,
                aes_counter=b"\xbb" * 8,
                start_address=0,
                end_address=0,
            )

    def test_invalid_peripheral_index(self) -> None:
        """OTFAD raises on peripheral_index not in [1,2]."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBLobOtfad(
                key_identifier=0x0300,  # peripheral_index=3
                key=b"\xaa" * 16,
                aes_counter=b"\xbb" * 8,
                start_address=0,
                end_address=0,
            )

    def test_invalid_aes_counter_length(self) -> None:
        """OTFAD raises on AES counter != 8 bytes."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBLobOtfad(
                key_identifier=0x0102,
                key=b"\xaa" * 16,
                aes_counter=b"\xbb" * 4,  # wrong length
                start_address=0,
                end_address=0,
            )

    def test_invalid_start_address_alignment(self) -> None:
        """OTFAD raises on unaligned start address."""
        with pytest.raises(SPSDKValueError):
            EleMessageGenerateKeyBLobOtfad(
                key_identifier=0x0102,
                key=b"\xaa" * 16,
                aes_counter=b"\xbb" * 8,
                start_address=0x01,  # not 1024-aligned
                end_address=0,
            )

    def test_info_method(self) -> None:
        """OTFAD info() returns formatted string."""
        msg = self._make_valid_otfad()
        msg.status = 0xD6
        info = msg.info()
        assert "OTFAD" in info


# EleMessageGenerateKeyBlobIee


class TestEleMessageGenerateKeyBlobIee:
    """Tests for EleMessageGenerateKeyBlobIee (IEE keyblob)."""

    def _make_iee_ctr(self) -> EleMessageGenerateKeyBlobIee:
        return EleMessageGenerateKeyBlobIee(
            key_identifier=0x01,
            algorithm=KeyBlobEncryptionAlgorithm.AES_CTR,
            key=b"\xaa" * 16,
            ctr_mode=KeyBlobEncryptionIeeCtrModes.AesCTRWAddress,
            aes_counter=b"\xcc" * 16,
            page_offset=0,
            region_number=0,
        )

    def test_command_data_length(self) -> None:
        """IEE CTR command_data has expected length."""
        msg = self._make_iee_ctr()
        data = msg.command_data
        # header(4) + options(4) + iee_config(UINT32+UINT32+32s+32s+4s=76) + crc(4) = 88 bytes
        assert len(data) == 88

    def test_xts_command_data(self) -> None:
        """IEE XTS command_data can be generated."""
        msg = EleMessageGenerateKeyBlobIee(
            key_identifier=0x01,
            algorithm=KeyBlobEncryptionAlgorithm.AES_XTS,
            key=b"\xaa" * 32,  # 256-bit for XTS
            ctr_mode=KeyBlobEncryptionIeeCtrModes.AesCTRWAddress,
            aes_counter=b"\xcc" * 16,
            page_offset=0,
            region_number=1,
        )
        data = msg.command_data
        assert len(data) > 0

    def test_info_method(self) -> None:
        """IEE info() returns formatted string."""
        msg = self._make_iee_ctr()
        msg.status = 0xD6
        info = msg.info()
        assert "IEE" in info


# EleMessageLoadKeyBLob


class TestEleMessageLoadKeyBlob:
    """Tests for EleMessageLoadKeyBLob."""

    def test_export_length(self) -> None:
        """LoadKeyBlob export is 4 + 12 = 16 bytes."""
        keyblob = b"\x00" * 32
        msg = EleMessageLoadKeyBLob(key_identifier=0x01, keyblob=keyblob)
        msg.set_buffer_params(0x1000, 0x400)
        data = msg.export()
        assert len(data) == 16

    def test_command_data_is_keyblob(self) -> None:
        """command_data returns the keyblob bytes."""
        keyblob = b"\xab" * 32
        msg = EleMessageLoadKeyBLob(key_identifier=0x01, keyblob=keyblob)
        assert msg.command_data == keyblob

    def test_info_method(self) -> None:
        """info() includes key ID and blob size."""
        keyblob = b"\x00" * 16
        msg = EleMessageLoadKeyBLob(key_identifier=0x07, keyblob=keyblob)
        msg.status = 0xD6
        info = msg.info()
        assert "Key ID" in info


# EleMessageWriteFuse (extended)


class TestEleMessageWriteFuseExtended:
    """Additional tests for EleMessageWriteFuse."""

    def test_export_with_lock(self) -> None:
        """Export sets lock bit in bit_length field when lock=True."""
        msg = EleMessageWriteFuse(bit_position=0, bit_length=32, lock=True, payload=0x1234)
        data = msg.export()
        # bytes 6-7: bit_length with lock bit (0x8000) ORed
        bit_length_word = int.from_bytes(data[6:8], "little")
        assert bit_length_word & 0x8000 != 0

    def test_export_without_lock(self) -> None:
        """Export does not set lock bit when lock=False."""
        msg = EleMessageWriteFuse(bit_position=0, bit_length=32, lock=False, payload=0x1234)
        data = msg.export()
        bit_length_word = int.from_bytes(data[6:8], "little")
        assert bit_length_word & 0x8000 == 0

    def test_decode_response_processed_idx(self) -> None:
        """decode_response extracts processed_idx."""
        msg = EleMessageWriteFuse(bit_position=0, bit_length=32, lock=False, payload=0)
        processed_idx = 42
        payload = pack(LITTLE_ENDIAN + UINT16 + UINT16, processed_idx, 0)
        response = make_response(cmd=msg.CMD, size=msg.response_words_count, payload=payload)
        msg.decode_response(response)
        assert msg.processed_idx == processed_idx


# EleMessageWriteShadowFuse


class TestEleMessageWriteShadowFuse:
    """Tests for EleMessageWriteShadowFuse."""

    def test_export_length(self) -> None:
        """WriteShadowFuse export is 4 + 8 = 12 bytes."""
        msg = EleMessageWriteShadowFuse(index=10, value=0xDEAD)
        assert len(msg.export()) == 12

    def test_export_fields(self) -> None:
        """Export contains correct index and value."""
        msg = EleMessageWriteShadowFuse(index=5, value=0x12345678)
        data = msg.export()
        assert int.from_bytes(data[4:8], "little") == 5
        assert int.from_bytes(data[8:12], "little") == 0x12345678


# Simple no-payload messages


class TestSimpleMessages:
    """Tests for simple messages that have only a header."""

    def test_enable_apc_export(self) -> None:
        """EleMessageEnableApc export is 4 bytes."""
        msg = EleMessageEnableApc()
        assert len(msg.export()) == 4

    def test_enable_rtc_export(self) -> None:
        """EleMessageEnableRtc export is 4 bytes."""
        msg = EleMessageEnableRtc()
        assert len(msg.export()) == 4

    def test_reset_apc_context_export(self) -> None:
        """EleMessageResetApcContext export is 4 bytes."""
        msg = EleMessageResetApcContext()
        assert len(msg.export()) == 4

    def test_release_container_cmd(self) -> None:
        """EleMessageReleaseContainer CMD is set."""
        assert EleMessageReleaseContainer.CMD == 0x89


# EleMessageSessionOpen


class TestEleMessageSessionOpen:
    """Tests for EleMessageSessionOpen."""

    def test_export_length(self) -> None:
        """SessionOpen export is 4+8=12 bytes."""
        msg = EleMessageSessionOpen()
        data = msg.export()
        assert len(data) == 12

    def test_export_version_is_hsm(self) -> None:
        """SessionOpen uses HSM version (0x07)."""
        msg = EleMessageSessionOpen()
        data = msg.export()
        assert data[0] == VERSION_HSM

    def test_decode_response_success(self) -> None:
        """SessionOpen decodes session handle."""
        msg = EleMessageSessionOpen()
        handle = 0xDEAD_CAFE
        payload = handle.to_bytes(4, "little")
        response = make_response(
            cmd=msg.CMD, size=msg.response_words_count, payload=payload, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.session_handle == handle
        assert msg.is_session_valid()

    def test_decode_response_bad_tag_raises(self) -> None:
        """SessionOpen decode raises on invalid tag."""
        msg = EleMessageSessionOpen()
        bad = pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8, VERSION_HSM, 3, msg.CMD, 0xFF)
        bad += pack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, 0xD6, 0, 0)
        with pytest.raises(SPSDKParsingError):
            msg.decode_response(bad)

    def test_get_session_handle_default(self) -> None:
        """get_session_handle returns 0 before response."""
        msg = EleMessageSessionOpen()
        assert msg.get_session_handle() == 0

    def test_is_session_valid_false_on_zero_handle(self) -> None:
        """is_session_valid returns False when handle is 0."""
        msg = EleMessageSessionOpen()
        assert msg.is_session_valid() is False

    def test_response_info(self) -> None:
        """response_info formats session handle."""
        msg = EleMessageSessionOpen()
        msg.session_handle = 0
        assert "failed" in msg.response_info().lower()

    def test_info_method(self) -> None:
        """info() includes Session Open info."""
        msg = EleMessageSessionOpen()
        msg.status = 0xD6
        assert "Session" in msg.info()


# EleMessageSessionClose


class TestEleMessageSessionClose:
    """Tests for EleMessageSessionClose."""

    def test_export_length(self) -> None:
        """SessionClose export is 4+4=8 bytes."""
        msg = EleMessageSessionClose(session_handle=0xABCD1234)
        assert len(msg.export()) == 8

    def test_export_version_is_hsm(self) -> None:
        """SessionClose uses HSM version (0x07)."""
        msg = EleMessageSessionClose(session_handle=0x1234)
        assert msg.export()[0] == VERSION_HSM

    def test_export_contains_handle(self) -> None:
        """SessionClose export contains session handle."""
        handle = 0xDEAD_CAFE
        msg = EleMessageSessionClose(session_handle=handle)
        data = msg.export()
        assert handle.to_bytes(4, "little") in data

    def test_decode_response_success(self) -> None:
        """SessionClose decodes response successfully."""
        msg = EleMessageSessionClose(session_handle=0x1234)
        response = make_response(
            cmd=msg.CMD, size=msg.response_header_words_count, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.status == 0xD6

    def test_info_method(self) -> None:
        """info() includes session handle info."""
        msg = EleMessageSessionClose(session_handle=0xABCD)
        msg.status = 0xD6
        assert "Session" in msg.info()


# EleMessageSabInit


class TestEleMessageSabInit:
    """Tests for EleMessageSabInit."""

    def test_export_is_header(self) -> None:
        """SabInit export is 4 bytes (header only)."""
        msg = EleMessageSabInit()
        data = msg.export()
        assert len(data) == 4

    def test_export_version_is_hsm(self) -> None:
        """SabInit uses HSM version (0x07)."""
        msg = EleMessageSabInit()
        assert msg.export()[0] == VERSION_HSM

    def test_decode_response_success(self) -> None:
        """SabInit decodes response correctly."""
        msg = EleMessageSabInit()
        response = make_response(
            cmd=msg.CMD, size=msg.response_header_words_count, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.status == 0xD6

    def test_info_method(self) -> None:
        """SabInit info() contains SAB Init text."""
        msg = EleMessageSabInit()
        msg.status = 0xD6
        assert "SAB" in msg.info()


# EleMessageKeyStoreOpen


class TestEleMessageKeyStoreOpen:
    """Tests for EleMessageKeyStoreOpen."""

    def test_export_length(self) -> None:
        """KeyStoreOpen export: header(4)+payload_no_crc(16)+crc(4)=24 bytes."""
        msg = EleMessageKeyStoreOpen(session_handle=0x1234, key_store_id=0x5678, nonce=0xABCD)
        data = msg.export()
        # payload_without_crc: UINT32*3 + UINT16 + UINT8 + UINT8 = 12+2+1+1=16 bytes
        assert len(data) == 24

    def test_flags_create(self) -> None:
        """flags property includes FLAG_CREATE_KEYSTORE."""
        msg = EleMessageKeyStoreOpen(
            session_handle=0, key_store_id=0, nonce=0, create_keystore=True
        )
        assert msg.flags & EleMessageKeyStoreOpen.FLAG_CREATE_KEYSTORE != 0

    def test_flags_shared(self) -> None:
        """flags property includes FLAG_SHARED_KEYSTORE."""
        msg = EleMessageKeyStoreOpen(
            session_handle=0, key_store_id=0, nonce=0, shared_keystore=True
        )
        assert msg.flags & EleMessageKeyStoreOpen.FLAG_SHARED_KEYSTORE != 0

    def test_flags_sync(self) -> None:
        """flags property includes FLAG_SYNC_OPERATION."""
        msg = EleMessageKeyStoreOpen(session_handle=0, key_store_id=0, nonce=0, sync_operation=True)
        assert msg.flags & EleMessageKeyStoreOpen.FLAG_SYNC_OPERATION != 0

    def test_flags_monotonic_counter(self) -> None:
        """flags property includes FLAG_MONOTONIC_COUNTER_INCREMENT."""
        msg = EleMessageKeyStoreOpen(
            session_handle=0, key_store_id=0, nonce=0, monotonic_counter_increment=True
        )
        assert msg.flags & EleMessageKeyStoreOpen.FLAG_MONOTONIC_COUNTER_INCREMENT != 0

    def test_flags_none(self) -> None:
        """flags is 0 when no flags are set."""
        msg = EleMessageKeyStoreOpen(session_handle=0, key_store_id=0, nonce=0)
        assert msg.flags == 0

    def test_decode_response_success(self) -> None:
        """KeyStoreOpen decodes key store handle."""
        msg = EleMessageKeyStoreOpen(session_handle=0x1234, key_store_id=0, nonce=0)
        ks_handle = 0xDEAD_CAFE
        payload = ks_handle.to_bytes(4, "little")
        response = make_response(
            cmd=msg.CMD, size=msg.response_words_count, payload=payload, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.key_store_handle == ks_handle
        assert msg.is_key_store_valid()

    def test_get_key_store_handle(self) -> None:
        """get_key_store_handle returns 0 before response."""
        msg = EleMessageKeyStoreOpen(session_handle=0, key_store_id=0, nonce=0)
        assert msg.get_key_store_handle() == 0

    def test_response_info_failed(self) -> None:
        """response_info reports failure when handle is 0."""
        msg = EleMessageKeyStoreOpen(session_handle=0, key_store_id=0, nonce=0)
        assert "failed" in msg.response_info().lower()

    def test_response_info_success(self) -> None:
        """response_info reports success when handle is non-zero."""
        msg = EleMessageKeyStoreOpen(session_handle=0, key_store_id=0, nonce=0)
        msg.key_store_handle = 0xABCD
        assert "successfully" in msg.response_info().lower()

    def test_info_method(self) -> None:
        """info() includes Key Store Open details."""
        msg = EleMessageKeyStoreOpen(session_handle=0xABCD, key_store_id=0x1234, nonce=0)
        msg.status = 0xD6
        assert "Key Store" in msg.info()


# EleMessagePublicKeyExport


class TestEleMessagePublicKeyExport:
    """Tests for EleMessagePublicKeyExport."""

    def test_export_length(self) -> None:
        """PublicKeyExport export: header(4)+payload_no_crc(20)+crc(4)=28 bytes."""
        msg = EleMessagePublicKeyExport(key_store_handle=0x1234, key_id=0x01)
        msg.set_buffer_params(0x1000, 0x1000)
        data = msg.export()
        # payload_without_crc: UINT32*4 + UINT16*2 = 16+4=20 bytes
        assert len(data) == 28

    def test_decode_response_success(self) -> None:
        """PublicKeyExport decodes output size from response."""
        msg = EleMessagePublicKeyExport(key_store_handle=0x1234, key_id=0x01, output_buffer_size=64)
        output_size = 64
        payload = pack(LITTLE_ENDIAN + UINT32 + UINT32, 0, output_size)
        response = make_response(
            cmd=msg.CMD, size=msg.response_words_count, payload=payload, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.status == 0xD6


# EleMessageKeyStoreClose


class TestEleMessageKeyStoreClose:
    """Tests for EleMessageKeyStoreClose."""

    def test_export_length(self) -> None:
        """KeyStoreClose export is 4+4=8 bytes."""
        msg = EleMessageKeyStoreClose(key_store_handle=0xABCD)
        assert len(msg.export()) == 8

    def test_export_version_is_hsm(self) -> None:
        """KeyStoreClose uses HSM version (0x07)."""
        msg = EleMessageKeyStoreClose(key_store_handle=0)
        assert msg.export()[0] == VERSION_HSM

    def test_export_contains_handle(self) -> None:
        """Export contains the key store handle."""
        handle = 0xDEAD_BEEF
        msg = EleMessageKeyStoreClose(key_store_handle=handle)
        data = msg.export()
        assert handle.to_bytes(4, "little") in data

    def test_decode_response_success(self) -> None:
        """KeyStoreClose decodes response successfully."""
        msg = EleMessageKeyStoreClose(key_store_handle=0x1234)
        response = make_response(
            cmd=msg.CMD, size=msg.response_header_words_count, version=VERSION_HSM
        )
        msg.decode_response(response)
        assert msg.status == 0xD6


# EleMessageDumpDebugBuffer


class TestEleMessageDumpDebugBuffer:
    """Tests for EleMessageDumpDebugBuffer."""

    def test_export_is_header(self) -> None:
        """DumpDebugBuffer export is 4 bytes."""
        msg = EleMessageDumpDebugBuffer()
        assert len(msg.export()) == 4

    def test_decode_response_with_no_logs(self) -> None:
        """DumpDebugBuffer decodes response with no debug logs."""
        msg = EleMessageDumpDebugBuffer()
        # size=2 means header words only; nb_logs = 2-2 = 0
        response = make_response(cmd=msg.CMD, size=2)
        msg.decode_response(response)
        assert msg.nb_logs == 0

    def test_decode_response_with_logs(self) -> None:
        """DumpDebugBuffer decodes response with debug logs (size=5: 2 header + 2 logs + 1 CRC)."""
        msg = EleMessageDumpDebugBuffer()
        log1 = (0xDEAD_BEEF).to_bytes(4, "little")
        log2 = (0xCAFE_BABE).to_bytes(4, "little")
        # Build header and status first so we can compute CRC
        header_bytes = make_response(cmd=msg.CMD, size=5)  # 8-byte header+status
        # The CRC is computed over response[0:debug_data_end] where debug_data_end=8+2*4=16
        crc_input = header_bytes + log1 + log2
        crc_bytes = EleMessage.get_msg_crc(crc_input)
        payload = log1 + log2 + crc_bytes
        # Reconstruct response with correct CRC
        response = header_bytes + payload
        msg.decode_response(response)
        assert msg.nb_logs == 2


# EleMessageGetInfo - attribute formatters


class TestEleMessageGetInfoAttributes:
    """Additional tests for EleMessageGetInfo attribute formatting."""

    def _make_populated_msg(self) -> EleMessageGetInfo:
        msg = EleMessageGetInfo()
        msg.info_cmd = 0xDA
        msg.info_version = 1
        msg.info_length = 92
        msg.info_soc_id = 0x9300
        msg.info_soc_rev = 0x1000
        msg.info_life_cycle = 0x0020
        msg.info_sssm_state = 0
        msg.info_attest_api_version = 0
        msg.info_uuid = b"\xaa" * 16
        msg.info_sha256_rom_patch = b"\xbb" * 32
        msg.info_sha256_fw = b"\xcc" * 32
        msg.info_oem_srkh = b"\xdd" * 32 + b"\x00" * 32  # second half zeros → short form
        msg.info_imem_state = 0
        msg.info_csal_state = 0
        msg.info_trng_state = 0
        msg.info_oem_pqc_srkh = b""
        return msg

    def test_get_attribute_cmd(self) -> None:
        """get_attribute('cmd') returns hex string."""
        msg = self._make_populated_msg()
        result = msg.get_attribute("cmd")
        assert result is not None
        assert "0xda" in result.lower()

    def test_get_attribute_uuid(self) -> None:
        """get_attribute('uuid') returns hex-encoded UUID."""
        msg = self._make_populated_msg()
        result = msg.get_attribute("uuid")
        assert result is not None
        assert "aa" * 16 in result.lower()

    def test_get_attribute_oem_pqc_srkh_empty(self) -> None:
        """get_attribute('oem_pqc_srkh') returns 'Not available' when empty."""
        msg = self._make_populated_msg()
        result = msg.get_attribute("oem_pqc_srkh")
        assert result is not None
        assert "Not available" in result

    def test_get_attribute_oem_pqc_srkh_present(self) -> None:
        """get_attribute('oem_pqc_srkh') returns hex when non-empty."""
        msg = self._make_populated_msg()
        msg.info_oem_pqc_srkh = b"\xee" * 64
        result = msg.get_attribute("oem_pqc_srkh")
        assert result is not None
        assert "ee" * 4 in result.lower()

    def test_get_attribute_oem_srkh_full(self) -> None:
        """get_attribute('oem_srkh') returns full hash when second half non-zero."""
        msg = self._make_populated_msg()
        msg.info_oem_srkh = b"\xdd" * 64  # both halves non-zero
        result = msg.get_attribute("oem_srkh")
        assert result is not None
        assert len(result) > 60  # should contain full hex string

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Unit tests for UbootSerial port and baudrate parsing."""

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_serial_open() -> Generator[None, None, None]:
    """Patch Serial and autoboot interrupt so UbootSerial can be constructed without hardware."""
    with (
        patch("spsdk.uboot.uboot.Serial") as mock_serial_cls,
        patch.object(
            __import__("spsdk.uboot.uboot", fromlist=["UbootSerial"]).UbootSerial,
            "open",
            return_value=None,
        ),
    ):
        mock_serial_cls.return_value = MagicMock()
        yield


class TestUbootSerialPortParsing:
    """Tests for UbootSerial 'port,baudrate' CLI string parsing."""

    def _make(self, port: str, **kwargs: Any) -> Any:
        """Create UbootSerial without opening the real serial port."""
        from spsdk.uboot.uboot import UbootSerial

        with patch.object(UbootSerial, "open", return_value=None):
            return UbootSerial(port, **kwargs)

    def test_plain_port_uses_default_baudrate(self) -> None:
        """Plain port string keeps default 115200 baudrate."""
        obj = self._make("/dev/ttyUSB0")
        assert obj.port == "/dev/ttyUSB0"
        assert obj.baudrate == 115200

    def test_port_with_baudrate_is_parsed(self) -> None:
        """'port,baudrate' string is split correctly."""
        obj = self._make("/dev/ttyACM0,9600")
        assert obj.port == "/dev/ttyACM0"
        assert obj.baudrate == 9600

    def test_port_with_hex_baudrate(self) -> None:
        """Baudrate expressed as hex literal is parsed correctly."""
        obj = self._make("COM3,0x1C200")  # 0x1C200 == 115200
        assert obj.port == "COM3"
        assert obj.baudrate == 115200

    def test_explicit_baudrate_overridden_by_port_string(self) -> None:
        """Baudrate embedded in port string takes precedence over kwarg."""
        obj = self._make("/dev/ttyUSB0,57600", baudrate=9600)
        assert obj.baudrate == 57600

    def test_windows_com_port_no_baudrate(self) -> None:
        """Windows COM port without baudrate keeps default."""
        obj = self._make("COM1")
        assert obj.port == "COM1"
        assert obj.baudrate == 115200

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication with a FRDM target device using BUSPAL protocol."""

import logging
import struct
from enum import Enum
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKError

from .base import Interface
from .buspal import BBConstants, Buspal, BuspalMode

logger = logging.getLogger(__name__)


def scan_buspal_i2c(
    port: Optional[str] = None,
    timeout: int = Buspal.DEFAULT_TIMEOUT,
    props: Optional[List[str]] = None,
) -> List[Interface]:
    """Scan connected serial ports and set BUSPAL properties.

    Returns list of serial ports with devices that respond to BUSPAL communication protocol.
    If 'port' is specified, only that serial port is checked
    If no devices are found, return an empty list.

    :param port: name of preferred serial port, defaults to None
    :param timeout: timeout in milliseconds
    :param props: buspal target properties
    :return: list of available interfaces
    """
    return BuspalI2C.scan_buspal(port, timeout, props)


# pylint: disable=invalid-name  # changing names is fairly dangerous
class I2cModeCommand(Enum):
    """I2c mode commands."""

    exit = 0x00  # 00000000 - Exit to bit bang mode
    version = 0x01  # 00000001 - Display mode version string, responds "I2Cx"
    start_bit = 0x02  # 00000010 - I2C start bit
    stop_bit = 0x03  # 00000011 - I2C stop bit
    read_byte = 0x04  # 00000100 - I2C read byte
    ack_bit = 0x06  # 00000110 - ACK bit
    nack_bit = 0x07  # 00000111 - NACK bit
    bus_sniff = 0x0F  # 00001111 - Start bus sniffer
    bulk_write = 0x10  # 0001xxxx - Bulk I2C write, send 1-16 bytes (0=1byte!)
    configure_periph = 0x40  # 0100wxyz - Configure peripherals w=power, x=pullups, y=AUX, z=CS
    pull_up_select = 0x50  # 010100xy - Pull up voltage select (BPV4 only)- x=5v y=3.3v
    set_speed = 0x60  # 011000xx - Set I2C speed, 3=~400kHz, 2=~100kHz, 1=~50kHz, 0=~5kHz (updated in v4.2 firmware)
    set_address = 0x70  # 11100000 - Set I2C address
    write_then_read = 0x08  # Write then read


class BuspalI2C(Buspal):
    """BUSPAL I2C interface."""

    TARGET_SETTINGS = ["speed", "address"]

    HDR_FRAME_RETRY_CNT = 3

    def __init__(self, port: str, timeout: int):
        """Initialize the BUSPAL I2C interface.

        :param port: name of the serial port, defaults to None
        :param timeout: read/write timeout in milliseconds
        """
        self.mode = BuspalMode.i2c
        super().__init__(port, timeout)

    def configure(self, props: List[str]) -> None:
        """Initialize the BUSPAL I2C interface.

        :param props: buspal settings
        """
        i2c_props: Dict[str, Any] = dict(zip(self.TARGET_SETTINGS, props))

        # get I2C configuration values, use default values if settings are not defined in input string)
        speed = int(i2c_props.get("speed", 100))
        address = int(i2c_props.get("address", 0x10))

        # set I2C address
        logger.debug(f"Set I2C address to {address}")
        i2c_data = struct.pack("<BB", I2cModeCommand.set_address.value, address)
        self._send_command_check_response(i2c_data, bytes([BBConstants.response_ok.value]))

        # set I2C speed."""
        logger.debug(f"Set I2C speed to {speed}bps")
        i2c_data = struct.pack("<BI", I2cModeCommand.set_speed.value, speed)
        self._send_command_check_response(i2c_data, bytes([BBConstants.response_ok.value]))

    def _send_frame(
        self, frames: bytes, wait_for_ack: bool = True, retry_cnt: int = HDR_FRAME_RETRY_CNT
    ) -> None:
        """Send a frame to BUSPAL I2C device.

        :param frames: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        :param retry_cnt: Number of retry in case the header frame is incorrect
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        """
        size = min(len(frames), BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", I2cModeCommand.write_then_read.value, size, 0)
        self._write(command)
        self._send_command_check_response(frames, bytes([BBConstants.response_ok.value]))
        if wait_for_ack:
            try:
                self._read_frame_header()
            except AssertionError as error:
                # retry reading the I2C header frame in case check has failed
                if retry_cnt > 0:
                    logger.error(
                        f"{error} (retry {self.HDR_FRAME_RETRY_CNT-retry_cnt+1}/{self.HDR_FRAME_RETRY_CNT})"
                    )
                    retry_cnt -= 1
                    self._send_frame(frames, wait_for_ack, retry_cnt)
                else:
                    raise SPSDKError("Failed retrying reading the I2C header frame")

    def _read_default(self, size: int) -> bytes:
        """Read 'length' amount of bytes from BUSPAL I2C device.

        :return: Data read from the device
        """
        size = min(size, BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", I2cModeCommand.write_then_read.value, 0, size)
        self._send_command_check_response(command, bytes([BBConstants.response_ok.value]))
        return self._read(size)

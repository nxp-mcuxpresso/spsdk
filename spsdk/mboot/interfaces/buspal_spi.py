#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication with a FRDM target device using BUSPAL protocol."""

import logging
import struct
import time
from enum import Enum
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKError

from .base import Interface
from .buspal import BBConstants, Buspal, BuspalMode

logger = logging.getLogger(__name__)


def scan_buspal_spi(
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
    return BuspalSPI.scan_buspal(port, timeout, props)


# pylint: disable=invalid-name
class SpiModeCommand(Enum):
    """Spi mode commands."""

    exit = 0x00  # 00000000 - Exit to bit bang mode
    version = 0x01  # 00000001 - Enter raw SPI mode, display version string
    chip_select = 0x02  # 0000001x - CS high (1) or low (0)
    sniff = 0x0C  # 000011XX - Sniff SPI traffic when CS low(10)/all(01)
    bulk_transfer = 0x10  # 0001xxxx - Bulk SPI transfer, send/read 1-16 bytes (0=1byte!)
    config_periph = 0x40  # 0100wxyz - Configure peripherals w=power, x=pull-ups, y=AUX, z=CS
    set_speed = 0x60  # 01100xxx - SPI speed
    config_spi = 0x80  # 1000wxyz - SPI config, w=HiZ/3.3v, x=CKP idle, y=CKE edge, z=SMP sample
    write_then_read = 0x04  # 00000100 - Write then read extended command


# pylint: disable=invalid-name
class SpiConfigShift(Enum):
    """Spi configuration shifts for the mask."""

    direction = 0
    phase = 1
    polarity = 2


# pylint: disable=invalid-name
class SpiClockPolarity(Enum):
    """SPI clock polarity configuration."""

    active_high = 0  # Active-high SPI clock (idles low).
    active_low = 1  # Active-low SPI clock (idles high).


# pylint: disable=invalid-name
class SpiClockPhase(Enum):
    """SPI clock phase configuration."""

    # First edge on SPSCK occurs at the middle of the first cycle of a data transfer.
    first_edge = 0
    # First edge on SPSCK occurs at the start of the first cycle of a data transfer.
    second_edge = 1


# pylint: disable=invalid-name
class SpiShiftDirection(Enum):
    """SPI clock phase configuration."""

    msb_first = 0  # Data transfers start with most significant bit.
    lsb_first = 1  # Data transfers start with least significant bit.


class SpiConfiguration:
    """Dataclass to store SPI configuration."""

    speed: int
    polarity: SpiClockPolarity
    phase: SpiClockPhase
    direction: SpiShiftDirection


class BuspalSPI(Buspal):
    """BUSPAL SPI interface."""

    TARGET_SETTINGS = ["speed", "polarity", "phase", "direction"]

    HDR_FRAME_RETRY_CNT = 3
    ACK_WAIT_DELAY = 0.01  # in seconds

    def __init__(self, port: str, timeout: int):
        """Initialize the BUSPAL SPI interface.

        :param port: name of the serial port, defaults to None
        :param timeout: read/write timeout in milliseconds
        """
        self.mode = BuspalMode.spi
        super().__init__(port, timeout)

    def configure(self, props: List[str]) -> None:
        """Configure the BUSPAL SPI interface.

        :param props: buspal settings
        """
        spi_props: Dict[str, Any] = dict(zip(self.TARGET_SETTINGS, props))

        speed = int(spi_props.get("speed", 100))
        polarity = SpiClockPolarity(spi_props.get("polarity", SpiClockPolarity.active_low))
        phase = SpiClockPhase(spi_props.get("phase", SpiClockPhase.second_edge))
        direction = SpiShiftDirection(spi_props.get("direction", SpiShiftDirection.msb_first))

        # set SPI config
        logger.debug("Set SPI config")
        spi_data = polarity.value << SpiConfigShift.polarity.value
        spi_data |= phase.value << SpiConfigShift.phase.value
        spi_data |= direction.value << SpiConfigShift.direction.value
        spi_data |= SpiModeCommand.config_spi.value
        self._send_command_check_response(bytes([spi_data]), bytes([BBConstants.response_ok.value]))

        # set SPI speed
        logger.debug(f"Set SPI speed to {speed}bps")
        spi_speed = struct.pack("<BI", SpiModeCommand.set_speed.value, speed)
        self._send_command_check_response(spi_speed, bytes([BBConstants.response_ok.value]))

    def _send_frame(
        self, frames: bytes, wait_for_ack: bool = True, retry_cnt: int = HDR_FRAME_RETRY_CNT
    ) -> None:
        """Send a frame to BUSPAL SPI device.

        :param frames: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        :param retry_cnt: Number of retry in case the header frame is incorrect
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        """
        size = min(len(frames), BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", SpiModeCommand.write_then_read.value, size, 0)
        self._write(command)
        self._send_command_check_response(frames, bytes([BBConstants.response_ok.value]))
        if wait_for_ack:
            try:
                # minimum delay between ack and response is 5-7ms
                time.sleep(self.ACK_WAIT_DELAY)
                self._read_frame_header()
            except AssertionError as error:
                # retry reading the SPI header frame in case check has failed
                if retry_cnt > 0:
                    logger.error(
                        f"{error} (retry {self.HDR_FRAME_RETRY_CNT-retry_cnt+1}/{self.HDR_FRAME_RETRY_CNT})"
                    )
                    retry_cnt -= 1
                    self._send_frame(frames, wait_for_ack, retry_cnt)
                else:
                    raise SPSDKError("Failed retrying reading the SPI header frame") from error

    def _read_default(self, size: int) -> bytes:
        """Read 'length' amount of bytes from BUSPAL SPI device.

        :return: Data read from the device
        """
        size = min(size, BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", SpiModeCommand.write_then_read.value, 0, size)
        self._send_command_check_response(command, bytes([BBConstants.response_ok.value]))
        return self._read(size)

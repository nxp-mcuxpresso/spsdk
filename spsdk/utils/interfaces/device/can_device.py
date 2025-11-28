#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CAN device interface implementation.

This module provides low-level CAN (Controller Area Network) device communication
interface for SPSDK, enabling reliable data exchange with NXP MCUs over CAN bus.
The CANDevice class implements the base device interface for CAN protocol operations.
"""

from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase, logger
from spsdk.utils.misc import split_data


class CANDevice(DeviceBase):
    """CAN device interface for SPSDK communication.

    This class provides a unified interface for CAN (Controller Area Network) communication
    across NXP MCU portfolio, enabling reliable data exchange for provisioning and debugging
    operations.

    :cvar DEFAULT_TIMEOUT: Default communication timeout in milliseconds (2000ms).
    :cvar DEFAULT_BITRATE: Default CAN bus bitrate (1,000,000 bps).
    :cvar DEFAULT_TX_ARBITRATION_ID: Default transmission arbitration ID (0x321).
    :cvar DEFAULT_RX_ARBITRATION_ID: Default reception arbitration ID (0x123).
    :cvar MAX_MESSAGE_SIZE: Maximum CAN message payload size in bytes (8).
    """

    DEFAULT_TIMEOUT = 2000
    DEFAULT_BITRATE = 1_000_000
    DEFAULT_TX_ARBITRATION_ID = 0x321
    DEFAULT_RX_ARBITRATION_ID = 0x123
    MAX_MESSAGE_SIZE = 8

    def __init__(
        self,
        interface: str,
        channel: Optional[Union[str, int]] = None,
        bitrate: Optional[int] = None,
        timeout: Optional[int] = None,
        txid: Optional[int] = None,
        rxid: Optional[int] = None,
    ) -> None:
        """Initialize the CAN interface object.

        Sets up the CAN communication interface with specified parameters and default values
        for unspecified options.

        :param interface: CAN interface type to use for communication.
        :param channel: CAN channel identifier, can be string or integer.
        :param bitrate: Communication bitrate in bits per second.
        :param timeout: Communication timeout in seconds.
        :param txid: Transmission arbitration ID for outgoing messages.
        :param rxid: Reception arbitration ID for incoming messages.
        """
        self._timeout = timeout or self.DEFAULT_TIMEOUT
        self._opened = False

        self.channel = channel
        self.bitrate = bitrate or self.DEFAULT_BITRATE
        self.interface = interface
        self.txid = txid or self.DEFAULT_TX_ARBITRATION_ID
        self.rxid = rxid or self.DEFAULT_RX_ARBITRATION_ID

        self.device: Optional[Any] = None
        self.listener: Optional[Any] = None

    @property
    def timeout(self) -> int:
        """Get timeout value for CAN device communication.

        :return: Timeout value in milliseconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout value for the device communication.

        :param value: Timeout value in milliseconds for device operations.
        """
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Check if the CAN device is currently opened.

        :return: True if device is open, False otherwise.
        """
        return self.device is not None and self._opened

    def open(self) -> None:
        """Open the CAN bus interface.

        Initializes the CAN bus connection using the configured channel, interface,
        and bitrate. Sets up a buffered reader for incoming messages and configures
        message filtering based on the receive arbitration ID.

        :raises SPSDKError: When python-can package is not installed.
        """
        if not self.device:
            try:
                from can import Bus, Notifier

                from spsdk.utils.interfaces.device.can_utils import BytesBufferedReader
            except ImportError as exc:
                raise SPSDKError(
                    "python-can package is missing, please install it with pip install 'spsdk[can]' in order to use can"
                ) from exc
            self.device = Bus(channel=self.channel, interface=self.interface, bitrate=self.bitrate)
            self.listener = BytesBufferedReader(self.timeout)
            Notifier(self.device, [self.listener])

            # Set filter for arbitration ID
            self.device.set_filters([{"can_id": self.rxid, "can_mask": 0x7FF}])

        self._opened = True

    def close(self) -> None:
        """Close the CAN device interface.

        This method closes the connection to the CAN device and marks the interface
        as no longer opened. After calling this method, the device will not be
        available for communication until opened again.
        """
        self._opened = False

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the CAN device.

        This method retrieves the specified number of bytes from the CAN device through
        the message listener. The operation will fail if the device is not properly
        opened or if no data is available.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in milliseconds, currently not used in implementation.
        :return: Data read from the device as bytes.
        :raises SPSDKTimeoutError: When no data is available to read.
        :raises SPSDKConnectionError: When device is not opened for reading.
        """
        if not self.device or not self.is_opened or not self.listener:
            raise SPSDKConnectionError("Device is not opened for reading")

        data = self.listener.get(length)
        if not data:
            raise SPSDKTimeoutError("Timeout reading the message")

        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to CAN device.

        The method splits data into chunks that fit the maximum CAN message size
        and sends them sequentially to the device using the configured transmission ID.

        :param data: Data bytes to send to the device.
        :param timeout: Write timeout in seconds (currently not used).
        :raises SPSDKConnectionError: When device is not opened or not available.
        :raises SPSDKError: When python-can package is not installed.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing.")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")

        try:
            from can.message import Message
        except ImportError as exc:
            raise SPSDKError(
                "python-can package is missing, please install it with pip install 'spsdk[can]' in order to use can"
            ) from exc
        for splitted_data in split_data(data, self.MAX_MESSAGE_SIZE):
            msg = Message(
                arbitration_id=self.txid,
                data=list(splitted_data),
                is_extended_id=False,
            )
            self.device.send(msg)

    def __str__(self) -> str:
        """Return string representation of the CAN device interface.

        Provides a formatted string containing the CAN interface name, channel number,
        and bitrate configuration for debugging and logging purposes.

        :return: Formatted string with CAN interface details.
        """
        return f"CAN interface: {self.interface}, channel: {self.channel}, bitrate: {self.bitrate} "

    @classmethod
    def scan(
        cls,
        interface: str,
        channel: Optional[Union[str, int]] = None,
        bitrate: Optional[int] = None,
        timeout: Optional[int] = None,
        txid: Optional[int] = None,
        rxid: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected CAN devices.

        The method attempts to create and test a CAN device connection with the specified
        parameters. If successful, returns the device in a list, otherwise returns empty list.

        :param interface: CAN interface name or type to use for communication.
        :param channel: CAN channel identifier, can be string or integer.
        :param bitrate: CAN bus bitrate in bits per second.
        :param timeout: Default timeout in seconds for read/write operations.
        :param txid: Default arbitration ID for transmitted messages.
        :param rxid: Default arbitration ID for received messages.
        :return: List containing the matched CAN device if found, empty list otherwise.
        """
        try:
            logger.debug(
                f"Checking device: <Interface> {interface} <Channel> {channel} <Bitrate> {bitrate}"
            )
            device = cls(interface, channel, bitrate, timeout, txid, rxid)
            device.open()
            device.close()
            devices = [device] if device else []
        except Exception as e:  # pylint: disable=broad-except
            logger.error(f"{type(e).__name__}: {e}")
            devices = []
        return devices

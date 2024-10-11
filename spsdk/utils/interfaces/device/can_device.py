#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level CAN device."""
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase, logger
from spsdk.utils.misc import split_data


class CANDevice(DeviceBase):
    """CAN device class."""

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
        """Initialize the CAN interface object."""
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
        """Timeout property."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Timeout property setter."""
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False otherwise.
        """
        return self.device is not None and self._opened

    def open(self) -> None:
        """Open the CAN bus interface."""
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
        """Close the interface."""
        self._opened = False

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKTimeoutError: Time-out
        :raises SPSDKConnectionError: When device was not open for reading
        """
        if not self.device or not self.is_opened or not self.listener:
            raise SPSDKConnectionError("Device is not opened for reading")

        data = self.listener.get(length)
        if not data:
            raise SPSDKTimeoutError("Timeout reading the message")

        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: Raises an error if device is not available
        :raises SPSDKConnectionError: When sending the data fails
        :raises SPSDKError: When the python-can cannot be imported
        :raises TimeoutError: When timeout occurs
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
        """Return information about the CAN interface."""
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

        :param interface: CAN interface
        :param channel: CAN channel
        :param bitrate: CAN bitrate
        :param timeout: default read/write timeout
        :param txid: default arbitration ID for TX
        :param rxid: default arbitration ID for RX
        :return: matched CAN device
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

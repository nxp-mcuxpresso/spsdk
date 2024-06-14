#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CAN utils."""
from queue import Empty, Queue
from typing import Any, Optional

from can import Listener  # pylint: disable=import-error
from can.message import Message  # pylint: disable=import-error

from spsdk.exceptions import SPSDKConnectionError


class ByteFIFO:
    """FIFO Queue for buffering incoming data."""

    def __init__(self, timeout: int) -> None:
        """FIFO Queue for buffering incoming data.

        :param timeout: timeout in ms
        """
        self.buffer: Queue = Queue()
        self.timeout = timeout

    def put(self, data: bytes) -> None:
        """Put data into buffer.

        :param data: bytes
        """
        for byte in data:
            self.buffer.put(byte)

    def get(self, length: int) -> Optional[bytes]:
        """Get data from buffer.

        :param length: length in bytes
        :return: bytes data
        """
        data = bytearray()
        try:
            for _ in range(length):
                data.append(self.buffer.get(block=True, timeout=self.timeout // 1000))
            return bytes(data)
        except Empty:
            return None


class BytesBufferedReader(Listener):  # pylint: disable=abstract-method
    """A BytesBufferedReader is a subclass of Listener implementing buffer.

    When the BytesBufferedReader instance is notified of a new
    message, it pushes it into a queue of bytes waiting to be serviced. The
    data can then be fetched with the get() method.

    :attr is_stopped: ``True`` if the reader has been stopped
    """

    def __init__(self, timeout: int, *args: Any, **kwargs: Any) -> None:
        """Constructor."""
        super().__init__(*args, **kwargs)
        self.buffer = ByteFIFO(timeout)
        self.is_stopped: bool = False

    def on_message_received(self, msg: Message) -> None:
        """Append a message to the buffer.

        :raises: SPSDKConnectionError
            if the reader has already been stopped
        """
        if self.is_stopped:
            raise SPSDKConnectionError("Reader has already been stopped")
        self.buffer.put(msg.data)

    def get(self, length: int) -> Optional[bytes]:
        """Get message from the buffer.

        :param length: length of the data to be read.
        :return: data or None in case data cannot be fetched in time.
        """
        return self.buffer.get(length)

    def on_error(self, exc: Exception) -> None:
        """This method is called to handle any exception in the receive thread.

        :param exc: The exception causing the thread to stop
        """
        raise SPSDKConnectionError(f"Error in buffer reader: {exc}") from exc

    def stop(self) -> None:
        """Prohibits any more additions to this reader."""
        self.is_stopped = True

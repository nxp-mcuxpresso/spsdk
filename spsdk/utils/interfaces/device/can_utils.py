#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CAN communication utilities.

This module provides utility classes for handling CAN bus communication
in SPSDK context, including buffered data reading and FIFO queue management
for CAN message processing.
"""

from queue import Empty, Queue
from typing import Any, Optional

from can import Listener  # pylint: disable=import-error
from can.message import Message  # pylint: disable=import-error

from spsdk.exceptions import SPSDKConnectionError


class ByteFIFO:
    """Byte-oriented FIFO queue for buffering incoming data streams.

    This class provides a thread-safe buffer for storing and retrieving individual bytes
    from incoming data streams with configurable timeout support. It manages byte-level
    queuing operations commonly used in communication interfaces.
    """

    def __init__(self, timeout: int) -> None:
        """Initialize FIFO Queue for buffering incoming CAN data.

        :param timeout: Timeout value in milliseconds for queue operations.
        """
        self.buffer: Queue = Queue()
        self.timeout = timeout

    def put(self, data: bytes) -> None:
        """Put data into buffer.

        The method iterates through the provided bytes and puts each byte
        individually into the internal buffer.

        :param data: Byte data to be stored in the buffer.
        """
        for byte in data:
            self.buffer.put(byte)

    def get(self, length: int) -> Optional[bytes]:
        """Get data from buffer.

        Retrieves the specified number of bytes from the internal buffer with timeout handling.

        :param length: Number of bytes to retrieve from buffer.
        :return: Retrieved bytes data if successful, None if timeout occurs.
        """
        data = bytearray()
        try:
            for _ in range(length):
                data.append(self.buffer.get(block=True, timeout=self.timeout // 1000))
            return bytes(data)
        except Empty:
            return None


class BytesBufferedReader(Listener):  # pylint: disable=abstract-method
    """Buffered message reader for CAN communication.

    This class extends the Listener interface to provide buffered reading of CAN
    messages. Incoming messages are queued in a FIFO buffer and can be retrieved
    on demand, enabling asynchronous message processing in SPSDK CAN operations.
    """

    def __init__(self, timeout: int, *args: Any, **kwargs: Any) -> None:
        """Initialize CAN utility interface.

        Sets up the CAN communication interface with a timeout-based buffer and
        initializes the stopped state flag.

        :param timeout: Timeout value in milliseconds for buffer operations.
        :param args: Additional positional arguments passed to parent class.
        :param kwargs: Additional keyword arguments passed to parent class.
        """
        super().__init__(*args, **kwargs)
        self.buffer = ByteFIFO(timeout)
        self.is_stopped: bool = False

    def on_message_received(self, msg: Message) -> None:
        """Append a message to the buffer.

        :param msg: CAN message to be appended to the buffer.
        :raises SPSDKConnectionError: If the reader has already been stopped.
        """
        if self.is_stopped:
            raise SPSDKConnectionError("Reader has already been stopped")
        self.buffer.put(msg.data)

    def get(self, length: int) -> Optional[bytes]:
        """Get message from the buffer.

        :param length: Length of the data to be read.
        :return: Data bytes if available, None if data cannot be fetched in time.
        """
        return self.buffer.get(length)

    def on_error(self, exc: Exception) -> None:
        """Handle exceptions that occur in the receive thread.

        This method is called when an exception occurs in the receive thread and
        converts it to an SPSDKConnectionError for proper error handling.

        :param exc: The exception that caused the thread to stop.
        :raises SPSDKConnectionError: Always raised with details about the original exception.
        """
        raise SPSDKConnectionError(f"Error in buffer reader: {exc}") from exc

    def stop(self) -> None:
        """Stop the reader and prohibit any more additions.

        This method sets the internal stopped state to prevent further data
        from being added to the reader instance.
        """
        self.is_stopped = True

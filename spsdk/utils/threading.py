#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK threading utilities for concurrent operations.

This module provides thread-safe utilities and helpers for managing
concurrent operations within SPSDK applications, including cancellable
waiting mechanisms and thread synchronization primitives.
"""

import logging
import threading
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CancellableWait:
    """SPSDK threading utility for interruptible operations.

    This class enables keyboard interrupt handling during blocking C library calls by executing
    operations in separate threads with periodic interrupt checking. It provides a mechanism
    to make otherwise non-interruptible operations responsive to user cancellation requests.
    """

    def __init__(self) -> None:
        """Initialize the InterruptibleWait instance.

        Sets up the initial state with result value, exception placeholder, and threading event
        for coordinating interruptible operations.
        """
        self.result: int = 0
        self.exception: Optional[Exception] = None
        self.finished = threading.Event()

    def _target_function(self, func: Callable, *args: Any, **kwargs: Any) -> None:
        """Execute function in a separate thread and capture results.

        This method serves as the target function for thread execution, handling
        both successful results and exceptions that may occur during function
        execution.

        :param func: The callable function to execute in the thread.
        :param args: Positional arguments to pass to the function.
        :param kwargs: Keyword arguments to pass to the function.
        """
        try:
            self.result = func(*args, **kwargs)
        except Exception as e:
            self.exception = e
        finally:
            self.finished.set()

    def run_interruptible(
        self, func: Callable, *args: Any, timeout_check_interval: float = 0.1, **kwargs: Any
    ) -> int:
        """Run a function in a separate thread and make it interruptible.

        This method executes the provided function in a daemon thread while periodically checking
        for keyboard interrupts. If an interrupt is detected, the method raises KeyboardInterrupt
        while the background thread may continue running.

        :param func: Function to call in the separate thread.
        :param timeout_check_interval: How often to check for interrupts in seconds.
        :param args: Positional arguments to pass to the function.
        :param kwargs: Keyword arguments to pass to the function.
        :return: Result of the function call.
        :raises KeyboardInterrupt: If user presses Ctrl+C during execution.
        :raises Exception: Any exception raised by the target function.
        """
        thread = threading.Thread(target=self._target_function, args=(func,) + args, kwargs=kwargs)
        thread.daemon = True
        thread.start()

        try:
            while thread.is_alive():
                # Wait for a short interval, allowing KeyboardInterrupt to be caught
                if self.finished.wait(timeout_check_interval):
                    break
        except KeyboardInterrupt:
            # The thread will continue running in the background, but we'll exit
            logger.warning(
                "Keyboard interrupt detected. The operation may still be running in the background."
            )
            raise

        if self.exception:
            raise self.exception

        return self.result

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO testing utilities.

This module provides utility functions and decorators for testing EL2GO
functionality, including mocking capabilities for time-related operations
and other test helpers.
"""

from functools import wraps
from typing import Any, Callable, TypeVar, cast
from unittest.mock import patch

F = TypeVar("F", bound=Callable[..., Any])


def mock_time_sleep(func: F) -> F:
    """Mock time.sleep calls in decorated function.

    This decorator patches the time.sleep function to prevent actual delays during testing,
    allowing tests to run faster while maintaining the same code paths.

    :param func: Function to be decorated that contains time.sleep calls.
    :return: Decorated function with time.sleep calls mocked.
    """

    @wraps(func)
    def decorator(*args: Any, **kwargs: Any) -> Any:
        """Decorator that patches time.sleep during function execution.

        This decorator wraps a function call with a mock patch for time.sleep,
        preventing actual sleep delays during test execution while maintaining
        the original function's behavior and return value.

        :param args: Positional arguments to pass to the wrapped function.
        :param kwargs: Keyword arguments to pass to the wrapped function.
        :return: The return value of the wrapped function.
        """
        with patch("time.sleep"):
            return func(*args, **kwargs)

    return cast(F, decorator)

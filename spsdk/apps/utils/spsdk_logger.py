#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK logging utilities with colored console output support.

This module provides enhanced logging functionality for SPSDK applications,
including colored console formatting and standardized logger installation
across the SPSDK toolkit.
"""

import logging
import logging.config
import logging.handlers
import os
import platform
import re
import sys
from datetime import datetime
from typing import Optional, TextIO

import colorama

from spsdk import SPSDK_DEBUG_LOG_FILE, SPSDK_DEBUG_LOGGING_DISABLED, __version__
from spsdk.utils.misc import find_file, load_configuration

colorama.just_fix_windows_console()

try:
    logging_config_file = find_file(
        "logging.yaml", search_paths=["../../", os.path.expanduser("~/.spsdk")]
    )
    config_data = load_configuration(logging_config_file)
    logging.config.dictConfig(config_data)
    print(f"Logging config loaded from {logging_config_file}")
except Exception:
    # no logging config file found
    pass


class ColoredFormatter(logging.Formatter):
    """SPSDK Colored Logging Formatter.

    Custom logging formatter that provides colored console output for different log levels
    with enhanced debug information. Extends Python's standard logging.Formatter to support
    both colored and plain text output modes.

    :cvar COLORED_FORMATS: Color-coded format strings for each logging level.
    :cvar FORMATS: Plain text format strings for each logging level.
    """

    FORMAT = logging.BASIC_FORMAT
    FORMAT_DEBUG = FORMAT + " (%(relativeCreated)dms since start, %(filename)s:%(lineno)d)"

    COLORED_FORMATS = {
        logging.DEBUG: colorama.Fore.BLUE + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.INFO: colorama.Fore.WHITE
        + colorama.Style.BRIGHT
        + FORMAT
        + colorama.Fore.RESET
        + colorama.Style.RESET_ALL,
        logging.WARNING: colorama.Fore.YELLOW + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.ERROR: colorama.Fore.RED + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.CRITICAL: colorama.Fore.RED
        + colorama.Style.BRIGHT
        + FORMAT_DEBUG
        + colorama.Fore.RESET
        + colorama.Style.RESET_ALL,
    }
    FORMATS = {
        logging.DEBUG: FORMAT_DEBUG,
        logging.INFO: FORMAT,
        logging.WARNING: FORMAT_DEBUG,
        logging.ERROR: FORMAT_DEBUG,
        logging.CRITICAL: FORMAT_DEBUG,
    }

    def __init__(
        self,
        colored: bool = True,
    ) -> None:
        """Overloaded init method to add colored parameter."""
        super().__init__()

        self.colored = colored
        self.formats = self.COLORED_FORMATS if colored else self.FORMATS

    def format(self, record: logging.LogRecord) -> str:
        """Modified format method.

        :param record: Input logging record to print.
        :return: Formatted logging string.
        """
        fmt = self.formats.get(record.levelno)
        formatter = logging.Formatter(fmt)
        if not self.colored:
            try:
                record.msg = re.sub(r"\\x1b\[\d{1,3}m", "", record.msg)
            except Exception:
                # Just ignore all exceptions on this "remove color" operation
                pass
        return formatter.format(record)


def install(
    level: Optional[int] = None,
    stream: TextIO = sys.stderr,
    colored: Optional[bool] = None,
    logger: Optional[logging.Logger] = None,
    create_debug_logger: bool = True,
) -> None:
    """Install SPSDK log handler for colored output.

    :param level: logging level, defaults to logging.WARNING
    :param stream: stream to output logging, defaults to sys.stderr
    :param colored: colored output, always colored if true
    :param logger: defaults to root logger
    :param create_debug_logger: create debug logger
    """
    color = True
    if not level:
        level = logging.WARNING

    # Use root logger by default, but allow specifying a different logger
    target_logger = logger or logging.getLogger("spsdk")

    # Set root logger to DEBUG to process all messages
    target_logger.setLevel(logging.DEBUG)

    # This env variable tells us that jupyter notebook is executed
    if "JUPYTER_SPSDK" in os.environ:
        stream = sys.stdout

    # Determine if colored output should be used
    if "NO_COLOR" in os.environ:
        # For details see https://no-color.org/
        color = False
    if not hasattr(stream, "isatty") or not stream.isatty():
        # disable color if the stream is not console
        color = False
    if "JUPYTER_SPSDK" in os.environ:
        # always colored for jupyter
        color = True
    if colored is not None:
        color = colored
        # enforce color if specified in constructor

    # Create and configure console handler
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)  # Only show messages at specified level and above in console
    handler.setFormatter(ColoredFormatter(color))

    # Add the handler to the target logger
    target_logger.addHandler(handler)
    target_logger.propagate = True

    # Create and configure debug file logger if requested
    if create_debug_logger and not SPSDK_DEBUG_LOGGING_DISABLED:
        try:
            if target_logger.hasHandlers():
                for h in target_logger.handlers:
                    if (
                        isinstance(h, logging.handlers.RotatingFileHandler)
                        and h.baseFilename == SPSDK_DEBUG_LOG_FILE
                    ):
                        return  # Prevent multiple debug file handlers
            # Create debug log directory if it doesn't exist
            os.makedirs(os.path.dirname(SPSDK_DEBUG_LOG_FILE), exist_ok=True)
            # Create and configure a rotating file handler
            debug_handler = logging.handlers.RotatingFileHandler(
                SPSDK_DEBUG_LOG_FILE, mode="a", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
            )
            debug_handler.setFormatter(ColoredFormatter(colored=False))
            debug_handler.setLevel(logging.DEBUG)  # Log all DEBUG and above messages to file

            # Add the debug handler directly to the root logger
            # This ensures all messages from all loggers will be captured in the debug log
            target_logger.addHandler(debug_handler)

            # Log debug session header information
            starter = (
                f"* SPSDK DEBUG LOGGING STARTED {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} *"
            )
            padding = len(starter) - 2
            target_logger.debug("*" * len(starter))
            target_logger.debug(starter)
            # pylint: disable=logging-not-lazy  # not sure why this is not an issue anywhere else
            target_logger.debug(f"* SPSDK version: {__version__}".ljust(padding) + " *")
            target_logger.debug(f"* Python version: {sys.version.split()[0]}".ljust(padding) + " *")
            target_logger.debug(f"* OS version: {platform.platform()}".ljust(padding) + " *")
            target_logger.debug(f"* Last command: {sys.argv}".ljust(padding) + " *")
            target_logger.debug("*" * len(starter))
        except Exception as e:
            # If debug logging fails, log a warning but don't crash the application
            target_logger.warning(f"Failed to initialize debug logging: {str(e)}")

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK colored logger."""

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
    """Colored Formatter.

    SPSDK modified formatter class.
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
    logger = logger or logging.getLogger()
    # This env variable tells us that jupyter notebook is executed
    if "JUPYTER_SPSDK" in os.environ:
        stream = sys.stdout
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)
    if "NO_COLOR" in os.environ:
        # For details see https://no-color.org/
        color = False
    if not handler.stream.isatty():
        # disable color if the stream is not console
        color = False
    if "JUPYTER_SPSDK" in os.environ:
        # always colored for jupyter
        color = True
    if colored is not None:
        color = colored
        # enforce color if specified in constructor
    handler.setFormatter(ColoredFormatter(color))
    # Adjust the level of the logger
    if logger.getEffectiveLevel() > level:
        logger.setLevel(level)
    # Install the stream handler
    logger.addHandler(handler)
    logger.propagate = False

    if create_debug_logger and not SPSDK_DEBUG_LOGGING_DISABLED:
        debug_handler = logging.handlers.RotatingFileHandler(
            SPSDK_DEBUG_LOG_FILE, mode="a", maxBytes=1_000_000, backupCount=5
        )
        debug_handler.setFormatter(ColoredFormatter(colored=False))
        debug_handler.setLevel(logging.DEBUG)

        debug_logger = logging.getLogger("spsdk.debug")
        debug_logger.setLevel(logging.DEBUG)
        debug_logger.propagate = False
        debug_logger.addHandler(debug_handler)
        starter = f"* SPSDK DEBUG LOGGING STARTED {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} *"
        padding = len(starter) - 2
        debug_logger.debug("*" * len(starter))
        debug_logger.debug(starter)
        # pylint: disable=logging-not-lazy  # not sure why this is not an issue anywhere else
        debug_logger.debug(f"* SPSDK version: {__version__}".ljust(padding) + " *")
        debug_logger.debug(f"* Python version: {sys.version.split()[0]}".ljust(padding) + " *")
        debug_logger.debug(f"* OS version: {platform.platform()}".ljust(padding) + " *")
        debug_logger.debug("*" * len(starter))

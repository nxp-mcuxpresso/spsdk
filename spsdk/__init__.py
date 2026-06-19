#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK - Secure Provisioning SDK by NXP.

The ultimate toolkit for NXP MCU/MPU development - where security meets simplicity!

WHAT YOU GET:
    - Unified API across the entire NXP MCU/MPU portfolio
    - Enterprise-grade security operations at your fingertips
    - Production-ready from prototype to deployment

MULTIPLE INTERFACES:
    - Pure Python library for custom integrations
    - Powerful CLI tools for automation and scripting

Whether you're a firmware engineer prototyping the next big thing or deploying
mission-critical production systems - SPSDK has got you covered!

Ready to supercharge your NXP development experience? Let's get started!
"""

import logging
import logging.config
import os
import sys
from typing import Optional, Union

from packaging.version import Version, parse
from platformdirs import PlatformDirs

# Custom TRACE log level for detailed communication/protocol data logging.
# TRACE (5) sits below DEBUG (10) and is intended for raw packet/byte-level data.
SPSDK_LOG_LEVEL_TRACE = 5
logging.addLevelName(SPSDK_LOG_LEVEL_TRACE, "TRACE")


class SPSDKLogger(logging.Logger):
    """SPSDK Logger with native TRACE level support.

    Extends the standard Logger with a trace() method for logging
    low-level communication data (packets, bytes, hex dumps).
    """

    def trace(self, message: str, *args: object, **kwargs: object) -> None:
        """Log a message at TRACE level on this logger."""
        if self.isEnabledFor(SPSDK_LOG_LEVEL_TRACE):
            self._log(SPSDK_LOG_LEVEL_TRACE, message, args, **kwargs)  # type: ignore[arg-type]


def get_logger(name: str) -> SPSDKLogger:
    """Get a typed SPSDK logger with TRACE level support.

    This function safely creates SPSDKLogger instances within the 'spsdk' namespace,
    ensuring proper logging hierarchy when SPSDK is used as a subpackage.
    It does not affect the global logging system or other packages.

    :param name: Logger name, typically __name__.
    :return: SPSDKLogger instance with TRACE level support.
    """
    # Ensure logger is in spsdk hierarchy
    if not name.startswith("spsdk"):
        full_name = f"spsdk.{name}"
    else:
        full_name = name

    # Temporarily set SPSDKLogger class, get the logger, then restore
    original_class = logging.getLoggerClass()
    try:
        logging.setLoggerClass(SPSDKLogger)
        logger = logging.getLogger(full_name)
    finally:
        logging.setLoggerClass(original_class)

    if not isinstance(logger, SPSDKLogger):
        logger.__class__ = SPSDKLogger

    return logger  # type: ignore[return-value]


def configure_logging(config_dict: dict) -> None:
    """Configure logging from a dictionary, with SPSDKLogger support.

    This function applies logging configuration and ensures all spsdk loggers
    use SPSDKLogger class to support the trace() method.

    IMPORTANT: Call this BEFORE any get_logger() calls to ensure all loggers
    are properly configured with TRACE level support.

    :param config_dict: Dictionary with logging configuration (as per logging.config.dictConfig).
    """
    # Extract SPSDK logger names from config
    spsdk_logger_names = set()
    if "loggers" in config_dict:
        for logger_name in config_dict["loggers"].keys():
            if logger_name.startswith("spsdk") or logger_name == "spsdk":
                spsdk_logger_names.add(logger_name)

    # Pre-create all SPSDK loggers with SPSDKLogger class before applying config
    for logger_name in spsdk_logger_names:
        _ = get_logger(logger_name)

    # Apply the configuration
    logging.config.dictConfig(config_dict)

    # Ensure any newly created spsdk.* loggers are also SPSDKLogger
    _ensure_spsdk_loggers_are_correct_type()


def _ensure_spsdk_loggers_are_correct_type() -> None:
    """Ensure all spsdk.* loggers are instances of SPSDKLogger.

    This function converts existing standard Logger instances to SPSDKLogger
    for all loggers in the 'spsdk' hierarchy.
    """
    # Get the logging manager
    logging_manager = logging.Logger.manager

    # Collect all spsdk loggers that need conversion
    for logger_name in list(logging_manager.loggerDict.keys()):
        if isinstance(logger_name, str) and logger_name.startswith("spsdk"):
            logger = logging_manager.loggerDict[logger_name]

            # Skip PlaceHolder objects and already-correct loggers
            if isinstance(logger, logging.Logger) and not isinstance(logger, SPSDKLogger):
                # We need to change the class of this logger instance
                # This is a bit "hacky" but it's the only way to convert existing loggers
                logger.__class__ = SPSDKLogger


class SPSDKPlatformDirs(PlatformDirs):
    """SPSDK Platform Directories Manager.

    This class extends platformdirs.PlatformDirs to provide unified directory structure
    behavior across different operating systems, specifically normalizing cache directory
    paths on Windows to align with the logs directory structure.
    """

    # default platformdirs behavior on win
    # cache -> AppData/$author/$app/Cache/$version
    # logs  -> AppData/$author/$app/$version/Logs
    # to unify that we change "cache" dir so it aligns to "logs" dir
    @property
    def user_cache_dir(self) -> str:
        """Get cache directory tied to the user.

        On Windows platforms, returns a subdirectory 'Cache' within the user data directory.
        On non-Windows platforms, delegates to the parent class implementation.
        The directory is automatically created if it doesn't exist.

        :return: Absolute path to the user cache directory.
        """
        if sys.platform != "win32":
            return super().user_cache_dir
        path = os.path.join(self.user_data_dir, "Cache")
        self._optionally_create_directory(path)
        return path


def get_spsdk_version() -> Version:
    """Get SPSDK version information.

    Retrieves the SPSDK version either from the pre-generated __version__ module
    or dynamically using setuptools_scm if the version file is not available.

    :raises ImportError: When both __version__ module and setuptools_scm are unavailable.
    :return: Parsed version object containing SPSDK version information.
    """
    try:
        from .__version__ import __version__ as spsdk_version
    except ImportError:
        from setuptools_scm import get_version

        spsdk_version = get_version()
    return parse(spsdk_version)


def value_to_bool(value: Optional[Union[bool, int, str]]) -> bool:
    """Convert value to boolean from various input formats.

    Supports conversion from string representations like "True", "true", "T", "1"
    and standard Python truthy/falsy values for other types.

    :param value: Value to convert to boolean (string, int, bool, or None).
    :return: Boolean representation of the input value.
    """
    if isinstance(value, str):
        return value in ("True", "true", "T", "1")
    return bool(value)


version = get_spsdk_version()

__author__ = "NXP"
__contact__ = "spsdk@nxp.com"
__license__ = "BSD-3-Clause"
__version__ = str(version)
__release__ = "beta"

# Public API exports
__all__ = [
    "SPSDK_LOG_LEVEL_TRACE",
    "SPSDKLogger",
    "get_logger",
    "configure_logging",
    "SPSDKPlatformDirs",
    "get_spsdk_version",
    "value_to_bool",
    "SPSDK_VERSION_BASE",
    "SPSDK_DATA_FOLDER",
    "SPSDK_PLATFORM_DIRS",
    "SPSDK_RESTRICTED_DATA_FOLDER",
    "SPSDK_ADDONS_DATA_FOLDER",
    "SPSDK_CACHE_FOLDER",
    "SPSDK_CACHE_DISABLED",
    "SPSDK_INTERACTIVE_DISABLED",
    "SPSDK_DEBUG",
    "SPSDK_DEBUG_DB",
    "SPSDK_YML_INDENT",
    "ROOT_DIR",
    "SPSDK_EXAMPLES_FOLDER",
    "SPSDK_DEBUG_LOGGING_DISABLED",
    "SPSDK_DEBUG_LOG_FILE",
    "SPSDK_SCHEMA_STRICT",
    "SPSDK_SECRETS_PATH",
]


# The SPSDK behavior settings
# SPSDK_DATA_FOLDER might be redefined by SPSDK_DATA_FOLDER_{version}
# or SPSDK_DATA_FOLDER env variable
SPSDK_VERSION_BASE = version.base_version
SPSDK_VERSION_FOLDER_SUFFIX = SPSDK_VERSION_BASE.replace(".", "_")
SPSDK_DATA_FOLDER_ENV_VERSION = "SPSDK_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_DATA_FOLDER = (
    os.environ.get(SPSDK_DATA_FOLDER_ENV_VERSION)
    or os.environ.get("SPSDK_DATA_FOLDER")
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
)
SPSDK_PLATFORM_DIRS = SPSDKPlatformDirs(
    appauthor="nxp",
    appname="spsdk",
    version=SPSDK_VERSION_BASE,
    ensure_exists=True,
)

# SPSDK_RESTRICTED_DATA_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_RESTRICTED_DATA_FOLDER_ENV_VERSION = (
    "SPSDK_RESTRICTED_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
)
SPSDK_RESTRICTED_DATA_FOLDER = os.environ.get(
    SPSDK_RESTRICTED_DATA_FOLDER_ENV_VERSION
) or os.environ.get("SPSDK_RESTRICTED_DATA_FOLDER")

# SPSDK_ADDONS_DATA_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_ADDONS_DATA_FOLDER_ENV_VERSION = "SPSDK_ADDONS_DATA_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_ADDONS_DATA_FOLDER = os.environ.get(SPSDK_ADDONS_DATA_FOLDER_ENV_VERSION) or os.environ.get(
    "SPSDK_ADDONS_DATA_FOLDER"
)

# SPSDK_CACHE_FOLDER could be specified by the system variable in same schema as for standard data
SPSDK_CACHE_FOLDER_ENV_VERSION = "SPSDK_CACHE_FOLDER_" + SPSDK_VERSION_FOLDER_SUFFIX
SPSDK_CACHE_FOLDER = os.environ.get(SPSDK_CACHE_FOLDER_ENV_VERSION) or os.environ.get(
    "SPSDK_CACHE_FOLDER"
)

# SPSDK_CACHE_DISABLED might be redefined by SPSDK_CACHE_DISABLED_{version} env variable, default is False
SPSDK_CACHE_DISABLED = value_to_bool(os.environ.get("SPSDK_CACHE_DISABLED"))
SPSDK_CACHE_DISABLED |= value_to_bool(
    os.environ.get(f"SPSDK_CACHE_DISABLED_{SPSDK_VERSION_FOLDER_SUFFIX}")
)

SPSDK_INTERACTIVE_DISABLED = value_to_bool(os.environ.get("SPSDK_INTERACTIVE_DISABLED"))

SPSDK_DEBUG = value_to_bool(os.environ.get("SPSDK_DEBUG"))
# SPSDK_DEBUG_DB enables debug loggers for utils/database module
SPSDK_DEBUG_DB = SPSDK_DEBUG or value_to_bool(os.environ.get("SPSDK_DEBUG_DB"))

SPSDK_YML_INDENT = 2


ROOT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SPSDK_EXAMPLES_FOLDER = os.path.abspath(os.path.join(ROOT_DIR, "examples"))

SPSDK_DEBUG_LOGGING_DISABLED = value_to_bool(os.environ.get("SPSDK_DEBUG_LOGGING_DISABLED"))
SPSDK_DEBUG_LOG_FILE = os.environ.get(
    "SPSDK_DEBUG_LOG_FILE", os.path.join(SPSDK_PLATFORM_DIRS.user_log_dir, "debug.log")
)
SPSDK_SCHEMA_STRICT = value_to_bool(os.environ.get("SPSDK_SCHEMA_STRICT"))

SPSDK_SECRETS_PATH = os.environ.get(
    "SPSDK_SECRETS_PATH", os.path.expanduser("~/.spsdk/secrets.yaml")
)

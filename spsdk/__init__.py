#!/usr/bin/env python
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


def _is_spsdk_logger_name(name: str) -> bool:
    """Return True if logger name is inside the SPSDK logging namespace.

    :param name: Logger name to check.
    :return: True if the logger belongs to the SPSDK namespace.
    """
    return name == "spsdk" or name.startswith("spsdk.")


def get_logger(name: str) -> SPSDKLogger:
    """Get a typed SPSDK logger with TRACE level support.

    This function safely creates SPSDKLogger instances within the 'spsdk' namespace,
    ensuring proper logging hierarchy when SPSDK is used as a subpackage.
    It does not affect the global logging system or other packages.

    :param name: Logger name, typically __name__.
    :return: SPSDKLogger instance with TRACE level support.
    """
    # Ensure logger is in spsdk hierarchy
    if not _is_spsdk_logger_name(name):
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
        for logger_name in config_dict["loggers"]:
            if _is_spsdk_logger_name(logger_name):
                spsdk_logger_names.add(logger_name)

    # Pre-create all SPSDK loggers with SPSDKLogger class before applying config
    for logger_name in spsdk_logger_names:
        _ = get_logger(logger_name)

    # Apply the configuration
    logging.config.dictConfig(config_dict)

    # Ensure any newly created spsdk.* loggers are also SPSDKLogger
    _ensure_spsdk_loggers_are_correct_type()

    # dictConfig may replace the handlers of the 'spsdk' logger, re-apply strict warnings
    refresh_warning_strict()


def _ensure_spsdk_loggers_are_correct_type() -> None:
    """Ensure all spsdk.* loggers are instances of SPSDKLogger.

    This function converts existing standard Logger instances to SPSDKLogger
    for all loggers in the 'spsdk' hierarchy.
    """
    # Get the logging manager
    logging_manager = logging.Logger.manager

    # Collect all spsdk loggers that need conversion
    for logger_name in list(logging_manager.loggerDict.keys()):
        if isinstance(logger_name, str) and _is_spsdk_logger_name(logger_name):
            logger = logging_manager.loggerDict[logger_name]

            # Skip PlaceHolder objects and already-correct loggers
            if isinstance(logger, logging.Logger) and not isinstance(logger, SPSDKLogger):
                # We need to change the class of this logger instance
                # This is a bit "hacky" but it's the only way to convert existing loggers
                logger.__class__ = SPSDKLogger


class SPSDKWarningStrictHandler(logging.Handler):
    """Logging handler promoting SPSDK warnings to errors.

    When attached to the 'spsdk' logger, every WARNING record emitted by any 'spsdk.*' logger
    is first dispatched to all remaining handlers (so the warning still appears in console and
    log files) and then an SPSDKWarningError is raised from the logging call site.
    Records of other levels (DEBUG, INFO, ERROR, CRITICAL) are not affected.
    """

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the handler.

        :param logger: Logger the handler is attached to.
        """
        super().__init__(level=logging.WARNING)
        self.logger = logger

    def _dispatch_to_other_handlers(self, record: logging.LogRecord) -> None:
        """Pass the record to handlers which would otherwise not see it due to the raise.

        These are the handlers registered on the attached logger after this handler and all
        handlers of its ancestors (respecting the 'propagate' flag), mimicking
        logging.Logger.callHandlers().

        :param record: Log record to dispatch.
        """
        handlers = self.logger.handlers
        if self in handlers:
            handlers = handlers[handlers.index(self) + 1 :]
        current: logging.Logger | None = self.logger
        while current:
            for handler in handlers:
                if record.levelno >= handler.level:
                    handler.handle(record)
            if not current.propagate:
                break
            current = current.parent
            handlers = current.handlers if current else []

    def emit(self, record: logging.LogRecord) -> None:
        """Log the warning record by remaining handlers and raise an exception.

        :param record: Log record to process.
        :raises SPSDKWarningError: When the record is a warning.
        """
        if record.levelno >= logging.ERROR:
            return
        # pylint: disable=import-outside-toplevel  # avoid circular import on package init
        from spsdk.exceptions import SPSDKWarningError

        self._dispatch_to_other_handlers(record)
        raise SPSDKWarningError(
            f"Warning promoted to error (SPSDK_WARNING_STRICT): {record.getMessage()}"
        )


_warning_strict_enabled = False


def set_warning_strict(enabled: bool) -> None:
    """Enable or disable promotion of all SPSDK warnings to errors.

    It is enabled automatically on import when the SPSDK_WARNING_STRICT environment variable
    is set to a truthy value. This function allows to change the behavior at runtime.

    :param enabled: True to raise SPSDKWarningError on every SPSDK warning, False to only log.
    """
    global _warning_strict_enabled  # pylint: disable=global-statement
    _warning_strict_enabled = enabled
    spsdk_logger = logging.getLogger("spsdk")
    for handler in list(spsdk_logger.handlers):
        if isinstance(handler, SPSDKWarningStrictHandler):
            spsdk_logger.removeHandler(handler)
    if enabled:
        spsdk_logger.addHandler(SPSDKWarningStrictHandler(spsdk_logger))


def is_warning_strict() -> bool:
    """Get information whether SPSDK warnings are promoted to errors.

    :return: True if strict warning mode is enabled.
    """
    return _warning_strict_enabled


def refresh_warning_strict() -> None:
    """Re-apply the current strict warning mode to the 'spsdk' logger.

    Must be called after any operation that may replace handlers of the 'spsdk' logger
    (e.g. logging.config.dictConfig) to keep the strict warning handler installed.
    """
    set_warning_strict(_warning_strict_enabled)


class SPSDKPlatformDirs(PlatformDirs):  # pylint: disable=abstract-method
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
        The directory is created if it doesn't exist and ``ensure_exists`` is enabled.

        :return: Absolute path to the user cache directory.
        """
        if sys.platform != "win32":
            return super().user_cache_dir
        path = os.path.join(self.user_data_dir, "Cache")
        if self.ensure_exists:
            os.makedirs(path, exist_ok=True)
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


def value_to_bool(value: bool | int | str | None) -> bool:
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
    "ROOT_DIR",
    "SPSDK_ADDONS_DATA_FOLDER",
    "SPSDK_CACHE_DISABLED",
    "SPSDK_CACHE_FOLDER",
    "SPSDK_DATA_FOLDER",
    "SPSDK_DEBUG",
    "SPSDK_DEBUG_DB",
    "SPSDK_DEPRECATED_STRICT",
    "SPSDK_DEBUG_LOGGING_DISABLED",
    "SPSDK_DEBUG_LOG_FILE",
    "SPSDK_EXAMPLES_FOLDER",
    "SPSDK_INTERACTIVE_DISABLED",
    "SPSDK_LOG_LEVEL_TRACE",
    "SPSDK_PLATFORM_DIRS",
    "SPSDK_RESTRICTED_DATA_FOLDER",
    "SPSDK_SCHEMA_STRICT",
    "SPSDK_SECRETS_PATH",
    "SPSDK_VERSION_BASE",
    "SPSDK_WARNING_STRICT",
    "SPSDK_YML_INDENT",
    "SPSDKLogger",
    "SPSDKPlatformDirs",
    "SPSDKWarningStrictHandler",
    "configure_logging",
    "get_logger",
    "get_spsdk_version",
    "is_warning_strict",
    "refresh_warning_strict",
    "set_warning_strict",
    "value_to_bool",
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
SPSDK_DEPRECATED_STRICT = value_to_bool(os.environ.get("SPSDK_DEPRECATED_STRICT"))
SPSDK_SCHEMA_STRICT = value_to_bool(os.environ.get("SPSDK_SCHEMA_STRICT"))
# SPSDK_WARNING_STRICT promotes every warning logged by any 'spsdk.*' logger to SPSDKWarningError
SPSDK_WARNING_STRICT = value_to_bool(os.environ.get("SPSDK_WARNING_STRICT"))
if SPSDK_WARNING_STRICT:
    set_warning_strict(True)

SPSDK_SECRETS_PATH = os.environ.get(
    "SPSDK_SECRETS_PATH", os.path.expanduser("~/.spsdk/secrets.yaml")
)

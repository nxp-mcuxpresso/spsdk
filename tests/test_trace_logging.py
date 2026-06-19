#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for TRACE log level functionality."""

import logging
import logging.config

import pytest
from click.testing import CliRunner

from spsdk import SPSDK_LOG_LEVEL_TRACE, SPSDKLogger, configure_logging, get_logger
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options


def test_trace_level_value() -> None:
    """Test that TRACE level is defined below DEBUG."""
    assert SPSDK_LOG_LEVEL_TRACE == 5
    assert SPSDK_LOG_LEVEL_TRACE < logging.DEBUG


def test_trace_level_registered() -> None:
    """Test that TRACE level is registered with the logging module."""
    assert logging.getLevelName(SPSDK_LOG_LEVEL_TRACE) == "TRACE"
    assert logging.getLevelName("TRACE") == SPSDK_LOG_LEVEL_TRACE


def test_get_logger_returns_spsdk_logger() -> None:
    """Test that get_logger returns an SPSDKLogger instance."""
    logger = get_logger("test.spsdk_logger_type")
    assert isinstance(logger, SPSDKLogger)


def test_logger_has_trace_method() -> None:
    """Test that Logger instances have the trace method."""
    logger = get_logger("test.trace_method")
    assert isinstance(logger, SPSDKLogger)
    assert hasattr(logger, "trace")
    assert callable(logger.trace)


def test_trace_method_logs_at_trace_level(caplog: pytest.LogCaptureFixture) -> None:
    """Test that logger.trace() emits records at TRACE level."""
    logger = get_logger("test.trace_emit")
    with caplog.at_level(SPSDK_LOG_LEVEL_TRACE, logger="spsdk.test.trace_emit"):
        logger.trace("trace message test")
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == SPSDK_LOG_LEVEL_TRACE
    assert caplog.records[0].levelname == "TRACE"
    assert "trace message test" in caplog.records[0].message


def test_trace_not_shown_at_debug_level(caplog: pytest.LogCaptureFixture) -> None:
    """Test that TRACE messages are filtered out when level is DEBUG."""
    logger = get_logger("test.trace_filter")
    with caplog.at_level(logging.DEBUG, logger="test.trace_filter"):
        logger.trace("should not appear")
    assert len(caplog.records) == 0


def test_debug_still_shown_at_debug_level(caplog: pytest.LogCaptureFixture) -> None:
    """Test that DEBUG messages still appear at DEBUG level."""
    logger = logging.getLogger("test.debug_still_works")
    with caplog.at_level(logging.DEBUG, logger="test.debug_still_works"):
        logger.debug("debug message")
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.DEBUG


def test_trace_shown_at_trace_level(caplog: pytest.LogCaptureFixture) -> None:
    """Test that both TRACE and DEBUG messages appear at TRACE level."""
    logger = get_logger("test.trace_shows_all")
    with caplog.at_level(SPSDK_LOG_LEVEL_TRACE, logger="spsdk.test.trace_shows_all"):
        logger.trace("trace msg")
        logger.debug("debug msg")
    assert len(caplog.records) == 2
    assert caplog.records[0].levelno == SPSDK_LOG_LEVEL_TRACE
    assert caplog.records[1].levelno == logging.DEBUG


def test_colored_formatter_handles_trace() -> None:
    """Test that ColoredFormatter has format entries for TRACE level."""
    formatter = spsdk_logger.ColoredFormatter(colored=True)
    assert SPSDK_LOG_LEVEL_TRACE in formatter.formats

    formatter_plain = spsdk_logger.ColoredFormatter(colored=False)
    assert SPSDK_LOG_LEVEL_TRACE in formatter_plain.formats


def test_colored_formatter_formats_trace_record() -> None:
    """Test that ColoredFormatter can format a TRACE log record."""
    formatter = spsdk_logger.ColoredFormatter(colored=False)
    record = logging.LogRecord(
        name="test",
        level=SPSDK_LOG_LEVEL_TRACE,
        pathname="test.py",
        lineno=1,
        msg="trace data: %s",
        args=("0xDEADBEEF",),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "trace data: 0xDEADBEEF" in formatted


def test_install_with_trace_level() -> None:
    """Test that spsdk_logger.install works with TRACE level."""
    import io

    stream = io.StringIO()
    test_logger = get_logger("test.install_trace")
    # Clear any existing handlers
    test_logger.handlers.clear()
    spsdk_logger.install(
        level=SPSDK_LOG_LEVEL_TRACE,
        stream=stream,
        colored=False,
        logger=test_logger,
        create_debug_logger=False,
    )
    test_logger.trace("install trace test")
    output = stream.getvalue()
    assert "install trace test" in output
    # Cleanup
    test_logger.handlers.clear()


def test_cli_vvv_option() -> None:
    """Test that -vvv flag maps to TRACE log level."""
    import click

    @click.command()
    @spsdk_apps_common_options
    def dummy_cmd(log_level: int) -> None:
        click.echo(f"level={log_level}")

    runner = CliRunner()
    result = runner.invoke(dummy_cmd, ["-vvv"])
    assert result.exit_code == 0
    assert f"level={SPSDK_LOG_LEVEL_TRACE}" in result.output


def test_cli_trace_long_option() -> None:
    """Test that --trace flag maps to TRACE log level."""
    import click

    @click.command()
    @spsdk_apps_common_options
    def dummy_cmd(log_level: int) -> None:
        click.echo(f"level={log_level}")

    runner = CliRunner()
    result = runner.invoke(dummy_cmd, ["--trace"])
    assert result.exit_code == 0
    assert f"level={SPSDK_LOG_LEVEL_TRACE}" in result.output


def test_cli_v_and_vv_still_work() -> None:
    """Test that -v and -vv flags still work correctly."""
    import click

    @click.command()
    @spsdk_apps_common_options
    def dummy_cmd(log_level: int) -> None:
        click.echo(f"level={log_level}")

    runner = CliRunner()

    result_v = runner.invoke(dummy_cmd, ["-v"])
    assert result_v.exit_code == 0
    assert f"level={logging.INFO}" in result_v.output

    result_vv = runner.invoke(dummy_cmd, ["-vv"])
    assert result_vv.exit_code == 0
    assert f"level={logging.DEBUG}" in result_vv.output


def test_get_logger_hierarchy_without_spsdk_prefix() -> None:
    """Test that get_logger adds spsdk prefix automatically for non-prefixed names."""
    logger = get_logger("test_module")
    assert logger.name == "spsdk.test_module"
    assert isinstance(logger, SPSDKLogger)


def test_get_logger_hierarchy_with_spsdk_prefix() -> None:
    """Test that get_logger preserves spsdk prefix when already present."""
    logger = get_logger("spsdk.utils.test")
    assert logger.name == "spsdk.utils.test"
    assert isinstance(logger, SPSDKLogger)


def test_get_logger_with_full_module_name() -> None:
    """Test that get_logger works with __name__ from submodules."""
    logger = get_logger("spsdk.crypto.keys")
    assert logger.name == "spsdk.crypto.keys"
    assert isinstance(logger, SPSDKLogger)


def test_logger_class_not_permanently_changed() -> None:
    """Test that get_logger doesn't permanently change the global logger class."""
    original_class = logging.getLoggerClass()
    _ = get_logger("test.isolation.1")
    assert logging.getLoggerClass() == original_class
    _ = get_logger("test.isolation.2")
    assert logging.getLoggerClass() == original_class


def test_multiple_get_logger_calls_safe() -> None:
    """Test that multiple get_logger calls are safe and don't interfere."""
    logger1 = get_logger("test.safety.1")
    logger2 = get_logger("test.safety.2")
    logger3 = get_logger("modules.external")

    assert logger1.name == "spsdk.test.safety.1"
    assert logger2.name == "spsdk.test.safety.2"
    assert logger3.name == "spsdk.modules.external"

    assert isinstance(logger1, SPSDKLogger)
    assert isinstance(logger2, SPSDKLogger)
    assert isinstance(logger3, SPSDKLogger)

    assert logging.getLoggerClass() == logging.Logger


def test_get_logger_child_hierarchy() -> None:
    """Test that get_logger creates proper parent-child relationships."""
    parent_logger = get_logger("spsdk.parent")
    child_logger = get_logger("spsdk.parent.child")

    assert child_logger.parent is not None
    assert child_logger.parent.name == "spsdk.parent"
    assert isinstance(parent_logger, SPSDKLogger)
    assert isinstance(child_logger, SPSDKLogger)


def test_trace_works_after_get_logger_calls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that trace() works correctly after using get_logger."""
    logger = get_logger("test.trace.after.get_logger")
    with caplog.at_level(SPSDK_LOG_LEVEL_TRACE, logger="spsdk.test.trace.after.get_logger"):
        logger.trace("test trace message")
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == SPSDK_LOG_LEVEL_TRACE
    assert "test trace message" in caplog.records[0].message


def test_configure_logging_with_dict_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that configure_logging works with dictConfig."""
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {"format": "%(name)s - %(message)s"},
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "simple",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "spsdk.config_test": {
                "level": "DEBUG",
                "handlers": ["console"],
            },
        },
    }

    configure_logging(config)

    logger = get_logger("spsdk.config_test")
    assert isinstance(logger, SPSDKLogger)
    with caplog.at_level(SPSDK_LOG_LEVEL_TRACE, logger="spsdk.config_test"):
        logger.trace("config trace test")
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == SPSDK_LOG_LEVEL_TRACE


def test_configure_logging_with_trace_level() -> None:
    """Test that configure_logging allows TRACE level in loggers."""
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "spsdk.config_trace": {
                "level": SPSDK_LOG_LEVEL_TRACE,
            },
        },
    }

    configure_logging(config)

    logger = get_logger("spsdk.config_trace")
    assert isinstance(logger, SPSDKLogger)
    # Logger should accept TRACE level
    assert logger.isEnabledFor(SPSDK_LOG_LEVEL_TRACE)


def test_configure_logging_preserves_other_loggers() -> None:
    """Test that configure_logging doesn't break other package loggers."""
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "external_package": {
                "level": "INFO",
            },
        },
    }

    configure_logging(config)

    # SPSDK logger should be SPSDKLogger
    spsdk_logger_instance = get_logger("spsdk.test_isolation")
    assert isinstance(spsdk_logger_instance, SPSDKLogger)

    # External logger should remain standard Logger
    external_logger = logging.getLogger("external_package")
    assert isinstance(external_logger, logging.Logger)
    assert not isinstance(external_logger, SPSDKLogger)


def test_get_logger_after_configure_logging() -> None:
    """Test that get_logger works properly after configure_logging."""
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "spsdk": {
                "level": SPSDK_LOG_LEVEL_TRACE,
            },
        },
    }

    configure_logging(config)

    # Get multiple loggers after configuration
    logger1 = get_logger("spsdk.module1")
    logger2 = get_logger("spsdk.module2.submodule")

    assert isinstance(logger1, SPSDKLogger)
    assert isinstance(logger2, SPSDKLogger)
    assert hasattr(logger1, "trace")
    assert hasattr(logger2, "trace")


def test_already_created_loggers_become_spsdk_logger() -> None:
    """Test that already-created loggers become SPSDKLogger after configure_logging."""
    # Create a logger before configuration
    early_logger = logging.getLogger("spsdk.early_creation")
    assert not isinstance(early_logger, SPSDKLogger)

    # Configure logging
    config = {
        "version": 1,
        "disable_existing_loggers": False,
    }
    configure_logging(config)

    # Get the same logger again - should now be SPSDKLogger
    late_logger = get_logger("spsdk.early_creation")
    assert isinstance(late_logger, SPSDKLogger)
    assert hasattr(late_logger, "trace")

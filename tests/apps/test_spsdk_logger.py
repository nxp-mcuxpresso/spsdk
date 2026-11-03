#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk_logger.py to cover uncovered branches."""

import logging
from io import StringIO
from pathlib import Path

import pytest

from spsdk.apps.utils.spsdk_logger import ColoredFormatter, install
from spsdk.exceptions import SPSDKVerificationError


def test_install_default() -> None:
    """Test install() with default parameters."""
    logger = logging.getLogger("spsdk_test_default")
    logger.handlers.clear()
    install(level=logging.DEBUG, stream=StringIO(), logger=logger, create_debug_logger=False)
    assert len(logger.handlers) >= 1


def test_install_no_color_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test install() with NO_COLOR env var set (lines 138-140)."""
    monkeypatch.setenv("NO_COLOR", "1")
    logger = logging.getLogger("spsdk_test_no_color")
    logger.handlers.clear()
    install(level=logging.DEBUG, stream=StringIO(), logger=logger, create_debug_logger=False)
    assert len(logger.handlers) >= 1


def test_install_jupyter_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test install() with JUPYTER_SPSDK env var (lines 134-135, 144-148)."""
    monkeypatch.setenv("JUPYTER_SPSDK", "1")
    logger = logging.getLogger("spsdk_test_jupyter")
    logger.handlers.clear()
    install(level=logging.DEBUG, logger=logger, create_debug_logger=False)
    assert len(logger.handlers) >= 1


def test_install_colored_true() -> None:
    """Test install() with colored=True overrides."""
    logger = logging.getLogger("spsdk_test_colored")
    logger.handlers.clear()
    install(
        level=logging.INFO,
        stream=StringIO(),
        colored=True,
        logger=logger,
        create_debug_logger=False,
    )
    assert len(logger.handlers) >= 1


def test_install_colored_false() -> None:
    """Test install() with colored=False."""
    logger = logging.getLogger("spsdk_test_uncolored")
    logger.handlers.clear()
    install(
        level=logging.WARNING,
        stream=StringIO(),
        colored=False,
        logger=logger,
        create_debug_logger=False,
    )
    assert len(logger.handlers) >= 1


def test_install_non_tty_stream() -> None:
    """Test install() with non-tty stream disables color (lines 141-143)."""
    # StringIO has no isatty method → color disabled
    stream = StringIO()
    assert not hasattr(stream, "isatty") or not stream.isatty()
    logger = logging.getLogger("spsdk_test_nontty")
    logger.handlers.clear()
    install(level=logging.DEBUG, stream=stream, logger=logger, create_debug_logger=False)
    assert len(logger.handlers) >= 1


def test_install_repeated_call_reuses_console_handler() -> None:
    """Test repeated install() calls don't duplicate console handlers and update level."""
    logger = logging.getLogger("spsdk_test_repeated_install")
    logger.handlers.clear()
    stream = StringIO()

    install(level=logging.WARNING, stream=stream, logger=logger, create_debug_logger=False)
    install(level=logging.DEBUG, stream=stream, logger=logger, create_debug_logger=False)

    console_handlers = [h for h in logger.handlers if getattr(h, "_spsdk_console_handler", False)]
    assert len(console_handlers) == 1

    logger.debug("debug message after reinstall")
    assert "debug message after reinstall" in stream.getvalue()
    logger.handlers.clear()


def test_install_with_debug_logger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test install() with create_debug_logger=True (lines 162-198)."""
    import spsdk.apps.utils.spsdk_logger as sl

    debug_log = str(tmp_path / "spsdk_debug.log")
    monkeypatch.setattr(sl, "SPSDK_DEBUG_LOG_FILE", debug_log)
    monkeypatch.setattr(sl, "SPSDK_DEBUG_LOGGING_DISABLED", False)

    logger = logging.getLogger("spsdk_test_debug_file")
    logger.handlers.clear()
    install(level=logging.DEBUG, stream=StringIO(), logger=logger, create_debug_logger=True)
    # Clean up handlers
    logger.handlers.clear()


def _make_record(msg: object) -> logging.LogRecord:
    """Create a log record carrying an arbitrary message object."""
    return logging.LogRecord(
        name="spsdk_test",
        level=logging.DEBUG,
        pathname="p.py",
        lineno=1,
        msg=msg,
        args=None,
        exc_info=None,
    )


def test_formatter_strips_color_escapes() -> None:
    """Uncolored formatter must remove the real ANSI escape sequences."""
    formatted = ColoredFormatter(colored=False).format(_make_record("\x1b[31mred\x1b[39m text"))
    assert "\x1b" not in formatted
    assert "red text" in formatted


def test_formatter_keeps_color_escapes_when_colored() -> None:
    """Colored formatter must keep the ANSI escape sequences untouched."""
    formatted = ColoredFormatter(colored=True).format(_make_record("\x1b[32mgreen\x1b[39m"))
    assert "\x1b[32m" in formatted


def test_formatter_accepts_non_string_message() -> None:
    """Formatting must not fail when the message is not a string.

    The bootable image parsing logs exception objects directly, which used to raise
    a TypeError inside the color-stripping code.
    """
    exc = SPSDKVerificationError("\x1b[31mverification failed\x1b[39m")
    formatted = ColoredFormatter(colored=False).format(_make_record(exc))
    assert "verification failed" in formatted
    assert "\x1b" not in formatted


def test_formatter_does_not_mutate_record() -> None:
    """The record is shared between handlers, so it must not be modified."""
    record = _make_record("\x1b[31mred\x1b[39m")
    ColoredFormatter(colored=False).format(record)
    assert record.msg == "\x1b[31mred\x1b[39m"

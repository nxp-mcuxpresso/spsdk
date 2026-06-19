#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk_logger.py to cover uncovered branches."""

import logging
from io import StringIO
from pathlib import Path

import pytest

from spsdk.apps.utils.spsdk_logger import install


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

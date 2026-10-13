#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the terminal progress bar manager.

The tests focus on correct handling of the terminal cursor, because a progress
bar that hides the cursor without restoring it leaves the user's terminal in an
unusable state after the application exits.
"""

import io
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

import pytest

import spsdk.utils.progress_bar as progress_bar_module
from spsdk.utils.progress_bar import (
    ESC_HIDE_CURSOR,
    ESC_SHOW_CURSOR,
    ProgressBarManager,
    restore_cursor_at_exit,
)


class TtyStringIO(io.StringIO):
    """StringIO that pretends to be a TTY."""

    def isatty(self) -> bool:
        """Report the stream as a terminal.

        :return: Always True.
        """
        return True


@contextmanager
def captured_stdout(is_tty: bool = True) -> Iterator[io.StringIO]:
    """Replace stdout by an in-memory stream for the duration of the block.

    The patch must be applied inside the test body (not in a fixture), because
    the pytest capture plugin re-installs its own stdout for the call phase.

    :param is_tty: Whether the replacement stream reports itself as a terminal.
    :yield: The stream capturing everything written to stdout.
    """
    stream: io.StringIO = TtyStringIO() if is_tty else io.StringIO()
    with (
        patch.object(sys, "stdout", stream),
        patch.object(progress_bar_module, "_hidden_cursor_count", 0),
    ):
        yield stream


def test_finish_restores_cursor() -> None:
    """Cursor hidden by an update must be shown again by finish()."""
    with captured_stdout() as stream:
        manager = ProgressBarManager()
        manager.update("task", 100, 50)
        assert ESC_HIDE_CURSOR in stream.getvalue()

        manager.finish()
        assert ESC_SHOW_CURSOR in stream.getvalue()


def test_context_manager_restores_cursor_on_exception() -> None:
    """Cursor must be restored even when the guarded block raises."""
    with captured_stdout() as stream:
        with pytest.raises(ValueError), ProgressBarManager() as manager:
            manager.update("task", 100, 10)
            raise ValueError("boom")

        assert ESC_SHOW_CURSOR in stream.getvalue()


def test_finish_without_update_is_noop() -> None:
    """finish() must not emit anything when no progress bar was drawn."""
    with captured_stdout() as stream:
        ProgressBarManager().finish()
        assert stream.getvalue() == ""


def test_finish_is_idempotent() -> None:
    """Repeated finish() calls must show the cursor exactly once."""
    with captured_stdout() as stream:
        manager = ProgressBarManager()
        manager.update("task", 100, 50)
        manager.finish()
        manager.finish()
        assert stream.getvalue().count(ESC_SHOW_CURSOR) == 1


def test_atexit_handler_restores_forgotten_cursor() -> None:
    """The exit safety net must restore a cursor left hidden by a caller."""
    with captured_stdout() as stream:
        manager = ProgressBarManager()
        manager.update("task", 100, 50)
        assert ESC_SHOW_CURSOR not in stream.getvalue()

        restore_cursor_at_exit()
        assert ESC_SHOW_CURSOR in stream.getvalue()


def test_atexit_handler_noop_when_cursor_visible() -> None:
    """The exit safety net must not touch stdout when no cursor is hidden."""
    with captured_stdout() as stream:
        restore_cursor_at_exit()
        assert stream.getvalue() == ""


def test_no_escape_sequences_when_not_tty() -> None:
    """No cursor manipulation may happen when stdout is redirected."""
    with captured_stdout(is_tty=False) as stream:
        with ProgressBarManager() as manager:
            manager.update("task", 100, 50)

        assert ESC_HIDE_CURSOR not in stream.getvalue()
        assert ESC_SHOW_CURSOR not in stream.getvalue()

#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Fixed-width terminal progress bar manager for SPSDK applications."""

import atexit
import logging
import shutil
import sys
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import click
from typing_extensions import Self

# ANSI escape sequences
ESC_HIDE_CURSOR = "\033[?25l"
ESC_SHOW_CURSOR = "\033[?25h"
ESC_CLEAR_FROM_CURSOR = "\033[J"

logger = logging.getLogger(__name__)

# Number of progress bar managers that currently keep the terminal cursor hidden.
# Used by the interpreter-exit safety net below, so that an unhandled exception,
# a Ctrl+C or a caller that forgets to call finish() can never leave the user's
# terminal without a visible cursor.
_hidden_cursor_count = 0


def write_escape(code: str) -> None:
    """Write ANSI escape code and flush.

    :param code: ANSI escape code to write.
    """
    click.echo(code, nl=False)


def restore_cursor_at_exit() -> None:
    """Restore the terminal cursor if any progress bar manager left it hidden.

    Registered as an :mod:`atexit` handler so the cursor is always given back to
    the user, even when the progress bar manager was not properly finished.
    """
    global _hidden_cursor_count  # pylint: disable=global-statement
    if _hidden_cursor_count <= 0:
        return
    _hidden_cursor_count = 0
    try:
        write_escape(ESC_SHOW_CURSOR)
    except Exception as exc:  # noqa: BLE001 # pragma: no cover
        # stdout may already be closed during interpreter shutdown
        logger.debug(f"Could not restore terminal cursor at exit: {exc}")


atexit.register(restore_cursor_at_exit)


ProgressBar = Any


@dataclass
class ProgressTask:
    """Represents a single progress bar task."""

    label: str
    total_steps: int
    step: int = 0
    bar: ProgressBar | None = None

    @property
    def is_complete(self) -> bool:
        """Check if task is complete."""
        return self.step >= self.total_steps


class ProgressBarManager:
    """Manages fixed-width progress bars for terminal display.

    This class provides a context manager interface for displaying one or more
    progress bars with a consistent fixed width, based on terminal size.
    """

    BAR_TEMPLATE = "%(info)s [%(bar)s] %(label)s"
    ELLIPSIS = "..."

    def __init__(self) -> None:
        """Initialize the progress bar manager."""
        self._tasks: dict[str, ProgressTask] = {}
        self._cursor_hidden = False
        self.MAX_TOTAL_WIDTH = self.get_terminal_width()
        self.BAR_WIDTH = 10
        self.INFO_WIDTH = 2 + 14 + 4
        self.MAX_LABEL_WIDTH = self.MAX_TOTAL_WIDTH - self.BAR_WIDTH - self.INFO_WIDTH

    def get_terminal_width(self) -> int:
        """Get terminal width for progress bar display.

        :return: Terminal width clamped between 80 and 120 columns.
        """
        try:
            width = shutil.get_terminal_size().columns
            return max(80, min(width, 120))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Terminal width detection failed: {exc}")
            return 80

    @property
    def is_tty(self) -> bool:
        """Check if stdout is a TTY."""
        return sys.stdout.isatty()

    def _truncate_label(self, label: str) -> str:
        """Truncate label to fit within MAX_LABEL_WIDTH, adding ellipsis if needed.

        :param label: Original label text.
        :return: Truncated and padded label.
        """
        if len(label) <= self.MAX_LABEL_WIDTH:
            return label.ljust(self.MAX_LABEL_WIDTH)
        return label[: self.MAX_LABEL_WIDTH - len(self.ELLIPSIS)] + self.ELLIPSIS

    def _hide_cursor(self) -> None:
        """Hide the terminal cursor."""
        global _hidden_cursor_count  # pylint: disable=global-statement
        if not self._cursor_hidden and self.is_tty:
            write_escape(ESC_HIDE_CURSOR)
            self._cursor_hidden = True
            _hidden_cursor_count += 1

    def _show_cursor(self) -> None:
        """Show the terminal cursor."""
        global _hidden_cursor_count  # pylint: disable=global-statement
        if self._cursor_hidden:
            write_escape(ESC_SHOW_CURSOR)
            self._cursor_hidden = False
            _hidden_cursor_count = max(0, _hidden_cursor_count - 1)

    def _create_progress_bar(self, task: ProgressTask) -> ProgressBar:
        """Create a click progress bar for a task.

        :param task: Progress task to create bar for.
        :return: Click progress bar instance.
        """
        return click.progressbar(
            length=task.total_steps,
            label=self._truncate_label(task.label),
            bar_template=self.BAR_TEMPLATE,
            width=self.BAR_WIDTH,
        )

    def update(self, task_name: str, total_steps: int, step: int) -> None:
        """Update progress bar for a task.

        Progress bar will not be drawn if stdout is not a TTY.

        :param task_name: Name/label of the task.
        :param total_steps: Total number of steps for completion.
        :param step: Current step number.
        """
        if not self.is_tty:
            return

        self._hide_cursor()

        if task_name not in self._tasks:
            task = ProgressTask(
                label=task_name,
                total_steps=total_steps,
            )
            task.bar = self._create_progress_bar(task)
            self._tasks[task_name] = task

        task = self._tasks[task_name]
        increment = step - task.step
        if increment > 0 and task.bar is not None:
            task.bar.update(increment)
        task.step = step

        click.echo("\r", nl=False)

        if task.is_complete:
            click.echo()

    def finish(self) -> None:
        """Clean up after all progress bars are complete.

        Restores the terminal cursor and clears any leftover progress bar output.
        The method is idempotent and does nothing when no progress bar has been
        drawn, so it is safe to call it unconditionally at the end of an operation.
        """
        if not self._tasks and not self._cursor_hidden:
            return
        if self.is_tty:
            write_escape(ESC_CLEAR_FROM_CURSOR)
        self._show_cursor()
        click.echo()
        self._tasks.clear()

    def __enter__(self) -> Self:
        """Enter context manager.

        :return: Self reference for context manager usage.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit context manager, ensuring cleanup runs even on exception.

        :param exc_type: Exception type if an exception occurred.
        :param exc_val: Exception value if an exception occurred.
        :param exc_tb: Exception traceback if an exception occurred.
        """
        self.finish()

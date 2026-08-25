#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK application utilities and helper functions.

This module provides common utility functions and classes used across SPSDK
applications for data formatting, error handling, file operations, and user
interface components.
"""

import contextlib
import logging
import os
import re
import sys
from collections.abc import Callable, Iterator
from functools import wraps
from typing import Any

import click
import hexdump

from spsdk import SPSDK_DEBUG_LOG_FILE, SPSDK_DEBUG_LOGGING_DISABLED
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_abs_path, get_printable_path, value_to_int, write_file
from spsdk.utils.verifier import Verifier, VerifierResult

WARNING_MSG = """
This is an experimental utility. Use with caution!
"""

logger = logging.getLogger(__name__)


class SPSDKAppError(SPSDKError):
    """SPSDK application error exception for CLI tools.

    This exception class represents non-fatal errors that occur during SPSDK
    application execution, providing structured error handling with custom
    error codes for command-line interface tools.

    :cvar fmt: Format string template for error message display.
    """

    fmt = "{description}"

    def __init__(self, desc: str | None = None, error_code: int = 1) -> None:
        """Initialize the AppError.

        :param desc: Description to print out on command line, defaults to None
        :param error_code: Error code passed to OS, defaults to 1
        """
        super().__init__(desc)
        self.description = desc
        self.error_code = error_code


class INT(click.ParamType):
    """Click parameter type for parsing integers with flexible format support.

    This class extends Click's ParamType to handle integer input in various formats
    including binary (0b), hexadecimal (0x), octal (0o) with support for underscore
    visual separators (e.g., 0xFF_FF, 1_000_000).

    :cvar name: Parameter type name used by Click framework.
    """

    name = "integer"

    def __init__(self, base: int = 0) -> None:
        """Initialize custom INT param class.

        :param base: requested base for the number, defaults to 0
        """
        super().__init__()
        self.base = base

    # pylint: disable=inconsistent-return-statements
    def convert(
        self,
        value: str,
        param: click.Parameter | None = None,
        ctx: click.Context | None = None,
    ) -> int:
        """Perform the conversion str -> int.

        :param value: value to convert
        :param param: Click parameter, defaults to None
        :param ctx: Click context, defaults to None
        :return: value as integer
        :raises TypeError: Value is not a string
        :raises ValueError: Value can't be interpreted as an integer
        """
        try:
            return int(value, self.base)
        except TypeError:
            self.fail(
                "expected string for int() conversion, got "
                f"{value!r} of type {type(value).__name__}",
                param,
                ctx,
            )
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)


def _split_string(string: str, length: int) -> list:
    """Split the string into chunks of same length."""
    return [string[i : i + length] for i in range(0, len(string), length)]


def format_raw_data(data: bytes, use_hexdump: bool = False, line_length: int = 16) -> str:
    """Format bytes data into human-readable form.

    :param data: Data to format
    :param use_hexdump: Use hexdump with addresses and ASCII, defaults to False
    :param line_length: bytes per line, defaults to 32
    :return: formatted string (multilined if necessary)
    """
    if use_hexdump:
        return hexdump.hexdump(data, result="return")
    data_string = data.hex()
    parts = [_split_string(line, 2) for line in _split_string(data_string, line_length * 2)]
    result = "\n".join(" ".join(line) for line in parts)
    return result


def format_vid_pid(dec_version: str) -> str:
    """Format VID:PID information in more human-readable format."""
    if ":" in dec_version:
        vid, pid = dec_version.split(":")
        return f"{int(vid, 0):#06x}:{int(pid, 0):#06x}"
    return dec_version


def catch_spsdk_error(function: Callable) -> Callable:
    """Catch and handle SPSDKError and other exceptions.

    This is a decorator function that wraps the decorated function to catch
    and handle various exceptions, including SPSDKError, SPSDKAppError,
    AssertionError, UnicodeEncodeError, and other general exceptions.

    When an SPSDKAppError is raised, it prints the error message and exits
    with the specified error code (default is 1).

    When an SPSDKError or AssertionError is raised, it prints the error message,
    logs the exception with debug information, and exits with an error code of 2.
    If debug logging is enabled, it also prints the path to the debug log file.

    When a UnicodeEncodeError is raised, it prints a warning message about the
    terminal not rendering UTF-8 symbols correctly and suggests setting the
    PYTHONIOENCODING environment variable. It also logs the exception with debug
    information and exits with an error code of 2.

    For other general exceptions (including KeyboardInterrupt), it prints the
    exception type and message, logs the exception with debug information, and
    exits with an error code of 3. If debug logging is enabled, it also prints
    the path to the debug log file.

    :param function: The function to be decorated.
    :return: The decorated function.
    """

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            retval = function(*args, **kwargs)
            return retval
        except SPSDKAppError as app_exc:
            if app_exc.description:
                click.echo(f"{app_exc.__class__.__name__}: {app_exc}", err=True)
            if app_exc.error_code > 0 and app_exc.error_code < 256:
                sys.exit(app_exc.error_code)
            sys.exit(1)
        except (AssertionError, SPSDKError) as spsdk_exc:
            click.echo(f"{spsdk_exc.__class__.__name__}: {spsdk_exc}", err=True)
            logger.debug(str(spsdk_exc), exc_info=True)
            if not SPSDK_DEBUG_LOGGING_DISABLED:
                click.secho(
                    f"See debug log file: {SPSDK_DEBUG_LOG_FILE} for more info", fg="yellow"
                )
            sys.exit(2)
        except UnicodeEncodeError as encode_exc:
            logger.warning(
                "Your terminal (Jupyter notebook) doesn't render UTF-8 symbols correctly.\n"
                "Please add the following environment variable and restart any opened shells.\n"
                "PYTHONIOENCODING=utf8"
            )
            logger.debug(str(encode_exc), exc_info=True)
            sys.exit(2)
        except (Exception, KeyboardInterrupt) as base_exc:  # pylint: disable=broad-except
            click.echo(f"GENERAL ERROR: {type(base_exc).__name__}: {base_exc}", err=True)
            logger.debug(str(base_exc), exc_info=True)
            if not SPSDK_DEBUG_LOGGING_DISABLED:
                click.secho(
                    f"See debug log file: {SPSDK_DEBUG_LOG_FILE} for more info.", fg="yellow"
                )
            sys.exit(3)

    return wrapper


def parse_file_and_size(file_and_size: str) -> tuple[str, int]:
    """Parse composite file-size params.

    :param file_and_size: original param that possibly contains size constrain
    :return: Tuple of path as str and size as int (if present)
    """
    if "," in file_and_size:
        file_path, size = file_and_size.split(",")
        file_size = int(size, 0)
    else:
        file_path = file_and_size
        file_size = -1
    return file_path, file_size


def parse_hex_data(hex_data: str) -> bytes:
    """Parse hex-data into bytes.

    :param hex_data: input hex-data, e.g: {{1122}}, {{11 22}}
    :raises SPSDKError: Failure to parse given input
    :return: data parsed from input
    """
    hex_data = hex_data.replace(" ", "")
    if not hex_data.startswith(("{{", "[[")) or not hex_data.endswith(("}}", "]]")):
        raise SPSDKError("Incorrectly formatted hex-data: Need to start with {{ and end with }}")

    hex_data = hex_data.replace("{{", "").replace("}}", "").replace("[[", "").replace("]]", "")
    if not re.fullmatch(r"[0-9a-fA-F]*", hex_data):
        raise SPSDKError("Incorrect hex-data: Need to have valid hex string")

    str_parts = [hex_data[i : i + 2] for i in range(0, len(hex_data), 2)]
    byte_pieces = [int(part, 16) for part in str_parts]
    result = bytes(byte_pieces)
    if not result:
        raise SPSDKError("Incorrect hex-data: Unable to get any data")
    return bytes(byte_pieces)


def store_key(file_name: str, key: bytes, reverse: bool = False) -> None:
    """Store the key in text hexadecimal and binary format.

    :param file_name: Base file name for the key file. The name will be enriched by *.txt and *.bin extension.
    :param key: The key that should be stored.
    :param reverse: Reverse bytes in binary file
    """
    write_file(key.hex(), file_name + ".txt", mode="w")
    if reverse:  # reverse binary order
        key_mutable = bytearray(key)
        key_mutable.reverse()
        write_file(key_mutable, file_name + ".bin", mode="wb")
    else:
        write_file(key, file_name + ".bin", mode="wb")


def filepath_from_config(
    config: Config,
    key: str,
    default_value: str,
    output_folder: str = "",
    file_extension: str = ".bin",
) -> str:
    """Get file path from configuration dictionary and append .bin if the value is not blank.

    Function returns the output_folder + filename if the filename does not contain path.
    In case filename contains path, return filename and append ".bin".
    The empty string "" indicates that the user doesn't want the output.
    :param config: Configuration dictionary
    :param key: Name of the key
    :param default_value: default value in case key value is not present
    :param output_folder: Output folder, if blank file path from config will be used
    :param file_extension: File extension that will be appended
    :return: filename with appended ".bin" or blank filename ""
    """
    filename = config.get(key, default_value)
    if filename == "":
        return filename
    if not os.path.dirname(filename):
        filename = os.path.join(output_folder, filename)
    if not filename.endswith(file_extension):
        filename += file_extension
    return get_abs_path(filename, config.config_dir)


@contextlib.contextmanager
def progress_bar(
    suppress: bool = False, **progress_bar_params: str | int
) -> Iterator[Callable[[int, int], None]]:
    """Creates a progress bar and return callback function for updating the progress bar.

    :param suppress: Suppress the progress bar creation; return an empty callback, defaults to False
    :param progress_bar_params: Standard parameters for progress bar (e.g., label)
    :yield: Callback for updating the progress bar
    """
    if suppress:
        yield lambda _x, _y: None
    else:
        from spsdk.utils.progress_bar import ProgressBarManager

        label = str(progress_bar_params.get("label", "Progress"))

        with ProgressBarManager() as manager:

            def progress(step: int, total_steps: int) -> None:
                manager.update(label, total_steps, step)

            yield progress


def print_verifier_to_console(v: Verifier, problems: bool = False) -> None:
    """Print verifier results to console.

    :param v: The Verifier object containing the results to print.
    :param problems: If True, only print WARNING and ERROR results.
    """
    results = None
    if problems:
        results = [VerifierResult.WARNING, VerifierResult.ERROR]
    click.echo(v.draw(results))

    click.echo("Summary table of verifier results:\n" + v.get_summary_table() + "\n")
    click.echo("Overall  result: " + VerifierResult.draw(v.result))


def print_files(files: list[str], title: str | None = None) -> None:
    """Print list of files to console."""
    if title:
        click.echo(title)
    for file in files:
        click.echo(get_printable_path(file))


def make_table_from_items(
    items: list[str], row_width: int = 75, column_width: int = 25
) -> list[str]:
    """Split long lists of items into table for better readability."""
    if not items:
        return []
    column_padding = 2
    max_item_width = max(len(item) for item in items)
    # Ensure column width is at least as wide as the longest item plus padding
    column_width = max(column_width, max_item_width + column_padding)

    num_columns = max(1, row_width // column_width)
    num_rows = (len(items) + num_columns - 1) // num_columns

    rows = []
    for row_idx in range(num_rows):
        row = []
        for col_idx in range(num_columns):
            item_idx = row_idx * num_columns + col_idx
            if item_idx < len(items):
                # Format each item to fill column width with right padding
                row.append(f"{items[item_idx]:<{column_width - column_padding}}")
        rows.append((column_padding * " ").join(row))
    return rows


def resolve_lifecycle(family: FamilyRevision, lifecycle: str) -> tuple[int, str]:
    """Resolve a CLI ``--lifecycle`` value to its 32-bit encoded form.

    Accepts either a string integer literal (supports ``0x``/``0b``/``0o`` prefixes
    and underscore separators) or a symbolic lifecycle name (e.g. ``IN_FIELD1``,
    ``DEVELOP``), including any deprecated aliases declared in the device's
    lifecycle register (such as ``ROP_LEVEL1``). Name matching is case-insensitive
    and delegated to :meth:`RegsBitField.get_enum_constant`, which emits a
    deprecation warning when a deprecated alias is used.

    The source of the symbolic names is device-specific and resolved from the
    database (``dat/program_lifecycle``), which maps to a PFR area class and the
    register whose first bitfield enumerates the lifecycle names. Devices that do
    not define this mapping accept integer values only.

    :param family: Target device family used to look up the symbolic names.
    :param lifecycle: Raw value as provided on the command line.
    :return: Tuple ``(value, pretty)`` where ``value`` is the 32-bit encoded
        lifecycle and ``pretty`` is a display string for user-facing output.
    :raises SPSDKAppError: When the value is neither a valid integer nor a known
        symbolic name for the target device.
    """
    # Lazy import: spsdk.pfr.pfr pulls in the full PFR machinery which is only
    # needed for this lifecycle resolution helper, not for every CLI app.
    from spsdk.pfr.pfr import get_ifr_pfr_class  # pylint: disable=import-outside-toplevel
    from spsdk.utils.database import DatabaseManager  # pylint: disable=import-outside-toplevel
    from spsdk.utils.family import get_db  # pylint: disable=import-outside-toplevel

    try:
        value = value_to_int(lifecycle)
    except SPSDKError:
        pass
    else:
        return value, f"({hex(value)})"

    lc_source = get_db(family).get_dict(DatabaseManager.DAT, "program_lifecycle", default={})
    if not lc_source:
        raise SPSDKAppError(
            f"Device {family.name} does not define symbolic lifecycle names; "
            f"provide {lifecycle!r} as an integer value."
        )

    try:
        area_cls = get_ifr_pfr_class(lc_source["pfr_area"], family)
        bitfield = area_cls(family).registers.find_reg(lc_source["register"]).get_bitfields()[0]
        value = bitfield.get_enum_constant(lifecycle)
    except SPSDKError as exc:
        raise SPSDKAppError(
            f"Cannot resolve lifecycle {lifecycle!r} for device {family.name}: {exc}"
        ) from exc

    canonical = next(
        (e.name for e in bitfield.get_enums() if e.get_value_int() == value),
        None,
    )
    return value, f"{canonical} ({hex(value)})" if canonical else f"({hex(value)})"

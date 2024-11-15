#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for general utilities used by applications."""

import contextlib
import logging
import os
import re
import sys
from functools import wraps
from typing import Any, Callable, Iterator, Optional, Union

import click
import hexdump

from spsdk import SPSDK_DEBUG_LOG_FILE, SPSDK_DEBUG_LOGGING_DISABLED
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import get_abs_path, load_configuration, write_file

WARNING_MSG = """
This is an experimental utility. Use with caution!
"""

logger = logging.getLogger(__name__)


class SPSDKAppError(SPSDKError):
    """Non-fatal error for applications. Sets CLI application error code to 1."""

    fmt = "{description}"

    def __init__(self, desc: Optional[str] = None, error_code: int = 1) -> None:
        """Initialize the AppError.

        :param desc: Description to print out on command line, defaults to None
        :param error_code: Error code passed to OS, defaults to 1
        """
        super().__init__(desc)
        self.description = desc
        self.error_code = error_code


class INT(click.ParamType):
    """Type that allows integers in bin, hex, oct format including _ as a visual separator."""

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
        param: Optional[click.Parameter] = None,
        ctx: Optional[click.Context] = None,
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
    """Catch the SPSDKError."""

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
                (
                    "Your terminal (Jupyter notebook) doesn't render UTF-8 symbols correctly.\n"
                    "Please add the following environment variable and restart any opened shells.\n"
                    "PYTHONIOENCODING=utf8"
                )
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
        key = bytearray(key)
        key.reverse()
        key = bytes(key)
    write_file(key, file_name + ".bin", mode="wb")


def filepath_from_config(
    config: dict,
    key: str,
    default_value: str,
    base_dir: str,
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
    :param base_dir: base directory for path expansion
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
    return get_abs_path(filename, base_dir)


@contextlib.contextmanager
def progress_bar(
    suppress: bool = False, **progress_bar_params: Union[str, int]
) -> Iterator[Callable[[int, int], None]]:
    """Creates a progress bar and return callback function for updating the progress bar.

    :param suppress: Suppress the progress bar creation; return an empty callback, defaults to False
    :param progress_bar_params: Standard parameters for click.progressbar
    :yield: Callback for updating the progress bar
    """
    if suppress:
        yield lambda _x, _y: None
    else:
        with click.progressbar(length=100, **progress_bar_params) as p_bar:  # type: ignore

            def progress(step: int, total_steps: int) -> None:
                per_step = 100 / total_steps
                increment = step * per_step - p_bar.pos
                p_bar.update(round(increment))

            yield progress


def resolve_path_relative_to_config(
    path_key: str,
    config: Optional[str] = None,
    override_path: Optional[str] = None,
) -> str:
    """Resolve path relative to config file. If override path is provided use that instead.

    :param path_key: key in configuration
    :param config: path to YAML/JSON configuration
    :param override_path: If provided path will be overridden, defaults to None
    :return: absolute path calculated from the relative path in config file
    """
    out_file = None
    if override_path:
        return override_path

    if config:
        cfg_dict = load_configuration(config)
        out_file = cfg_dict.get(path_key)

    if out_file and config:
        return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(config)), out_file))
    raise SPSDKAppError(f"Path in {path_key} cannot be resolved")


def deprecated_option_warning(
    option_name: Optional[str], custom_text: Optional[str] = None
) -> None:
    """Print deprecated option warning."""
    if not (option_name or custom_text):
        raise SPSDKValueError("Either option name or custom text must be provided.")
    msg = custom_text or (
        f"The '{option_name}' option has been deprecated and will be removed in the future release"
    )
    click.secho(msg, fg="yellow")

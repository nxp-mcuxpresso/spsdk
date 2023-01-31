#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for general utilities used by applications."""

import logging
import os
import re
import sys
from functools import wraps
from typing import Any, Callable, List, Optional, Tuple, Union

import click
import hexdump

from spsdk import SPSDKError
from spsdk.mboot import interfaces as MBootInterfaceModule
from spsdk.mboot.interfaces import MBootInterface
from spsdk.sdp import interfaces as SDPInterfaceModule
from spsdk.sdp.interfaces import SDPInterface
from spsdk.utils.misc import (  # pylint: disable=unused-import #backward-compatibility
    find_file,
    load_binary,
    load_file,
    value_to_bytes,
    write_file,
)

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


def get_interface(
    module: str,
    port: Optional[str] = None,
    usb: Optional[str] = None,
    timeout: int = 5000,
    buspal: Optional[str] = None,
    lpcusbsio: Optional[str] = None,
) -> Union[MBootInterface, SDPInterface]:
    """Get appropriate interface.

    'port' and 'usb' parameters are mutually exclusive; one of them is required.

    :param module: name of module to get interface from, 'sdp' or 'mboot'
    :param port: name and speed of the serial port (format: name[,speed]), defaults to None
    :param usb: PID,VID of the USB interface, defaults to None
    :param buspal: buspal interface settings, defaults to None
    :param timeout: timeout in milliseconds
    :param lpcusbsio: LPCUSBSIO spi or i2c config string
    :return: Selected interface instance
    :raises SPSDKError: Only one of 'port' or 'usb' must be specified
    :raises AttributeError: target is not supported
    :raises SPSDKError: When SPSDK-specific error occurs
    """
    # check that one and only one interface is defined
    all_interfaces = (port, usb, lpcusbsio)
    count_interfaces = sum(i is not None for i in all_interfaces)
    interface_module = {"mboot": MBootInterfaceModule, "sdp": SDPInterfaceModule}[module]

    missing_interface_msg = {
        "mboot": "One of '--port', '--usb' or '--lpcusbsio' must be specified.",
        "sdp": "One of '--port', '--usb' must be specified.",
    }[module]

    multiple_interfaces_msg = {
        "mboot": "Only one of '--port', '--usb' or '--lpcusbsio' must be specified.",
        "sdp": "Only one of '--port', '--usb' must be specified.",
    }[module]

    if count_interfaces == 0:
        raise SPSDKError(missing_interface_msg)
    if count_interfaces > 1:
        raise SPSDKError(multiple_interfaces_msg)

    devices = []
    if port:
        port_parts = port.split(",")
        name = port_parts.pop(0)
        baudrate = int(port_parts.pop(), 0) if port_parts else None

        if buspal and interface_module is MBootInterfaceModule:
            props = buspal.split(",")
            target = props.pop(0)
            if target == "i2c":
                devices = interface_module.scan_buspal_i2c(port=name, timeout=timeout, props=props)  # type: ignore
            elif target == "spi":
                devices = interface_module.scan_buspal_spi(port=name, timeout=timeout, props=props)  # type: ignore
            else:
                raise SPSDKError(f"Target '{target}' is not supported, should be spi or i2c")

            if len(devices) != 1:
                raise SPSDKError(
                    f"Error: cannot communicate with BUSPAL target on UART port '{name}'."
                )
        else:
            devices = interface_module.scan_uart(port=name, baudrate=baudrate, timeout=timeout)  # type: ignore
            if len(devices) != 1:
                raise SPSDKError(f"Cannot ping device on UART port '{name}'.")
    if usb:
        vid_pid = usb.replace(",", ":")
        devices = interface_module.scan_usb(vid_pid)  # type: ignore
        if len(devices) == 0:
            raise SPSDKError(f"Cannot find USB device '{format_vid_pid(vid_pid)}'")
        if len(devices) > 1:
            raise SPSDKError(f"More than one device '{format_vid_pid(vid_pid)}' found")
        devices[0].timeout = timeout
    if lpcusbsio:
        devices = interface_module.scan_usbsio(lpcusbsio, timeout=timeout)  # type: ignore
        if len(devices) != 1:
            raise SPSDKError(
                f"Cannot initialize USBSIO device '{lpcusbsio}',"
                f" exactly one device has to be specified, found: {devices}. "
            )
    return devices[0]


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
    def wrapper(*args: tuple, **kwargs: dict) -> Any:
        try:
            retval = function(*args, **kwargs)
            return retval
        except SPSDKAppError as app_exc:
            if app_exc.description:
                click.echo(str(app_exc))
            sys.exit(app_exc.error_code)
        except (AssertionError, SPSDKError) as spsdk_exc:
            click.echo(f"ERROR:{spsdk_exc}", err=True)
            logger.debug(str(spsdk_exc), exc_info=True)
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
            sys.exit(3)

    return wrapper


def parse_file_and_size(file_and_size: str) -> Tuple[str, int]:
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


# pylint: disable=inconsistent-return-statements
def check_file_exists(path: str, force_overwrite: bool = False) -> bool:  # type: ignore
    """Check if file exists, exits if file exists and overwriting is disabled.

    :param path: Path to a file
    :param force_overwrite: Allows file overwriting
    :raises SPSDKAppError: File already exists and overwriting is disabled
    :return: if file overwriting is allowed, it return True if file exists
    """
    if force_overwrite:
        return os.path.isfile(path)
    if os.path.isfile(path) and not force_overwrite:
        raise SPSDKAppError(f"File '{path}' already exists. Use --force to overwrite it.")


def get_key(key_source: str, expected_size: int, search_paths: Optional[List[str]] = None) -> bytes:
    """Get the key from the command line parameter.

    :param key_source: File path to key file or hexadecimal value. If not specified random value is used.
    :param expected_size: Expected size of key in bytes.
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKError: Invalid key
    :return: Key in bytes.
    """
    key = None
    assert expected_size > 0, "Invalid expected size of key"
    if not key_source:
        logger.debug(
            f"The key source is not specified, the random value is used in size of {expected_size} B."
        )
        # pylint: disable=import-outside-toplevel
        from spsdk.utils.crypto.common import crypto_backend

        return crypto_backend().random_bytes(expected_size)
    try:
        file_path = find_file(key_source, search_paths=search_paths)
        try:
            str_key = load_file(file_path)
            assert isinstance(str_key, str)
            if not str_key.startswith(("0x", "0X")):
                str_key = "0x" + str_key
            key = value_to_bytes(str_key, byte_cnt=expected_size)
            if len(key) != expected_size:
                raise SPSDKError("Invalid Key size.")
        except (SPSDKError, UnicodeDecodeError):
            key = load_binary(file_path)
    except:
        try:
            if not key_source.startswith(("0x", "0X")):
                key_source = "0x" + key_source
            key = value_to_bytes(key_source, byte_cnt=expected_size)
        except SPSDKError:
            pass

    if key is None or len(key) != expected_size:
        raise SPSDKError(f"Invalid key input: {key_source}")

    return key


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

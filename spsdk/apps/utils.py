#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for general utilities used by applications."""

import logging
import os
import re
import sys
from functools import wraps
from typing import Any, Callable, Tuple, Union

import click
import commentjson as json
import hexdump
import yaml

from spsdk import SPSDKError
from spsdk.mboot import interfaces as MBootInterfaceModule
from spsdk.mboot.interfaces import Interface as MBootInterface
from spsdk.sdp import interfaces as SDPInterfaceModule
from spsdk.sdp.interfaces import Interface as SDPInterface

logger = logging.getLogger(__name__)


class INT(click.ParamType):
    """Type that allows integers in bin, hex, oct format including _ as a visual separator."""

    name = "integer"

    def __init__(self, base: int = 0) -> None:
        """Initialize custom INT param class.

        :param base: requested base for the number, defaults to 0
        :type base: int, optional
        """
        super().__init__()
        self.base = base

    def convert(self, value: str, param: click.Parameter = None, ctx: click.Context = None) -> int:
        """Perform the conversion str -> int.

        :param value: value to convert
        :param param: Click parameter, defaults to None
        :param ctx: Click context, defaults to None
        :return: value as integer
        :raises TypeError: Value is not a string
        :raises ValueError: Value is can't be interpretted as integer
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
    module: str, port: str = None, usb: str = None, timeout: int = 5000, lpcusbsio: str = None
) -> Union[MBootInterface, SDPInterface]:
    """Get appropriate interface.

    'port' and 'usb' parameters are mutually exclusive; one of them is required.

    :param module: name of module to get interface from, 'sdp' or 'mboot'
    :param port: name and speed of the serial port (format: name[,speed]), defaults to None
    :param usb: PID,VID of the USB interface, defaults to None
    :param timeout: timeout in milliseconds
    :param lpcusbsio: LPCUSBSIO spi or i2c config string
    :return: Selected interface instance
    :rtype: Interface
    :raises SPSDKError: Only one of 'port' or 'usb' must be specified
    :raises SPSDKError: When SPSDK-specific error occurs
    """
    # check that one and only one interface is defined
    all_interfaces = (port, usb, lpcusbsio)
    count_interfaces = sum(i is not None for i in all_interfaces)
    if count_interfaces == 0:
        raise SPSDKError("One of '--port', '--usb' or '--lpcusbsio' must be specified.")
    if count_interfaces > 1:
        raise SPSDKError("Only one of '--port', '--usb' or '--lpcusbsio' must be specified.")

    interface_module = {"mboot": MBootInterfaceModule, "sdp": SDPInterfaceModule}[module]
    devices = []
    if port:
        port_parts = port.split(",")
        name = port_parts.pop(0)
        baudrate = int(port_parts.pop(), 0) if port_parts else None
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
        devices = interface_module.scan_usbsio(lpcusbsio)  # type: ignore
        if len(devices) != 1:
            raise SPSDKError(f"Cannot initialize USBSIO device '{lpcusbsio}'.")
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
        except (AssertionError, SPSDKError) as spsdk_exc:
            click.echo(f"ERROR:{spsdk_exc}")
            logger.debug(str(spsdk_exc), exc_info=True)
            sys.exit(2)
        except (Exception, KeyboardInterrupt) as base_exc:  # pylint: disable=broad-except
            click.echo(f"GENERAL ERROR: {type(base_exc).__name__}: {base_exc}")
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
    if not hex_data.startswith("{{") or not hex_data.endswith("}}"):
        raise SPSDKError("Incorrectly formated hex-data: Need to start with {{ and end with }}")

    hex_data = hex_data.replace("{{", "").replace("}}", "")
    if len(hex_data) % 2:
        raise SPSDKError("Incorrectly formated hex-data: Need to have even number of characters")
    if not re.fullmatch(r"[0-9a-fA-F]*", hex_data):
        raise SPSDKError("Incorrect hex-data: Need to have valid hex string")

    str_parts = [hex_data[i : i + 2] for i in range(0, len(hex_data), 2)]
    byte_pieces = [int(part, 16) for part in str_parts]
    result = bytes(byte_pieces)
    if not result:
        raise SPSDKError("Incorrect hex-data: Unable to get any data")
    return bytes(byte_pieces)


def check_destination_dir(path: str, create_folder: bool = False) -> None:
    """Checks path's destination dir, optionally create the destination folder.

    :param path: Path to file to create/consider
    :param create_folder: Create destination folder
    """
    dest_dir = os.path.dirname(path)
    if not dest_dir:
        return
    if create_folder:
        os.makedirs(dest_dir, exist_ok=True)
        return
    if not os.path.isdir(dest_dir):
        click.echo(f"Can't create '{path}', folder '{dest_dir}' doesn't exit.")
        sys.exit(1)


def check_file_exists(path: str, force_overwrite: bool = False) -> bool:  # type: ignore
    """Check if file exists, exits if file exists and overwriting is disabled.

    :param path: Path to a file
    :param force_overwrite: allows file overwriting
    :return: if file overwriting is allowed, it return True if file exists
    """
    if force_overwrite:
        return os.path.isfile(path)
    if os.path.isfile(path) and not force_overwrite:
        click.echo(f"File '{path}' already exists. Use --force to overwrite it.")
        sys.exit(1)


def load_configuration(path: str) -> dict:
    """Load configuration from yml/json file.

    :param path: Path to configuration file
    :raises SPSDKError: When unsupported file is provided
    :return: Content of configuration as dictionary
    """
    content = None
    try:
        with open(path) as f:
            content = json.load(f)
            return content
    except json.JSONLibraryException:
        content = None
    try:
        with open(path) as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError:
        content = None
    if content is None:
        raise SPSDKError(f"Unable to load '{path}'.")
    return content

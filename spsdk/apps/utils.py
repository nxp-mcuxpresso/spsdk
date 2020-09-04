#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for general utilities used by applications."""

import sys
from typing import Union

import click

from spsdk.mboot import interfaces as MBootInterfaceModule
from spsdk.mboot.interfaces import Interface as MBootInterface
from spsdk.sdp import interfaces as SDPInterfaceModule
from spsdk.sdp.interfaces import Interface as SDPInterface


class INT(click.ParamType):
    """Type that allows integers in bin, hex, oct format including _ as a visual separator."""
    name = 'integer'

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


def get_interface(module: str, port: str = None, usb: str = None,
                  timeout: int = 5000) -> Union[MBootInterface, SDPInterface]:
    """Get appropriate interface.

    'port' and 'usb' parameters are mutually exclusive; one of them is required.

    :param module: name of module to get interface from, 'sdp' or 'mboot'
    :param port: name and speed of the serial port (format: name[,speed]), defaults to None
    :param usb: PID,VID of the USB interface, defaults to None
    :param timeout: timeout in milliseconds
    :return: Selected interface instance
    :rtype: Interface
    :raises ValueError: only one of 'port' or 'usb' must be specified
    """
    # check that one and only one interface is defined
    if port is None and usb is None:
        raise ValueError("One of 'port' or 'uart' must be specified.")
    if port is not None and usb is not None:
        raise ValueError("Only one of 'port' or 'uart' must be specified.")

    interface_module = {
        'mboot': MBootInterfaceModule,
        'sdp': SDPInterfaceModule
    }[module]
    devices = []
    if port:
        # it seems that the variable baudrate doesn't work properly
        name = port.split(',')[0] if ',' in port else port
        devices = interface_module.scan_uart(port=name, timeout=timeout)  # type: ignore
        if len(devices) != 1:
            click.echo(f"Error: cannot open PC UART port '{name}'.")
            sys.exit(1)
    if usb:
        pid_vid = usb.replace(',', ':')
        devices = interface_module.scan_usb(pid_vid)    # type: ignore
        if len(devices) == 0:
            click.echo(f"Error: cannot open USB device '{pid_vid}'")
            sys.exit(1)
        if len(devices) > 1:
            click.echo(f"Error: more than one device '{pid_vid}' found")
            sys.exit(1)
        devices[0].timeout = timeout
    return devices[0]

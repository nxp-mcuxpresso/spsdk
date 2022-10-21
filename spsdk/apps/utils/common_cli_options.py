#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI helper for Click."""

import logging
from gettext import gettext
from typing import Any, Callable, List, Optional, Sequence, Tuple, TypeVar, Union

import click
from click_command_tree import _build_command_tree, _CommandWrapper

from spsdk import __version__ as spsdk_version

FC = TypeVar("FC", bound=Union[Callable[..., Any], click.Command])

_uart_option = click.option(
    "-p",
    "--port",
    metavar="COM[,speed]",
    help="""Serial port configuration. Default baud rate is 57600.
    Use 'nxpdevscan' utility to list devices on serial port.""",
)

_sdp_uart_option = click.option(
    "-p",
    "--port",
    metavar="COM[,speed]",
    help="""Serial port configuration. Default baud rate is 115200.
    Use 'nxpdevscan' utility to list devices on serial port.""",
)

_usb_option = click.option(
    "-u",
    "--usb",
    metavar="VID:PID|USB_PATH|DEV_NAME",
    help="""USB device identifier.

    \b
    Following formats are supported: <vid>, <vid:pid> or <vid,pid>, device/instance path, device name.
    <vid>: hex or dec string; e.g. 0x0AB12, 43794.
    <vid/pid>: hex or dec string; e.g. 0x0AB12:0x123, 1:3451.
    Use 'nxpdevscan' utility to list connected device names.
""",
)

_lpcusbsio_option = click.option(
    "-l",
    "--lpcusbsio",
    metavar="[usb,VID:PID|USB_PATH|SER_NUM,]spi|i2c",
    help="""USB-SIO bridge interface.

    Optional USB device filtering formats:
    [usb,vid:pid|usb_path|serial_number]

    Following serial interfaces are supported:

    \b
    spi[index][,port,pin,speed_kHz,polarity,phase]
     - index ... optional index of SPI peripheral. Example: "spi1" (default=0)
     - port ... bridge GPIO port used as SPI SSEL(default=0)
     - pin  ... bridge GPIO pin used as SPI SSEL
        default SSEL is set to 0.15 which works
        for the LPCLink2 bridge. The MCULink OB
        bridge ignores the SSEL value anyway.(default=15)
     - speed_kHz ... SPI clock in kHz (default 1000)
     - polarity ... SPI CPOL option (default=1)
     - phase ... SPI CPHA option (default=1)

    \b
    i2c[index][,address,speed_kHz]
     - index ... optional index of I2C peripheral. Example: "i2c1" (default=0)
     - address ... I2C device address (default 0x10)
     - speed_kHz ... I2C clock in kHz (default 100)
""",
)

_buspal_option = click.option(
    "-b",
    "--buspal",
    metavar="spi[,speed,polarity,phase,lsb|msb] | i2c[,address,speed]",
    help="buspal settings",
)

_json_option = click.option(
    "-j",
    "--json",
    "use_json",
    is_flag=True,
    help="Use JSON output",
)

_timeout_option = click.option(
    "-t",
    "--timeout",
    metavar="<ms>",
    help="""Sets timeout when waiting on data over a serial line. The default is 5000 milliseconds.""",
    default=5000,
)


def spsdk_apps_common_options(options: FC) -> FC:
    """Common click options.

    Sets --help, --version; provides: `log_level: int` for logging.

    :return: click decorator
    """
    options = click.help_option("--help")(options)
    options = click.version_option(spsdk_version, "--version")(options)
    options = click.option(
        "-vv",
        "--debug",
        "log_level",
        flag_value=logging.DEBUG,
        help="Display more debugging information.",
    )(options)
    options = click.option(
        "-v",
        "--verbose",
        "log_level",
        flag_value=logging.INFO,
        help="Print more detailed information",
    )(options)
    return options


def isp_interfaces(
    uart: bool = False,
    usb: bool = False,
    lpcusbsio: bool = False,
    buspal: bool = False,
    json_option: bool = True,
    timeout_option: bool = True,
    is_sdp: bool = False,
) -> Callable:
    """Interfaces Click CLI options.

    :param uart: UART interface, defaults to False
    :param usb: USB interface, defaults to False
    :param lpcusbsio: LPCUSBSIO interface, defaults to False
    :param buspal: BUSPAL interface, defaults to False
    :param json_option: add -j option, defaults to True
    :param timeout_option: add timeout option, defaults to True
    :param is_sdp: Specifies whether the ISP interface is meant for SDP(S) protocol
    :return: click decorator
    """

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        options = []

        if uart:
            options.append(_sdp_uart_option if is_sdp else _uart_option)
        if usb:
            options.append(_usb_option)
        if lpcusbsio:
            options.append(_lpcusbsio_option)
        if buspal:
            options.append(_buspal_option)
        if json_option:
            options.append(_json_option)
        if timeout_option:
            options.append(_timeout_option)

        for option in reversed(options):
            func = option(func)

        return func

    return decorator


class CommandsTreeGroup(click.Group):
    """Custom help formatter, overrides click.Group standard formatter.

    Provides command section in help as command tree

    :param click: click.Group
    """

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Extra format methods for multi methods that adds all the commands after the options.

        :param ctx: click Context
        :param formatter: click HelpFormatter
        """
        root_cmd = _build_command_tree(ctx.find_root().command)
        rows = _get_tree(root_cmd)

        with formatter.section(gettext("Commands")):
            formatter.width = 160
            formatter.write_dl(rows, col_max=80)


class GroupAliasedGetCfgTemplate(click.Group):
    """Alias for get-cfg-template click group extension.

    Temporary class to handle deprecated 'get-cfg-template' command to provide
    better user experience.
    """

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        """Override original click get_command function to implement alias for get-cfg-template obsolete command.

        :param ctx: click Context
        :param cmd_name: Requested command name
        :return: Suitable command representation.
        """
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        if cmd_name == "get-cfg-template":
            click.secho(
                "The 'get-cfg-template' is deprecated command, use 'get-template' instead of.",
                fg="yellow",
                bold=True,
                err=True,
            )
            return click.Group.get_command(self, ctx, "get-template")

        ctx.fail(f"Not supported command: '{cmd_name}'")


class CommandsTreeGroupAliasedGetCfgTemplate(CommandsTreeGroup, GroupAliasedGetCfgTemplate):
    """Mix of Command Tree and get-cfg-template alias."""


def _get_tree(
    command: _CommandWrapper,
    rows: Optional[List] = None,
    depth: int = 0,
    is_last_item: bool = False,
    is_last_parent: bool = False,
    parent_prefix: str = "",
) -> Sequence[Tuple[str, str]]:
    """Generate tree of commands to be used with Click HelpFormatter.

    :param command: command wrapper
    :param rows: list of str lines to be printed, defaults to None
    :param depth: tree depth, defaults to 0
    :param is_last_item: last item has different formatting, defaults to False
    :param is_last_parent: last parent item, defaults to False
    :param parent_prefix: visual prefix used by parent node
    :return: definition list to be used with click HelpFormatter
    """
    if rows is None:
        rows = []
    if depth == 0:
        prefix = ""
        tree_item = ""
    else:
        prefix = "    " if is_last_parent else "│   "
        tree_item = "└── " if is_last_item else "├── "

    parent_prefix = parent_prefix + (prefix if depth > 1 else "")
    col1 = parent_prefix + tree_item + command.name
    col2 = str()
    doc: str = command.command.__doc__
    if doc:
        formatted_doc = doc.partition("\n")[0]  # take just first line of doc
        # truncate length to be compliant with max width
        formatted_doc = formatted_doc[:78] + (formatted_doc[78:] and "..")
        col2 += formatted_doc

    rows.append((col1, col2))

    for i, child in enumerate(sorted(command.children, key=lambda x: x.name)):
        _get_tree(
            child,
            rows,
            depth=(depth + 1),
            is_last_item=(i == (len(command.children) - 1)),
            is_last_parent=is_last_item,
            parent_prefix=parent_prefix,
        )
    return rows

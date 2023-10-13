#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI helper for Click."""

import logging
import os
from gettext import gettext
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar, Union

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

_sdio_option = click.option(
    "-sd",
    "--sdio",
    metavar="SDIO_PATH|DEV_NAME",
    help="""SDIO device identifier.

    \b
    Following formats are supported: device/instance path, device name.
    device/instance path: device string; e.g. /dev/mcu-sdio.
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
    help="Buspal settings",
)

_plugin_option = click.option(
    "-x",
    "--plugin",
    metavar="identifier=PLUGIN_IDENTIFIER[,param1=value1,param2=value2]",
    help="""Plugin interface settings.

    Following format of plugin setting is supported:

    \b
    identifier=<PLUGIN_IDENTIFIER>[,<key1>=<value1>,<key2>=<value2>,...]
     - <PLUGIN_IDENTIFIER>: Corresponds to the 'identifier' attribute of the plugin class
     - <key1>=<value1>: Represent a single interface parameter

    \b
    Optional interface settings:
     - Any number of optional <key>=<value> scan settings separated by comma can be defined
     - The <key>=<value> pairs are used as keyword parameters for 'scan' method of a plugin class
    """,
)

_json_option = click.option(
    "-j",
    "--json",
    "use_json",
    is_flag=True,
    help="Use JSON output",
)


def _timeout_option(use_long_option: bool, timeout: int) -> Callable[[FC], FC]:
    """Get the timeout option.

    :param use_long_option: Use long version only
    :param timeout: Default timeout in miliseconds

    :return: click decorator
    """
    options = [] if use_long_option else ["-t"]
    options.append("--timeout")
    return click.option(
        *options,
        metavar="<ms>",
        help=f"""Sets timeout when waiting on data over a serial line. The default is {timeout} milliseconds.""",
        default=timeout,
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


def spsdk_plugin_option(options: FC) -> FC:
    """Plugin click option decorator.

    Provides: `plugin: str` a full path to plugin file.

    :return: Click decorator
    """
    return click.option(
        "--plugin",
        required=False,
        type=click.Path(resolve_path=True, dir_okay=False, exists=True),
        help="External python file/package containing a custom plugin implementation.",
    )(options)


def spsdk_family_option(
    families: List[str],
    required: bool = True,
    default: Optional[str] = None,
    help: Optional[str] = None,  # pylint: disable=redefined-builtin
) -> Callable:
    """Click decorator handling family selection.

    Provides: `family: str` selected family name.

    :param families: List of available families
    :param required: Family selection is required
    :param default: Default selection, defaults to None (user selection is required)
    :param help: Customized help message, defaults to None
    :return: Click decorator.
    """

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        func = click.option(
            "-f",
            "--family",
            type=click.Choice(choices=families, case_sensitive=False),
            default=default,
            required=required,
            help=help or "Select the chip family.",
        )(func)
        return func

    return decorator


def spsdk_config_option(
    required: bool = True,
    help: Optional[str] = None,  # pylint: disable=redefined-builtin
) -> Callable:
    """Click decorator handling config files.

    Provides: `config: str` a full path to config file.

    :param required: Config file is required
    :param help: Customized help message, defaults to None
    :return: Click decorator.
    """

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        func = click.option(
            "-c",
            "--config",
            type=click.Path(resolve_path=True, exists=True, dir_okay=False),
            required=required,
            help=help or "Path to the YAML/JSON configuration file.",
        )(func)
        return func

    return decorator


_DEFAULT_OUTPUT_HELP = {
    True: "Path to a directory, where to store generated/parsed files.",
    False: "Path to a file, where to store the output.",
}


def spsdk_output_option(
    required: bool = True,
    directory: bool = False,
    force: bool = False,
    help: Optional[str] = None,  # pylint: disable=redefined-builtin
) -> Callable:
    """Click decorator handling on output file or directory.

    Provides: `output: str` a full path to directory or file.
    If a directory is required, it's automatically created.
    The force option is not passed to click command.

    :param required: Output option is required, defaults to True
    :param directory: Output is a directory, defaults to False
    :param force: Include --force option, defaults to False
    :param help: Customized help message, defaults to None
    :return: Click decorator
    """

    def callback(
        ctx: click.Context,
        param: click.Parameter,  # pylint: disable=unused-argument  # click's callback signature
        value: str,
    ) -> str:
        if ctx.resilient_parsing:
            return value
        if force and value and os.path.exists(value) and not ctx.params["force"]:
            if (directory and len(os.listdir(value))) or not directory:
                output_type = "directory" if directory else "file"
                click.echo(
                    f"Output {output_type} already exists. "
                    "Please use --force is you want to overwrite existing files."
                )
                ctx.abort()
        if "force" in ctx.params:
            del ctx.params["force"]
        if required and directory:
            os.makedirs(value, exist_ok=True)
        return value

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        if force:
            func = click.option(
                "--force",
                default=False,
                is_flag=True,
                help="Force overwriting of existing files.",
                is_eager=True,
            )(func)
        func = click.option(
            "-o",
            "--output",
            type=click.Path(resolve_path=True, dir_okay=directory, file_okay=not directory),
            required=required,
            help=help or _DEFAULT_OUTPUT_HELP[directory],
            callback=callback,
        )(func)

        return func

    return decorator


def isp_interfaces(
    uart: bool = False,
    usb: bool = False,
    sdio: bool = False,
    lpcusbsio: bool = False,
    buspal: bool = False,
    plugin: bool = False,
    json_option: bool = True,
    timeout_option: bool = True,
    is_sdp: bool = False,
    use_long_timeout_option: bool = False,
    default_timeout: int = 5000,
) -> Callable:
    """Interfaces Click CLI options.

    :param uart: UART interface, defaults to False
    :param usb: USB interface, defaults to False
    :param sdio: SDIO interface, defaults to False
    :param lpcusbsio: LPCUSBSIO interface, defaults to False
    :param buspal: BUSPAL interface, defaults to False
    :param plugin: Additional plugin to be used
    :param json_option: add -j option, defaults to True
    :param timeout_option: add timeout option, defaults to True
    :param is_sdp: Specifies whether the ISP interface is meant for SDP(S) protocol
    :param use_long_timeout_option: Use only the long form for timeout (--timeout)
    :param default_timeout: Default timeout to be set when getting the timeout_option
    :return: click decorator
    """

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        options = []

        if uart:
            options.append(_sdp_uart_option if is_sdp else _uart_option)
        if usb:
            options.append(_usb_option)
        if sdio:
            options.append(_sdio_option)
        if lpcusbsio:
            options.append(_lpcusbsio_option)
        if buspal:
            options.append(_buspal_option)
        if plugin:
            options.append(_plugin_option)
        if json_option:
            options.append(_json_option)
        if timeout_option:
            option = _timeout_option(use_long_timeout_option, default_timeout)
            options.append(option)
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


def is_click_help(ctx: click.Context, argv: List[str]) -> bool:
    """Is help command?

    :param ctx: Click content
    :param argv: Command line arguments
    :return: True if this command is just for help, False otherwise
    """

    def check_commands(argv: List[str], cmd: click.Command) -> bool:
        if len(argv) == 0:
            return cmd.no_args_is_help

        if not hasattr(ctx.command, "commands"):
            return False
        commands: Dict[str, click.Command] = ctx.command.commands
        for x in range(len(argv)):
            if argv[x] in commands:
                return check_commands(argv[x + 1 :], commands[argv[x]])

        return False

    if ctx is None or argv is None:
        return False
    if "--help" in argv[1:]:
        return True
    if ctx.command.name and not ctx.command.name in argv[0]:
        return False
    return check_commands(argv[1:], ctx.command)

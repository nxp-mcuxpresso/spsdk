#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI helper for Click."""

import functools
import logging
import os
import sys
from gettext import gettext
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar, Union

import click
from click_command_tree import _build_command_tree, _CommandWrapper

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.protocol.base import SDPProtocolBase

FC = TypeVar("FC", bound=Union[Callable[..., Any], click.Command])


def port_option(baud_rate: int = 57600) -> Callable[[FC], FC]:
    """Click decorator handling serial port configuration.

    Provides: `port: str` a port number.

    :param baud_rate: Default baud rate
    :return: Click decorator.
    """
    return click.option(
        "-p",
        "--port",
        metavar="COM[,speed]",
        help=f"""Serial port configuration. Default baud rate is {baud_rate}.
        Use 'nxpdevscan' utility to list devices on serial port.""",
    )


def usb_option(identify_by_family: bool = False) -> Callable[[FC], FC]:
    """Click decorator handling USB port configuration.

    Provides: `usb: str` a usb identifier.

    :return: Click decorator.
    """
    help_msg = """USB device identifier.
        \b
        Following formats are supported: <vid>, <vid:pid> or <vid,pid>, device/instance path, device name.
        <vid>: hex or dec string; e.g. 0x0AB12, 43794.
        <vid/pid>: hex or dec string; e.g. 0x0AB12:0x123, 1:3451.
        Use 'nxpdevscan' utility to list connected device names.

        """
    if identify_by_family:
        help_msg += """\b
        This option can be omitted if '--family' option is used."""
    option = click.option(
        "-u",
        "--usb",
        metavar="VID:PID|USB_PATH|DEV_NAME",
        help=help_msg,
    )
    return option


def sdio_option() -> Callable[[FC], FC]:
    """Click decorator handling Sdio configuration.

    Provides: `sdio: str` a sdio device identifier.

    :return: Click decorator.
    """
    return click.option(
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


def lpcusbsio_option() -> Callable[[FC], FC]:
    """Click decorator handling Lpcusbsio configuration.

    Provides: `lpcusbsio: str` a lpcusbsio device identifier.

    :return: Click decorator.
    """
    return click.option(
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


def buspal_option() -> Callable[[FC], FC]:
    """Click decorator handling Buspal configuration.

    Provides: `buspal: str` a buspal device identifier.

    :return: Click decorator.
    """
    return click.option(
        "-b",
        "--buspal",
        metavar="spi[,speed,polarity,phase,lsb|msb] | i2c[,address,speed]",
        help="Buspal settings",
    )


def can_option() -> Callable[[FC], FC]:
    """Click decorator handling Can bus configuration.

    Provides: `can: str` a can device identifier.

    :return: Click decorator.
    """
    return click.option(
        "-cb",
        "--can",
        metavar="interface[,channel,bitrate,rxid,txid]",
        help="""CAN Bus settings

    \b
    interface[,channel,bitrate,rxid,txid]
    - interface ... CAN interface name (refer to python-can library)
    - channel ... CAN channel number
    - bitrate ... CAN bitrate (default=1000000)
    - rxid ... default arbitration ID for RX (default=0x123)
    - txid ... default arbitration ID for TX (default=0x321)

    \b
    """,
    )


def interface_plugin_option() -> Callable[[FC], FC]:
    """Click decorator handling interface plugin configuration.

    Provides: `plugin: str` a plugin configuration.

    :return: Click decorator.
    """
    return click.option(
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


def spsdk_use_json_option(options: FC) -> FC:
    """Use json click option decorator.

    Provides: `use_json: bool` a use_json flag.

    :return: Click decorator
    """
    return click.option(
        "-j",
        "--json",
        "use_json",
        is_flag=True,
        help="Use JSON output",
    )(options)


def timeout_option(
    timeout: int,
    use_long_form_only: bool = False,
) -> Callable[[FC], FC]:
    """Get the timeout option.

    :param use_long_form_only: Use long version only
    :param timeout: Default timeout in miliseconds

    :return: click decorator
    """
    options = [] if use_long_form_only else ["-t"]
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
    FAMILY_OPTION = "family"

    def decorator(func: Callable[[FC], FC]) -> Callable[[FC], FC]:
        @functools.wraps(func)
        @click.pass_context
        def wrapper(
            ctx: click.Context,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if is_click_help(ctx, sys.argv):
                return None
            if required and ctx.params.get(FAMILY_OPTION) is None:
                param = next(param for param in ctx.command.params if param.name == FAMILY_OPTION)
                raise click.MissingParameter(ctx=ctx, param=param, param_type="option")
            return func(*args, **kwargs)

        wrapper = click.option(
            "-f",
            f"--{FAMILY_OPTION}",
            type=click.Choice(choices=families, case_sensitive=False),
            default=default,
            required=False,  # will be validated in the wrapper method
            help=help or "Select the chip family.",
        )(wrapper)
        return wrapper

    return decorator


def spsdk_revision_option(options: FC) -> FC:
    """Click decorator handling revision selection.

    Provides: `revision: str` a name of revision to be used.

    :return: Click decorator
    """
    return click.option(
        "-r",
        "--revision",
        type=str,
        default="latest",
        help="Chip revision; if not specified, most recent one will be used",
    )(options)


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


def spsdk_sdp_interface(
    port: bool = True,
    usb: bool = True,
    plugin: bool = True,
    timeout: int = 10000,
    identify_by_family: bool = False,
    use_long_timeout_form: bool = False,
) -> Callable:
    """Click decorator handling SDP interface.

    Provides: `interface: str` an instance of SDPInterface class.

    :return: Click decorator.
    """

    def decorator(func: Callable[[FC], FC]) -> Callable:
        @functools.wraps(func)
        @click.pass_context
        def wrapper(
            ctx: click.Context,
            timeout: int,
            *args: Any,
            port: Optional[str] = None,
            usb: Optional[str] = None,
            plugin: Optional[str] = None,
            **kwargs: Any,
        ) -> Any:
            # if --help is provided anywhere on command line, skip interface lookup
            if is_click_help(ctx, sys.argv):
                return None
            if identify_by_family:
                usb = usb or kwargs.get("family") if not (port or plugin) else usb
            interface_params = load_interface_config(
                {
                    "port": port,
                    "usb": usb,
                    "plugin": plugin,
                    "timeout": timeout,
                }
            )
            interface_cls = SDPProtocolBase.get_interface_class(interface_params.IDENTIFIER)
            interface = interface_cls.scan_single(**interface_params.get_scan_args())
            kwargs["interface"] = interface
            return func(*args, **kwargs)

        interface_options: Dict[Callable, Tuple[bool, Dict]] = {
            interface_plugin_option: (plugin, {}),
            usb_option: (usb, {"identify_by_family": identify_by_family}),
            port_option: (port, {"baud_rate": SdpUARTInterface.default_baudrate}),
        }

        wrapper = timeout_option(timeout, use_long_timeout_form)(wrapper)
        for option, (is_used, decorator_args) in interface_options.items():
            if is_used:
                wrapper = option(**decorator_args)(wrapper)
        return wrapper

    return decorator


def spsdk_mboot_interface(
    port: bool = True,
    usb: bool = True,
    sdio: bool = True,
    lpcusbsio: bool = True,
    buspal: bool = True,
    can: bool = True,
    plugin: bool = True,
    timeout: int = 5000,
    identify_by_family: bool = False,
    use_long_timeout_form: bool = False,
) -> Callable:
    """Click decorator handling Mboot interface.

    Provides: `interface: str` an instance of MbootInterface class.

    :return: Click decorator.
    """

    def decorator(func: Callable[[FC], FC]) -> Callable:
        @functools.wraps(func)
        @click.pass_context
        def wrapper(
            ctx: click.Context,
            timeout: int,
            *args: Any,
            port: Optional[str] = None,
            usb: Optional[str] = None,
            sdio: Optional[str] = None,
            buspal: Optional[str] = None,
            can: Optional[str] = None,
            lpcusbsio: Optional[str] = None,
            plugin: Optional[str] = None,
            **kwargs: Any,
        ) -> Any:
            # if --help is provided anywhere on command line, skip interface lookup
            if is_click_help(ctx, sys.argv):
                return None
            if identify_by_family:
                usb = (
                    usb or kwargs.get("family")
                    if not (port or buspal or lpcusbsio or sdio or can or plugin)
                    else usb
                )
            cli_params = {
                "port": port,
                "usb": usb,
                "sdio": sdio,
                "buspal": buspal,
                "can": can,
                "lpcusbsio": lpcusbsio,
                "plugin": plugin,
                "timeout": timeout,
            }
            interface_params = load_interface_config(cli_params)
            interface_cls = MbootProtocolBase.get_interface_class(interface_params.IDENTIFIER)
            interface = interface_cls.scan_single(**interface_params.get_scan_args())
            kwargs["interface"] = interface
            return func(*args, **kwargs)

        interface_options: Dict[Callable, Tuple[bool, Dict]] = {
            interface_plugin_option: (plugin, {}),
            buspal_option: (buspal, {}),
            can_option: (can, {}),
            lpcusbsio_option: (lpcusbsio, {}),
            sdio_option: (sdio, {}),
            usb_option: (usb, {"identify_by_family": identify_by_family}),
            port_option: (port, {"baud_rate": MbootUARTInterface.default_baudrate}),
        }
        wrapper = timeout_option(timeout, use_long_timeout_form)(wrapper)

        for option, (is_used, decorator_args) in interface_options.items():
            if is_used:
                wrapper = option(**decorator_args)(wrapper)
        return wrapper

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

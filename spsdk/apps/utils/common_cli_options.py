#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI helper for Click."""

import functools
import logging
import os
import sys
import textwrap
from copy import deepcopy
from gettext import gettext, ngettext
from typing import Any, Callable, Optional, Sequence, TypeVar, Union, cast

import click
import colorama
from click_command_tree import _build_command_tree, _CommandWrapper

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.apps.utils.utils import INT, SPSDKAppError
from spsdk.el2go.interface import EL2GOInterfaceHandler
from spsdk.exceptions import SPSDKError
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.utils.database import DatabaseManager

FC = TypeVar("FC", bound=Union[Callable[..., Any], click.Command])
logger = logging.getLogger(__name__)


class FamilyChoice(click.Choice):
    """The SPSDK modification of Click Choice type.

    It supports solid checking, but modified help prints.
    """

    name = "choice"
    MAX_FAMILIES_TO_PRINT = 4

    def __repr__(self) -> str:
        return f"Family Choice({list(self.choices)})"

    def __init__(self, choices: Sequence[str]) -> None:
        """Constructor of SPSDK Family Choice click type.

        :param choices: List of families to choice from.
        """
        self.predecessor_choices = DatabaseManager().quick_info.devices.get_predecessors(
            list(choices)
        )
        super().__init__(choices, False)

    def to_info_dict(self) -> dict[str, Any]:
        """Just prepare the dict with base info."""
        info_dict = super().to_info_dict()
        info_dict["choices"] = self.choices
        if self.predecessor_choices:
            info_dict["predecessor_choices"] = self.predecessor_choices
        info_dict["case_sensitive"] = self.case_sensitive
        return info_dict

    def get_metavar(self, param: click.Parameter) -> str:
        """Prepare the help string.

        :param param: Input click parameter object.
        :return: Help string.
        """
        if len(self.choices) > self.MAX_FAMILIES_TO_PRINT:
            choices_str = (
                "|".join(self.choices[: self.MAX_FAMILIES_TO_PRINT])
                + "..., and more. Use 'get-families' command to show all."
            )
        else:
            choices_str = "|".join(self.choices)

        # Use curly braces to indicate a required argument.
        if param.required and param.param_type_name == "argument":
            return f"{{{choices_str}}}"

        # Use square braces to indicate an option or optional argument.
        return f"[{choices_str}]"

    def convert(
        self, value: Any, param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> Any:
        """Normalize user input."""
        # Match through normalization and case sensitivity
        # first do token_normalize_func, then lowercase
        # preserve original `value` to produce an accurate message in
        # `self.fail`
        normed_value = value
        all_choices = list(self.choices)
        if self.predecessor_choices:
            all_choices += list(self.predecessor_choices.keys())
        normed_choices = {choice: choice for choice in all_choices}

        if ctx is not None and ctx.token_normalize_func is not None:
            normed_value = ctx.token_normalize_func(value)
            normed_choices = {
                ctx.token_normalize_func(normed_choice): original
                for normed_choice, original in normed_choices.items()
            }

        if not self.case_sensitive:
            normed_value = normed_value.casefold()
            normed_choices = {
                normed_choice.casefold(): original
                for normed_choice, original in normed_choices.items()
            }

        if normed_value in normed_choices:
            if normed_value in self.predecessor_choices:
                new_value = self.predecessor_choices[normed_value]
                logger.warning(
                    f"The obsolete device name '{normed_value}' "
                    f"has been translated to current one: '{new_value}')"
                )
                normed_value = new_value

            return normed_choices[normed_value]

        choices_str = ", ".join(map(repr, self.choices))
        self.fail(
            ngettext(
                "{value!r} is not {choice}.",
                "{value!r} is not one of {choices}.",
                len(self.choices),
            ).format(value=value, choice=choices_str, choices=choices_str),
            param,
            ctx,
        )


def move_cmd_to_grp(
    org_grp: click.Group, grp: click.Group, name: str, new_name: Optional[str] = None
) -> None:
    """Move the command to new group from the main and make it depreciated.

    :param org_grp: Original group with depreciated place
    :param grp: TArget group where the command should be moved
    :param name: Name of original command
    :param new_name: Optional new name of command, defaults to None
    """
    cmd = org_grp.commands[name]
    moved_cmd = deepcopy(cmd)
    new_name = new_name or name
    moved_cmd.name = new_name
    grp.add_command(moved_cmd, new_name)
    cmd.hidden = True
    cmd.deprecated = True


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
        - nirq_port ... nIRQ port number (default None)
        - nirq_pin ... nIRQ pin number (default None)

        \b
        i2c[index][,address,speed_kHz]
        - index ... optional index of I2C peripheral. Example: "i2c1" (default=0)
        - address ... I2C device address (default 0x10)
        - speed_kHz ... I2C clock in kHz (default 100)
        - nirq_port ... nIRQ port number (default None)
        - nirq_pin ... nIRQ pin number (default None)

        \b
        Following types of interface configuration formats are supported:
        - string with coma separated arguments i.e. spi1,0,15,1000,1
        - string with coma separated keyword arguments (the order may not be maintained) i.e.spi1,port=0,speed_kHz=1000,nirq_port=1,nirq_pin=7
        - string with combination of coma separated arguments and keyword arguments i.e.spi1,0,15,nirq_port=1,nirq_pin=7

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


def el2go_interface_option() -> Callable[[FC], FC]:
    """Click decorator handling El2Go interface configuration."""
    return click.option(
        "-d",
        "--device",
        type=click.Choice(
            EL2GOInterfaceHandler.get_supported_el2go_interfaces(),
            case_sensitive=False,
        ),
        required=False,
        help="Select connection method for El2Go communication, otherwise default from DB will be used",
    )


def fb_buffer_address() -> Callable[[FC], FC]:
    """Click decorator handling Fastboot buffer address configuration.

    Provides: `fb_buffer_address: int` a buffer address.

    :return: Click decorator.
    """
    return click.option(
        "--fb-addr",
        type=INT(),
        required=False,
        help="Override default buffer address for fastboot",
    )


def fb_buffer_size() -> Callable[[FC], FC]:
    """Click decorator handling Fastboot buffer size configuration.

    Provides: `fb_buffer_size: int` a buffer size.

    :return: Click decorator.
    """
    return click.option(
        "--fb-size",
        type=INT(),
        required=False,
        help="Override default buffer size for fastboot",
    )


def usbpath_option() -> Callable[[FC], FC]:
    """Click decorator handling USB path configuration.

    Provides: `usbpath: str` a usb path.

    :return: Click decorator.
    """
    return click.option(
        "-up",
        "--usbpath",
        type=str,
        required=False,
        metavar="USB_PATH",
        help="Filter UUU devices by USB path",
    )


def usbserial_option() -> Callable[[FC], FC]:
    """Click decorator handling USB serial configuration.

    Provides: `usbserial: str` a usb serial.

    :return: Click decorator.
    """
    return click.option(
        "-us",
        "--usbserial",
        type=str,
        required=False,
        metavar="SERIAL_NUMBER",
        help="Filter UUU devices by USB serial number",
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
    timeout: int = 5000,
    use_long_form_only: bool = False,
) -> Callable[[FC], FC]:
    """Get the timeout option.

    :param use_long_form_only: Use long version only
    :param timeout: Default timeout in milliseconds

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
    families: list[str],
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
            type=FamilyChoice(choices=families),
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

        interface_options: dict[Callable, tuple[bool, dict]] = {
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
    required: bool = True,
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
            try:
                interface_params = load_interface_config(cli_params)
                interface_cls = MbootProtocolBase.get_interface_class(interface_params.IDENTIFIER)
                interface = interface_cls.scan_single(**interface_params.get_scan_args())
                kwargs["interface"] = interface
            except SPSDKAppError:
                if required:
                    raise
                kwargs["interface"] = None

            return func(*args, **kwargs)

        interface_options: dict[Callable, tuple[bool, dict]] = {
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


def spsdk_el2go_interface(
    port: bool = True,
    usb: bool = True,
    sdio: bool = True,
    lpcusbsio: bool = True,
    buspal: bool = True,
    can: bool = True,
    device: bool = True,
    plugin: bool = True,
    timeout: int = 5000,
    identify_by_family: bool = True,
    use_long_timeout_form: bool = False,
    required: bool = True,
    fb_addr: bool = True,
    fb_size: bool = True,
    usbpath: bool = True,
    usbserial: bool = True,
) -> Callable:
    """Click decorator handling EL2Go interface.

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
            device: Optional[str] = None,
            family: Optional[str] = None,
            revision: Optional[str] = None,
            fb_addr: Optional[int] = None,
            fb_size: Optional[int] = None,
            usbpath: Optional[str] = None,
            usbserial: Optional[str] = None,
            **kwargs: Any,
        ) -> Any:
            # if --help is provided anywhere on command line, skip interface lookup
            if is_click_help(ctx, sys.argv):
                return None

            if identify_by_family:
                usb = (
                    usb or family
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

            try:
                interface_params = load_interface_config(cli_params)
                interface_handler = EL2GOInterfaceHandler.get_el2go_interface_handler(
                    interface_params, family, revision, device, fb_addr, fb_size, usbpath, usbserial
                )
                kwargs["interface"] = interface_handler
            except SPSDKError:
                if required:
                    raise
                kwargs["interface"] = None
            return func(*args, **kwargs)

        interface_options: dict[Callable, tuple[bool, dict]] = {
            interface_plugin_option: (plugin, {}),
            buspal_option: (buspal, {}),
            can_option: (can, {}),
            lpcusbsio_option: (lpcusbsio, {}),
            sdio_option: (sdio, {}),
            usb_option: (usb, {"identify_by_family": identify_by_family}),
            port_option: (port, {"baud_rate": MbootUARTInterface.default_baudrate}),
            el2go_interface_option: (device, {}),
            fb_buffer_address: (fb_addr, {}),
            fb_buffer_size: (fb_size, {}),
            usbpath_option: (usbpath, {}),
            usbserial_option: (usbserial, {}),
        }

        wrapper = timeout_option(timeout, use_long_timeout_form)(wrapper)
        wrapper = spsdk_family_option(
            EL2GOInterfaceHandler.get_supported_families(), required=False
        )(wrapper)
        wrapper = spsdk_revision_option(wrapper)

        for option, (_is_used, decorator_args) in interface_options.items():
            if _is_used:
                wrapper = option(**decorator_args)(wrapper)
        return wrapper

    return decorator


class GetFamiliesCommand(click.Command):
    """Shows the full families information for commands in this group."""

    def __init__(self) -> None:
        """Constructor of get families command."""
        super().__init__(
            name="get-families",
            help="Shows the full family info for commands in this group.",
            callback=self.handle_families_info,
        )

        self.group_family_param: Optional[click.Parameter] = None
        self.cmd_family_params: dict[str, click.Parameter] = {}

    def add_cmd(self, family_param: click.Parameter, cmd_name: Optional[str] = None) -> None:
        """Add the command or group family choices parameter.

        :param family_param: Mandatory family choices parameters
        :param cmd_name: If None the the family choices are for the parent group,
            when name is specified it should be for the command name, defaults to None
        """
        if cmd_name is None:
            self.group_family_param = family_param
        else:
            if len(self.params) == 0:
                self.params.append(
                    click.Option(
                        param_decls=["-c", "--cmd-name"],
                        type=click.Choice([], case_sensitive=False),
                        help="Choose the command name to get full information about NXP families support.",
                    )
                )
            self.cmd_family_params[cmd_name] = family_param
            choice = cast(click.Choice, self.params[0].type)
            cast(list, choice.choices).append(cmd_name)

    def handle_families_info(self, cmd_name: Optional[str] = None) -> None:
        """Show the supported families."""

        def print_families(family_param: click.Parameter) -> None:
            if isinstance(family_param.type, (FamilyChoice, click.Choice)):
                click.echo(colorama.Fore.GREEN + "Supported families:" + colorama.Fore.RESET)
                sorted_choices = DatabaseManager().quick_info.sort_devices_to_groups(
                    list(family_param.type.choices)
                )
                for purpose, devices in sorted_choices.items():
                    click.echo(f"{colorama.Fore.MAGENTA} - {purpose}:{colorama.Fore.RESET}")
                    for line in textwrap.wrap(", ".join(devices)):
                        click.echo(f"    {line}")

                if isinstance(family_param.type, FamilyChoice):
                    click.echo(
                        colorama.Fore.YELLOW + "\nObsolete predecessor families names "
                        "(Warning: Those names will be removed in some following version of SPSDK):"
                        + colorama.Fore.RESET
                    )
                    for line in textwrap.wrap(", ".join(family_param.type.predecessor_choices)):
                        click.echo(f"    {line}")

        if cmd_name:
            click.echo(f"Shown families for command '{cmd_name}':")
            print_families(self.cmd_family_params[cmd_name])
            return

        if self.group_family_param:
            click.echo("Shown families for this group of commands:")
            print_families(self.group_family_param)
            return
        click.echo(
            f"Missing option '-c'/'--cmd-name' with this possible options: [{', '.join(self.cmd_family_params.keys())}]"
        )


class SpsdkClickGroup(click.Group):
    """SPSDK Click group, overrides click.Group standard class.

    To check and add additional command get-families

    :param click: click.Group
    """

    def __init__(self, **attrs: Any) -> None:
        """SPSDK Click group descriptor."""
        super().__init__(**attrs)
        self.get_families: Optional[GetFamiliesCommand] = None
        if "params" in attrs:
            params: list[click.Parameter] = attrs["params"]
            for param in params:
                if param.name == "family":
                    self.get_families = GetFamiliesCommand()
                    self.get_families.add_cmd(param, None)
                    self.add_command(self.get_families)
                    break

    def add_command(self, cmd: click.Command, name: Optional[str] = None) -> None:
        """Overload add command method, to check commands if contains family option."""
        super().add_command(cmd, name)
        name = name or cmd.name
        for param in cmd.params:
            if param.name == "family":
                if self.get_families is None:
                    self.get_families = GetFamiliesCommand()
                    self.add_command(self.get_families)
                self.get_families.add_cmd(param, name)


class CommandsTreeGroup(SpsdkClickGroup):
    """Custom help formatter, overrides SPSDK click group standard formatter.

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
    rows: Optional[list] = None,
    depth: int = 0,
    is_last_item: bool = False,
    is_last_parent: bool = False,
    parent_prefix: str = "",
) -> Sequence[tuple[str, str]]:
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


def is_click_help(ctx: click.Context, argv: list[str]) -> bool:
    """Is help command?

    :param ctx: Click content
    :param argv: Command line arguments
    :return: True if this command is just for help, False otherwise
    """

    def check_commands(argv: list[str], cmd: click.Command) -> bool:
        if len(argv) == 0:
            return cmd.no_args_is_help

        if not hasattr(ctx.command, "commands"):
            return False
        commands: dict[str, click.Command] = ctx.command.commands
        for x in range(len(argv)):
            if argv[x] in commands:
                return check_commands(argv[x + 1 :], commands[argv[x]])

        return False

    if ctx is None or argv is None:
        return False
    if "get-families" in argv[1:]:
        return True
    if "--help" in argv[1:]:
        return True
    if ctx.command.name and ctx.command.name not in argv[0]:
        return False
    return check_commands(argv[1:], ctx.command)

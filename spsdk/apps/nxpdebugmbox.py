#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import contextlib
import datetime
import logging
import os
import struct
import sys
from dataclasses import dataclass
from time import sleep
from typing import Callable, Iterator, List, Optional

import click
import colorama
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
    spsdk_plugin_option,
)
from spsdk.apps.utils.utils import (
    INT,
    SPSDKAppError,
    catch_spsdk_error,
    format_raw_data,
    progress_bar,
)
from spsdk.dat import dm_commands
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import DebugCredential
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.famode_image import (
    check_famode_data,
    create_config,
    generate_config_templates,
    get_supported_families,
    modify_input_config,
)
from spsdk.debuggers.utils import PROBES, load_all_probe_types, open_debug_probe, test_ahb_access
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.mbi.mbi import MasterBootImage, get_mbi_class
from spsdk.utils.crypto.cert_blocks import find_root_certificates
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    Endianness,
    find_file,
    get_abs_path,
    load_binary,
    load_configuration,
    value_to_int,
    write_file,
)
from spsdk.utils.plugins import load_plugin_from_source
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


def get_debug_probe_options_help() -> str:
    """Get Click help for debug probe user params.

    :return: Help string.
    """
    ret = (
        "This option could be used multiply to setup non-standard option for debug probe.\n\n"
        "The example of use: -o KEY=VALUE"
    )
    for probe, probe_cls in PROBES.items():
        options_help = probe_cls.get_options_help()
        if options_help:
            ret += f"\n\n[{probe}]:"
            for option, help_text in options_help.items():
                ret += f"\n\n  [{option}]: {help_text}"

    return ret


@dataclass
class DatProtocol:
    """Debug Authentication protocol."""

    VERSIONS = [
        "1.0",
        "1.1",
        "2.0",
        "2.1",
        "2.2",
    ]

    version: str

    def is_rsa(self) -> bool:
        """Determine whether rsa or ecc is used.

        :return: True if the protocol is RSA type. False otherwise
        """
        protocol_version = self.version.split(".")
        is_rsa = protocol_version[0] == "1"
        return is_rsa

    def validate(self) -> None:
        """Validate protocol value.

        :raises SPSDKValueError: In case that protocol is using unsupported key type.
        """
        if self.version not in self.VERSIONS:
            raise SPSDKValueError(f"Unsupported protocol '{self.version}' was given.")


@dataclass
class DebugProbeParams:
    """Debug probe related parameters."""

    interface: str
    serial_no: str
    debug_probe_user_params: dict


@dataclass
class DebugMailboxParams:
    """Debug mailbox related parameters."""

    reset: bool
    more_delay: float
    operation_timeout: int


@contextlib.contextmanager
def _open_debugmbox(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> Iterator[DebugMailbox]:
    """Method opens DebugMailbox object based on input arguments.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :return: Active DebugMailbox object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        dm = DebugMailbox(
            debug_probe=debug_probe,
            reset=debug_mailbox_params.reset,
            moredelay=debug_mailbox_params.more_delay,
            op_timeout=debug_mailbox_params.operation_timeout,
        )
        try:
            yield dm
        except SPSDKError as exc:
            raise SPSDKError(f"Problem with debug mailbox occurred: {exc}") from exc
        finally:
            dm.close()


@click.group(name="nxpdebugmbox", no_args_is_help=True, cls=CommandsTreeGroup)
@click.option(
    "-i",
    "--interface",
    type=str,
    help=(
        "Probe interface selection, if not specified, all available debug probe"
        f" interfaces are used. {list(PROBES.keys())}"
    ),
)
@click.option(
    "-s",
    "--serial-no",
    help="Debug probe hardware ID/serial number to select the probe in system.",
)
@click.option(
    "-p",
    "--protocol",
    "protocol",
    metavar="VERSION",
    help=f"Set the protocol version. Currently this option is used for gendc and auth sub commands"
    f'Available options are: {", ".join(DatProtocol.VERSIONS)}',
    type=click.Choice(DatProtocol.VERSIONS),
)
@click.option(
    "-t",
    "--timing",
    type=float,
    default=0.0,
    help="Duration of additional delay after reset sequence, defaults to 0 seconds",
)
@click.option(
    "-n",
    "--no-reset",
    "no_reset",
    is_flag=True,
    default=True,
    help=(
        "Omit reset of debug mailbox during initialization,"
        " default behavior is reset debug mailbox during initialization."
    ),
)
@click.option(
    "-o",
    "--debug-probe-option",
    multiple=True,
    help=get_debug_probe_options_help(),
)
@click.option(
    "--operation-timeout",
    type=INT(),
    default="1000",
    help="Special option to change the standard operation timeout used"
    " for communication with debug mailbox. Default value is 1000ms.",
)
@spsdk_apps_common_options
@spsdk_plugin_option
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    protocol: str,
    log_level: int,
    timing: float,
    serial_no: str,
    debug_probe_option: List[str],
    no_reset: bool,
    operation_timeout: int,
    plugin: str,
) -> int:
    """Tool for working with Debug Mailbox."""
    spsdk_logger.install(level=log_level)
    spsdk_logger.configure_pyocd_logger()

    if plugin:
        load_plugin_from_source(plugin)
        load_all_probe_types()

    if interface and interface not in PROBES:
        raise SPSDKAppError(
            f"Defined interface({interface}) is not in available interfaces: {list(PROBES.keys())}"
        )

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")

        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
        "debug_mailbox_params": DebugMailboxParams(
            reset=no_reset, more_delay=timing, operation_timeout=operation_timeout
        ),
        "debug_probe_params": DebugProbeParams(
            interface=interface, serial_no=serial_no, debug_probe_user_params=probe_user_params
        ),
        "protocol": DatProtocol(version=protocol),
    }

    return 0


@main.command(name="auth", no_args_is_help=True)
@click.option("-b", "--beacon", type=INT(), help="Authentication beacon")
@click.option("-c", "--certificate", help="Path to Debug Credentials.")
@click.option("-k", "--key", help="Path to DCK private key.")
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.option(
    "-x",
    "--nxp-keys",
    type=bool,
    is_flag=True,
    default=False,
    help="Use the ROM NXP keys to authenticate.",
)
@click.pass_obj
def auth_command(
    pass_obj: dict, beacon: int, certificate: str, key: str, no_exit: bool, nxp_keys: bool
) -> None:
    """Perform the Debug Authentication.

    The -p protocol option must be defined in main application.
    """
    auth(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        pass_obj["protocol"],
        beacon,
        certificate,
        key,
        no_exit,
        nxp_keys,
    )


def auth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    protocol: DatProtocol,
    beacon: int,
    certificate: str,
    key: str,
    no_exit: bool,
    nxp_keys: bool,
) -> None:
    """Perform the Debug Authentication.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param protocol: Debug authentication protocol.
    :param beacon: Authentication beacon.
    :param certificate: Path to Debug Credentials.
    :param key: Path to DCK private key.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :param nxp_keys: When true, Use the ROM NXP keys to authenticate.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    protocol.validate()
    try:
        logger.info("Starting Debug Authentication")

        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            debug_cred_data = load_binary(certificate)
            debug_cred = DebugCredential.parse(debug_cred_data)
            dac_rsp_len = (
                30 if debug_cred.HASH_LENGTH == 48 and debug_cred.socc in [4, 6, 7, 0xA] else 26
            )
            if nxp_keys:
                dac_data = dm_commands.NxpDebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            else:
                dac_data = dm_commands.DebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            # convert List[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
            logger.info(f"DAC: \n{str(dac)}")
            dac.validate_against_dc(debug_cred)
            dar = DebugAuthenticateResponse.create(
                version=protocol.version,
                dc=debug_cred,
                auth_beacon=beacon,
                dac=dac,
                dck=key,
            )
            logger.info(f"DAR:\n{str(dar)}")
            dar_data = dar.export()
            # convert bytes to List[int]
            dar_data_words = list(struct.unpack(f"<{len(dar_data) // 4}I", dar_data))
            if nxp_keys:
                dar_response = dm_commands.NxpDebugAuthenticationResponse(
                    dm=mail_box, paramlen=len(dar_data_words)
                ).run(dar_data_words)
            else:
                dar_response = dm_commands.DebugAuthenticationResponse(
                    dm=mail_box, paramlen=len(dar_data_words)
                ).run(dar_data_words)
            logger.debug(f"DAR response: {dar_response}")
            if not no_exit:
                exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                logger.debug(f"Exit response: {exit_response}")
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                # Do test of access to AHB bus
                sleep(0.2)
                ahb_access_granted = test_ahb_access(mail_box.debug_probe)
                res_str = (
                    (colorama.Fore.GREEN + "successfully")
                    if ahb_access_granted
                    else (colorama.Fore.RED + "without AHB access")
                )
                click.echo(f"Debug Authentication ends {res_str}{colorama.Fore.RESET}.")
                if not ahb_access_granted:
                    raise SPSDKAppError("Access to AHB is not granted.")
            else:
                click.echo("Debug Authentication ends without exit and without test of AHB access.")

    except SPSDKError as e:
        raise SPSDKAppError(
            f"{colorama.Fore.RED}Debug Mailbox authentication failed:{colorama.Fore.RESET}\n{e}"
        ) from e


@main.command(name="reset")
@click.option(
    "-h",
    "--hard-reset",
    is_flag=True,
    default=False,
    help="When used, the hardware reset is used instead of debug mailbox reset.",
)
@click.pass_obj
def reset_command(pass_obj: dict, hard_reset: bool) -> None:
    """Reset MCU by DebugMailBox.

    The reset command implemented in NXPDEBUGMBOX has two modes (option -h):

    Reset by RESET REQUEST of debug mailbox that causes the reset of MCU by SYSRESET_REQ.
    The chip is reset, but the ROM code returns back the chip into debug mailbox handler
    (without -h/--hard-reset option).

    Reset by external reset signal. This reset is done by asserting external reset signal over
    debug probe. After this reset type the chip behavior is same as after standard reset button on the board.
    (with -h/--hard-reset option)
    """
    reset(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], hard_reset)
    click.echo("Reset MCU by Debug Mailbox succeeded.")


def reset(
    debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams, hard_reset: bool
) -> None:
    """Reset MCU by DebugMailBox.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param hard_reset: If true, use the hardware reset instead of debug mailbox reset.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        debug_mailbox_params.reset = True
        if hard_reset:
            with open_debug_probe(
                interface=debug_probe_params.interface,
                serial_no=debug_probe_params.serial_no,
                debug_probe_params=debug_probe_params.debug_probe_user_params,
                print_func=click.echo,
            ) as debug_probe:
                debug_probe.reset()
        else:
            with _open_debugmbox(debug_probe_params, debug_mailbox_params):
                pass
    except Exception as e:
        raise SPSDKAppError(f"Reset MCU by Debug Mailbox failed: {e}") from e


@main.command(name="start")
@click.pass_obj
def start_command(pass_obj: dict) -> None:
    """Start DebugMailBox."""
    start(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Start Debug Mailbox succeeded")


def start(debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams) -> None:
    """Start DebugMailBox.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.StartDebugMailbox(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Start Debug Mailbox failed: {e}") from e


@main.command(name="exit")
@click.pass_obj
def exit_command(pass_obj: dict) -> None:  # pylint: disable=redefined-builtin
    """Exit DebugMailBox."""
    exit_debug_mbox(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Exit Debug Mailbox succeeded")


def exit_debug_mbox(
    debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams
) -> None:  # pylint: disable=redefined-builtin
    """Exit DebugMailBox.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.ExitDebugMailbox(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Exit Debug Mailbox failed: {e}") from e


@main.command(name="erase")
@click.pass_obj
def erase_command(pass_obj: dict) -> None:
    """Erase Flash."""
    erase(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Mass flash erase succeeded")


def erase(debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams) -> None:
    """Erase Flash.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EraseFlash(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Mass flash erase failed: {e}") from e


@main.command(name="famode")
@click.option(
    "-m",
    "--message",
    type=click.Path(),
    required=False,
    help="Path to message file.",
)
@click.pass_obj
def famode_command(pass_obj: dict, message: str) -> None:
    """Set Fault Analysis Mode."""
    famode(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], message)
    click.echo("Set fault analysis mode succeeded.")


def famode(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    message: str,
) -> None:
    """Set Fault Analysis Mode.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param message: Path to message file..
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            if message:
                data = load_binary(message)
                data_words = list(struct.unpack(f"<{len(data) // 4}I", data))
                dm_commands.SetFaultAnalysisMode(dm=mail_box, paramlen=len(data_words)).run(
                    data_words
                )
            else:
                dm_commands.SetFaultAnalysisMode(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Set fault analysis mode failed: {e}") from e


@main.command(name="ispmode", no_args_is_help=True)
@click.option("-m", "--mode", type=INT(), required=True)
@click.pass_obj
def ispmode_command(pass_obj: dict, mode: int) -> None:
    """Enter ISP Mode."""
    ispmode(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], mode)
    click.echo("Entering into ISP mode succeeded")


def ispmode(
    debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams, mode: int
) -> None:
    """Enter ISP Mode.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param mode: ISP mode
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EnterISPMode(dm=mail_box).run([mode])
    except Exception as e:
        raise SPSDKAppError(f"Entering into ISP mode failed: {e}") from e


@main.command(name="token_auth", no_args_is_help=True)
@click.option(
    "-f", "--file", type=click.Path(), required=True, help="Path to token file (string hex format)."
)
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.pass_obj
def token_auth_command(pass_obj: dict, file: str, no_exit: bool) -> None:
    """Debug Authentication using token."""
    token_auth(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], file, no_exit)
    click.echo("Debug authentication using token succeeded")


def token_auth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    token_file: str,
    no_exit: bool,
) -> None:
    """Debug Authentication using token.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param token_file: Path to token file.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    token = []
    logger.info("Starting Debug Authentication for Blank Device..")
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            with open(token_file, "rb") as f:
                while True:
                    chunk = f.read(8).strip()
                    if not chunk:
                        break
                    token.append(int(chunk, 16))

            dm_commands.EnterBlankDebugAuthentication(dm=mail_box).run(token)
            if not no_exit:
                exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                logger.debug(f"Exit response: {exit_response}")
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                # Do test of access to AHB bus
                ahb_access_granted = test_ahb_access(mail_box.debug_probe)
                res_str = (
                    (colorama.Fore.GREEN + "successfully")
                    if ahb_access_granted
                    else (colorama.Fore.RED + "without AHB access")
                )
                if not ahb_access_granted:
                    raise SPSDKAppError("Access to AHB is not granted.")

                logger.info(
                    f"Debug Authentication using token ends {res_str}{colorama.Fore.RESET}."
                )
            else:
                logger.info(
                    "Debug Authentication using token ends without exit and without test of AHB access."
                )
    except Exception as e:
        raise SPSDKAppError(f"Debug authentication using token  failed: {e}") from e


@main.command(name="get-crp")
@click.pass_obj
def get_crp_command(pass_obj: dict) -> None:
    """Get CRP level. This command should be called after 'start' command and with no-reset '-n' option."""
    get_crp(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Get CRP Level succeeded")


def get_crp(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Get CRP level.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            crp_level = dm_commands.GetCRPLevel(dm=mail_box).run()[0]
            click.echo(f"CRP level is: 0x{crp_level:02X}.")
    except Exception as e:
        raise SPSDKAppError(f"Get CRP Level failed: {e}") from e


@main.command(name="start-debug-session")
@click.pass_obj
def start_debug_session_command(pass_obj: dict) -> None:
    """Start debug session."""
    start_debug_session(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Start debug session succeeded")


def start_debug_session(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Start debug session.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.StartDebugSession(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Start debug session failed: {e}") from e


@main.command(name="test-connection")
@click.pass_obj
def test_connection_command(pass_obj: dict) -> None:
    """Method just try if the device debug port is opened or not."""
    ahb_access_granted = test_connection(pass_obj["debug_probe_params"])
    access_str = colorama.Fore.GREEN if ahb_access_granted else colorama.Fore.RED + "not-"
    click.echo(f"The device is {access_str}accessible for debugging.{colorama.Fore.RESET}")


def test_connection(debug_probe_params: DebugProbeParams) -> bool:
    """Method just try if the device debug port is opened or not.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with open_debug_probe(
            interface=debug_probe_params.interface,
            serial_no=debug_probe_params.serial_no,
            debug_probe_params=debug_probe_params.debug_probe_user_params,
            print_func=click.echo,
        ) as debug_probe:
            ahb_access_granted = test_ahb_access(debug_probe)
        return ahb_access_granted
    except Exception as e:
        raise SPSDKAppError(f"Testing AHB access failed: {e}") from e


@main.command(name="read-memory", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.option("-c", "--count", type=INT(), required=True, help="Number of bytes to read")
@spsdk_output_option(required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_obj
def read_memory_command(
    pass_obj: dict,
    address: int,
    count: int,
    output: str,
    use_hexdump: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout."""
    with progress_bar(suppress=logger.getEffectiveLevel() > logging.INFO) as progress_callback:
        data = read_memory(pass_obj["debug_probe_params"], address, count, progress_callback)
    if output:
        write_file(data, output, mode="wb")
        click.echo(f"The memory has been read and written into {output}")
    else:
        click.echo(format_raw_data(data, use_hexdump=use_hexdump))


def read_memory(
    debug_probe_params: DebugProbeParams,
    address: int,
    byte_count: int,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> bytes:
    """Reads the memory.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param address: Starting address.
    :param byte_count: Number of bytes to read.
    :param progress_callback: Progressbar callback method.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    bin_image = BinaryImage("memRead", byte_count, offset=address)
    start_addr = bin_image.aligned_start(4)
    length = bin_image.aligned_length(4)

    data = bytes()
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        try:
            for addr in range(start_addr, start_addr + length, 4):
                if progress_callback:
                    progress_callback(addr, start_addr + length)
                data += debug_probe.mem_reg_read(addr).to_bytes(4, Endianness.LITTLE.value)
        except SPSDKError as exc:
            raise SPSDKAppError(str(exc)) from exc

    if not data:
        raise SPSDKAppError("The read operation failed.")
    if len(data) != length:
        logger.warning(
            f"The memory wasn't read complete. It was read just first {len(data) - (address-start_addr)} Bytes."
        )
    # Shrink start padding data
    data = data[address - start_addr :]
    # Shrink end padding data
    data = data[:byte_count]
    return data


@main.command(name="write-memory", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@optgroup("Data Source", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-f", "--file", type=click.Path(exists=True, dir_okay=False), help="Path to file to write"
)
@optgroup.option("-h", "--hex-string", type=str, help="String of hex values. e.g. '1234', '12 34'")
@click.option("-c", "--count", type=INT(), required=False, help="Number of bytes to write")
@click.pass_obj
def write_memory_command(
    pass_obj: dict, address: int, file: str, hex_string: str, count: int
) -> None:
    """Writes memory from a file or a hex-data."""
    if file:
        with open(file, "rb") as f:
            data = f.read(count)
    else:
        data = bytes.fromhex(hex_string)[:count]
    write_memory(pass_obj["debug_probe_params"], address, data)
    click.echo("The memory has been written successfully.")


def write_memory(debug_probe_params: DebugProbeParams, address: int, data: bytes) -> None:
    """Writes memory from a file or a hex-data.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param address: Starting address.
    :param data: Data to write into memory.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    byte_count = len(data)
    bin_image = BinaryImage("memRead", byte_count, offset=address)
    start_addr = bin_image.aligned_start(4)
    length = bin_image.aligned_length(4)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        start_padding = address - start_addr
        align_data = data
        if start_padding:
            align_start_word = debug_probe.mem_reg_read(start_addr).to_bytes(
                4, Endianness.LITTLE.value
            )
            align_data = align_start_word[:start_padding] + data

        end_padding = length - byte_count - start_padding
        if end_padding:
            align_end_word = debug_probe.mem_reg_read(start_addr + length - 4).to_bytes(
                4, Endianness.LITTLE.value
            )
            align_data = align_data + align_end_word[4 - end_padding :]

        with progress_bar(suppress=logger.getEffectiveLevel() > logging.INFO) as progress_callback:
            for i, addr in enumerate(range(start_addr, start_addr + length, 4)):
                progress_callback(addr, start_addr + length)
                to_write = int.from_bytes(align_data[i * 4 : i * 4 + 4], Endianness.LITTLE.value)
                debug_probe.mem_reg_write(addr, to_write)
                # verify write
                try:
                    verify_data = debug_probe.mem_reg_read(addr)
                except SPSDKError as ver_exc:
                    raise SPSDKAppError("The write verification failed.") from ver_exc
                if to_write != verify_data:
                    raise SPSDKAppError(
                        f"Data verification failed! {hex(to_write)} != {hex(verify_data)}"
                    )


@main.command(name="get-uuid")
@click.pass_obj
def get_uuid_command(pass_obj: dict) -> None:
    """Get the UUID from target if possible.

    Some devices need to call 'start' command prior the get-uuid!
    Also there could be issue with repeating of this command without hard reset of device 'reset -h'.
    """
    uuid = get_uuid(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    if uuid:
        click.echo(f"The device UUID is: {uuid.hex()}")
    else:
        click.echo("The device UUID is not possible to retrieve from target.")


def get_uuid(
    debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams
) -> Optional[bytes]:
    """Get the UUID from target if possible.

    Some devices need to call 'start' command prior the get-uuid!
    Also there could be issue with repeating of this command without hard reset of device 'reset -h'.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    :return: UUID value in bytes if succeeded, None otherwise.
    """
    try:
        with open_debug_probe(
            debug_probe_params.interface,
            debug_probe_params.serial_no,
            debug_probe_params.debug_probe_user_params,
            print_func=click.echo,
        ) as debug_probe:
            try:
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=26).run()
            except SPSDKError:
                debug_probe.close()
                debug_probe.open()
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=30).run()
            # convert List[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
    except Exception as e:
        raise SPSDKAppError(f"Getting UUID from target failed: {e}") from e

    if dac.uuid == bytes(16):
        logger.warning("The valid UUID is not included in DAC.")
        logger.info(f"DAC info:\n {str(dac)}")
        return None

    logger.info(f"Got DAC from SOCC:'0x{dac.socc:08X}' to retrieve UUID.")
    return dac.uuid


@main.command(name="gendc", no_args_is_help=True)
@spsdk_config_option()
@click.option(
    "-e",
    "--rot-config",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Specify Root Of Trust from MBI or Cert block configuration file",
)
@spsdk_plugin_option
@spsdk_output_option(force=True)
@click.pass_obj
def gendc_command(
    pass_obj: dict,
    plugin: str,
    output: str,
    config: str,
    rot_config: str,
) -> None:
    """Generate debug certificate (DC)."""
    gendc(
        pass_obj["protocol"],
        plugin,
        output,
        config,
        rot_config,
    )
    click.echo("Creating Debug credential file succeeded")


def gendc(
    protocol: DatProtocol,
    plugin: str,
    output: str,
    config: str,
    rot_config: str,
) -> None:
    """Generate debug certificate (DC).

    :param protocol: Debug authentication protocol.
    :param plugin: Path to external python file containing a custom SignatureProvider implementation.
    :param output: Path to debug certificate file.
    :param config: YAML credential config file.
    :param rot_config: Root Of Trust from MBI or Cert block configuration file.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    protocol.validate()

    try:
        if plugin:
            load_plugin_from_source(plugin)
        logger.info("Loading configuration from yml file...")
        yaml_content = load_configuration(config)
        socc = yaml_content.get("socc")
        if socc is None:
            raise SPSDKAppError("SOCC must be defined in configuration.")

        if rot_config:
            rot_config_dir = os.path.dirname(rot_config)
            logger.info("Loading configuration from cert block/MBI config file...")

            config_data = load_configuration(rot_config, search_paths=[rot_config_dir])
            if "certBlock" in config_data:
                try:
                    config_data = load_configuration(
                        config_data["certBlock"], search_paths=[rot_config_dir]
                    )
                except SPSDKError as e:
                    raise SPSDKAppError("certBlock must be provided as YAML configuration") from e

            public_keys = find_root_certificates(config_data)
            yaml_content["rot_meta"] = [
                find_file(x, search_paths=[rot_config_dir]) for x in public_keys
            ]

            private_key = (
                config_data.get("signPrivateKey")
                or config_data.get("mainCertPrivateKeyFile")
                or config_data.get("mainRootCertPrivateKeyFile")
            )
            if private_key:
                yaml_content["rotk"] = find_file(private_key, search_paths=[rot_config_dir])

            sp_config = config_data.get("signProvider")
            if sp_config:
                yaml_content["sign_provider"] = sp_config

            rot_index = config_data.get("mainRootCertId", config_data.get("mainCertChainId"))
            if rot_index is not None:
                yaml_content["rot_id"] = value_to_int(rot_index)

        family_ambassador = DebugCredential.get_family_ambassador(socc)

        check_config(
            yaml_content,
            DebugCredential.get_validation_schemas(family_ambassador),
            search_paths=[os.path.dirname(config)],
        )

        logger.info(f"Creating {'RSA' if protocol.is_rsa() else 'ECC'} debug credential object...")
        dc = DebugCredential.create_from_yaml_config(
            version=protocol.version,
            yaml_config=yaml_content,
            search_paths=[os.path.dirname(config)],
        )
        dc.sign()
        data = dc.export()
        click.echo(f"RKTH: {dc.get_rotkh().hex()}")
        logger.debug(f"Debug credential file details:\n {str(dc)}")
        logger.info(f"Saving the debug credential to a file: {output}")
        write_file(data, output, mode="wb")

    except Exception as e:
        raise SPSDKAppError(f"The generating of Debug Credential file failed: {e}") from e


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(
    families=DebugCredential.get_supported_families(),
    required=True,
    help="If needed select the chip family.",
)
@click.option(
    "-r",
    "--revision",
    type=str,
    default="latest",
    help="Chip revision; if not specified, most recent one will be used",
)
@spsdk_output_option(force=True)
def get_template_command(family: str, revision: str, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file."""
    get_template(family, revision, output)
    click.echo("The configuration template file has been created.")


def get_template(family: str, revision: str, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    :param family: Optional family to have specific template per family.
    :param revision: Optional chip revision to specify MCU family.
    :param output: Path to output file.
    """
    write_file(DebugCredential.generate_config_template(family, revision), output)


@main.command(name="erase-one-sector", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.pass_obj
def erase_one_sector_command(pass_obj: dict, address: int) -> None:
    """Erase one flash sector."""
    erase_one_sector(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], address)
    click.echo("Erasing one sector succeeded")


def erase_one_sector(
    debug_probe_params: DebugProbeParams, debug_mailbox_params: DebugMailboxParams, address: int
) -> None:
    """Erase one sector.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param address: Flash sector address
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EraseOneSector(dm=mail_box).run([address])
    except Exception as e:
        raise SPSDKAppError(f"Erasing one sector failed: {e}") from e


@main.command(name="write-to-flash", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.option("-f", "--file", type=click.Path(), required=True, help="Path to file.")
@click.pass_obj
def write_to_flash_command(pass_obj: dict, address: int, file: str) -> None:
    """Write data to flash."""
    write_to_flash(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], address, file)
    click.echo("Write data to flash succeeded")


def write_to_flash(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    address: int,
    file: str,
) -> None:
    """Write to flash.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param address: Flash sector address
    :param file: File with binary data
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            data = load_binary(file)
            formatted_data = [data[i : i + 16] for i in range(0, len(data), 16)]
            if len(formatted_data[-1]) < 16:
                logger.debug(f"Added padding to the original data source file: {file}")
                formatted_data[-1] = formatted_data[-1].ljust(16, b"\x00")
            for i in range(len(formatted_data)):
                params = [address]
                params.extend(list(struct.unpack("<4I", formatted_data[i])))
                dm_commands.WriteToFlash(dm=mail_box).run(params)
    except Exception as e:
        raise SPSDKAppError(f"Write words to flash failed: {e}") from e


@main.group("famode-image", no_args_is_help=True)
def famode_image_group() -> None:
    """Group of sub-commands related to Fault Analysis Mode Image (related to some families)."""


@famode_image_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(required=True)
@spsdk_plugin_option
def famode_image_export_command(config: str, plugin: str) -> None:
    """Generate Fault Analysis mode image from YAML/JSON configuration.

    The configuration template files could be generated by subcommand 'get-templates'.
    """
    famode_image_export(config, plugin)


def famode_image_export(config: str, plugin: Optional[str] = None) -> None:
    """Generate Fault Analysis mode image from YAML/JSON configuration.

    :param config: Path to the YAML/JSON configuration
    :param plugin: Path to external python file containing a custom SignatureProvider implementation.
    """
    config_data = load_configuration(config)
    if plugin:
        load_plugin_from_source(plugin)
    config_dir = os.path.dirname(config)
    config_data = modify_input_config(config_data)
    mbi_cls = get_mbi_class(config_data)
    check_config(config_data, mbi_cls.get_validation_schemas(), search_paths=[config_dir, "."])
    mbi_obj = mbi_cls()
    mbi_obj.load_from_config(config_data, search_paths=[config_dir, "."])
    mbi_data = mbi_obj.export()
    if mbi_obj.rkth:
        click.echo(f"RKTH: {mbi_obj.rkth.hex()}")
    mbi_output_file_path = get_abs_path(config_data["masterBootOutputFile"], config_dir)
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


@famode_image_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=get_supported_families())
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary FA Mode image to parse.",
)
@spsdk_output_option(directory=True)
def famode_image_parse_command(family: str, binary: str, output: str) -> None:
    """Parse MBI Image into YAML configuration and binary images."""
    famode_image_parse(family, binary, output)


def famode_image_parse(family: str, binary: str, output: str) -> None:
    """Parse FA Mode Image into YAML configuration and binary images."""
    mbi = MasterBootImage.parse(family=family, data=load_binary(binary))

    if not mbi:
        click.echo(f"Failed. (FA mode image: {binary} parsing failed.)")
        return
    check_famode_data(mbi)
    cfg = create_config(mbi, output)
    yaml_data = CommentedConfig(
        main_title=(
            f"Fault Analysis mode Image ({mbi.__class__.__name__}) recreated configuration from :"
            f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
        ),
        schemas=mbi.get_validation_schemas(),
    ).get_config(cfg)

    write_file(yaml_data, os.path.join(output, "famode_config.yaml"))

    click.echo(f"Success. (FA mode image: {binary} has been parsed and stored into {output} )")


@famode_image_group.command("get-templates", no_args_is_help=True)
@spsdk_family_option(families=get_supported_families())
@spsdk_output_option(directory=True, force=True)
def famode_image_get_templates_command(family: str, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    famode_image_get_templates(family, output)


def famode_image_get_templates(family: str, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    templates = generate_config_templates(family)
    for file_name, template in templates.items():
        full_file_name = os.path.join(output, file_name + ".yaml")
        click.echo(f"Creating {full_file_name} template file.")
        write_file(template, full_file_name)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import contextlib
import datetime
import inspect
import logging
import os
import struct
import sys
from dataclasses import dataclass
from time import sleep
from typing import Any, Iterator, Optional, Type

import click
import colorama
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    SpsdkClickGroup,
    move_cmd_to_grp,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
    spsdk_plugin_option,
    spsdk_revision_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error, format_raw_data
from spsdk.dat import dm_commands, famode_image
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import (
    DebugCredentialCertificate,
    DebugCredentialCertificateEcc,
    ProtocolVersion,
)
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.debuggers.utils import (
    PROBES,
    get_test_address,
    load_all_probe_types,
    open_debug_probe,
    test_ahb_access,
)
from spsdk.exceptions import SPSDKError
from spsdk.image.mbi.mbi import MasterBootImage, get_mbi_class
from spsdk.utils.crypto.cert_blocks import find_root_certificates
from spsdk.utils.misc import (
    align_block,
    find_file,
    get_abs_path,
    get_printable_path,
    load_binary,
    load_configuration,
    value_to_int,
    write_file,
)
from spsdk.utils.plugins import load_plugin_from_source
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


class NxpDebugMbox_DeprecatedCommand2_4(click.Command):
    """Better printing deprecated warning of command."""

    def format_help_text(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Writes the help text to the formatter if it exists."""
        if self.help is not None:
            # truncate the help text to the first form feed
            text = inspect.cleandoc(self.help).partition("\f")[0]
        else:
            text = ""

        if self.deprecated:
            text = (
                colorama.Fore.YELLOW
                + "Deprecated Command! It will be removed in SPSDK v2.4. The command has been moved to sub group.\n"
                + colorama.Fore.RESET
                + text
            )

        if text:
            formatter.write_paragraph()

            with formatter.indentation():
                formatter.write_text(text)


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
class DebugProbeParams:
    """Debug probe related parameters."""

    interface: str
    serial_no: str
    debug_probe_user_params: dict

    def set_test_address(self, test_address: int) -> None:
        """Set if not already sets, the test address for AHB access.

        :param test_address: New overriding address.
        """
        if "test_address" not in self.debug_probe_user_params:
            self.debug_probe_user_params["test_address"] = test_address


@dataclass
class DebugMailboxParams:
    """Debug mailbox related parameters."""

    family: str
    revision: str
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
        debug_probe.connect()
        dm = DebugMailbox(
            debug_probe=debug_probe,
            family=debug_mailbox_params.family,
            revision=debug_mailbox_params.revision,
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
@spsdk_family_option(
    families=DebugCredentialCertificate.get_supported_families(),
    required=False,
    help="Select the chip family.",
)
@spsdk_revision_option
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
    help=f"Set the protocol version. Currently this option is used for gendc and auth sub commands."
    f'Available options are: {", ".join(ProtocolVersion.VERSIONS)}. '
    "If not set, the version will be determined from the RoT public key type.",
    type=click.Choice(ProtocolVersion.VERSIONS, case_sensitive=False),
    hidden=True,
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
    family: str,
    revision: str,
    interface: str,
    protocol: str,
    log_level: int,
    timing: float,
    serial_no: str,
    debug_probe_option: list[str],
    no_reset: bool,
    operation_timeout: int,
    plugin: str,
) -> int:
    """Tool for working with Debug Mailbox."""
    spsdk_logger.install(level=log_level)

    if protocol:
        logger.warning("The -p/--protocol option is deprecated and will be removed in version 2.4.")

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

    debug_params = DebugProbeParams(
        interface=interface, serial_no=serial_no, debug_probe_user_params=probe_user_params
    )

    if not family:
        logger.warning(
            "The Family is not specified. This is a new option that will be "
            "mandatory since SPSDK 2.4. Please update your scripts."
        )
    else:
        debug_params.set_test_address(get_test_address(family, revision))

    ctx.obj = {
        "debug_mailbox_params": DebugMailboxParams(
            family=family,
            revision=revision,
            reset=no_reset,
            more_delay=timing,
            operation_timeout=operation_timeout,
        ),
        "debug_probe_params": debug_params,
    }

    return 0


@main.command(
    name="auth",
    no_args_is_help=True,
    cls=NxpDebugMbox_DeprecatedCommand2_4,
    hidden=True,
    deprecated=True,
)
@click.option("-b", "--beacon", type=INT(), default="0", help="Authentication beacon")
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
@click.option(
    "-a",
    "--address",
    type=INT(),
    help=("Deprecated option, use in '-o test-address=0x2000_1000' in root command instead of."),
    hidden=True,
)
@click.pass_obj
def auth_command(
    pass_obj: dict,
    beacon: int,
    certificate: str,
    key: str,
    no_exit: bool,
    nxp_keys: bool,
    address: Optional[int],
) -> None:
    """Perform the Debug Authentication.

    The -p option must be defined in main application.
    """
    if address is not None:
        logger.warning(
            "The address option is deprecated, if you really need override test address, "
            "use '-o test-address=xx' in root command."
        )
    debug_mailbox_params: DebugMailboxParams = pass_obj["debug_mailbox_params"]

    family = debug_mailbox_params.family
    if not family:
        debug_cred_data = load_binary(certificate)
        debug_cred = DebugCredentialCertificate.parse(debug_cred_data)
        family = DebugCredentialCertificate.get_family_ambassador(debug_cred.socc)
    # auth command can recognize the file or signature provider
    sign_prov = None
    local_key = None
    if not key:
        raise SPSDKAppError("Path to DCK private key or signature provider must be provided")
    if os.path.exists(key):
        local_key = key
    else:
        sign_prov = key
    config = {
        "family": family,
        "certificate": certificate,
        "beacon": beacon,
        "srk_set": "nxp" if nxp_keys else "oem",
        "dck_private_key": local_key,
        "sign_provider": sign_prov,
    }

    auth(
        pass_obj["debug_probe_params"],
        debug_mailbox_params,
        config=config,
        no_exit=no_exit,
    )


def auth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    config: dict[str, Any],
    no_exit: bool,
    search_paths: Optional[list[str]] = None,
) -> None:
    """Perform the Debug Authentication.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param config: Configuration of DAT.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :param search_paths: Optional list of search paths.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Starting Debug Authentication")

        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            debug_cred_data = load_binary(config["certificate"], search_paths)
            debug_cred = DebugCredentialCertificate.parse(debug_cred_data)
            dac_rsp_len = 18 + debug_cred.rot_hash_length // 4

            nxp_keys = config.get("srk_set", "oem") == "nxp"
            if nxp_keys:
                dac_data = dm_commands.NxpDebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            else:
                dac_data = dm_commands.DebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            # convert list[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)

            logger.info(f"DAC: \n{str(dac)}")
            family = debug_mailbox_params.family
            if not family:
                family = debug_cred.get_family_ambassador(debug_cred.socc)
            dac.validate_against_dc(family, debug_cred)
            search_paths = search_paths or []
            search_paths.append(os.path.dirname(config["certificate"]))
            dar = DebugAuthenticateResponse.load_from_config(
                config=config, dac=dac, search_paths=search_paths
            )
            logger.info(f"DAR:\n{str(dar)}")
            dar_data = align_block(dar.export(), alignment=4)
            # convert bytes to list[int]
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
                try:
                    exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                    logger.debug(f"Exit response: {exit_response}")
                except SPSDKError:
                    logger.error("Exit command failed. Maybe too early reset happen on hardware.")
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                mail_box.debug_probe.connect()
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


@main.command(name="reset", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="start", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="exit", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="erase", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="famode", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="ispmode", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="token_auth", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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
                try:
                    exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
                    logger.debug(f"Exit response: {exit_response}")
                except SPSDKError:
                    logger.debug(
                        "Exit command failed. Possibly the target reset happened too early."
                    )
                # Re-open debug probe
                mail_box.debug_probe.close()
                mail_box.debug_probe.open()
                mail_box.debug_probe.connect()
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


@main.command(name="get-crp", cls=NxpDebugMbox_DeprecatedCommand2_4)
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
            if dm_commands.GetCRPLevel.CMD_ID in mail_box.non_standard_statuses:
                if crp_level in mail_box.non_standard_statuses[dm_commands.GetCRPLevel.CMD_ID]:
                    click.echo(
                        f"CRP level is: {mail_box.non_standard_statuses[dm_commands.GetCRPLevel.CMD_ID][crp_level]}."
                    )
                else:
                    click.echo(f"CRP level is: 0x{crp_level:08X}.")
            else:
                click.echo(f"CRP level is: 0x{crp_level:02X}.")
    except Exception as e:
        raise SPSDKAppError(f"Get CRP Level failed: {e}") from e


@main.command(name="start-debug-session", cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="test-connection", cls=NxpDebugMbox_DeprecatedCommand2_4)
@click.option(
    "-a",
    "--address",
    type=INT(),
    help=("Deprecated option, use in '-o test-address=0x2000_1000' in root command instead of."),
    hidden=True,
)
@click.option(
    "-d",
    "--destination",
    type=click.Choice(["cpu_mem", "debug_port"], case_sensitive=False),
    default="cpu_mem",
    help="""
        Test connection destination:

         - cpu_mem: Test that is able to communicate with target memory

         - debug_port: Test that is able to communicate with chip debug port (basic chip connection)
    """,
)
@click.pass_obj
def test_connection_command(pass_obj: dict, destination: str, address: Optional[int]) -> None:
    """Method just try if the device debug port is opened or not."""
    if address is not None:
        logger.warning(
            "The address option is deprecated, if you really need override test address, "
            "use '-o test-address=xx' in root command."
        )
    ahb_access_granted = test_connection(pass_obj["debug_probe_params"], destination=destination)
    access_str = colorama.Fore.GREEN if ahb_access_granted else colorama.Fore.RED + "NOT "
    click.echo(f"The test connection ends {access_str}successfully.{colorama.Fore.RESET}")


def test_connection(debug_probe_params: DebugProbeParams, destination: str) -> bool:
    """Method just try if the device debug port is opened or not.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param destination: Test destination [cpu_mem, debug_port].
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with open_debug_probe(
            interface=debug_probe_params.interface,
            serial_no=debug_probe_params.serial_no,
            debug_probe_params=debug_probe_params.debug_probe_user_params,
            print_func=click.echo,
        ) as debug_probe:
            debug_probe.connect()
            if destination == "cpu_mem":
                return test_ahb_access(debug_probe)
            if destination == "debug_port":
                try:
                    dp_idr = debug_probe.read_dp_idr()
                    logger.info(f"The debug port IDR: 0x{dp_idr:08X}")
                    return True
                except SPSDKError:
                    return False
            raise SPSDKAppError(f"Unsupported test connection destination: {destination}")
    except Exception as e:
        raise SPSDKAppError(f"Testing AHB access failed: {e}") from e


@main.command(name="read-memory", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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
    data = read_memory(pass_obj["debug_probe_params"], address, count)
    if output:
        write_file(data, output, mode="wb")
        click.echo(f"The memory has been read and written into {output}")
    else:
        click.echo(format_raw_data(data, use_hexdump=use_hexdump))


def read_memory(
    debug_probe_params: DebugProbeParams,
    address: int,
    byte_count: int,
) -> bytes:
    """Reads the memory.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param address: Starting address.
    :param byte_count: Number of bytes to read.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    data = bytes()
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect()
        try:
            data = debug_probe.mem_block_read(addr=address, size=byte_count)
        except SPSDKError as exc:
            raise SPSDKAppError(str(exc)) from exc

    if not data:
        raise SPSDKAppError("The read operation failed.")
    if len(data) != byte_count:
        logger.warning(
            f"The memory wasn't read complete. It was read just first {len(data) - (address-address)} Bytes."
        )
    return data


@main.command(name="write-memory", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect()
        try:
            debug_probe.mem_block_write(addr=address, data=data)
        except SPSDKError as exc:
            raise SPSDKAppError(f"Failed to write memory: {str(exc)}") from exc


@main.command(name="get-uuid", cls=NxpDebugMbox_DeprecatedCommand2_4)
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
            debug_probe.connect()
            try:
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    family=debug_mailbox_params.family,
                    revision=debug_mailbox_params.revision,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=26).run()
            except SPSDKError:
                debug_probe.close()
                debug_probe.open()
                debug_probe.connect()
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    family=debug_mailbox_params.family,
                    revision=debug_mailbox_params.revision,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=30).run()
            # convert list[int] to bytes
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


@main.command(name="gendc", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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
        plugin,
        output,
        config,
        rot_config,
    )
    click.echo("Creating Debug credential file succeeded")


def gendc(
    plugin: str,
    output: str,
    config: str,
    rot_config: str,
) -> None:
    """Generate debug certificate (DC).

    :param plugin: Path to external python file containing a custom SignatureProvider implementation.
    :param output: Path to debug certificate file.
    :param config: YAML credential config file.
    :param rot_config: Root Of Trust from MBI or Cert block configuration file.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        if plugin:
            load_plugin_from_source(plugin)
        logger.info("Loading configuration from yml file...")
        yaml_content = load_configuration(config)

        family = yaml_content.get("family")
        revision = yaml_content.get("revision", "latest")
        if not family:  # backward compatibility code to get at least ambassador of family
            socc_raw = yaml_content.get("socc")
            if socc_raw is None:
                raise SPSDKAppError("You need to define 'family' in the configuration file")
            socc = value_to_int(socc_raw)
            family = DebugCredentialCertificate.get_family_ambassador(socc)

        config_dir = os.path.dirname(config)
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

            try:
                public_keys = find_root_certificates(config_data)
                yaml_content["rot_meta"] = [
                    find_file(x, search_paths=[rot_config_dir]) for x in public_keys
                ]
            except SPSDKError:
                logger.warning(
                    "Cannot load RoT certificates from RoT configuration (MBI/CertBlock)"
                )

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

        klass = DebugCredentialCertificate._get_class_from_cfg(
            config=yaml_content, family=family, search_paths=[config_dir], revision=revision
        )
        check_config(
            yaml_content,
            klass.get_validation_schemas(family, revision),
            search_paths=[config_dir],
        )

        dc = klass.create_from_yaml_config(
            config=yaml_content,
            search_paths=[config_dir],
        )
        logger.info(
            f"Creating {'RSA' if dc.version.is_rsa() else 'ECC'} debug credential object..."
        )

        dc.sign()
        data = dc.export()
        click.echo(f"RKTH: {dc.calculate_hash().hex()}")
        logger.debug(f"Debug credential file details:\n {str(dc)}")
        logger.info(f"Saving the debug credential to a file: {output}")
        write_file(data, output, mode="wb")

    except Exception as e:
        raise SPSDKAppError(f"The generating of Debug Credential file failed: {e}") from e


@main.command(name="get-template", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
@spsdk_output_option(force=True)
@click.pass_obj
def get_template_command(pass_obj: dict, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file."""
    dm_params: DebugMailboxParams = pass_obj["debug_mailbox_params"]
    if not dm_params.family:
        raise SPSDKAppError("The family must be specified.")

    get_template(dm_params, output)
    click.echo(
        f"The Debug Credentials template for {dm_params.family} has been saved into "
        f"{get_printable_path(output)} YAML file"
    )


def get_template(dm_params: DebugMailboxParams, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    :param dm_params: Debug mailbox parameters.
    :param output: Path to output file.
    """
    try:
        klass: Type[DebugCredentialCertificate] = DebugCredentialCertificate._get_class(
            family=dm_params.family, revision=dm_params.revision
        )
    except SPSDKError:
        klass = DebugCredentialCertificateEcc

    write_file(
        klass.generate_config_template(dm_params.family, dm_params.revision),
        output,
    )


@main.command(name="erase-one-sector", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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


@main.command(name="write-to-flash", no_args_is_help=True, cls=NxpDebugMbox_DeprecatedCommand2_4)
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
    if address % 16 != 0:
        raise SPSDKAppError("The address must be aligned to 16 bytes.")
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            data = load_binary(file)
            formatted_data = [data[i : i + 16] for i in range(0, len(data), 16)]
            if len(formatted_data[-1]) < 16:
                logger.debug(f"Added padding to the original data source file: {file}")
                formatted_data[-1] = formatted_data[-1].ljust(16, b"\x00")
            for i in range(len(formatted_data)):
                params = [address + 16 * i]
                params.extend(list(struct.unpack("<4I", formatted_data[i])))
                dm_commands.WriteToFlash(dm=mail_box).run(params)
    except Exception as e:
        raise SPSDKAppError(f"Write words to flash failed: {e}") from e


@main.group("famode-image", no_args_is_help=True, cls=SpsdkClickGroup)
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
    config_data = famode_image.modify_input_config(config_data)
    mbi_cls = get_mbi_class(config_data)
    check_config(
        config_data,
        mbi_cls.get_validation_schemas(config_data["family"]),
        search_paths=[config_dir, "."],
    )
    mbi_obj = mbi_cls()
    mbi_obj.load_from_config(config_data, search_paths=[config_dir, "."])
    mbi_data = mbi_obj.export()
    if mbi_obj.rkth:
        click.echo(f"RKTH: {mbi_obj.rkth.hex()}")
    mbi_output_file_path = get_abs_path(config_data["masterBootOutputFile"], config_dir)
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


@famode_image_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=famode_image.get_supported_families())
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
    famode_image.check_famode_data(mbi)
    cfg = famode_image.create_config(mbi, output)
    yaml_data = CommentedConfig(
        main_title=(
            f"Fault Analysis mode Image ({mbi.__class__.__name__}) recreated configuration from :"
            f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
        ),
        schemas=mbi.get_validation_schemas(family),
    ).get_config(cfg)

    write_file(yaml_data, os.path.join(output, "famode_config.yaml"))

    click.echo(f"Success. (FA mode image: {binary} has been parsed and stored into {output} )")


@famode_image_group.command("get-templates", no_args_is_help=True)
@spsdk_family_option(families=famode_image.get_supported_families())
@spsdk_output_option(directory=True, force=True)
def famode_image_get_templates_command(family: str, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    famode_image_get_templates(family, output)


def famode_image_get_templates(family: str, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    templates = famode_image.generate_config_templates(family)
    for file_name, template in templates.items():
        full_file_name = os.path.join(output, file_name + ".yaml")
        click.echo(f"Creating {full_file_name} template file.")
        write_file(template, full_file_name)


@main.group("dat", no_args_is_help=True, cls=SpsdkClickGroup)
def dat_group() -> None:
    """Group of commands for working with Debug Authentication Procedure."""


@dat_group.command(name="auth", no_args_is_help=True)
@click.option("-c", "--config", help="Path to Debug Authentication configuration file.")
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.option(
    "-a",
    "--address",
    type=INT(),
    help=("Deprecated option, use in '-o test-address=0x2000_1000' in root command instead of."),
    hidden=True,
)
@click.pass_obj
def auth_command_new(
    pass_obj: dict,
    config: str,
    no_exit: bool,
    address: int,
) -> None:
    """Perform the Debug Authentication."""
    if address is not None:
        logger.warning(
            "The address option is deprecated, if you really need override test address, "
            "use '-o test-address=xx' in root command."
        )
    auth(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        config=load_configuration(config),
        no_exit=no_exit,
        search_paths=[os.path.dirname(config)],
    )


@dat_group.command("get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@click.pass_obj
def dat_get_template_command(pass_obj: dict, output: str) -> None:
    """Create template of Debug authentication configurations in YAML format."""
    dm_params: DebugMailboxParams = pass_obj["debug_mailbox_params"]
    dat_get_template(dm_params.family, output, dm_params.revision)


def dat_get_template(family: str, output: str, revision: str = "latest") -> None:
    """Create template of Debug authentication configurations in YAML format."""
    template = DebugAuthenticateResponse.generate_config_template(family, revision)
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(template, output)


@main.group("cmd", no_args_is_help=True, cls=SpsdkClickGroup)
def cmd_group() -> None:
    """Group of commands for working with raw Debug MailBox commands."""


move_cmd_to_grp(main, cmd_group, "erase")
move_cmd_to_grp(main, cmd_group, "erase-one-sector")
move_cmd_to_grp(main, cmd_group, "exit")
move_cmd_to_grp(main, cmd_group, "famode")
move_cmd_to_grp(main, cmd_group, "get-crp")
move_cmd_to_grp(main, cmd_group, "ispmode")
move_cmd_to_grp(main, cmd_group, "start")
move_cmd_to_grp(main, cmd_group, "start-debug-session")
move_cmd_to_grp(main, cmd_group, "token_auth", "token-auth")
move_cmd_to_grp(main, cmd_group, "write-to-flash")


@cmd_group.command(name="get-dac", no_args_is_help=True)
@spsdk_output_option()
@click.option(
    "-l",
    "--rot-hash-length",
    type=click.Choice(["32", "48", "66"], case_sensitive=False),
    help="""
    \b
    The length of Root of Trust hash in Debug authentication challenge packet.
    There is simple key do decide:
        - Most device depends on used RoT keys type:
        -- RSA (all types): 32
        -- ECC 256: 32
        -- ECC 384: 48
        -- ECC 521: 66
        - The exceptions:
        -- The KW45xx devices has always 32 bytes
        -- Devices based on EdgeLock Enclave security element has 32 bytes""",
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
def get_dac_command(
    pass_obj: dict,
    nxp_keys: bool,
    rot_hash_length: int,
    output: str,
) -> None:
    """Perform the Start of Debug Authentication and get the DAC.

    The -p option must be defined in main application.
    """
    dac_data = get_dac(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        rot_hash_length=int(rot_hash_length),
        nxp_keys=nxp_keys,
    )
    click.echo(f"The DAC data has been stored to: {output}.")
    write_file(dac_data, output, mode="wb")


def get_dac(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    rot_hash_length: int,
    nxp_keys: bool = False,
) -> bytes:
    """Perform the Start of Debug Authentication and get the DAC.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param rot_hash_length: Select the RoT hash length, choices are [32,48,66].
    :param nxp_keys: When true, the NXP start authentication challenge is performed instead of OEM.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Starting Debug Authentication")
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            dac_rsp_len = 18 + rot_hash_length // 4
            if nxp_keys:
                dac_data = dm_commands.NxpDebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            else:
                dac_data = dm_commands.DebugAuthenticationStart(
                    dm=mail_box, resplen=dac_rsp_len
                ).run()
            # convert list[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)

            logger.info(f"DAC: \n{str(dac)}")
            return dac_data_bytes
    except SPSDKError as exc:
        raise SPSDKAppError(f"The Start of Debug Authentication failed: {str(exc)}") from exc


@cmd_group.command(name="send-dar", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary with DAR packet.",
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
def send_dar_command(
    pass_obj: dict,
    binary: str,
    nxp_keys: bool,
) -> None:
    """Send the Debug Authentication response to device."""
    send_dar(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        dar=load_binary(binary),
        nxp_keys=nxp_keys,
    )
    click.echo("The DAR data has been sent to device.")


def send_dar(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    dar: bytes,
    nxp_keys: bool = False,
) -> None:
    """Send the Debug Authentication response.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param dar: The DAR packet in bytes.
    :param nxp_keys: When true, the NXP start authentication challenge is performed instead of OEM.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Sending Debug Authentication Response")
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            # logger.info(str(DebugAuthenticateResponse.parse(dar)))
            dar_data = align_block(dar, alignment=4)
            # convert bytes to list[int]
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
    except SPSDKError as exc:
        raise SPSDKAppError(f"The send Debug Authentication Response failed: {str(exc)}") from exc


@dat_group.group("dc", no_args_is_help=True, cls=SpsdkClickGroup)
def dc_group() -> None:
    """Group of commands for Debug Credential binaries."""


move_cmd_to_grp(main, dc_group, "gendc", "export")
move_cmd_to_grp(main, dc_group, "get-template")


@main.group("mem-tool", no_args_is_help=True, cls=SpsdkClickGroup)
def mem_group() -> None:
    """Group of commands for working with target memory over debug probe."""


move_cmd_to_grp(main, mem_group, "read-memory")
move_cmd_to_grp(main, mem_group, "write-memory")
move_cmd_to_grp(main, mem_group, "test-connection")


@main.group("tool", no_args_is_help=True, cls=SpsdkClickGroup)
def tool_group() -> None:
    """Group of commands for working with various tools over debug probe."""


move_cmd_to_grp(main, tool_group, "reset")
move_cmd_to_grp(main, tool_group, "get-uuid")


@tool_group.command(name="halt")
@click.pass_obj
def debug_halt_command(pass_obj: dict) -> None:
    """Halt CPU execution."""
    try:
        debug_halt(pass_obj["debug_probe_params"])
        click.echo("The CPU execution has been halted.")
    except SPSDKError as exc:
        raise SPSDKAppError(f"Halt of CPU execution failed. ({str(exc)})") from exc


def debug_halt(debug_probe_params: DebugProbeParams) -> None:
    """Halt CPU execution.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    """
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect()
        debug_probe.debug_halt()


@tool_group.command(name="resume")
@click.pass_obj
def debug_resume_command(pass_obj: dict) -> None:
    """Resume CPU execution."""
    try:
        debug_resume(pass_obj["debug_probe_params"])
        click.echo("The CPU execution has been resumed.")
    except SPSDKError as exc:
        raise SPSDKAppError(f"Resume of CPU execution failed. ({str(exc)})") from exc


def debug_resume(debug_probe_params: DebugProbeParams) -> None:
    """Resume CPU execution.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    """
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect()
        debug_probe.debug_resume()


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

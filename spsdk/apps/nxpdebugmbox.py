#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import contextlib
import logging
import os
import struct
import sys
from dataclasses import dataclass
from time import sleep
from typing import Callable, Iterator, List, Optional

import click
import colorama

from spsdk import SPSDK_DATA_FOLDER, SPSDKError
from spsdk.apps.blhost_helper import progress_bar
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroupAliasedGetCfgTemplate,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import (
    INT,
    SPSDKAppError,
    catch_spsdk_error,
    check_file_exists,
    format_raw_data,
    parse_file_and_size,
    parse_hex_data,
)
from spsdk.dat import DebugAuthenticateResponse, DebugAuthenticationChallenge, dm_commands
from spsdk.dat.debug_credential import DebugCredential
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.debuggers.utils import PROBES, open_debug_probe, test_ahb_access
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.crypto.rkht import RKHT
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import find_file, load_binary, load_configuration, load_text, write_file

logger = logging.getLogger(__name__)
NXPDEBUGMBOX_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpdebugmbox")


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

    def __post_init__(self) -> None:
        """Post init validation.

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
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :return: Active DebugMailbox object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
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
            raise exc
        finally:
            dm.close()


@click.group(name="nxpdebugmbox", no_args_is_help=True, cls=CommandsTreeGroupAliasedGetCfgTemplate)
@click.option(
    "-i",
    "--interface",
    type=click.Choice(list(PROBES.keys())),
    help="Probe interface selection,if not specified, all available debug probe interfaces are used.",
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
    default="1.0",
    help=f"Set the protocol version. Default is 1.0 (RSA). "
    f'Available options are: {", ".join(DatProtocol.VERSIONS)}',
    type=click.Choice(DatProtocol.VERSIONS),
)
@click.option(
    "-t",
    "--timing",
    type=float,
    default=0.0,
    help="Time of extra delay after reset sequence, defaults to 1.0 second",
)
@click.option(
    "-n",
    "--no-reset",
    "reset",
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
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    protocol: str,
    log_level: int,
    timing: float,
    serial_no: str,
    debug_probe_option: List[str],
    reset: bool,
    operation_timeout: int,
) -> int:
    """Tool for working with Debug Mailbox."""
    logging.basicConfig(level=log_level or logging.WARNING)

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")

        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
        "debug_mailbox_params": DebugMailboxParams(
            reset=reset, more_delay=timing, operation_timeout=operation_timeout
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
@click.pass_obj
def auth_command(pass_obj: dict, beacon: int, certificate: str, key: str, no_exit: bool) -> None:
    """Perform the Debug Authentication."""
    auth(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        pass_obj["protocol"],
        beacon,
        certificate,
        key,
        no_exit,
    )


def auth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    protocol: DatProtocol,
    beacon: int,
    certificate: str,
    key: str,
    no_exit: bool,
) -> None:
    """Perform the Debug Authentication.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param protocol: Debug authentication protocol.
    :param beacon: Authentication beacon.
    :param certificate: Path to Debug Credentials.
    :param key: Path to DCK private key.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Starting Debug Authentication")

        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            debug_cred_data = load_binary(certificate)
            debug_cred = DebugCredential.parse(debug_cred_data)
            dac_rsp_len = 30 if debug_cred.HASH_LENGTH == 48 and debug_cred.socc == 4 else 26
            dac_data = dm_commands.DebugAuthenticationStart(dm=mail_box, resplen=dac_rsp_len).run()
            # convert List[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
            logger.info(f"DAC: \n{dac.info()}")
            dac.validate_against_dc(debug_cred)
            dar = DebugAuthenticateResponse.create(
                version=protocol.version,
                socc=dac.socc,
                dc=debug_cred,
                auth_beacon=beacon,
                dac=dac,
                dck=key,
            )
            logger.info(f"DAR:\n{dar.info()}")
            dar_data = dar.export()
            # convert bytes to List[int]
            dar_data_words = list(struct.unpack(f"<{len(dar_data) // 4}I", dar_data))
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
                logger.info(f"Debug Authentication ends {res_str}{colorama.Fore.RESET}.")
                if not ahb_access_granted:
                    raise SPSDKAppError()
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )

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
    exit(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Exit Debug Mailbox succeeded")


def exit(
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


@main.command(name="famode", no_args_is_help=True)
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


@main.command(name="blankauth", no_args_is_help=True)
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
def blankauth_command(pass_obj: dict, file: str, no_exit: bool) -> None:
    """Debug Authentication for Blank Device."""
    blankauth(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], file, no_exit)
    click.echo("Debug authentication for blank device succeeded")


def blankauth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    token_file: str,
    no_exit: bool,
) -> None:
    """Debug Authentication for Blank Device.

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

                logger.info(f"Debug Authentication ends {res_str}{colorama.Fore.RESET}.")
            else:
                logger.info(
                    "Debug Authentication ends without exit and without test of AHB access."
                )
    except Exception as e:
        raise SPSDKAppError(f"Debug authentication for blank device failed: {e}") from e


@main.command(name="get-crp")
@click.pass_obj
def get_crp_command(pass_obj: dict) -> None:
    """Get CRP level."""
    get_crp(pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Get CRP Level succeeded")


def get_crp(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Get CRP level. This command should be called after 'start' command and with no-reset '-n' option.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(debug_probe_params, debug_mailbox_params) as mail_box:
            crp_level = dm_commands.GetCRPLevel(dm=mail_box).run()[0]
            logger.info(f"CRP level is: {crp_level}.")
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
        ) as debug_probe:
            ahb_access_granted = test_ahb_access(debug_probe)
        return ahb_access_granted
    except Exception as e:
        raise SPSDKAppError(f"Testing AHB access failed: {e}") from e


@main.command(name="read-memory", no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.Path(), required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_obj
def read_memory_command(
    pass_obj: dict,
    address: int,
    byte_count: int,
    out_file: str,
    use_hexdump: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout.

    Returns the contents of memory at the given <ADDRESS>, for a specified <BYTE_COUNT>.
    Data are read by 4 bytes at once and are store in little endian format!
    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout
    """
    with progress_bar(suppress=logger.getEffectiveLevel() > logging.INFO) as progress_callback:
        data = read_memory(pass_obj["debug_probe_params"], address, byte_count, progress_callback)
    if out_file:
        write_file(data, out_file, mode="wb")
        click.echo(f"The memory has been read and write into {out_file}")
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
    ) as debug_probe:
        try:
            for addr in range(start_addr, start_addr + length, 4):
                if progress_callback:
                    progress_callback(addr, start_addr + length)
                data += debug_probe.mem_reg_read(addr).to_bytes(4, "little")
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
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.pass_obj
def write_memory_command(pass_obj: dict, address: int, data_source: str) -> None:
    """Writes memory from a file or a hex-data.

    Writes memory at <ADDRESS> from <FILE> or <HEX-DATA>
    Writes a provided buffer to a specified <BYTE_COUNT> in memory.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
                - when using Jupyter notebook, use [[ ]] instead of {{ }}: eg. [[11 22 33]]
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(size)
    write_memory(pass_obj["debug_probe_params"], address, data)
    click.echo("The memory has been write successfully.")


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
    ) as debug_probe:
        start_padding = address - start_addr
        align_data = data
        if start_padding:
            align_start_word = debug_probe.mem_reg_read(start_addr).to_bytes(4, "little")
            align_data = align_start_word[:start_padding] + data

        end_padding = length - byte_count - start_padding
        if end_padding:
            align_end_word = debug_probe.mem_reg_read(start_addr + length - 4).to_bytes(4, "little")
            align_data = align_data + align_end_word[4 - end_padding :]

        with progress_bar(suppress=logger.getEffectiveLevel() > logging.INFO) as progress_callback:
            for i, addr in enumerate(range(start_addr, start_addr + length, 4)):
                progress_callback(addr, start_addr + length)
                to_write = int.from_bytes(align_data[i * 4 : i * 4 + 4], "little")
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


@main.command(name="gendc", no_args_is_help=True)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Specify YAML credential config file.",
)
@click.option(
    "-e",
    "--elf2sb-config",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Specify Root Of Trust from configuration file used by elf2sb tool",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
@click.option(
    "--plugin",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="External python file containing a custom SignatureProvider implementation.",
)
@click.argument("dc_file_path", metavar="PATH", type=click.Path(file_okay=True))
@click.pass_obj
def gendc_command(
    pass_obj: dict,
    plugin: str,
    dc_file_path: str,
    config: str,
    elf2sb_config: str,
    force: bool,
) -> None:
    """Generate debug certificate (DC).

    \b
    PATH    - path to dc file
    """
    gendc(
        pass_obj["protocol"],
        plugin,
        dc_file_path,
        config,
        elf2sb_config,
        force,
    )
    click.echo("Creating Debug credential file succeeded")


def gendc(
    protocol: DatProtocol,
    plugin: str,
    dc_file_path: str,
    config: str,
    elf2sb_config: str,
    force: bool,
) -> None:
    """Generate debug certificate (DC).

    :param protocol: Debug authentication protocol.
    :param plugin: External python file containing a custom SignatureProvider implementation.
    :param dc_file_path: Path to debug certificate file.
    :param config: YAML credential config file.
    :param elf2sb_config: Root Of Trust from configuration file used by elf2sb tool.
    :param force: Force overwriting of an existing file.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        if plugin:
            # if a plugin is present simply load it
            # The SignatureProvider will automatically pick up any implementation(s)
            from importlib.util import (  # pylint: disable=import-outside-toplevel
                module_from_spec,
                spec_from_file_location,
            )

            spec = spec_from_file_location(name="plugin", location=plugin)  # type: ignore
            assert spec
            mod = module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore

        check_file_exists(dc_file_path, force)

        logger.info("Loading configuration from yml file...")
        yaml_content = load_configuration(config)
        if elf2sb_config:
            elf2sb_config_dir = os.path.dirname(elf2sb_config)
            logger.info("Loading configuration from elf2sb config file...")
            rot_info = RootOfTrustInfo(
                load_configuration(elf2sb_config), search_paths=[elf2sb_config_dir]
            )
            yaml_content["rot_meta"] = [
                find_file(x, search_paths=[elf2sb_config_dir]) for x in rot_info.public_keys
            ]
            assert rot_info.private_key
            yaml_content["rotk"] = find_file(rot_info.private_key, search_paths=[elf2sb_config_dir])
            yaml_content["rot_id"] = rot_info.public_key_index

        # enforcing rot_id presence in yaml config...
        assert "rot_id" in yaml_content, "Config file doesn't contain the 'rot_id' field"

        logger.info(f"Creating {'RSA' if protocol.is_rsa() else 'ECC'} debug credential object...")
        dc = DebugCredential.create_from_yaml_config(
            version=protocol.version,
            yaml_config=yaml_content,
            search_paths=[os.path.dirname(config)],
        )
        dc.sign()
        data = dc.export()
        click.echo(f"RoT Key Hash: {dc.get_rotkh().hex()}")
        logger.debug(f"Debug credential file details:\n {dc.info()}")
        logger.info(f"Saving the debug credential to a file: {dc_file_path}")
        write_file(data, dc_file_path, mode="wb")

    except Exception as e:
        raise SPSDKAppError(f"The generating of Debug Credential file failed: {e}") from e


@main.command(name="get-template", no_args_is_help=True)
@click.argument("output", metavar="PATH", type=click.Path())
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
def get_template_command(output: str, force: bool) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    \b
    PATH    - file name path to write template config file
    """
    get_template(output, force)
    click.echo("The configuration template file has been created.")


def get_template(output: str, force: bool) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    :param output: Path to output file.
    :param force: Force overwriting of an existing file.
    """
    check_file_exists(str(output), force)
    write_file(load_text(os.path.join(NXPDEBUGMBOX_DATA_FOLDER, "template_config.yml")), output)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Mailbox Tool application.

This module provides a comprehensive command-line interface for debug authentication
and mailbox operations on NXP MCUs. It supports debug probe communication, flash
operations, certificate management, and various debug authentication protocols.
Main functionality includes debug session management, flash memory operations,
fault analysis mode, ISP mode control, and debug authentication certificate handling.
"""

import contextlib
import logging
import os
import struct
import sys
from dataclasses import dataclass
from time import sleep
from typing import Iterator, Optional, Type

import click
import colorama
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    hex_value_option,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error, format_raw_data
from spsdk.dat import dm_commands
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import (
    DebugCredentialCertificate,
    DebugCredentialCertificateEcc,
    ProtocolVersion,
)
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.dat.famode_image import FaModeImage
from spsdk.dat.rot_meta import RotMetaEcc, RotMetaRSA
from spsdk.debuggers.utils import PROBES, get_test_address, open_debug_probe, test_ahb_access
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import align_block, get_printable_path, load_binary, write_file

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
class DebugProbeParams:
    """Debug probe configuration container for SPSDK operations.

    This class holds configuration parameters for debug probe connections including
    interface settings, serial number identification, and device-specific parameters
    for NXP MCU debugging and provisioning operations.
    """

    interface: str
    serial_no: str
    debug_probe_user_params: dict

    def set_test_address(self, test_address: int) -> None:
        """Set if not already sets, the test address for AHB access.

        :param test_address: New overriding address.
        """
        if "test_address" not in self.debug_probe_user_params:
            self.debug_probe_user_params["test_address"] = test_address

    def set_family(self, family: FamilyRevision) -> None:
        """Set family to debug probe params.

        :param family: Device family
        """
        self.debug_probe_user_params["family"] = family.name
        self.debug_probe_user_params["revision"] = family.revision
        self.set_test_address(get_test_address(family))


@dataclass
class DebugMailboxParams:
    """Debug mailbox configuration parameters container.

    This class holds configuration parameters that control debug mailbox
    operations including reset behavior, timing delays, and timeout settings.
    """

    reset: bool
    more_delay: float
    operation_timeout: int


@contextlib.contextmanager
def _open_debugmbox(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> Iterator[DebugMailbox]:
    """Method opens DebugMailbox object based on input arguments.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :return: Active DebugMailbox object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    debug_probe_params.set_family(family)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect_safe()
        dm = DebugMailbox(
            debug_probe=debug_probe,
            family=family,
            reset=debug_mailbox_params.reset,
            moredelay=debug_mailbox_params.more_delay,
            op_timeout=debug_mailbox_params.operation_timeout,
        )
        try:
            yield dm
        except SPSDKError as exc:
            msg = (
                colorama.Fore.RED + exc.description + colorama.Fore.RESET
                if exc.description
                else "Problem with debug mailbox occurred"
            )
            raise SPSDKError(msg) from exc
        finally:
            dm.close()


@click.group(name="nxpdebugmbox", cls=CommandsTreeGroup)
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
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    log_level: int,
    timing: float,
    serial_no: str,
    debug_probe_option: list[str],
    no_reset: bool,
    operation_timeout: int,
) -> int:
    """Tool for working with Debug Mailbox."""
    spsdk_logger.install(level=log_level)

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

    ctx.obj = {
        "debug_mailbox_params": DebugMailboxParams(
            reset=no_reset,
            more_delay=timing,
            operation_timeout=operation_timeout,
        ),
        "debug_probe_params": debug_params,
    }

    return 0


@main.group("cmd", cls=CommandsTreeGroup)
@spsdk_family_option(DebugCredentialCertificate.get_supported_families())
@click.pass_obj
def cmd_group(pass_obj: dict, family: FamilyRevision) -> None:
    """Group of commands for working with raw Debug MailBox commands."""
    pass_obj["family"] = family


@cmd_group.command(name="start", no_args_is_help=False)
@click.pass_obj
def start_command(pass_obj: dict) -> None:
    """Start DebugMailBox."""
    start(pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Start Debug Mailbox succeeded")


def start(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Start DebugMailBox.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.StartDebugMailbox(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Start Debug Mailbox failed: {e}") from e


@cmd_group.command(name="exit", no_args_is_help=False)
@click.pass_obj
def exit_command(pass_obj: dict) -> None:  # pylint: disable=redefined-builtin
    """Exit DebugMailBox."""
    exit_debug_mbox(
        pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"]
    )
    click.echo("Exit Debug Mailbox succeeded")


def exit_debug_mbox(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:  # pylint: disable=redefined-builtin
    """Exit DebugMailBox.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.ExitDebugMailbox(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Exit Debug Mailbox failed: {e}") from e


@cmd_group.command(name="erase", no_args_is_help=False)
@click.pass_obj
def erase_command(pass_obj: dict) -> None:
    """Erase Flash."""
    erase(pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Mass flash erase succeeded")


def erase(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Erase Flash.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EraseFlash(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Mass flash erase failed: {e}") from e


@cmd_group.command(name="famode", no_args_is_help=False)
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
    famode(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        message,
    )
    click.echo("Set fault analysis mode succeeded.")


def famode(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    message: str,
) -> None:
    """Set Fault Analysis Mode.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param message: Path to message file..
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
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


@cmd_group.command(name="ispmode", no_args_is_help=False)
@click.option(
    "-m",
    "--mode",
    type=INT(),
    required=False,
    default="1",
    help="ISP download mode based on the ISP mode value in boot configuration register in CMPA/fuses.",
)
@click.pass_obj
def ispmode_command(pass_obj: dict, mode: int) -> None:
    """Enter ISP Mode."""
    ispmode(
        pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], mode
    )
    click.echo("Entering into ISP mode succeeded")


def ispmode(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    mode: int,
) -> None:
    """Enter ISP Mode.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param mode: ISP mode
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EnterISPMode(dm=mail_box).run([mode])
    except Exception as e:
        raise SPSDKAppError(f"Entering into ISP mode failed: {e}") from e


@cmd_group.command(name="token-auth", no_args_is_help=True)
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
    token_auth(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        file,
        no_exit,
    )
    click.echo("Debug authentication using token succeeded")


def token_auth(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    token_file: str,
    no_exit: bool,
) -> None:
    """Debug Authentication using token.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param token_file: Path to token file.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    token = []
    logger.info("Starting Debug Authentication for Blank Device..")
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
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
                mail_box.debug_probe.connect_safe()
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


@cmd_group.command(name="get-crp", no_args_is_help=False)
@click.pass_obj
def get_crp_command(pass_obj: dict) -> None:
    """Get CRP level. This command should be called after 'start' command and with no-reset '-n' option."""
    get_crp(pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    click.echo("Get CRP Level succeeded")


def get_crp(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Get CRP level.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            crp_level = dm_commands.GetCRPLevel(dm=mail_box).run()[0]
            if dm_commands.GetCRPLevel.CMD.tag in mail_box.non_standard_statuses:
                if crp_level in mail_box.non_standard_statuses[dm_commands.GetCRPLevel.CMD.tag]:
                    click.echo(
                        f"CRP level is: {mail_box.non_standard_statuses[dm_commands.GetCRPLevel.CMD.tag][crp_level]}."
                    )
                else:
                    click.echo(f"CRP level is: 0x{crp_level:08X}.")
            else:
                click.echo(f"CRP level is: 0x{crp_level:02X}.")
    except Exception as e:
        raise SPSDKAppError(f"Get CRP Level failed: {e}") from e


@cmd_group.command(name="start-debug-session", no_args_is_help=False)
@click.pass_obj
def start_debug_session_command(pass_obj: dict) -> None:
    """Start debug session."""
    start_debug_session(
        pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"]
    )
    click.echo("Start debug session succeeded")


def start_debug_session(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Start debug session.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.StartDebugSession(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Start debug session failed: {e}") from e


@cmd_group.command(name="erase-one-sector", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.pass_obj
def erase_one_sector_command(pass_obj: dict, address: int) -> None:
    """Erase one flash sector."""
    erase_one_sector(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        address,
    )
    click.echo("Erasing one sector succeeded")


def erase_one_sector(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    address: int,
) -> None:
    """Erase one sector.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param address: Flash sector address
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.EraseOneSector(dm=mail_box).run([address])
    except Exception as e:
        raise SPSDKAppError(f"Erasing one sector failed: {e}") from e


@cmd_group.command(name="write-to-flash", no_args_is_help=True)
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.option("-f", "--file", type=click.Path(), required=True, help="Path to file.")
@click.pass_obj
def write_to_flash_command(pass_obj: dict, address: int, file: str) -> None:
    """Write data to flash."""
    write_to_flash(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        address,
        file,
    )
    click.echo("Write data to flash succeeded")


def write_to_flash(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    address: int,
    file: str,
) -> None:
    """Write to flash.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param address: Flash sector address
    :param file: File with binary data
    :raises SPSDKAppError: Raised if any error occurred.
    """
    if address % 16 != 0:
        raise SPSDKAppError("The address must be aligned to 16 bytes.")
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
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
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        rot_hash_length=int(rot_hash_length),
        nxp_keys=nxp_keys,
    )
    click.echo(f"The DAC data has been stored to: {output}.")
    write_file(dac_data, output, mode="wb")


def get_dac(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    rot_hash_length: int,
    nxp_keys: bool = False,
) -> bytes:
    """Perform the Start of Debug Authentication and get the DAC.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param rot_hash_length: Select the RoT hash length, choices are [32,48,66].
    :param nxp_keys: When true, the NXP start authentication challenge is performed instead of OEM.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Starts getting Debug Authentication challenge")
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
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
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes, family=family)

            logger.info(f"DAC: \n{str(dac)}")
            return dac_data_bytes
    except SPSDKError as exc:
        raise SPSDKAppError(f"Get Debug Authentication challenge failed: {str(exc)}") from exc


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
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        dar=load_binary(binary),
        nxp_keys=nxp_keys,
    )
    click.echo("The DAR data has been sent to device.")


def send_dar(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    dar: bytes,
    nxp_keys: bool = False,
) -> None:
    """Send the Debug Authentication response.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param dar: The DAR packet in bytes.
    :param nxp_keys: When true, the NXP start authentication challenge is performed instead of OEM.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Sending Debug Authentication Response")
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
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


@main.group("famode-image", cls=CommandsTreeGroup)
def famode_image_group() -> None:
    """Group of sub-commands related to Fault Analysis Mode Image (related to some families)."""


@famode_image_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=FaModeImage)
def famode_image_export_command(config: Config) -> None:
    """Generate Fault Analysis mode image from YAML/JSON configuration.

    The configuration template files could be generated by subcommand 'get-templates'.
    """
    famode_image_export(config)


def famode_image_export(config: Config) -> None:
    """Generate Fault Analysis mode image from YAML/JSON configuration.

    :param config: Path to the YAML/JSON configuration
    """
    fa_image = FaModeImage.load_from_config(config)
    mbi_data = fa_image.export()
    if fa_image.mbi.rkth:
        click.echo(f"RKTH: {fa_image.mbi.rkth.hex()}")
    mbi_output_file_path = config.get_output_file_name("masterBootOutputFile")
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


@famode_image_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=FaModeImage.get_supported_families())
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary FA Mode image to parse.",
)
@spsdk_output_option(directory=True)
def famode_image_parse_command(family: FamilyRevision, binary: str, output: str) -> None:
    """Parse MBI Image into YAML configuration and binary images."""
    famode_image_parse(family, binary, output)


def famode_image_parse(family: FamilyRevision, binary: str, output: str) -> None:
    """Parse FA Mode Image into YAML configuration and binary images."""
    fa_image = FaModeImage.parse(data=load_binary(binary), family=family)

    if not fa_image:
        raise SPSDKAppError(f"Failed. (FA mode image: {binary} parsing failed.)")

    fa_image.check_famode_data()
    yaml_data = fa_image.get_config_yaml(output)

    write_file(yaml_data, os.path.join(output, "famode_config.yaml"))

    click.echo(f"Success. (FA mode image: {binary} has been parsed and stored into {output} )")


@famode_image_group.command("get-templates", no_args_is_help=True)
@spsdk_family_option(families=FaModeImage.get_supported_families())
@spsdk_output_option(directory=True, force=True)
def famode_image_get_templates_command(family: FamilyRevision, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    famode_image_get_templates(family, output)


def famode_image_get_templates(family: FamilyRevision, output: str) -> None:
    """Create template of Fault Analysis mode image configurations in YAML format."""
    full_file_name = os.path.join(output, "famode_image.yaml")
    click.secho(
        "The get-templates command will be removed and replaced by get-template in the next major release.",
        fg="yellow",
    )
    click.echo(f"Creating {get_printable_path(full_file_name)} template file.")
    write_file(FaModeImage.get_config_template(family), full_file_name)


@main.group("dat", cls=CommandsTreeGroup)
def dat_group() -> None:
    """Group of commands for working with Debug Authentication Procedure."""


@dat_group.command(name="auth", no_args_is_help=True)
@spsdk_config_option(
    klass=DebugAuthenticateResponse,
    help="Path to Debug Authentication configuration file.",
)
@click.option(
    "-n",
    "--no-exit",
    is_flag=True,
    help="When used, exit debug mailbox command is not executed after debug authentication.",
)
@click.pass_obj
def auth_command(pass_obj: dict, config: Config, no_exit: bool) -> None:
    """Perform the Debug Authentication."""
    auth(
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        config=config,
        no_exit=no_exit,
    )


def auth(
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    config: Config,
    no_exit: bool,
) -> None:
    """Perform the Debug Authentication.

    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param config: Configuration of DAT.
    :param no_exit: When true, exit debug mailbox command is not executed after debug authentication.
    :raises SPSDKAppError: Raised if any error occurred.
    :raises KeyboardInterrupt: Internal use to cancel checking of result.
    """
    try:
        logger.info("Starting Debug Authentication")
        family = FamilyRevision.load_from_config(config)
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            debug_cred_data = load_binary(config.get_input_file_name("certificate"))
            debug_cred = DebugCredentialCertificate.parse(debug_cred_data, family)
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
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes, family=family)

            logger.info(f"DAC: \n{str(dac)}")

            dar_class = DebugAuthenticateResponse._get_class(family, dac.version)
            dar = dar_class.load_from_config(config=config, dac=dac)
            verifier = dar.verify()
            if verifier.has_errors:
                raise SPSDKAppError(f"DAR verify failed:\n {verifier.draw()}")

            logger.info(f"\n{verifier.draw()}")
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
                    based_on_ele = get_db(family).get_bool(
                        DatabaseManager.DAT, "based_on_ele", False
                    )
                    if based_on_ele:
                        logger.info(
                            "Exit command ends without response as usual on devices based on EdgeLock Enclave."
                        )
                    else:
                        logger.error(
                            "Exit command failed. Maybe too early reset happen on hardware."
                        )

                        # Do test of access to AHB bus with retry logic
                sleep(0.2)
                ahb_access_granted = False
                max_attempts = 20
                retry_delay = 0.5

                click.echo("Testing AHB access (Press Ctrl+C to stop)", nl=False)
                try:
                    for attempt in range(max_attempts):
                        try:
                            # Reopen debug probe for each attempt to ensure clean state
                            mail_box.debug_probe.close()
                            mail_box.debug_probe.open()
                            mail_box.debug_probe.connect_safe()

                            ahb_access_granted = test_ahb_access(mail_box.debug_probe)
                            if ahb_access_granted:
                                logger.debug(f" SUCCESS (attempt {attempt + 1})")
                                break
                            else:
                                click.echo(".", nl=attempt == max_attempts - 1)
                                if attempt < max_attempts - 1:  # Don't sleep on last attempt
                                    sleep(retry_delay)
                        except KeyboardInterrupt as exc:
                            # Re-raise to be caught by outer try-catch
                            raise exc
                        except Exception as e:
                            logger.debug(f"AHB access test attempt {attempt + 1} failed: {e}")
                            click.echo(".", nl=attempt == max_attempts - 1)
                            if attempt < max_attempts - 1:  # Don't sleep on last attempt
                                sleep(retry_delay)
                except KeyboardInterrupt:
                    click.echo(" INTERRUPTED")
                    logger.info("AHB access test interrupted by user")
                    # Set ahb_access_granted to False to trigger the existing error handling
                    ahb_access_granted = False

                res_str = (
                    (colorama.Fore.GREEN + "successfully")
                    if ahb_access_granted
                    else (colorama.Fore.RED + "without AHB access")
                )
                click.echo(f"\nDebug Authentication ends {res_str}{colorama.Fore.RESET}.")
                if not ahb_access_granted:
                    raise SPSDKAppError("Access to AHB is not granted.")
            else:
                click.echo("Debug Authentication ends without exit and without test of AHB access.")

    except SPSDKError as e:
        raise SPSDKAppError(
            f"{colorama.Fore.RED}Debug Mailbox authentication failed:{colorama.Fore.RESET}\n{e}"
        ) from e


@cmd_group.command(name="nxp-ssf-insert-duk", no_args_is_help=True)
@hex_value_option(
    "-s", "--seed", bit_length=256, help_description="The tester seed value.", required=True
)
@click.pass_obj
def nxp_ssf_insert_duk_command(pass_obj: dict, seed: bytes) -> None:
    """Create NXP PUF AC code store area as part of Self sign flow (SSF)."""
    resp = nxp_ssf_insert_duk(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        seed=seed,
    )
    click.echo(
        "The create NXP PUF AC code store area as part of Self sign flow (SSF) succeed."
        f"\n Seed: {resp.hex()}"
    )


def nxp_ssf_insert_duk(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    seed: bytes,
) -> bytes:
    """Create NXP PUF AC code store area as part of Self sign flow (SSF).

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param seed: The tester seed in bytes (256 bit).
    :return: Bytes representing the response from the NXP SSF Insert DUK command.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Creating NXP PUF AC code store area as part of Self sign flow (SSF)")
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            seed_data = align_block(seed, alignment=4)
            # convert bytes to list[int]
            seed_data_words = list(struct.unpack(f"<{len(seed_data) // 4}I", seed_data))
            seed_response = dm_commands.NxpSsfInsertDuk(dm=mail_box).run(seed_data_words)
            logger.debug(f"Command response: {seed_response}")
            return struct.pack(f"<{len(seed_response)}I", *seed_response)
    except SPSDKError as exc:
        raise SPSDKAppError(
            f"The create NXP PUF AC code store area as part of Self sign flow (SSF) failed: {str(exc)}"
        ) from exc


@cmd_group.command(name="nxp-exec-prov-fw", no_args_is_help=False)
@click.pass_obj
def nxp_exec_prov_fw_command(pass_obj: dict) -> None:
    """Execute NXP Provisioning Firmware."""
    nxp_exec_prov_fw(
        pass_obj["family"], pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"]
    )
    click.echo("Executing of NXP provisioning firmware succeeded")


def nxp_exec_prov_fw(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> None:
    """Execute NXP Provisioning Firmware.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            dm_commands.NxpExecuteProvisioningFw(dm=mail_box).run()
    except Exception as e:
        raise SPSDKAppError(f"Executing of NXP provisioning firmware failed: {e}") from e


@cmd_group.command(name="nxp-ssf-insert-cert", no_args_is_help=True)
@hex_value_option(
    "-s", "--seed", bit_length=256, help_description="The tester seed value.", required=True
)
@click.option(
    "-e", "--output-ecdsa-puk", type=click.Path(), help="Path to save the ECDSA PUK (0x60 bytes)."
)
@click.option(
    "-y",
    "--output-hybrid-puk",
    type=click.Path(),
    help="Path to save the Hybrid PUK (0xA80 bytes).",
)
@click.option(
    "-rd",
    "--response-delay",
    help="Delay before reading response in seconds",
    type=float,
    show_default=True,
    default=1.0,
)
@click.pass_obj
def nxp_ssf_insert_cert_command(
    pass_obj: dict,
    seed: bytes,
    output_ecdsa_puk: str,
    output_hybrid_puk: str,
    response_delay: float,
) -> None:
    """Command to create self-signed certificate as part of Self sign flow (SSF)."""
    response = nxp_ssf_insert_cert(
        pass_obj["family"],
        pass_obj["debug_probe_params"],
        pass_obj["debug_mailbox_params"],
        seed=seed,
        output_ecdsa_puk=output_ecdsa_puk,
        output_hybrid_puk=output_hybrid_puk,
        response_delay=response_delay,
    )
    click.echo(
        "The self-signed certificate creation as part of Self sign flow (SSF) succeeded."
        f"Seed response: {response.hex()}"
    )
    if output_ecdsa_puk:
        click.echo(f"ECDSA PUK saved to: {output_ecdsa_puk}")
    if output_hybrid_puk:
        click.echo(f"Hybrid PUK saved to: {output_hybrid_puk}")


def nxp_ssf_insert_cert(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    seed: bytes,
    output_ecdsa_puk: Optional[str] = None,
    output_hybrid_puk: Optional[str] = None,
    response_delay: float = 1.0,
) -> bytes:
    """Command to create self-signed certificate as part of Self sign flow (SSF).

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :param seed: The tester seed in bytes (256 bit).
    :param output_ecdsa_puk: Optional path to save the ECDSA PUK (0x60 bytes).
    :param output_hybrid_puk: Optional path to save the Hybrid PUK (0xA80 bytes).
    :param response_delay: Delay before reading response in seconds.
    :return: Bytes representing the response from the NXP SSF Insert Certificate command.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Creating self-signed certificate as part of Self sign flow (SSF)")

        # Check if the device supports this feature
        db = get_db(family)
        features = db.get_list(DatabaseManager.DAT, "sub_features", [])
        if "ssf_cert" not in features:
            raise SPSDKAppError(f"The device {family} does not support SSF certificate feature")

        # Get memory addresses from database
        ecdsa_puk_address = db.get_int(DatabaseManager.DAT, ["ssf_cert", "ecdsa_puk_address"], 0)
        ecdsa_puk_size = db.get_int(DatabaseManager.DAT, ["ssf_cert", "ecdsa_puk_size"], 0)
        hybrid_puk_address = db.get_int(DatabaseManager.DAT, ["ssf_cert", "hybrid_puk_address"], 0)
        hybrid_puk_size = db.get_int(DatabaseManager.DAT, ["ssf_cert", "hybrid_puk_size"], 0)

        if (
            not ecdsa_puk_address
            or not ecdsa_puk_size
            or not hybrid_puk_address
            or not hybrid_puk_size
        ):
            raise SPSDKAppError(f"The device {family} has incomplete SSF certificate configuration")

        with _open_debugmbox(family, debug_probe_params, debug_mailbox_params) as mail_box:
            seed_data = align_block(seed, alignment=4)
            # convert bytes to list[int]
            seed_data_words = list(struct.unpack(f"<{len(seed_data) // 4}I", seed_data))
            seed_response = dm_commands.NxpSsfInsertCert(
                dm=mail_box, resplen=0x2B8, response_delay=response_delay
            ).run(seed_data_words)
            logger.debug(f"Command response length: {len(seed_response)}")

            seed_response_bytes = struct.pack(f"<{len(seed_response)}I", *seed_response)

            # Read the PUK data from memory
            if output_ecdsa_puk:
                ecdsa_puk = seed_response_bytes[:ecdsa_puk_size]
                write_file(ecdsa_puk, output_ecdsa_puk, mode="wb")
                logger.info(f"ECDSA PUK saved to {output_ecdsa_puk}")

            if output_hybrid_puk:
                ecdsa_puk = seed_response_bytes[ecdsa_puk_size : ecdsa_puk_size * 2]
                ecdsa_path = os.path.splitext(output_hybrid_puk)[0] + "_ecdsa.bin"
                write_file(ecdsa_puk, ecdsa_path, mode="wb")
                logger.info(f"Hybrid-ECC PUK saved to {ecdsa_path}")

                mldsa_puk = seed_response_bytes[ecdsa_puk_size * 2 :]
                mldsa_path = os.path.splitext(output_hybrid_puk)[0] + "_mldsa.bin"
                write_file(mldsa_puk, mldsa_path, mode="wb")
                logger.info(f"Hybrid-MLDSA PUK saved to {mldsa_path}")
            return struct.pack(f"<{len(seed_response)}I", *seed_response)

    except SPSDKError as exc:
        raise SPSDKAppError(
            f"The create self-signed certificate as part of Self sign flow (SSF) failed: {str(exc)}"
        ) from exc


@dat_group.command("get-template", no_args_is_help=True)
@spsdk_family_option(DebugAuthenticateResponse.get_supported_families())
@spsdk_output_option(force=True)
def dat_get_template_command(family: FamilyRevision, output: str) -> None:
    """Create template of Debug authentication configurations in YAML format."""
    dat_get_template(family, output)


def dat_get_template(family: FamilyRevision, output: str) -> None:
    """Create template of Debug authentication configurations in YAML format."""
    template = DebugAuthenticateResponse._get_class(
        family, ProtocolVersion("2.0")
    ).get_config_template(family)
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(template, output)


@dat_group.group("dc", cls=CommandsTreeGroup)
def dc_group() -> None:
    """Group of commands for Debug Credential binaries."""


@dc_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=DebugCredentialCertificate)
@click.option(
    "-e",
    "--rot-config",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="Specify Root Of Trust from MBI or Cert block configuration file",
)
@spsdk_output_option(force=True)
def dc_export_command(
    output: str,
    config: Config,
    rot_config: str,
) -> None:
    """Generate debug certificate (DC)."""
    dc_export(
        output,
        config,
        rot_config,
    )
    click.echo("Creating Debug credential file succeeded")


def dc_export(
    output: str,
    config: Config,
    rot_config: str,
) -> None:
    """Generate debug certificate (DC).

    :param output: Path to debug certificate file.
    :param config: Debug Credential config file.
    :param rot_config: Root Of Trust from MBI or Cert block configuration file.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        logger.info("Loading configuration from yml file...")
        family = FamilyRevision.load_from_config(config)
        klass = DebugCredentialCertificate._get_class_from_cfg(config=config)
        if rot_config:
            if klass.ROT_META_CLASS in [RotMetaRSA, RotMetaEcc]:
                config["rot_config"] = rot_config
            else:
                logger.warning(f"Root of Trust configuration is not supported for {family} family.")
        klass.pre_check_config(config)
        dc = klass.load_from_config(config=config)
        logger.info(
            f"Creating {'RSA' if dc.version.is_rsa() else 'ECC'} debug credential object..."
        )
        dc.sign()
        data = dc.export()
        if dc.srk_count:
            click.echo(f"RKTH: {dc.calculate_hash().hex()}")
        logger.debug(f"Debug credential file details:\n {str(dc)}")
        logger.info(f"Saving the debug credential to a file: {output}")
        write_file(data, output, mode="wb")

    except Exception as e:
        raise SPSDKAppError(f"The generating of Debug Credential file failed: {e}") from e


@dc_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(DebugCredentialCertificate.get_supported_families())
@spsdk_output_option(force=True)
def dc_get_template_command(family: FamilyRevision, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file."""
    dc_get_template(family, output)
    click.echo(f"Creating {get_printable_path(output)} template file.")


def dc_get_template(family: FamilyRevision, output: str) -> None:
    """Generate the template of Debug Credentials YML configuration file.

    :param family: Device family.
    :param output: Path to output file.
    """
    try:
        klass: Type[DebugCredentialCertificate] = DebugCredentialCertificate._get_class(
            family=family
        )
    except SPSDKError:
        klass = DebugCredentialCertificateEcc

    write_file(klass.get_config_template(family), output)


@main.group("mem-tool", cls=CommandsTreeGroup)
def mem_group() -> None:
    """Group of commands for working with target memory over debug probe."""


@mem_group.command(name="read-memory", no_args_is_help=True)
@spsdk_family_option(get_families())  # All supported families by SPSDK
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@click.option("-c", "--count", type=INT(), required=True, help="Number of bytes to read")
@spsdk_output_option(required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_obj
def read_memory_command(
    pass_obj: dict,
    family: FamilyRevision,
    address: int,
    count: int,
    output: str,
    use_hexdump: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout."""
    data = read_memory(family, pass_obj["debug_probe_params"], address, count)
    if output:
        write_file(data, output, mode="wb")
        click.echo(f"The memory has been read and written into {output}")
    else:
        click.echo(format_raw_data(data, use_hexdump=use_hexdump))


def read_memory(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    address: int,
    byte_count: int,
) -> bytes:
    """Reads the memory.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param address: Starting address.
    :param byte_count: Number of bytes to read.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    data = bytes()
    debug_probe_params.set_family(family)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect_safe()
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


@mem_group.command(name="write-memory", no_args_is_help=True)
@spsdk_family_option(get_families())  # Get all supported families by SPSDK
@click.option("-a", "--address", type=INT(), required=True, help="Starting address")
@optgroup("Data Source", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "--file", type=click.Path(exists=True, dir_okay=False), help="Path to file to write"
)
@optgroup.option("-h", "--hex-string", type=str, help="String of hex values. e.g. '1234', '12 34'")
@click.option("-c", "--count", type=INT(), required=False, help="Number of bytes to write")
@click.pass_obj
def write_memory_command(
    pass_obj: dict, family: FamilyRevision, address: int, file: str, hex_string: str, count: int
) -> None:
    """Writes memory from a file or a hex-data."""
    if file:
        with open(file, "rb") as f:
            data = f.read(count)
    else:
        data = bytes.fromhex(hex_string)[:count]
    write_memory(family, pass_obj["debug_probe_params"], address, data)
    click.echo("The memory has been written successfully.")


def write_memory(
    family: FamilyRevision, debug_probe_params: DebugProbeParams, address: int, data: bytes
) -> None:
    """Writes memory from a file or a hex-data.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param address: Starting address.
    :param data: Data to write into memory.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    debug_probe_params.set_family(family)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect_safe()
        try:
            debug_probe.mem_block_write(addr=address, data=data)
        except SPSDKError as exc:
            raise SPSDKAppError(f"Failed to write memory: {str(exc)}") from exc


@mem_group.command(name="test-connection", no_args_is_help=False)
@spsdk_family_option(get_families())
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
def test_connection_command(pass_obj: dict, family: FamilyRevision, destination: str) -> None:
    """Method just try if the device debug port is opened or not."""
    ahb_access_granted = test_connection(
        family, pass_obj["debug_probe_params"], destination=destination
    )
    access_str = colorama.Fore.GREEN if ahb_access_granted else colorama.Fore.RED + "NOT "
    click.echo(f"The test connection ends {access_str}successfully.{colorama.Fore.RESET}")


def test_connection(
    family: FamilyRevision, debug_probe_params: DebugProbeParams, destination: str
) -> bool:
    """Method just try if the device debug port is opened or not.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param destination: Test destination [cpu_mem, debug_port].
    :raises SPSDKAppError: Raised if any error occurred.
    """
    debug_probe_params.set_family(family)
    try:
        with open_debug_probe(
            interface=debug_probe_params.interface,
            serial_no=debug_probe_params.serial_no,
            debug_probe_params=debug_probe_params.debug_probe_user_params,
            print_func=click.echo,
        ) as debug_probe:
            debug_probe.connect_safe()
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


@main.group("tool", cls=CommandsTreeGroup)
def tool_group() -> None:
    """Group of commands for working with various tools over debug probe."""


@tool_group.command(name="reset", no_args_is_help=False)
@spsdk_family_option(get_families())
@click.option(
    "-h",
    "--hard-reset",
    is_flag=True,
    default=False,
    help="When used, the hardware reset is used instead of debug mailbox reset.",
)
@click.pass_obj
def reset_command(pass_obj: dict, family: FamilyRevision, hard_reset: bool) -> None:
    """Reset MCU by DebugMailBox.

    The reset command implemented in NXPDEBUGMBOX has two modes (option -h):

    Reset by RESET REQUEST of debug mailbox that causes the reset of MCU by SYSRESET_REQ.
    The chip is reset, but the ROM code returns back the chip into debug mailbox handler
    (without -h/--hard-reset option).

    Reset by external reset signal. This reset is done by asserting external reset signal over
    debug probe. After this reset type the chip behavior is same as after standard reset button on the board.
    (with -h/--hard-reset option)
    """
    reset(family, pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"], hard_reset)
    click.echo("Reset MCU by Debug Mailbox succeeded.")


def reset(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
    hard_reset: bool,
) -> None:
    """Reset MCU by DebugMailBox.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debugmailbox.
    :param hard_reset: If true, use the hardware reset instead of debug mailbox reset.
    :raises SPSDKAppError: Raised if any error occurred.
    """
    try:
        debug_probe_params.set_family(family)
        if hard_reset:
            with open_debug_probe(
                interface=debug_probe_params.interface,
                serial_no=debug_probe_params.serial_no,
                debug_probe_params=debug_probe_params.debug_probe_user_params,
                print_func=click.echo,
            ) as debug_probe:
                debug_probe.reset()
        else:
            debug_mailbox_params.reset = True
            with _open_debugmbox(family, debug_probe_params, debug_mailbox_params):
                pass
    except Exception as e:
        raise SPSDKAppError(f"Reset MCU by Debug Mailbox failed: {e}") from e


@tool_group.command(name="get-uuid", no_args_is_help=False)
@spsdk_family_option(DebugCredentialCertificate.get_supported_families())
@click.pass_obj
def get_uuid_command(pass_obj: dict, family: FamilyRevision) -> None:
    """Get the UUID from target if possible.

    Some devices need to call 'start' command prior the get-uuid!
    Also there could be issue with repeating of this command without hard reset of device 'reset -h'.
    """
    uuid = get_uuid(family, pass_obj["debug_probe_params"], pass_obj["debug_mailbox_params"])
    if uuid:
        click.echo(f"The device UUID is: {uuid.hex()}")
    else:
        click.echo("The device UUID is not possible to retrieve from target.")


def get_uuid(
    family: FamilyRevision,
    debug_probe_params: DebugProbeParams,
    debug_mailbox_params: DebugMailboxParams,
) -> Optional[bytes]:
    """Get the UUID from target if possible.

    Some devices need to call 'start' command prior the get-uuid!
    Also there could be issue with repeating of this command without hard reset of device 'reset -h'.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    :param debug_mailbox_params: DebugMailboxParams object holding information about parameters for debug mailbox.
    :raises SPSDKAppError: Raised if any error occurred.
    :return: UUID value in bytes if succeeded, None otherwise.
    """
    try:
        debug_probe_params.set_family(family)
        with open_debug_probe(
            debug_probe_params.interface,
            debug_probe_params.serial_no,
            debug_probe_params.debug_probe_user_params,
            print_func=click.echo,
        ) as debug_probe:
            debug_probe.connect_safe()
            try:
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    family=family,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=26).run()
            except SPSDKError:
                debug_probe.close()
                debug_probe.open()
                debug_probe.connect_safe()
                dm = DebugMailbox(
                    debug_probe=debug_probe,
                    family=family,
                    reset=debug_mailbox_params.reset,
                    moredelay=debug_mailbox_params.more_delay,
                    op_timeout=debug_mailbox_params.operation_timeout,
                )
                dac_data = dm_commands.DebugAuthenticationStart(dm=dm, resplen=30).run()
            # convert list[int] to bytes
            dac_data_bytes = struct.pack(f"<{len(dac_data)}I", *dac_data)
            dac = DebugAuthenticationChallenge.parse(dac_data_bytes, family=family)
    except Exception as e:
        raise SPSDKAppError(f"Getting UUID from target failed: {e}") from e

    if dac.uuid == bytes(16):
        logger.warning("The valid UUID is not included in DAC.")
        logger.info(f"DAC info:\n {str(dac)}")
        return None

    logger.info(f"Got DAC from SOCC:'0x{dac.socc:08X}' to retrieve UUID.")
    return dac.uuid


@tool_group.command(name="halt", no_args_is_help=False)
@spsdk_family_option(get_families())  # Get all supported families by SPSDK
@click.pass_obj
def debug_halt_command(pass_obj: dict, family: FamilyRevision) -> None:
    """Halt CPU execution."""
    try:
        debug_halt(family, pass_obj["debug_probe_params"])
        click.echo("The CPU execution has been halted.")
    except SPSDKError as exc:
        raise SPSDKAppError(f"Halt of CPU execution failed. ({str(exc)})") from exc


def debug_halt(family: FamilyRevision, debug_probe_params: DebugProbeParams) -> None:
    """Halt CPU execution.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    """
    debug_probe_params.set_family(family)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect_safe()
        debug_probe.debug_halt()


@tool_group.command(name="resume", no_args_is_help=False)
@spsdk_family_option(get_families())  # Get all supported families by SPSDK
@click.pass_obj
def debug_resume_command(pass_obj: dict, family: FamilyRevision) -> None:
    """Resume CPU execution."""
    try:
        debug_resume(family, pass_obj["debug_probe_params"])
        click.echo("The CPU execution has been resumed.")
    except SPSDKError as exc:
        raise SPSDKAppError(f"Resume of CPU execution failed. ({str(exc)})") from exc


def debug_resume(family: FamilyRevision, debug_probe_params: DebugProbeParams) -> None:
    """Resume CPU execution.

    :param family: Device family
    :param debug_probe_params: DebugProbeParams object holding information about parameters for debug probe.
    """
    debug_probe_params.set_family(family)
    with open_debug_probe(
        interface=debug_probe_params.interface,
        serial_no=debug_probe_params.serial_no,
        debug_probe_params=debug_probe_params.debug_probe_user_params,
        print_func=click.echo,
    ) as debug_probe:
        debug_probe.connect_safe()
        debug_probe.debug_resume()


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

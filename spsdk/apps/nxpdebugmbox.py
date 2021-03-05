#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import logging
import struct
import sys

from typing import List, Dict
import click

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import INT, catch_spsdk_error
from spsdk.dat import (DebugAuthenticationChallenge, DebugCredential,
                       DebugAuthenticateResponse, dm_commands)
from spsdk.dat.debug_mailbox import DebugMailbox
from spsdk.debuggers.utils import DebugProbeUtils
from spsdk.exceptions import SPSDKError

logger = logging.getLogger("DebugMBox")

LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]
PROTOCOL_VERSIONS = ['1.0', '1.1', '2.0', '2.1', '2.2']

def _open_debugmbox(pass_obj: Dict) -> DebugMailbox:
    """Method opens DebugMailbox object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active DebugMailbox object.
    :raise SPSDKError: Raised with any kind of problems with debug probe.
    """
    interface = pass_obj['interface']
    serial_no = pass_obj['serial_no']
    debug_probe_params = pass_obj['debug_probe_params']
    timing = pass_obj['timing']
    reset = pass_obj['reset']

    debug_probes = DebugProbeUtils.get_connected_probes(interface=interface,
                                                        hardware_id=serial_no,
                                                        user_params=debug_probe_params)
    selected_probe = debug_probes.select_probe()
    debug_probe = selected_probe.get_probe(debug_probe_params)
    debug_probe.open()

    return DebugMailbox(
        debug_probe=debug_probe,
        reset=reset,
        moredelay=timing
        )

@click.group()
@click.option('-i', '--interface')
@click.option('-p', '--protocol', 'protocol', metavar='VERSION', default='1.0',
              help=f'Set the protocol version. Default is 1.0 (RSA). '
                   f'Available options are: {", ".join(PROTOCOL_VERSIONS)}',
              type=click.Choice(PROTOCOL_VERSIONS))
@click.option('-d', '--debug', 'log_level', metavar='LEVEL', default='debug',
              help=f'Set the level of system logging output. '
                   f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
              type=click.Choice(LOG_LEVEL_NAMES))
@click.option('-t', '--timing', type=float, default=0.0)
@click.option('-s', '--serial-no')
@click.option('-n', '--no-reset', 'reset', is_flag=True, default=True)
@click.option('-o', '--debug-probe-option', multiple=True, help="This option could be used "
              "multiply to setup non-standard option for debug probe.")
@click.version_option(spsdk_version, '-v', '--version')
@click.help_option('--help')
@click.pass_context
def main(ctx: click.Context, interface: str, protocol: str, log_level: str, timing: float,
         serial_no: str, debug_probe_option: List[str], reset: bool) -> int:
    """NXP Debug Mailbox Tool."""
    logging.basicConfig(level=log_level.upper())
    logger.setLevel(level=log_level.upper())

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")

        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
        'protocol': protocol,
        'interface': interface,
        'serial_no': serial_no,
        'debug_probe_params': probe_user_params,
        'timing': timing,
        'reset': reset,
        }

    return 0


@main.command()
@click.option('-b', '--beacon', type=INT(), help='Authentication beacon')
@click.option('-c', '--certificate', help='Path to Debug Credentials.')
@click.option('-k', '--key', help='Path to DCK private key.')
@click.option('-f', '--force', is_flag=True, default=True)
@click.pass_obj
def auth(pass_obj: dict, beacon: int, certificate: str, key: str, force: bool) -> None:
    """Perform the Debug Authentication."""
    try:
        logger.info("Starting Debug Authentication")
        mail_box = _open_debugmbox(pass_obj)
        with open(certificate, 'rb') as f:
            debug_cred_data = f.read()
        debug_cred = DebugCredential.parse(debug_cred_data)
        dac_data = dm_commands.DebugAuthenticationStart(dm=mail_box).run()
        # convert List[int] to bytes
        dac_data_bytes = struct.pack(f'<{len(dac_data)}I', *dac_data)
        dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
        logger.debug(f'DAC: \n{dac.info()}')
        dar = DebugAuthenticateResponse.create(
            version=pass_obj['protocol'], socc=dac.socc,
            dc=debug_cred, auth_beacon=beacon, dac=dac, dck=key
        )
        logger.debug(f'DAR:\n{dar.info()}')
        dar_data = dar.export()
        # convert bytes to List[int]
        dar_data_words = list(struct.unpack(f'<{len(dar_data) // 4}I', dar_data))
        dar_response = dm_commands.DebugAuthenticationResponse(
            dm=mail_box, paramlen=len(dar_data_words)
        ).run(dar_data_words)
        logger.debug(f'DAR response: {dar_response}')
        exit_response = dm_commands.ExitDebugMailbox(dm=mail_box).run()
        logger.debug(f'Exit response: {exit_response}')
        logger.info("Debug Authentication successful")
    except Exception as e:
        logger.error(f"Start Debug Mailbox failed!\n{e}")


@main.command()
@click.pass_obj
def start(pass_obj: dict) -> None:
    """Start DebugMailBox."""
    try:
        dm_commands.StartDebugMailbox(dm=_open_debugmbox(pass_obj)).run()
        logger.info("Start Debug Mailbox successful")
    except:
        logger.error("Start Debug Mailbox failed!")


@main.command()
@click.pass_obj
def exit(pass_obj: dict) -> None:
    """Exit DebugMailBox."""
    try:
        dm_commands.ExitDebugMailbox(dm=_open_debugmbox(pass_obj)).run()
        logger.info("Exit Debug Mailbox successful")
    except:
        logger.error("Exit Debug Mailbox failed!")


@main.command()
@click.pass_obj
def erase(pass_obj: dict) -> None:
    """Erase Flash."""
    try:
        dm_commands.EraseFlash(dm=_open_debugmbox(pass_obj)).run()
        logger.info("Mass flash erase successful")
    except:
        logger.error("Mass flash erase failed!")


@main.command()
@click.pass_obj
def famode(pass_obj: dict) -> None:
    """Set Fault Analysis Mode."""
    try:
        dm_commands.SetFaultAnalysisMode(dm=_open_debugmbox(pass_obj)).run()
        logger.info("Set fault analysis mode successful")
    except:
        logger.error("Set fault analysis mode failed!")


@main.command()
@click.option('-m', '--mode', type=int, required=True)
@click.pass_obj
def ispmode(pass_obj: dict, mode: int) -> None:
    """Enter ISP Mode."""
    try:
        dm_commands.EnterISPMode(dm=_open_debugmbox(pass_obj)).run([mode])
        logger.info("ISP mode entered successfully!")
    except:
        logger.error("Entering into ISP mode failed!")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover

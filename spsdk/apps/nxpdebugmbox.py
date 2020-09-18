#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Main Debug Authentication Tool application."""

import logging
import struct
import sys

import click

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import INT
from spsdk.dat import (DebugAuthenticationChallenge, DebugCredential,
                       dar_packet, dm_commands)
from spsdk.dat.debug_mailbox import DebugMailbox

logger = logging.getLogger("DebugMBox")

LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]
PROTOCOL_VERSIONS = ['1.0', '1.1', '2.0', '2.1', '2.2']


@click.group()
@click.option('-i', '--interface')
@click.option('-p', '--protocol', 'protocol', metavar='VERSION', default='1.0',
              help=f'Set the protocol version. Default is 1.0 (RSA). '
                   f'Available options are: {", ".join(PROTOCOL_VERSIONS)}',
              type=click.Choice(PROTOCOL_VERSIONS), )
@click.option('-d', '--debug', 'log_level', metavar='LEVEL', default='debug',
              help=f'Set the level of system logging output. '
                   f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
              type=click.Choice(LOG_LEVEL_NAMES))
@click.option('-t', '--timing', type=float, default=0.0)
@click.option('-s', '--serial-no', type=INT())
@click.option('-ip', '--ip', 'ip_addr')
@click.option('--pemicroid', 'hardware_id')
@click.option('-n', '--no-reset', 'reset', is_flag=True, default=True)
@click.version_option(spsdk_version, '-v', '--version')
@click.help_option('--help')
@click.pass_context
def main(ctx: click.Context, interface: str, protocol: str, log_level: str, timing: float,
         serial_no: int, ip_addr: str, hardware_id: str, reset: bool) -> int:
    """NXP Debug Mailbox Tool."""
    logging.basicConfig(level=log_level.upper())
    logger.setLevel(level=log_level.upper())

    ctx.obj = {
        'protocol': protocol,
        'debug_mailbox':
            DebugMailbox(
                debug_interface=interface, reset=reset, moredelay=timing,
                serial_no=serial_no, ip_addr=ip_addr, tool=None, hardware_id=hardware_id
            ) if '--help' not in click.get_os_args() else None,
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
        mail_box = pass_obj['debug_mailbox']
        with open(certificate, 'rb') as f:
            debug_cred_data = f.read()
        debug_cred = DebugCredential.parse(debug_cred_data)
        dac_data = dm_commands.DebugAuthenticationStart(dm=mail_box).run()
        # convert List[int] to bytes
        dac_data_bytes = struct.pack(f'<{len(dac_data)}I', *dac_data)
        dac = DebugAuthenticationChallenge.parse(dac_data_bytes)
        logger.debug(f'DAC: \n{dac.info()}')
        is_rsa = pass_obj['protocol'].startswith('1')
        dar_class = dar_packet.DebugAuthenticateResponseRSA if is_rsa else dar_packet.DebugAuthenticateResponseECC
        dar = dar_class(debug_credential=debug_cred, auth_beacon=beacon, dac=dac, path_dck_private=key)
        logger.debug(f'DAR:\n{dar.info()}')
        dar_data = dar.export()
        # convert bytes to List[int]
        dar_data_words = list(struct.unpack(f'<{len(dar_data)//4}I', dar_data))
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
        dm_commands.StartDebugMailbox(dm=pass_obj['debug_mailbox']).run()
        logger.info("Start Debug Mailbox successful")
    except:
        logger.error("Start Debug Mailbox failed!")


@main.command()
@click.pass_obj
def exit(pass_obj: dict) -> None:
    """Exit DebugMailBox."""
    try:
        dm_commands.ExitDebugMailbox(dm=pass_obj['debug_mailbox']).run()
        logger.info("Exit Debug Mailbox successful")
    except:
        logger.error("Exit Debug Mailbox failed!")


@main.command()
@click.pass_obj
def erase(pass_obj: dict) -> None:
    """Erase Flash."""
    try:
        dm_commands.EraseFlash(dm=pass_obj['debug_mailbox']).run()
        logger.info("Mass flash erase successful")
    except:
        logger.error("Mass flash erase failed!")


@main.command()
@click.pass_obj
def famode(pass_obj: dict) -> None:
    """Set Fault Analysis Mode."""
    try:
        dm_commands.SetFaultAnalysisMode(dm=pass_obj['debug_mailbox']).run()
        logger.info("Set fault analysis mode successful")
    except:
        logger.error("Set fault analysis mode failed!")


@main.command()
@click.option('-m', '--mode', type=int, required=True)
@click.pass_obj
def ispmode(pass_obj: dict, mode: int) -> None:
    """Enter ISP Mode."""
    try:
        dm_commands.EnterISPMode(dm=pass_obj['debug_mailbox']).run([mode])
        logger.info("ISP mode entered successfully!")
    except:
        logger.error("Entering into ISP mode failed!")


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover # pylint: disable=no-value-for-parameter

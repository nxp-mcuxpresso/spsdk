#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for testing debuggers support in SPSDK."""

import logging
import sys
import random
import click

from spsdk.exceptions import SPSDKError
from spsdk.apps.utils import INT

from spsdk.debuggers.utils import DebugProbeUtils

logger = logging.getLogger("DebugProbesUtils")
LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]

@click.group()
@click.option('-i', '--interface')
@click.option('-d', '--debug', 'log_level', metavar='LEVEL', default='debug',
              help=f'Set the level of system logging output. '
                   f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
              type=click.Choice(LOG_LEVEL_NAMES))
@click.option('-s', '--serial-no')
@click.option('-ip', '--ip', 'ip_addr')
@click.pass_context
def main(ctx: click.Context, interface: str, log_level: str,
         serial_no: str, ip_addr: str) -> int:
    """NXP Debug Mailbox Tool."""
    logging.basicConfig(level=log_level.upper())
    logger.setLevel(level=log_level.upper())

    # Get the Debug probe object
    try:
        #TODO solve following parameters:
        # ip_addr
        # tool
        debug_probes = DebugProbeUtils.get_connected_probes(interface=interface, hardware_id=serial_no)
        selected_probe = debug_probes.select_probe()
        debug_probe = DebugProbeUtils.get_probe(interface=selected_probe.interface,
                                                hardware_id=selected_probe.hardware_id)
        debug_probe.open()

        ctx.obj = {
            'debug_probe': debug_probe
        }

    except:
        logger.error("Test of SPSDK debug probes failed")
        return -1
    return 0

@main.command()
@click.option('-a', '--address', type=INT(), help='Testing address', default="0x20000000")
@click.option('-s', '--size', type=INT(), help='Testing block size', default="1")
@click.pass_obj
def regs(pass_obj: dict, address: int, size: int) -> None:
    """Test Shadow registers."""
    if size == 0:
        logger.error("Invalid test vector size")
        return
    error_cnt = 0

    try:
        probe = pass_obj['debug_probe']
        test_vector = [random.randint(0, 0xffffffff) for x in range(size)]

        for i in range(size):
            probe.mem_reg_write(address + i * 4, test_vector[i])

        for i in range(size):
            if test_vector[i] != probe.mem_reg_read(address + i * 4):
                error_cnt += 1

        if error_cnt == 0:
            logger.info("Debug Probe shadow register test ends  successfully")
        else:
            logger.error(f"Debug Probe shadow register test ends with {error_cnt} fails from {size}")
    except Exception as exc:
        logger.error(f"Debug Probe shadow register test failed! ({str(exc)})")

if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover # pylint: disable=no-value-for-parameter
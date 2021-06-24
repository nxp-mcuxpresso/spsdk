#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Main Debug Authentication Tool application."""

import logging
import sys
import os

from typing import List, Dict

import click

from spsdk import __version__ as spsdk_version
from spsdk.shadowregs import ShadowRegisters, enable_debug
from spsdk.debuggers.utils import DebugProbeUtils
from spsdk.exceptions import SPSDKError
from spsdk.utils.registers import Registers, RegsRegister
from spsdk.utils.reg_config import RegConfig
from spsdk.apps.utils import catch_spsdk_error
from spsdk import SPSDK_DATA_FOLDER

logger = logging.getLogger("ShadowRegs")

# pylint: disable=protected-access
LOG_LEVEL_NAMES = [name.lower() for name in logging._nameToLevel]

CONFIG_DIR = os.path.join(SPSDK_DATA_FOLDER, "shadowregs")
CONFIG_FILE = "database.json"


def _open_shadow_registers(pass_obj: Dict) -> ShadowRegisters:
    """Method opens ShadowRegisters object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active ShadowRegisters object.
    :raise SPSDKError: Raised with any kind of problems with debug probe.
    """
    config_file = pass_obj["config_file"]
    interface = pass_obj["interface"]
    serial_no = pass_obj["serial_no"]
    debug_probe_params = pass_obj["debug_probe_params"]
    device = pass_obj["device"]
    revision = pass_obj["revision"]

    if device not in RegConfig.devices(config_file):
        raise SPSDKError(
            "Invalid or none device parameter(-dev). Use 'listdevs' command to get supported devices."
        )

    regs_cfg = RegConfig(config_file)

    try:
        debug_probes = DebugProbeUtils.get_connected_probes(
            interface=interface, hardware_id=serial_no, user_params=debug_probe_params
        )
        selected_probe = debug_probes.select_probe()
        debug_probe = selected_probe.get_probe(debug_probe_params)
        debug_probe.open()
        if not enable_debug(debug_probe):
            raise SPSDKError("Cannot enable debug interface")

        debug_probe.enable_memory_interface()
    except SPSDKError as exc:
        raise SPSDKError(f"Error with opening debug probe: ({str(exc)})")

    return ShadowRegisters(
        debug_probe=debug_probe, config=regs_cfg, device=device, revision=revision
    )


@click.group()
@click.option(
    "-i",
    "--interface",
    help="The interface allow specify to use only one debug probe interface"
    " like: 'PyOCD', 'jlink' or 'pemicro'",
)
@click.option(
    "-d",
    "--debug",
    "log_level",
    metavar="LEVEL",
    default="error",
    help=f"Set the level of system logging output. "
    f'Available options are: {", ".join(LOG_LEVEL_NAMES)}',
    type=click.Choice(LOG_LEVEL_NAMES),
)
@click.option(
    "-s",
    "--serial-no",
    help="Serial number of debug probe to avoid select menu after startup.",
)
@click.option(
    "-dev",
    "--device",
    type=str,
    help="The connected device - to list supported devices use 'listdevs' command.",
)
@click.option(
    "-r",
    "--revision",
    help="Chip revision; if not specified, most recent one will be used",
)
@click.option(
    "-o",
    "--debug-probe-option",
    multiple=True,
    help="This option could be used " "multiply to setup non-standard option for debug probe.",
)
@click.version_option(spsdk_version, "-v", "--version")
@click.help_option("--help")
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    log_level: str,
    serial_no: str,
    debug_probe_option: List[str],
    device: str,
    revision: str,
) -> int:
    """NXP Shadow Registers control Tool."""
    logging.basicConfig(level=log_level.upper())
    logger.setLevel(level=log_level.upper())

    config_filename = os.path.join(CONFIG_DIR, CONFIG_FILE)

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")
        else:
            par_splitted = par.split("=")
            probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
        "config_file": config_filename,
        "interface": interface,
        "serial_no": serial_no,
        "debug_probe_params": probe_user_params,
        "device": device,
        "revision": revision or "latest",
    }

    return 0


# Enable / Disable debug
@main.command()
@click.option(
    "-f",
    "--filename",
    default="sr_config.yml",
    help="The name of file used to save the current configuration."
    " Default name is 'sr_config'. The extension is always '.yml'.",
)
@click.option(
    "-r",
    "--raw",
    is_flag=True,
    default=False,
    help="The stored configuration will include also the computed fields "
    "and anti-pole registers.",
)
@click.pass_obj
def saveconfig(pass_obj: dict, filename: str = "sr_config.yml", raw: bool = False) -> None:
    """Save current state of shadow registers to YML file."""
    try:
        shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
        shadow_regs.reload_registers()
        shadow_regs.create_yml_config(filename, raw)
        click.echo(f"The Shadow registers has been saved into {filename} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Save configuration of Shadow registers failed! ({str(exc)})")


@main.command()
@click.option(
    "-f",
    "--filename",
    default="sr_config.yml",
    help="The name of file used to load a new configuration."
    " Default name is 'sr_config'. The extension is always '.yml'.",
)
@click.option(
    "-r",
    "--raw",
    is_flag=True,
    default=False,
    help="In loaded configuration will accepted also the computed fields "
    "and anti-pole registers.",
)
@click.pass_obj
def loadconfig(pass_obj: dict, filename: str = "sr_config.yml", raw: bool = False) -> None:
    """Load new state of shadow registers from YML file into microcontroller."""
    try:
        shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
        shadow_regs.load_yml_config(filename, raw)
        shadow_regs.sets_all_registers()
        click.echo(f"The Shadow registers has been loaded by configuration in {filename} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Load configuration of Shadow registers failed ({str(exc)})!")


@main.command()
@click.option(
    "-r",
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@click.pass_obj
def printregs(pass_obj: dict, rich: bool = False) -> None:
    """Print all Shadow registers including theirs current values.

    In case of needed more information, there is also provided rich format of print.
    """
    try:
        shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
        shadow_regs.reload_registers()

        for reg in shadow_regs.regs.get_registers():
            click.echo(f"Register Name:        {reg.name}")
            click.echo(f"Register value:       {reg.get_hex_value()}")
            if rich:
                click.echo(f"Register description: {reg.description}")
                address = shadow_regs.offset + reg.offset
                click.echo(f"Register address:     0x{address:08X}")
                click.echo(f"Register width:       {reg.width} bits")
            click.echo()
    except SPSDKError as exc:
        raise SPSDKError(f"Print of Shadow registers failed! ({str(exc)})")


@main.command()
@click.option("-r", "--reg", type=str, help="The name of register to be read.")
@click.pass_obj
def getreg(pass_obj: dict, reg: str) -> None:
    """The command prints the current value of one shadow register."""
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
    try:
        register: RegsRegister = shadow_regs.regs.find_reg(reg)
        shadow_regs.reload_register(register)
        click.echo(f"Value of {reg} is: {register.get_hex_value()}")
    except SPSDKError as exc:
        raise SPSDKError(f"Getting Shadow register failed! ({str(exc)})")


@main.command()
@click.option("-r", "--reg", type=str, help="The name of register to be set.")
@click.option("-v", "--reg_val", type=str, help="The new value of register in hex format.")
@click.pass_obj
def setreg(pass_obj: dict, reg: str, reg_val: str) -> None:
    """The command sets a value of one shadow register defined by parameter."""
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
    try:
        shadow_regs.set_register(reg, reg_val)
        click.echo(f"The Shadow register {reg} has been set to {reg_val} value")
    except SPSDKError as exc:
        raise SPSDKError(f"Setting Shadow register failed! ({str(exc)})")


@main.command()
@click.pass_obj
def reset(pass_obj: dict) -> None:
    """The command resets connected device."""
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
    shadow_regs.probe.reset()
    click.echo(f"The target has been reset.")


@main.command()
@click.pass_obj
def listdevs(pass_obj: dict) -> None:
    """The command prints a list of supported devices."""
    config_filename = pass_obj["config_file"]
    for index, device in enumerate(RegConfig.devices(config_filename)):
        click.echo(f"{index:03}: {device}")


@main.command()
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    required=True,
    help="Save the output into a file instead of console",
)
@click.option(
    "-p",
    "--open",
    "open_result",
    is_flag=True,
    help="Open the generated description file",
)
@click.pass_obj
def info(pass_obj: dict, output: str, open_result: bool) -> None:
    """The command generate HTML of Shadow registers."""
    config = RegConfig(pass_obj["config_file"])
    device = pass_obj["device"]
    revision = pass_obj["revision"]
    registers = Registers(device)
    rev = revision if revision != "latest" else config.get_latest_revision(device)
    registers.load_registers_from_xml(config.get_data_file(device, rev))
    html_output = registers.generate_html(
        f"{device} - Shadow Registers",
        f"The table with Shadow registers description for {device}",
    )
    with open(output, "w", encoding="utf-8") as f:
        f.write(html_output)

    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f"{output}")


@catch_spsdk_error
def safe_main() -> None:
    """Safe main method."""
    sys.exit(main())  # pragma: no cover # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

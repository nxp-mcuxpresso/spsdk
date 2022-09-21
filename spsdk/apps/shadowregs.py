#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Main Debug Authentication Tool application."""

import logging
import os
import sys
from typing import Dict, List

import click

from spsdk import SPSDK_DATA_FOLDER
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.debuggers.utils import DebugProbeUtils
from spsdk.exceptions import SPSDKError
from spsdk.shadowregs import ShadowRegisters, enable_debug
from spsdk.utils.misc import load_configuration, write_file
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers, RegsRegister

logger = logging.getLogger(__name__)

CONFIG_DIR = os.path.join(SPSDK_DATA_FOLDER, "shadowregs")
CONFIG_DATABASE = os.path.join(CONFIG_DIR, "database.yaml")


def _open_shadow_registers(pass_obj: Dict, connect: bool = True) -> ShadowRegisters:
    """Method opens ShadowRegisters object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :param connect: Create Shadow register object connected to device.
    :return: Active ShadowRegisters object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    interface = pass_obj["interface"]
    serial_no = pass_obj["serial_no"]
    debug_probe_params = pass_obj["debug_probe_params"]
    device = pass_obj["device"]
    revision = pass_obj["revision"]

    if device not in RegConfig.devices(CONFIG_DATABASE):
        raise SPSDKError(
            "Invalid or none device parameter(-dev). Use 'listdevs' command to get supported devices."
        )

    regs_cfg = RegConfig(CONFIG_DATABASE)

    debug_probe = None
    if connect:
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
            raise SPSDKError(f"Error with opening debug probe: ({str(exc)})") from exc

    return ShadowRegisters(
        debug_probe=debug_probe, config=regs_cfg, device=device, revision=revision
    )


@click.group(name="shadowregs", no_args_is_help=True, cls=CommandsTreeGroup)
@click.option(
    "-i",
    "--interface",
    help="The interface allow specify to use only one debug probe interface"
    " like: 'PyOCD', 'jlink' or 'pemicro'",
)
@spsdk_apps_common_options
@click.option(
    "-s",
    "--serial-no",
    help="Serial number of debug probe to avoid select menu after startup.",
)
@click.option(
    "-dev",
    "--device",
    type=click.Choice(RegConfig.devices(CONFIG_DATABASE)),
    help="The target device family.",
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
    help=(
        "This option could be used multiply to setup non-standard option for debug probe."
        " The example of use: -o KEY=VALUE"
    ),
)
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    log_level: int,
    serial_no: str,
    debug_probe_option: List[str],
    device: str,
    revision: str,
) -> int:
    """NXP Shadow Registers control Tool."""
    logging.basicConfig(level=log_level or logging.WARNING)

    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")
        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    ctx.obj = {
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
@click.option(
    "-d",
    "--save-diff",
    is_flag=True,
    default=False,
    help="Save differences comparing to defaults",
)
@click.pass_obj
def saveconfig(pass_obj: dict, filename: str, raw: bool, save_diff: bool) -> None:
    """Save current state of shadow registers to YML file."""
    try:
        shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
        shadow_regs.reload_registers()
        shadow_regs.create_yml_config(filename, raw, diff=save_diff)
        click.echo(f"The Shadow registers has been saved into {filename} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Save configuration of Shadow registers failed! ({str(exc)})") from exc


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
        raise SPSDKError(f"Load configuration of Shadow registers failed ({str(exc)})!") from exc


@main.command(name="get-template", no_args_is_help=True)
@click.argument("output", metavar="PATH", type=click.Path())
@click.option(
    "-r",
    "--raw",
    is_flag=True,
    default=False,
    help="In loaded configuration will accepted also the computed fields "
    "and anti-pole registers.",
)
@click.pass_obj
def get_template(pass_obj: dict, output: str, raw: bool) -> None:
    """Generate the template of Shadow registers YML configuration file.

    \b
    PATH    - file name path to write template config file
    """
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj, connect=False)
    shadow_regs.create_yml_config(output, raw)
    click.echo(
        f"The Shadow registers template for {pass_obj['device']} has been saved into {output} YAML file"
    )


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
        raise SPSDKError(f"Print of Shadow registers failed! ({str(exc)})") from exc


@main.command()
@click.option("-r", "--reg", type=str, help="The name of register to be read.")
@click.pass_obj
def getreg(pass_obj: dict, reg: str) -> None:
    """The command prints the current value of one shadow register."""
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
    try:
        register: RegsRegister = shadow_regs.regs.find_reg(reg, include_group_regs=True)
        shadow_regs.reload_register(register)
        click.echo(f"Value of {reg} is: {register.get_hex_value()}")
    except SPSDKError as exc:
        raise SPSDKError(f"Getting Shadow register failed! ({str(exc)})") from exc


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
        raise SPSDKError(f"Setting Shadow register failed! ({str(exc)})") from exc


@main.command()
@click.pass_obj
def reset(pass_obj: dict) -> None:
    """The command resets connected device."""
    shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj)
    assert shadow_regs.probe
    shadow_regs.probe.reset()
    click.echo("The target has been reset.")


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
    config = RegConfig(CONFIG_DATABASE)
    device = pass_obj["device"]
    revision = pass_obj["revision"]
    registers = Registers(device)
    rev = revision if revision != "latest" else config.get_latest_revision(device)
    registers.load_registers_from_xml(config.get_data_file(device, rev))
    html_output = registers.generate_html(
        f"{device} - Shadow Registers",
        f"The table with Shadow registers description for {device}",
    )
    write_file(html_output, output, encoding="utf-8")
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f"{output}")


@main.command(name="fuses-script", no_args_is_help=True)
@click.option(
    "-c",
    "--config",
    type=click.Path(),
    help="The name of shadow register configuration file used to generate burn fuses BLHOST script.",
    required=True,
)
@click.argument(
    "output",
    type=click.Path(),
    required=True,
)
@click.pass_obj
def fuses_script(pass_obj: dict, config: str, output: str) -> None:
    """The command generate BLHOST script to burn up fuses in device by configuration.

    The OUTPUT argument specify file name of generate BLHOST burn fuses script.
    """
    try:
        shadow_regs: ShadowRegisters = _open_shadow_registers(pass_obj, connect=False)
        shadow_regs.load_yml_config(config, False)
        cfg = load_configuration(config)
        write_file(shadow_regs.create_fuse_blhost_script(list(cfg["registers"].keys())), output)
        click.echo(f"BLHOST script to burn fuses has been generated: {output}")
    except SPSDKError as exc:
        raise SPSDKError(
            f"Creating BLHOST script from shadow register configuration failed! ({str(exc)})"
        ) from exc


@catch_spsdk_error
def safe_main() -> None:
    """Safe main method."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

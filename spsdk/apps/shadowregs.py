#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Main Debug Authentication Tool application."""

import contextlib
import logging
import os
import sys
from typing import Dict, Iterator, List

import click

from spsdk import SPSDK_DATA_FOLDER
from spsdk.apps.nxpdebugmbox import get_debug_probe_options_help
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.debuggers.utils import PROBES, DebugProbe, open_debug_probe
from spsdk.exceptions import SPSDKError
from spsdk.shadowregs.shadowregs import ShadowRegisters, enable_debug
from spsdk.utils.misc import load_configuration, write_file
from spsdk.utils.reg_config import RegConfig
from spsdk.utils.registers import Registers

logger = logging.getLogger(__name__)

CONFIG_DIR = os.path.join(SPSDK_DATA_FOLDER, "shadowregs")
CONFIG_DATABASE = os.path.join(CONFIG_DIR, "database.yaml")


@contextlib.contextmanager
def _open_debug_probe(pass_obj: Dict) -> Iterator[DebugProbe]:
    """Method opens DebugProbe object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :return: Active DebugProbe object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    interface = pass_obj["interface"]
    serial_no = pass_obj["serial_no"]
    debug_probe_params = pass_obj["debug_probe_params"]

    with open_debug_probe(
        interface=interface,
        serial_no=serial_no,
        debug_probe_params=debug_probe_params,
        print_func=click.echo,
    ) as probe:
        yield probe


@contextlib.contextmanager
def _open_shadow_registers(pass_obj: Dict, connect: bool = True) -> Iterator[ShadowRegisters]:
    """Method opens ShadowRegisters object based on input arguments.

    :param pass_obj: Input dictionary with arguments.
    :param connect: Create Shadow register object connected to device.
    :return: Active ShadowRegisters object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    device = pass_obj["family"]
    revision = pass_obj["revision"]

    if device not in RegConfig(CONFIG_DATABASE).devices.device_names:
        raise SPSDKError(
            "Invalid or none device parameter(-f/--family). Check '--help' to get supported devices."
        )

    regs_cfg = RegConfig(CONFIG_DATABASE)

    if not connect:
        yield ShadowRegisters(debug_probe=None, config=regs_cfg, device=device, revision=revision)
    else:
        with _open_debug_probe(pass_obj) as debug_probe:
            if not enable_debug(debug_probe):
                raise SPSDKError("Cannot enable debug interface")

            yield ShadowRegisters(
                debug_probe=debug_probe, config=regs_cfg, device=device, revision=revision
            )


@click.group(name="shadowregs", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
@click.option(
    "-i",
    "--interface",
    type=click.Choice(list(PROBES.keys())),
    help="Probe interface selection, if not specified, all available debug probe interfaces are used.",
)
@click.option(
    "-s",
    "--serial-no",
    help="Serial number of debug probe to avoid select menu after startup.",
)
@spsdk_family_option(families=RegConfig.get_devices(CONFIG_DATABASE).device_names, required=False)
@click.option(
    "-r",
    "--revision",
    help="Chip revision; if not specified, most recent one will be used",
)
@click.option(
    "-o",
    "--debug-probe-option",
    multiple=True,
    help=get_debug_probe_options_help(),
)
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    log_level: int,
    serial_no: str,
    debug_probe_option: List[str],
    family: str,
    revision: str,
) -> int:
    """NXP Shadow Registers control Tool."""
    spsdk_logger.install(level=log_level)
    spsdk_logger.configure_pyocd_logger()

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
        "family": family,
        "revision": revision or "latest",
    }

    return 0


# Enable / Disable debug
@main.command(no_args_is_help=True)
@spsdk_output_option()
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
def saveconfig(pass_obj: dict, output: str, raw: bool, save_diff: bool) -> None:
    """Save current state of shadow registers to YAML file."""
    try:
        with _open_shadow_registers(pass_obj) as shadow_regs:
            shadow_regs.reload_registers()
            shadow_regs.create_yaml_config(output, raw, diff=save_diff)
        click.echo(f"The Shadow registers has been saved into {output} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Save configuration of Shadow registers failed! ({str(exc)})") from exc


@main.command(no_args_is_help=True)
@spsdk_config_option()
@click.option(
    "-r",
    "--raw",
    is_flag=True,
    default=False,
    help="In loaded configuration will accepted also the computed fields "
    "and anti-pole registers.",
)
@click.option(
    "--verify/--no-verify",
    is_flag=True,
    default=True,
    help="Verify write operation (verify by default)",
)
@click.pass_obj
def loadconfig(pass_obj: dict, config: str, raw: bool, verify: bool) -> None:
    """Load new state of shadow registers from YAML file into micro controller."""
    try:
        with _open_shadow_registers(pass_obj) as shadow_regs:
            shadow_regs.load_yaml_config(config, raw)
            shadow_regs.sets_all_registers(verify)
        click.echo(f"The Shadow registers has been loaded by configuration in {config} YAML file")

    except SPSDKError as exc:
        raise SPSDKError(f"Load configuration of Shadow registers failed ({str(exc)})!") from exc


@main.command(name="get-template", no_args_is_help=True)
@click.option(
    "-r",
    "--raw",
    is_flag=True,
    default=False,
    help="In loaded configuration will accepted also the computed fields "
    "and anti-pole registers.",
)
@spsdk_output_option(force=True)
@click.pass_obj
def get_template(pass_obj: dict, output: str, raw: bool) -> None:
    """Generate the template of Shadow registers YAML configuration file."""
    with _open_shadow_registers(pass_obj, connect=False) as shadow_regs:
        shadow_regs.create_yaml_config(output, raw)
    click.echo(
        f"The Shadow registers template for {pass_obj['family']} has been saved into {output} YAML file"
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
        with _open_shadow_registers(pass_obj) as shadow_regs:
            shadow_regs.reload_registers()

            for reg in shadow_regs.regs.get_registers():
                click.echo(f"Register Name:        {reg.name}")
                click.echo(f"Register value:       {reg.get_hex_value()}")
                click.echo(f"Register raw value:   {reg.get_hex_value(raw=True)}")
                if rich:
                    click.echo(f"Register description: {reg.description}")
                    address = shadow_regs.offset + reg.offset
                    click.echo(f"Register address:     0x{address:08X}")
                    click.echo(f"Register width:       {reg.width} bits")
                click.echo()
    except SPSDKError as exc:
        raise SPSDKError(f"Print of Shadow registers failed! ({str(exc)})") from exc


@main.command(no_args_is_help=True)
@click.option("-r", "--reg", type=str, required=True, help="The name of register to be read.")
@click.pass_obj
def getreg(pass_obj: dict, reg: str) -> None:
    """The command prints the current value of one shadow register."""
    try:
        with _open_shadow_registers(pass_obj) as shadow_regs:
            value = shadow_regs.get_register(reg)
            click.echo(f"Value of {reg} is: {value.hex()}")
    except SPSDKError as exc:
        raise SPSDKError(f"Getting Shadow register failed! ({str(exc)})") from exc


@main.command(no_args_is_help=True)
@click.option("-r", "--reg", type=str, required=True, help="The name of register to be set.")
@click.option(
    "-v", "--reg-val", type=str, required=True, help="The new value of register in hex format."
)
@click.option(
    "--verify/--no-verify",
    is_flag=True,
    default=True,
    help="Verify write operation (verify by default)",
)
@click.option(
    "--raw/--computed",
    is_flag=True,
    default=False,
    help="If computed is set, the modification hooks will be used",
)
@click.pass_obj
def setreg(pass_obj: dict, reg: str, reg_val: str, verify: bool, raw: bool) -> None:
    """The command sets a value of one shadow register defined by parameter."""
    try:
        with _open_shadow_registers(pass_obj) as shadow_regs:
            shadow_regs.set_register(
                reg,
                reg_val,
                verify,
                raw,
            )
        click.echo(f"The Shadow register {reg} has been set to {reg_val} value")
    except SPSDKError as exc:
        raise SPSDKError(f"Setting Shadow register failed! ({str(exc)})") from exc


@main.command()
@click.pass_obj
def reset(pass_obj: dict) -> None:
    """The command resets connected device."""
    with _open_debug_probe(pass_obj) as probe:
        if pass_obj["family"] == "rw61x":
            # Do a NVIC system reset
            logger.debug("Writing register address: 0xE000ED0C, data: 0x05FA0004")
            probe.mem_reg_write(addr=0xE000ED0C, data=0x05FA0004)
        else:
            probe.reset()
    click.echo("The target has been reset.")


@main.command(no_args_is_help=True)
@spsdk_output_option(help="File name of generated output HTML description file")
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
    device = pass_obj["family"]
    revision = pass_obj["revision"]
    registers = Registers(device)
    rev = (
        revision
        if revision != "latest"
        else config.devices.get_by_name(device).revisions.get_latest().name
    )
    registers.load_registers_from_xml(config.get_data_file(device, rev))
    html_output = registers.generate_html(
        f"{device} - Shadow Registers",
        f"The table with Shadow registers description for {device}",
    )
    write_file(html_output, output, encoding="utf-8")
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f"{output}")


@main.command(name="fuses-script", no_args_is_help=True)
@spsdk_config_option(required=True)
@spsdk_output_option()
@click.pass_obj
def fuses_script(pass_obj: dict, config: str, output: str) -> None:
    """The command generate BLHOST script to burn up fuses in device by configuration."""
    try:
        with _open_shadow_registers(pass_obj, connect=False) as shadow_regs:
            shadow_regs.load_yaml_config(config, False)
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

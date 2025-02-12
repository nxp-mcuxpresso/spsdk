#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Main Debug Authentication Tool application."""

import contextlib
import logging
import sys
from dataclasses import dataclass
from typing import Iterator, Optional

import click

from spsdk.apps.nxpdebugmbox import get_debug_probe_options_help
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    is_click_help,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
    spsdk_plugin_option,
    spsdk_revision_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.debuggers.utils import (
    PROBES,
    DebugProbe,
    get_test_address,
    load_all_probe_types,
    open_debug_probe,
)
from spsdk.exceptions import SPSDKError
from spsdk.fuses.fuse_registers import FuseRegister
from spsdk.fuses.shadowregs import ShadowRegisters, enable_debug
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import get_printable_path, load_configuration, write_file
from spsdk.utils.plugins import load_plugin_from_source
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


def print_register_info(fuse_register: FuseRegister, rich: bool = False) -> None:
    """Print info about a fuse register.

    :param fuse_register: Fuse register to be printed
    :param rich: Print additional information
    """
    click.echo(f"Shadow Register name:        {fuse_register.name}")
    value = fuse_register.get_hex_value()
    click.echo(f"Shadow Register value:       {fuse_register.get_hex_value()}")
    click.echo(f"Shadow Register access:      {fuse_register.access.description}")
    locks = fuse_register.get_active_locks()
    click.echo(
        f"Shadow Register locks:       {','.join([lock.label for lock in locks]) if locks else 'No locks'}"
    )
    if value != fuse_register.get_hex_value(raw=True):
        click.echo(f"Shadow Register raw value:   {fuse_register.get_hex_value(raw=True)}")
    if rich:
        click.echo(f"Shadow Register description: {fuse_register.description}")
        click.echo(f"Shadow Register address:     0x{fuse_register.shadow_register_addr:08X}")
        click.echo(f"Shadow Register width:       {fuse_register.width} bits")


@dataclass
class DebugProbeCfg:
    """Debug probe configuration."""

    interface: Optional[str] = None
    serial_no: Optional[str] = None
    debug_probe_params: Optional[dict] = None

    def set_test_address(self, test_address: int) -> None:
        """Set if not already sets, the test address for AHB access.

        :param test_address: New overriding address.
        """
        if self.debug_probe_params is not None and "test_address" not in self.debug_probe_params:
            self.debug_probe_params["test_address"] = test_address


@contextlib.contextmanager
def _open_debug_probe(debug_probe_cfg: DebugProbeCfg) -> Iterator[DebugProbe]:
    """Method opens DebugProbe object based on input arguments.

    :param debug_probe_cfg: Debug probe configuration.
    :return: Active DebugProbe object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    with open_debug_probe(
        interface=debug_probe_cfg.interface,
        serial_no=debug_probe_cfg.serial_no,
        debug_probe_params=debug_probe_cfg.debug_probe_params,
        print_func=click.echo,
    ) as probe:
        probe.connect()
        try:
            yield probe
        except SPSDKError as exc:
            raise exc
        finally:
            probe.close()


@contextlib.contextmanager
def _open_shadow_registers(
    family: str, revision: str, debug_probe_cfg: DebugProbeCfg, connect: bool = True
) -> Iterator[ShadowRegisters]:
    """Method opens ShadowRegisters object based on input arguments.

    :param family: Target family.
    :param revision: Target family revision.
    :param debug_probe_cfg: Debug probe configuration.
    :param connect: Create Shadow register object connected to device.
    :return: Active ShadowRegisters object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    if not connect:
        yield ShadowRegisters(family=family, revision=revision, debug_probe=None)
    else:
        with _open_debug_probe(debug_probe_cfg) as debug_probe:
            if not enable_debug(debug_probe, family):
                raise SPSDKError("Cannot enable debug interface")

            yield ShadowRegisters(family=family, revision=revision, debug_probe=debug_probe)


@click.group(name="shadowregs", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
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
    help="Serial number of debug probe to avoid select menu after startup.",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@spsdk_revision_option
@click.option(
    "-o",
    "--debug-probe-option",
    multiple=True,
    help=get_debug_probe_options_help(),
)
@spsdk_plugin_option
@click.pass_context
def main(
    ctx: click.Context,
    interface: str,
    log_level: int,
    serial_no: str,
    debug_probe_option: list[str],
    family: str,
    revision: str,
    plugin: str,
) -> int:
    """NXP Shadow Registers control Tool."""
    spsdk_logger.install(level=log_level)

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

    debug_probe_cfg = DebugProbeCfg(
        interface=interface, serial_no=serial_no, debug_probe_params=probe_user_params
    )
    debug_probe_cfg.set_test_address(get_test_address(family, revision))

    if not is_click_help(ctx, sys.argv):
        if not family:
            click.echo("Missing family option !")
            ctx.exit(-1)
        ctx.obj = {
            "family": family,
            "revision": revision or "latest",
            "debug_probe_cfg": debug_probe_cfg,
        }

    return 0


# Enable / Disable debug
@main.command(name="saveconfig", no_args_is_help=True)
@spsdk_output_option()
@click.option(
    "-d",
    "--save-diff",
    is_flag=True,
    default=False,
    help="Save differences comparing to defaults",
)
@click.pass_obj
def save_config(pass_obj: dict, output: str, save_diff: bool) -> None:
    """Save current state of shadow registers to YAML file."""
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"]
        ) as shadow_regs:
            shadow_regs.reload_registers()
            cfg = shadow_regs.get_config(save_diff)
        schemas = shadow_regs.get_validation_schemas(shadow_regs.device, shadow_regs.revision)
        ret = CommentedConfig(
            main_title="Shadow register configuration", schemas=schemas
        ).get_config(cfg)
        write_file(ret, output)

        click.echo(f"The Shadow registers has been saved into {output} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Save configuration of Shadow registers failed! ({str(exc)})") from exc


@main.command(name="loadconfig", no_args_is_help=True)
@spsdk_config_option()
@click.option(
    "--verify/--no-verify",
    is_flag=True,
    default=True,
    help="Verify write operation (verify by default)",
)
@click.pass_obj
def load_config(pass_obj: dict, config: str, verify: bool) -> None:
    """Load new state of shadow registers from YAML file into micro controller."""
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"]
        ) as shadow_regs:
            if verify and not shadow_regs.possible_verification:
                logger.warning(
                    f"Verification is not possible on the {shadow_regs.device}, it won't be performed."
                )
            cfg = load_configuration(config)
            schema = shadow_regs.get_validation_schemas(shadow_regs.device, shadow_regs.revision)
            check_config(cfg, schema)
            shadow_regs.load_config(cfg)
            shadow_regs.set_loaded_registers(verify)
        click.echo(f"The Shadow registers has been loaded by configuration in {config} YAML file")
    except SPSDKError as exc:
        raise SPSDKError(f"Load configuration of Shadow registers failed ({str(exc)})!") from exc


@main.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@click.pass_obj
def get_template(pass_obj: dict, output: str) -> None:
    """Generate the template of Shadow registers YAML configuration file."""
    schemas = ShadowRegisters.get_validation_schemas(pass_obj["family"], pass_obj["revision"])
    ret = CommentedConfig(
        main_title="Shadow register configuration template", schemas=schemas
    ).get_template()
    write_file(ret, output, encoding="utf-8")
    click.echo(
        f"The Shadow registers template for {pass_obj['family']} has been saved into "
        f"{get_printable_path(output)} YAML file"
    )


@main.command(name="printregs")
@click.option(
    "-r",
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@click.pass_obj
def print_regs(pass_obj: dict, rich: bool = False) -> None:
    """Print all Shadow registers including theirs current values.

    In case of needed more information, there is also provided rich format of print.
    """
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"]
        ) as shadow_regs:
            shadow_regs.reload_registers()

            for reg in shadow_regs.registers.get_registers():
                print_register_info(reg, rich)
                click.echo()
    except SPSDKError as exc:
        raise SPSDKError(f"Print of Shadow registers failed! ({str(exc)})") from exc


@main.command(name="getreg", no_args_is_help=True)
@click.option("-r", "--reg", type=str, required=True, help="The name of register to be read.")
@click.pass_obj
def get_reg(pass_obj: dict, reg: str) -> None:
    """The command prints the current value of one shadow register."""
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"]
        ) as shadow_regs:
            value = shadow_regs.get_register(reg)
            click.echo(f"Value of {reg} is: {value.hex()}")
    except SPSDKError as exc:
        raise SPSDKError(f"Getting Shadow register failed! ({str(exc)})") from exc


@main.command(name="setreg", no_args_is_help=True)
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
def set_reg(pass_obj: dict, reg: str, reg_val: str, verify: bool, raw: bool) -> None:
    """The command sets a value of one shadow register defined by parameter."""
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"]
        ) as shadow_regs:
            if verify and not shadow_regs.possible_verification:
                logger.warning(
                    f"Verification is not possible on the {shadow_regs.device}, it won't be performed."
                )
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
    with _open_debug_probe(pass_obj["debug_probe_cfg"]) as probe:
        reset_type = get_db(pass_obj["family"], pass_obj["revision"]).get_str(
            DatabaseManager.SHADOW_REGS, "reset_type"
        )
        if reset_type == "nvic_reset":
            # Do a NVIC system reset
            logger.debug("Writing register address: 0xE000ED0C, data: 0x05FA0004")
            probe.mem_reg_write(addr=0xE000ED0C, data=0x05FA0004)
        else:
            probe.reset()
    click.echo("The target has been reset.")


@main.command(name="fuses-script", no_args_is_help=True)
@spsdk_config_option(required=True)
@spsdk_output_option()
@click.pass_obj
def fuses_script(pass_obj: dict, config: str, output: str) -> None:
    """The command generate BLHOST script to burn up fuses in device by configuration."""
    try:
        with _open_shadow_registers(
            pass_obj["family"], pass_obj["revision"], pass_obj["debug_probe_cfg"], connect=False
        ) as shadow_regs:
            cfg = load_configuration(config)
            shadow_regs.load_config(cfg)
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

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Shadow Registers management application.

This module provides a command-line application for reading, writing, and managing
shadow registers on NXP MCUs through debug probes. It includes functionality for
register manipulation, configuration management, and fuse programming scripts.
"""

import contextlib
import logging
import sys
from dataclasses import dataclass
from typing import Iterator, Optional

import click
import colorama

from spsdk.apps.nxpdebugmbox import get_debug_probe_options_help
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    is_click_help,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error, progress_bar
from spsdk.debuggers.utils import PROBES, DebugProbe, get_test_address, open_debug_probe
from spsdk.exceptions import SPSDKError
from spsdk.fuses.fuse_registers import print_register_info
from spsdk.fuses.fuses import ShadowregsOperator, SPSDKFuseOperationFailure
from spsdk.fuses.shadowregs import ShadowRegisters
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import get_printable_path, value_to_int, write_file

logger = logging.getLogger(__name__)

MISSING_FAMILY_ERROR_MSG = "Missing '--family' option.  Please specify the target family"


@dataclass
class DebugProbeCfg:
    """Debug probe configuration container.

    This class holds configuration parameters for debug probe connections
    including interface type, serial number, and additional probe-specific
    parameters used for device communication and debugging operations.
    """

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
        probe.connect_safe()
        try:
            yield probe
        except SPSDKError as exc:
            raise exc
        finally:
            probe.close()


@contextlib.contextmanager
def _open_shadow_registers(
    family: FamilyRevision, debug_probe_cfg: DebugProbeCfg, connect: bool = True
) -> Iterator[ShadowRegisters]:
    """Method opens ShadowRegisters object based on input arguments.

    :param family: Target family.
    :param debug_probe_cfg: Debug probe configuration.
    :param connect: Create Shadow register object connected to device.
    :return: Active ShadowRegisters object.
    :raises SPSDKError: Raised with any kind of problems with debug probe.
    """
    if not connect:
        yield ShadowRegisters(family=family)
    else:
        with _open_debug_probe(debug_probe_cfg) as debug_probe:
            operator = ShadowregsOperator(family=family, probe=debug_probe)
            if not operator.enable_debug():
                raise SPSDKError("Cannot enable debug interface")
            yield ShadowRegisters(family=family, fuse_operator=operator)


def create_debug_probe_cfg(
    family: FamilyRevision,
    interface: Optional[str],
    serial_no: Optional[str],
    debug_probe_option: list[str],
) -> DebugProbeCfg:
    """Create DebugProbeCfg from command line options.

    :param interface: Debug probe interface type.
    :param serial_no: Serial number of debug probe.
    :param debug_probe_option: List of debug probe options in key=value format.
    :param family: Target family for setting test address.
    :return: Configured DebugProbeCfg object.
    :raises SPSDKError: If debug probe option format is invalid.
    """
    probe_user_params = {}
    for par in debug_probe_option:
        if par.count("=") != 1:
            raise SPSDKError(f"Invalid -o parameter {par}!")
        par_splitted = par.split("=")
        probe_user_params[par_splitted[0]] = par_splitted[1]

    debug_probe_cfg = DebugProbeCfg(
        interface=interface, serial_no=serial_no, debug_probe_params=probe_user_params
    )

    debug_probe_cfg.set_test_address(get_test_address(family))

    return debug_probe_cfg


@click.group(name="shadowregs", cls=CommandsTreeGroup)
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
@spsdk_family_option(
    families=get_families(DatabaseManager.SHADOW_REGS), required=False, hidden=True
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
    debug_probe_option: list[str],
    family: FamilyRevision,
) -> int:
    """NXP Shadow Registers control Tool."""
    spsdk_logger.install(level=log_level)
    if interface and interface not in PROBES:
        raise SPSDKAppError(
            f"Defined interface({interface}) is not in available interfaces: {list(PROBES.keys())}"
        )

    if not is_click_help(ctx, sys.argv) and family:
        click.secho(
            "DeprecationWarning: Option '--family' for shadowregs is deprecated. "
            "Use the family option for the specific command instead.",
            fg="red",
        )
    ctx.obj = {
        "family": family,
        "interface": interface,
        "serial_no": serial_no,
        "debug_probe_option": debug_probe_option,
    }

    return 0


# Enable / Disable debug
@main.command(
    name="saveconfig",
    no_args_is_help=True,
    hidden=True,
    deprecated="Use 'get-config' command instead",
)
@spsdk_output_option()
@click.option(
    "-d",
    "--save-diff",
    is_flag=True,
    default=False,
    help="Save differences comparing to defaults",
)
@click.option(
    "-ia",
    "--ignore-access-rights",
    is_flag=True,
    default=False,
    help="Force reading shadow registers even when access rights are set to WO (Write-Only) or Reserved.",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def save_config(
    pass_obj: dict,
    output: str,
    save_diff: bool,
    ignore_access_rights: bool,
    family: Optional[FamilyRevision],
) -> None:
    """Save current state of shadow registers to YAML file."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    get_config_command(family, debug_probe_cfg, save_diff, ignore_access_rights, output)


@main.command(name="get-config", no_args_is_help=True)
@spsdk_output_option()
@click.option(
    "-do",
    "--diff-only",
    is_flag=True,
    default=False,
    help="Save differences compared to default values.",
)
@click.option(
    "-ia",
    "--ignore-access-rights",
    is_flag=True,
    default=False,
    help="Force reading shadow registers even when access rights are set to WO (Write-Only) or Reserved.",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def get_config(
    pass_obj: dict,
    output: str,
    diff_only: bool,
    ignore_access_rights: bool,
    family: Optional[FamilyRevision],
) -> None:
    """Save current state of shadow registers to YAML file."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    get_config_command(family, debug_probe_cfg, diff_only, ignore_access_rights, output)


def get_config_command(
    family: FamilyRevision,
    debug_probe_cfg: DebugProbeCfg,
    diff_only: bool,
    ignore_access_rights: bool,
    output: str,
) -> None:
    """Read shadow registers from device and save configuration to YAML file.

    This function connects to the target device via debug probe, reads all shadow
    registers, and saves their current state to a YAML configuration file. It can
    optionally save only the differences from default values.

    :param family: Target MCU family and revision information.
    :param debug_probe_cfg: Debug probe configuration for device connection.
    :param diff_only: If True, save only registers that differ from default values.
    :param ignore_access_rights: Force reading registers even when access rights
        are set to WO (Write-Only) or Reserved.
    :param output: Path to the output YAML configuration file.
    :raises SPSDKAppError: When reading shadow registers fails.
    """
    with _open_shadow_registers(family, debug_probe_cfg) as shadow_regs:
        with progress_bar(label="Reading shadow registers") as progress_callback:
            try:
                shadow_regs.read_all(
                    force=ignore_access_rights, progress_callback=progress_callback
                )
            except SPSDKFuseOperationFailure as e:
                click.echo(f"{e}. Check debug logs for details.")
            except SPSDKError as exc:
                raise SPSDKAppError(f"Reading the shadow registers failed: ({str(exc)})") from exc
        write_file(shadow_regs.get_config_yaml(diff=diff_only), output)
        click.echo(f"The shadow registers configuration has been saved into {output}")


@main.command(
    name="loadconfig", no_args_is_help=True, hidden=True, deprecated="Use 'write' command instead"
)
@spsdk_config_option(klass=ShadowRegisters)
@click.option(
    "--verify/--no-verify",
    is_flag=True,
    default=True,
    help="Verify write operation (verify by default)",
)
@click.pass_obj
def load_config(pass_obj: dict, config: Config, verify: bool) -> None:
    """Load new state of shadow registers from YAML file into micro controller."""
    family = FamilyRevision.load_from_config(config)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    write_command(family, debug_probe_cfg, config, verify)


@main.command(name="write", no_args_is_help=True)
@spsdk_config_option(klass=ShadowRegisters)
@click.option(
    "--verify/--no-verify",
    is_flag=True,
    default=True,
    help="Verify write operation (verify by default)",
)
@click.pass_obj
def write(pass_obj: dict, config: Config, verify: bool) -> None:
    """Write shadow registers from configuration into device."""
    family = FamilyRevision.load_from_config(config)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    write_command(family, debug_probe_cfg, config, verify)


def write_command(
    family: FamilyRevision, debug_probe_cfg: DebugProbeCfg, config: Config, verify: bool
) -> None:
    """Write shadow registers from configuration file to device.

    This function connects to the target device via debug probe and writes shadow
    register values from the provided configuration to the device. It validates
    the configuration and reports any errors during the write operation.

    :param family: Target MCU family and revision information.
    :param debug_probe_cfg: Debug probe configuration for device connection.
    :param config: Configuration object containing shadow register values to write.
    :param verify: Verify write operation after setting each register.
    :raises SPSDKAppError: When writing shadow registers fails or configuration is invalid.
    """
    with _open_debug_probe(debug_probe_cfg) as debug_probe:
        operator = ShadowregsOperator(family=family, probe=debug_probe)
        shadow_regs = ShadowRegisters.load_from_config(config, operator)
        try:
            shadow_regs.write_loaded(verify)
        except SPSDKError as e:
            click.echo(f"{colorama.Fore.RED}Error: {e}{colorama.Fore.RESET}")
            raise SPSDKAppError(str(e)) from e
        click.echo(
            f"The shadow registers has been loaded from configuration in {config.config_name} YAML file"
        )


@main.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def get_template(pass_obj: dict, output: str, family: Optional[FamilyRevision]) -> None:
    """Generate the template of Shadow registers YAML configuration file."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    template = ShadowRegisters.get_config_template(family)
    write_file(template, output, encoding="utf-8")
    click.echo(
        f"The Shadow registers template for {family} has been saved into "
        f"{get_printable_path(output)} YAML file"
    )


@main.command(
    name="printregs", no_args_is_help=False, hidden=True, deprecated="Use 'print' command instead"
)
@click.option(
    "-r",
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def print_regs(pass_obj: dict, rich: bool, family: Optional[FamilyRevision]) -> None:
    """Print all Shadow registers including theirs current values.

    In case of needed more information, there is also provided rich format of print.
    """
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    print_registers_command(family, debug_probe_cfg, None, rich, True)


@main.command(
    name="getreg", no_args_is_help=True, hidden=True, deprecated="Use 'print' command instead"
)
@click.option("-r", "--reg", type=str, required=True, help="The name of register to be read.")
@click.option(
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def get_reg(pass_obj: dict, reg: str, rich: bool, family: Optional[FamilyRevision]) -> None:
    """The command prints the current value of one shadow register."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    print_registers_command(family, debug_probe_cfg, reg, rich, True)


@main.command(name="print")
@click.option(
    "-n",
    "--name",
    help="Shadow register name/uid/otp_index to be printed.",
)
@click.option(
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@click.option(
    "-ia",
    "--ignore-access-rights",
    is_flag=True,
    default=False,
    help="Force reading shadow register even when access rights are set to WO (Write-Only).",
)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def print_registers(
    pass_obj: dict,
    name: Optional[str],
    rich: bool,
    ignore_access_rights: bool,
    family: Optional[FamilyRevision],
) -> None:
    """Print the current state of shadow registers from device."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    print_registers_command(family, debug_probe_cfg, name, rich, ignore_access_rights)


def print_registers_command(
    family: FamilyRevision,
    debug_probe_cfg: DebugProbeCfg,
    name: Optional[str],
    rich: bool,
    ignore_access_rights: bool,
) -> None:
    """Print shadow register values from device to console.

    This function connects to the target device via debug probe and reads shadow
    register values. It can print either a single register or all registers,
    with optional rich formatting for enhanced output display.

    :param family: Target MCU family and revision information.
    :param debug_probe_cfg: Debug probe configuration for device connection.
    :param name: Optional shadow register name/uid/otp_index to print. If None,
        all registers are printed.
    :param rich: Enable rich format for enhanced output display with additional details.
    :param ignore_access_rights: Force reading registers even when access rights
        are set to WO (Write-Only) or Reserved.
    """
    error_count = 0
    with _open_shadow_registers(family, debug_probe_cfg) as shadow_regs:
        if name:
            shadow_regs.read_single(name, force=ignore_access_rights)
            reg = shadow_regs.registers.find_reg(name, include_group_regs=True)
            print_register_info(reg, rich, click.echo)
        else:
            for reg in shadow_regs:
                try:
                    shadow_regs.read_single(reg.uid, force=ignore_access_rights)
                    print_register_info(reg, rich, click.echo)
                    click.echo()
                except SPSDKFuseOperationFailure as e:
                    logger.debug(
                        f"Permission error, unable to read shadow register {reg.name}: {str(e)}"
                    )
                    error_count += 1
                except SPSDKError as e:
                    logger.debug(
                        f"Error occurred, unable to read the shadow register {reg.name}: {str(e)}"
                    )
                    error_count += 1

            if error_count > 0:
                click.echo(
                    f"Warning: {error_count} shadow register(s) could not be read. Check debug logs for details."
                )


@main.command(
    name="setreg", no_args_is_help=True, hidden=True, deprecated="Use 'write' command instead"
)
@click.option(
    "-r", "--reg", "reg_name", type=str, required=True, help="The name of register to be set."
)
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
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def set_reg(
    pass_obj: dict,
    reg_name: str,
    reg_val: str,
    verify: bool,
    raw: bool,
    family: Optional[FamilyRevision],
) -> None:
    """The command sets a value of one shadow register defined by parameter."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    write_single_command(family, debug_probe_cfg, reg_name, reg_val, raw, verify)


@main.command(name="write-single", no_args_is_help=True)
@click.option(
    "-n",
    "--name",
    type=str,
    required=True,
    help="Shadow register name/uid/otp_index to be written.",
)
@click.option(
    "-v", "--value", type=str, required=True, help="The new value of shadow register in hex format."
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
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def write_single(
    pass_obj: dict, name: str, value: str, verify: bool, raw: bool, family: Optional[FamilyRevision]
) -> None:
    """Write single shadow register into device."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    write_single_command(family, debug_probe_cfg, name, value, raw, verify)


def write_single_command(
    family: FamilyRevision,
    debug_probe_cfg: DebugProbeCfg,
    name: str,
    value: str,
    raw: bool,
    verify: bool,
) -> None:
    """Write a single shadow register value to device.

    This function connects to the target device via debug probe and writes a
    specified value to a single shadow register. The register can be identified
    by name, UID, or OTP index. The value can be written as raw or computed
    (with modification hooks applied).

    :param family: Target MCU family and revision information.
    :param debug_probe_cfg: Debug probe configuration for device connection.
    :param name: Shadow register name/uid/otp_index to write.
    :param value: The value to write to the shadow register in hex format.
    :param raw: If True, write raw value; if False, apply modification hooks.
    :param verify: Verify the write operation after writing the register.
    """
    with _open_shadow_registers(family, debug_probe_cfg) as shadow_regs:
        try:
            otp_index = value_to_int(name)  # name is otp index
            name = shadow_regs.registers.get_by_otp_index(otp_index).uid
        except SPSDKError:
            pass
        shadow_regs.set_value(name, value, raw=raw)
        shadow_regs.write_single(name, verify=verify)
    click.echo(f"The Shadow register {name} has been set to {value} value")


@main.command(no_args_is_help=False)
@spsdk_family_option(families=get_families(DatabaseManager.SHADOW_REGS), required=False)
@click.pass_obj
def reset(pass_obj: dict, family: Optional[FamilyRevision]) -> None:
    """The command resets connected device."""
    family = pass_obj["family"] or family
    if not family:
        raise SPSDKAppError(MISSING_FAMILY_ERROR_MSG)
    debug_probe_cfg = create_debug_probe_cfg(
        interface=pass_obj["interface"],
        serial_no=pass_obj["serial_no"],
        debug_probe_option=pass_obj["debug_probe_option"],
        family=family,
    )
    with _open_debug_probe(debug_probe_cfg) as probe:
        db = get_db(family)
        reset_type = db.get_str(DatabaseManager.SHADOW_REGS, "reset_type")
        if reset_type == "nvic_reset":
            # Do a NVIC system reset
            nvic_reset = db.get_dict(DatabaseManager.SHADOW_REGS, "nvic_reset")
            address = nvic_reset.get("address")
            value = nvic_reset.get("value")
            if not address or not value:
                raise SPSDKError(f"The NVIC reset configuration missing for device {family}")
            logger.debug(f"Writing register address: {address}, data: {value}")
            probe.mem_reg_write(addr=address, data=value)
        else:
            probe.reset()
    click.echo("The target has been reset.")


@main.command(name="fuses-script", no_args_is_help=True)
@spsdk_config_option(klass=ShadowRegisters)
@spsdk_output_option()
@click.pass_obj
def fuses_script(pass_obj: dict, config: Config, output: str) -> None:
    """The command generate BLHOST script to burn up fuses in device by configuration."""
    shadow_regs = ShadowRegisters.load_from_config(config)
    write_file(
        shadow_regs.create_fuse_blhost_script(list(config.get_dict("registers").keys())),
        output,
    )
    click.echo(f"BLHOST script to burn fuses has been generated: {output}")


@catch_spsdk_error
def safe_main() -> None:
    """Safe main method."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

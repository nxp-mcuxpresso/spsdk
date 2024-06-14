#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI application to manage external memory configuration."""

import logging
import os
import sys
from typing import Any, Dict, List, Optional

import click
import colorama
import prettytable
from click_option_group import AllOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.memcfg.memcfg import MemoryConfig
from spsdk.utils.misc import load_configuration, write_file
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)


@click.group(name="nxpmemcfg", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """Collection of utilities for memory configuration operations."""
    spsdk_logger.install(level=log_level)


@main.command(name="family-info", no_args_is_help=False)
@spsdk_family_option(MemoryConfig.get_supported_families(), required=False)
@click.option(
    "-p",
    "--peripheral",
    type=click.Choice(MemoryConfig.PERIPHERALS, case_sensitive=False),
    required=False,
    help="Restrict results just for this one peripheral, if used.",
)
def family_info(family: str, peripheral: Optional[str] = None) -> None:
    """List known memory configurations for the family."""

    def _get_instance_val(val: List[int]) -> str:
        if val:
            if len(val) == 1 and val[0] == 0:
                return colorama.Fore.BLUE + "Yes" + colorama.Style.RESET_ALL
            return colorama.Fore.BLUE + str(val) + colorama.Style.RESET_ALL
        return colorama.Fore.RED + "N/A" + colorama.Style.RESET_ALL

    families = [family] if family else MemoryConfig.get_supported_families()
    peripherals = [peripheral] if peripheral else MemoryConfig.PERIPHERALS

    # ####### Print all peripheral information ##############
    click.echo("List of all supported peripherals and its instances:")
    table_p_header = ["#", "Family"]
    table_p_header.extend(peripherals)
    table_p = prettytable.PrettyTable(table_p_header)
    table_p.set_style(prettytable.DOUBLE_BORDER)
    for i, f in enumerate(families):
        row = [
            colorama.Fore.YELLOW + str(i) + colorama.Style.RESET_ALL,
            colorama.Fore.GREEN + f + colorama.Style.RESET_ALL,
        ]
        for p in peripherals:
            row.append(_get_instance_val(MemoryConfig.get_peripheral_instances(f, p)))
        table_p.add_row(row)
    click.echo(table_p)

    # ####### Print out known Option words if any ##############
    known_option_words = (
        MemoryConfig.get_known_option_words(family=family, peripheral=peripheral)
        if family
        else MemoryConfig.get_all_known_option_words(peripheral)
    )
    if known_option_words:
        click.echo("List of all known memory configuration option words:")
        table_ow = prettytable.PrettyTable(
            ["#", "Peripheral", "Manufacturer", "Name", "Interface", "Option words"]
        )
        table_ow.set_style(prettytable.DOUBLE_BORDER)
        table_ow.align["Option words"] = "l"
        i = 0
        for p, man_dict in known_option_words.items():
            for manufacturer, chips_dict in man_dict.items():
                for chip_name, mem_type_dict in chips_dict.items():
                    for mem_type, option_words in mem_type_dict.items():
                        option_words_pretty = f"Opt0: 0x{option_words[0]:08X}"
                        for ow_i, ow in enumerate(option_words[1:]):
                            option_words_pretty += f", Opt{ow_i+1}: 0x{ow:08X}"
                        table_ow.add_row(
                            [
                                colorama.Fore.YELLOW + str(i) + colorama.Style.RESET_ALL,
                                colorama.Fore.GREEN + p + colorama.Style.RESET_ALL,
                                colorama.Fore.WHITE + manufacturer + colorama.Style.RESET_ALL,
                                colorama.Fore.WHITE + chip_name + colorama.Style.RESET_ALL,
                                colorama.Fore.CYAN + mem_type + colorama.Style.RESET_ALL,
                                colorama.Fore.BLUE + option_words_pretty + colorama.Style.RESET_ALL,
                            ]
                        )
                        i += 1
            table_ow._dividers[-1] = True

        click.echo(table_ow)
        click.echo(colorama.Style.RESET_ALL)


@main.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=MemoryConfig.get_supported_families())
@optgroup("Known chip select", cls=AllOptionGroup)
@optgroup.option(
    "-m",
    "--memory-chip",
    type=str,
    help="Select supported memory chip name. Use family-info command to get the known names.",
)
@optgroup.option(
    "-i",
    "--interface",
    type=str,
    help="Select supported memory chip interface. Use family-info command to get the known interfaces.",
)
@optgroup(
    "General option words definition. It could be defined instead of known chip", cls=AllOptionGroup
)
@optgroup.option(
    "-p",
    "--peripheral",
    type=click.Choice(MemoryConfig.PERIPHERALS, case_sensitive=False),
    help="Choose the peripheral of the input option words",
)
@optgroup.option(
    "-w",
    "--option-word",
    type=INT(),
    multiple=True,
    help="Define one or more memory configuration option words to be parsed.",
)
@spsdk_output_option(force=True)
def parse_command(
    family: str,
    memory_chip: Optional[str],
    interface: Optional[str],
    peripheral: Optional[str],
    option_word: Optional[List[int]],
    output: str,
) -> None:
    """Parse the existing memory configuration option words."""
    write_file(
        parse(
            family=family,
            peripheral=peripheral,
            memory_chip=memory_chip,
            interface=interface,
            option_word=option_word,
        ).get_yaml(),
        output,
    )
    click.echo(f"Parsed option words has been stored: {os.path.abspath(output)}")


def parse(
    family: str,
    memory_chip: Optional[str],
    interface: Optional[str],
    peripheral: Optional[str],
    option_word: Optional[List[int]],
) -> MemoryConfig:
    """Parse the existing memory configuration option words.

    :param family: Chip family.
    :param memory_chip: If defined, it is used to get know
        configuration to parse
    :param interface: Chip communication interface
    :param peripheral: Peripheral name in case that the option words are used
    :param option_word: If the memory chip is not used this option
        word must be used to parse customized Option words.
    :returns: Generated memory configuration class
    """
    if memory_chip and interface:
        peripheral = MemoryConfig.get_known_chip_peripheral(memory_chip)
        click.echo(f"Detected peripheral {peripheral} for {memory_chip}")
        option_words = MemoryConfig.get_known_chip_option_words(
            peripheral=peripheral, chip_name=memory_chip, interface=interface
        )
        click.echo(f"Loaded option words: {MemoryConfig.get_option_words_string(option_words)}")
    elif option_word:
        option_words = option_word
    else:
        raise SPSDKAppError(
            "Invalid specification of option words. "
            "Neither chip name & interface, neither option words are defined."
        )
    assert peripheral
    memcfg = MemoryConfig.parse(
        data=MemoryConfig.option_words_to_bytes(option_words),
        family=family,
        peripheral=peripheral,
        interface=interface,
    )
    return memcfg


@main.command(name="export", no_args_is_help=True)
@spsdk_config_option(help="Option word configuration YAML file")
def export_command(
    config: str,
) -> None:
    """Export the configuration option words from configuration."""
    memcfg = export(config=load_configuration(config))
    assert memcfg.option_words
    click.echo(
        f"Exported config options: {MemoryConfig.get_option_words_string(memcfg.option_words)}"
    )


def export(config: Dict[str, Any]) -> MemoryConfig:
    """Export the configuration option words from configuration.

    :param config: Memory Configuration dictionary.
    """
    # Validate base items in config
    check_config(config, MemoryConfig.get_validation_schemas_base())
    memcfg = MemoryConfig(family=config["family"], peripheral=config["peripheral"])
    check_config(config, memcfg.get_validation_schemas(config["peripheral"]))

    memcfg = MemoryConfig.load_config(config)
    logger.info(f"Family:     {memcfg.family}")
    logger.info(f"Revision:   {memcfg.revision}")
    logger.info(f"Peripheral: {memcfg.peripheral}")
    logger.info(f"Interface:  {memcfg.interface}")
    return memcfg


@main.command(name="blhost-script", no_args_is_help=True)
@optgroup(
    "Known chip select. Alternative to known chip is YAML configuration '-c'", cls=AllOptionGroup
)
@optgroup.option(
    "-f",
    "--family",
    type=click.Choice(choices=MemoryConfig.get_supported_families(), case_sensitive=False),
    help="Select the chip family.",
)
@optgroup.option(
    "-m",
    "--memory-chip",
    type=str,
    help="Select supported memory chip name. Use family-info command to get the known names.",
)
@optgroup.option(
    "-i",
    "--interface",
    type=str,
    help="Select supported memory chip interface. Use family-info command to get the known interfaces.",
)
@spsdk_config_option(
    required=False,
    help="Option word configuration YAML file, in case that known chip has not been used",
)
@click.option("-ix", "--instance", type=INT(), help="Instance of peripheral if applicable")
@click.option(
    "--fcb",
    type=click.Path(resolve_path=False),
    help=(
        "Optional filename of FCB block generated by HW and read back to PC. "
        "Be aware that script will contain also erase of 4KB on base address."
    ),
)
@spsdk_output_option(
    required=False,
    force=True,
    help="Name of BLHOST script. If not specified, the script will be printed to command line",
)
def blhost_script_command(
    config: Optional[str],
    family: Optional[str],
    memory_chip: Optional[str],
    interface: Optional[str],
    instance: Optional[int],
    fcb: Optional[str],
    output: Optional[str],
) -> None:
    """Export the configuration option words to blhost script."""
    if config and family and memory_chip and interface:
        click.echo(
            "Because configuration is defined by YAML config file, family/memory-chip/interface settings are omitted."
        )

    if not config:
        if not (family and memory_chip and interface):
            raise SPSDKAppError(
                "Config file or family/memory-chip/interface settings must be defined."
            )
        memcfg = parse(
            family=family,
            memory_chip=memory_chip,
            interface=interface,
            peripheral=None,
            option_word=None,
        )
    else:
        memcfg = export(load_configuration(config))

    script = memcfg.create_blhost_batch_config(instance=instance, fcb_output_name=fcb)

    click.echo("Exported blhost script.")
    if output:
        write_file(script, output)
    else:
        click.echo(script)


@main.command(name="get-templates", no_args_is_help=True)
@spsdk_family_option(families=MemoryConfig.get_supported_families())
@spsdk_output_option(directory=True, force=True)
def get_templates_command(family: str, output: str) -> None:
    """Create template of Memory option words in YAML format."""
    get_templates(family, output)


def get_templates(family: str, output: str) -> None:
    """Create template of Memory option words in YAML format."""
    for peripheral in MemoryConfig.get_supported_peripherals(family):
        memcfg = MemoryConfig(family=family, peripheral=peripheral)
        schemas = memcfg.get_validation_schemas(peripheral)
        yaml_data = CommentedConfig(
            main_title=f"Option Words Configuration template for {family}, {peripheral}.",
            schemas=schemas,
            note="Note for settings:\n" + Registers.TEMPLATE_NOTE,
        ).get_template()

        full_file_name = os.path.join(output, f"ow_{peripheral}.yaml")
        click.echo(f"Creating {full_file_name} template file.")
        write_file(yaml_data, full_file_name)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

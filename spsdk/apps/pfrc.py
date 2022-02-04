#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfrc (Utility to search for brick-conditions in PFR settings)."""
import logging
import os
import sys
from typing import Any, Dict, List

import click

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import catch_spsdk_error, load_configuration
from spsdk.pfr import PFR_DATA_FOLDER, Processor, Translator
from spsdk.pfr.pfr import PfrConfiguration

PFRC_DATA_FOLDER = os.path.join(PFR_DATA_FOLDER, "pfrc")
DATABASE_FILE = os.path.join(PFRC_DATA_FOLDER, "database.yaml")

SUPPORTED_FAMILIES = list(load_configuration(DATABASE_FILE).keys())


def load_rules(family: str, additional_rules_file: click.Path = None) -> List[Dict[str, str]]:
    """The function loads the rules for family and optionally add additional rules from user.

    :param family: Chip family
    :param additional_rules_file: Additional rules file, defaults to None
    :return: Loaded rules in list of dictionaries.
    """
    rules: List[Dict[str, str]] = []
    database = load_configuration(DATABASE_FILE)
    assert family in database.keys()
    rules_files = database[family]["rules"]
    for rules_file in rules_files:
        rules.extend(load_configuration(os.path.join(PFRC_DATA_FOLDER, rules_file)))

    if additional_rules_file:
        rules.extend(load_configuration(additional_rules_file))

    return rules


@click.command(no_args_is_help=True)
@click.option(
    "-m",
    "--cmpa-config",
    required=True,
    type=click.Path(exists=True),
    help="Path to CMPA config json file",
)
@click.option(
    "-f",
    "--cfpa-config",
    required=True,
    type=click.Path(exists=True),
    help="Path to CFPA config json file",
)
@click.option(
    "-r",
    "--rules-file",
    required=False,
    type=click.Path(exists=True),
    help="Custom additional file containing checker rules",
)
@click.option("-d", "--debug", is_flag=True, default=False, help="Enable debugging output")
@click.version_option(spsdk_version, "--version")
def main(
    cmpa_config: click.Path,
    cfpa_config: click.Path,
    rules_file: click.Path,
    debug: bool,
) -> None:
    """Utility to search for brick-conditions in PFR settings."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)

    cmpa_prf_cfg = PfrConfiguration(cmpa_config)
    cfpa_prf_cfg = PfrConfiguration(cfpa_config)
    if cmpa_prf_cfg.device != cfpa_prf_cfg.device:
        click.echo(
            "Error: CMPA has different chip family than CFPA configuration."
            f" {cmpa_prf_cfg.device}!={cfpa_prf_cfg.device}"
        )
        click.get_current_context().exit(3)
    chip_family = cmpa_prf_cfg.device

    if chip_family not in SUPPORTED_FAMILIES:
        click.echo(
            "Error: chip family from configuration is not supported. "
            f"{chip_family} is not in supported families:{SUPPORTED_FAMILIES}"
        )
        click.get_current_context().exit(3)

    assert chip_family
    rules = load_rules(chip_family, rules_file)

    translator = Translator(cmpa=cmpa_prf_cfg, cfpa=cfpa_prf_cfg)
    processor = Processor(translator=translator)

    valid = True
    try:
        for rule in rules:
            click.echo(f"Requirement: {rule['req_id']}")
            click.echo(f"{rule['desc']}...")
            result, condition = processor.process(rule["cond"])
            click.echo(f"Brick condition: {rule['cond']}")
            click.echo(condition)
            click.echo(
                f"FAIL: you are going to brick your device\n{rule['msg']}"
                if result
                else "OK: Brick condition not fulfilled"
            )
            if result:
                valid = False
            click.echo("-" * 40)

    except SyntaxError as e:
        click.echo(f"\nERROR: Unable to parse: '{e}'")
        click.get_current_context().exit(2)
    except (KeyError, ValueError, TypeError) as e:
        click.echo(f"\nERROR: Unable to lookup identifier: {e}")
        click.get_current_context().exit(2)
    except Exception as e:  # pylint: disable=broad-except
        click.echo(f"Error e({e}) while evaluating {rule['cond']}")
        click.get_current_context().exit(2)

    click.get_current_context().exit(0 if valid else 1)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

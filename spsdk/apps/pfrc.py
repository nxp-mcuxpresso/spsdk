#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfrc (Utility to search for brick-conditions in PFR settings)."""
import json
import logging
import os
import sys

import click

from spsdk.pfr.pfr import PfrConfiguration
from spsdk.apps.utils import catch_spsdk_error
from spsdk.pfr import Translator, Processor, PFR_DATA_FOLDER


RULES_FILE = os.path.join(PFR_DATA_FOLDER, 'rules.json')


@click.command()
@click.option('-m', '--cmpa-config', required=True, type=click.Path(),
              help='Path to CMPA config json file')
@click.option('-f', '--cfpa-config', required=True, type=click.Path(),
              help='Path to CFPA config json file')
@click.option('-r', '--rules-file', required=False, type=click.File('r'),
              default=RULES_FILE, help='Custom file containing checker rules')
@click.option('-d', '--debug', is_flag=True, default=False, help='Enable debugging output')
def main(cmpa_config: click.Path, cfpa_config: click.Path, rules_file: click.File, debug: bool) -> None:
    """Utility to search for brick-conditions in PFR settings."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)

    cmpa_prf_cfg = PfrConfiguration(str(cmpa_config))
    cfpa_prf_cfg = PfrConfiguration(str(cfpa_config))
    rules = json.load(rules_file)  # type: ignore

    translator = Translator(cmpa=cmpa_prf_cfg, cfpa=cfpa_prf_cfg)
    processor = Processor(translator=translator)

    for rule in rules:
        try:
            click.echo("Requirement: {}".format(rule["req_id"]))
            click.echo(f"{rule['desc']}...")
            result, condition = processor.process(rule['cond'])
            click.echo(f"Brick condition: {rule['cond']}")
            click.echo(condition)
            click.echo(f"FAIL: you are going to brick your device\n{rule['msg']}" if result \
                else "OK: Brick condition not fulfilled")
        except SyntaxError as e:
            click.echo(f"\nERROR: Unable to parse: '{e}'")
        except (KeyError, ValueError, TypeError) as e:
            click.echo(f"\nERROR: Unable to lookup identifier: {e}")
        except Exception as e: # pylint: disable=broad-except
            click.echo(f"Error e({e}) while evaluating {rule['cond']}")
        click.echo("-" * 40)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover

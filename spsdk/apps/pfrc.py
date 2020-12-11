#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for MBoot module aka BLHost."""
import json
import logging
import os
import sys

import click

from spsdk.apps.utils import catch_spsdk_error
from spsdk.pfr import Translator, Processor, PFR_DATA_FOLDER


RULES_FILE = os.path.join(PFR_DATA_FOLDER, 'rules.json')


@click.command()
@click.option('-m', '--cmpa-config', required=True, type=click.File('r'),
              help='Path to CMPA config json file')
@click.option('-f', '--cfpa-config', required=True, type=click.File('r'),
              help='Path to CFPA config json file')
@click.option('-r', '--rules-file', required=False, type=click.File('r'),
              default=RULES_FILE, help='Custom file containing checker rules')
@click.option('-d', '--debug', is_flag=True, default=False, help='Enable debugging output')
def main(cmpa_config: click.File, cfpa_config: click.File, rules_file: click.File, debug: bool) -> None:
    """Utility to search for brick-conditions in PFR settings."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)

    cmpa_data = json.load(cmpa_config)  # type: ignore
    cfpa_data = json.load(cfpa_config)  # type: ignore
    rules = json.load(rules_file)  # type: ignore

    translator = Translator(cmpa_data=cmpa_data, cfpa_data=cfpa_data)
    processor = Processor(translator=translator)

    for rule in rules:
        try:
            print("Requirement: {}".format(rule["req_id"]))
            print(f"{rule['desc']}...")
            result, cond = processor.process(rule['cond'])
            print(f"Brick condition: {rule['cond']}")
            print(cond)
            print(f"FAIL: you are going to brick your device\n{rule['msg']}" if result \
                else "OK: Brick condition not fulfilled")
        except SyntaxError as e:
            print(f"\nERROR: Unable to parse: '{e}'")
        except (KeyError, ValueError, TypeError) as e:
            print(f"\nERROR: Unable to lookup identifier: {e}")
        except Exception as e:
            print(f"Error e({e}) while evaluating {rule['cond']}")
        print("-" * 40)


@catch_spsdk_error
def safe_main() -> int:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example demonstrates how to create TZM and PFR (IFR).

- TZM - TrustZone
- PFR - Protected Flash Region (divided into CMPA and CFPA regions)
"""

import json
import os

from spsdk.image import TrustZone
from spsdk.pfr import CFPA
from spsdk.pfr.pfr import PfrConfiguration
from spsdk.utils.misc import load_configuration

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(THIS_DIR, "data")
CFPA_TEST_FILE = os.path.join(DATA_DIR, "cfpa_lpc55s6x_test.yaml")


def generate_trustzone() -> None:
    """Generate custom trustzone presets.

    For this example we have only few settings in configuration file.
    The full set is available in `spsdk/data/tz_presets` folder
    """
    supported_families = TrustZone().get_families()
    print("Supported families:")
    print("\n".join(supported_families))

    with open(os.path.join(DATA_DIR, "lpc55xx_tz.json")) as config_file:
        config_data = json.load(config_file)

    tz_presets = TrustZone.custom(family="lpc55xx", customizations=config_data)
    tz_data = tz_presets.export()

    with open(os.path.join(THIS_DIR, "tz.bin"), "wb") as binary_file:
        binary_file.write(tz_data)


def generate_pfr() -> None:
    """Generate CFPA data.

    Alternatively, to generate data you may use the `pfr` command line utility
    After generating the data, you can upload them to the device using McuBoot.write_memory
    !!! Caution !!!
    Incorrectly configured data may lock the device from further use
    """
    config_data = PfrConfiguration(load_configuration(CFPA_TEST_FILE))
    cfpa = CFPA("lpc55s6x", revision="1b", user_config=config_data)
    cfpa_data = cfpa.export()

    with open(os.path.join(THIS_DIR, "cfpa.bin"), "wb") as binary_file:
        binary_file.write(cfpa_data)


if __name__ == "__main__":
    generate_trustzone()
    generate_pfr()

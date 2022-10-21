#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The test file for Translator API."""
import os

import pytest

from spsdk.pfr import PfrConfiguration
from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError
from spsdk.pfr.translator import Translator


def test_cfpa_translation(data_dir):
    """Test Translation of CFPA."""
    cfpa_config_path = os.path.join(data_dir, "cfpa_pfrc_lpc55s3x.yml")
    cfpa_config = PfrConfiguration(cfpa_config_path)
    translator = Translator(cfpa=cfpa_config)
    assert translator.translate("CFPA.IMG0_CMAC0") == 0


def test_cmpa_translation(data_dir):
    """Test Translation of CMPA."""
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = PfrConfiguration(cmpa_config_path)
    translator = Translator(cmpa=cmpa_config)
    assert translator.translate("CMPA.BOOT_CFG") == 0


def test_cfpa_translation_with_no_configuration():
    """Test Translation of CMPA without any configuration."""
    translator = Translator()
    with pytest.raises(
        SPSDKPfrcMissingConfigError,
        match="SPSDK: Cannot translate IMG0_CMAC0. CFPA config not defined",
    ):
        translator.translate("CFPA.IMG0_CMAC0")


def test_cmpa_translation_with_no_configuration():
    translator = Translator()
    with pytest.raises(
        SPSDKPfrcMissingConfigError,
        match="SPSDK: Cannot translate BOOT_CFG. CMPA config not defined",
    ):
        translator.translate("CMPA.BOOT_CFG")

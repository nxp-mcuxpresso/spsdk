#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK PFR Translator API test suite.

This module contains comprehensive tests for the PFR (Protected Flash Region)
Translator functionality, which handles translation between different PFR
configuration formats for NXP MCUs.
"""

import os

import pytest

from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError
from spsdk.pfr.pfr import CFPA, CMPA
from spsdk.pfr.translator import Translator
from spsdk.utils.config import Config


def test_cfpa_translation(data_dir: str) -> None:
    """Test CFPA translation functionality.

    Verifies that the Translator class can correctly translate CFPA register paths
    to their corresponding values by loading a CFPA configuration from a YAML file
    and testing the translation of a specific register path.

    :param data_dir: Directory path containing test data files including the CFPA configuration file.
    """
    cfpa_config_path = os.path.join(data_dir, "cfpa_pfrc_lpc55s3x.yml")
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    translator = Translator(cfpa=cfpa)
    assert translator.translate("CFPA.IMG0_CMAC0") == 0


def test_cmpa_translation(data_dir: str) -> None:
    """Test CMPA translation functionality.

    Verifies that the Translator class can correctly translate CMPA configuration
    paths to their corresponding values by loading a CMPA configuration from file
    and testing the translation of a specific boot configuration parameter.

    :param data_dir: Directory path containing test data files including CMPA configuration.
    :raises AssertionError: If the translation result doesn't match expected value.
    :raises SPSDKError: If CMPA configuration loading or translation fails.
    """
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    translator = Translator(cmpa=cmpa)
    assert translator.translate("CMPA.BOOT_CFG") == 0


def test_cfpa_translation_with_no_configuration() -> None:
    """Test CFPA translation behavior when no configuration is provided.

    Verifies that the Translator raises SPSDKPfrcMissingConfigError when attempting
    to translate a CFPA field without having a CFPA configuration defined.

    :raises SPSDKPfrcMissingConfigError: When CFPA config is not defined for translation.
    """
    translator = Translator()
    with pytest.raises(
        SPSDKPfrcMissingConfigError,
        match="Cannot translate IMG0_CMAC0. CFPA config not defined",
    ):
        translator.translate("CFPA.IMG0_CMAC0")


def test_cmpa_translation_with_no_configuration() -> None:
    """Test CMPA translation behavior when no configuration is provided.

    Verifies that the Translator raises SPSDKPfrcMissingConfigError when attempting
    to translate a CMPA register without having a CMPA configuration defined.

    :raises SPSDKPfrcMissingConfigError: When CMPA config is not defined for translation.
    """
    translator = Translator()
    with pytest.raises(
        SPSDKPfrcMissingConfigError,
        match="Cannot translate BOOT_CFG. CMPA config not defined",
    ):
        translator.translate("CMPA.BOOT_CFG")

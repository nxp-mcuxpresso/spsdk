#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK TrustZone image functionality tests.

This module contains comprehensive test cases for the TrustZone image
functionality in SPSDK, including configuration validation, binary
operations, and error handling.
"""

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.trustzone import TrustZone
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


@pytest.fixture(scope="module")
def sample_tz_data(data_dir: str) -> Config:
    """Load sample TrustZone configuration data for testing.

    This method loads a preset configuration file for the LPC55S6xA1 device
    from the specified data directory to create a TrustZone configuration object.

    :param data_dir: Directory path containing the test data files.
    :raises SPSDKError: If the preset file cannot be found or loaded.
    :return: Configuration object created from the preset file.
    """
    preset_file = os.path.join(data_dir, "lpc55s6xA1.yaml")
    return Config.create_from_file(preset_file)


def test_tz_types(sample_tz_data: Config) -> None:
    """Test TrustZone types and customization states.

    This test verifies that TrustZone objects behave correctly when created
    with default settings versus when loaded from configuration data. It checks
    the customization state in both scenarios.

    :param sample_tz_data: Configuration data for TrustZone setup.
    """
    # TZ is enabled by default
    tz = TrustZone(family=FamilyRevision("lpc55s69"))
    assert not tz.is_customized

    tz = TrustZone.load_from_config(sample_tz_data)
    assert tz.is_customized


def test_errors() -> None:
    """Test error handling for TrustZone initialization.

    Verifies that TrustZone constructor properly raises SPSDKError when:
    - An invalid/non-existent family name is provided
    - A valid family that doesn't support TrustZone is used

    :raises SPSDKError: When TrustZone is created with invalid family or family without TZ support.
    """
    with pytest.raises(SPSDKError):
        TrustZone(family=FamilyRevision("totally_legit_family"))
    # throw error when TZ is created for family that has NO TZ
    with pytest.raises(SPSDKError):
        TrustZone(family=FamilyRevision("lpc5506"))


def test_simplified_export() -> None:
    """Test simplified export functionality of TrustZone.

    Verifies that TrustZone can be instantiated with lpc55s69 family revision
    and successfully export its configuration without any additional parameters.

    :raises AssertionError: If the export operation fails or returns falsy value.
    """
    assert TrustZone(family=FamilyRevision("lpc55s69")).export()


# in data dir, there are example json config files and their associated binaries
# to create new datasets:
#  - create config file (as per nxpimage documentation)
#  - store both config file into data_dir
#  - insert new data set into parametrize


@pytest.mark.parametrize(
    "family,json_config,binary", [("lpc55s6x", "lpc55s6xA1.yaml", "lpc55s6xA1_tzFile.bin")]
)
def test_binary(data_dir: str, family: str, json_config: str, binary: str) -> None:
    """Test binary data generation against reference binary file.

    This test method validates that the TrustZone configuration loaded from a JSON file
    produces the same binary output as a reference binary file when exported.

    :param data_dir: Directory path containing test data files.
    :param family: Target MCU family name for the test.
    :param json_config: Filename of the JSON configuration file.
    :param binary: Filename of the reference binary file to compare against.
    :raises AssertionError: When generated binary data doesn't match reference binary.
    :raises SPSDKError: When configuration loading or TrustZone export fails.
    """
    json_config_data = Config.create_from_file(os.path.join(data_dir, json_config))
    binary_data = load_binary(os.path.join(data_dir, binary))
    my_data = TrustZone.load_from_config(json_config_data).export()
    assert my_data == binary_data


def test_tz_incorrect_config() -> None:
    """Test that TrustZone.load_from_config raises SPSDKError with incorrect configuration.

    Verifies that attempting to load TrustZone configuration from an empty
    Config object properly raises an SPSDKError exception.

    :raises SPSDKError: When loading TrustZone from invalid/empty configuration.
    """
    with pytest.raises(SPSDKError):
        TrustZone.load_from_config(config=Config({}))


def test_tz_incorrect_family() -> None:
    """Test TrustZone validation with incorrect family parameter.

    Verifies that TrustZone.get_validation_schemas() raises SPSDKError
    when called with an invalid family revision that doesn't exist
    in the supported families list.

    :raises SPSDKError: When invalid family revision is provided.
    """
    with pytest.raises(SPSDKError):
        TrustZone.get_validation_schemas(FamilyRevision("nonsense"))

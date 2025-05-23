#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.trustzone import TrustZone
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary
from spsdk.utils.family import FamilyRevision


@pytest.fixture(scope="module")
def sample_tz_data(data_dir) -> Config:
    preset_file = os.path.join(data_dir, "lpc55s6xA1.yaml")
    return Config.create_from_file(preset_file)


def test_tz_types(sample_tz_data):
    # TZ is enabled by default
    tz = TrustZone(family=FamilyRevision("lpc55s69"))
    assert tz.is_customized == False

    tz = TrustZone.load_from_config(sample_tz_data)
    assert tz.is_customized == True


def test_errors():
    with pytest.raises(SPSDKError):
        TrustZone(family=FamilyRevision("totally_legit_family"))
    # throw error when TZ is created for family that has NO TZ
    with pytest.raises(SPSDKError):
        TrustZone(family=FamilyRevision("lpc5506"))


def test_simplified_export():
    assert TrustZone(family=FamilyRevision("lpc55s69")).export()


# in data dir, there are example json config files and their associated binaries
# to create new datasets:
#  - create config file (as per nxpimage documentation)
#  - store both config file into data_dir
#  - insert new data set into parametrize


@pytest.mark.parametrize(
    "family,json_config,binary", [("lpc55s6x", "lpc55s6xA1.yaml", "lpc55s6xA1_tzFile.bin")]
)
def test_binary(data_dir, family, json_config, binary):
    json_config_data = Config.create_from_file(os.path.join(data_dir, json_config))
    binary_data = load_binary(os.path.join(data_dir, binary))
    my_data = TrustZone.load_from_config(json_config_data).export()
    assert my_data == binary_data


def test_tz_incorrect_config():
    with pytest.raises(SPSDKError):
        TrustZone.load_from_config(config={})


def test_tz_incorrect_family():
    with pytest.raises(SPSDKError):
        TrustZone.get_validation_schemas(FamilyRevision("nonsense"))

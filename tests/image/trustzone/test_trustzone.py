#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import json
import os

import pytest

from spsdk import SPSDKError
from spsdk.image import TrustZone, TrustZoneType


@pytest.fixture(scope="module")
def sample_tz_data(data_dir):
    with open(os.path.join(data_dir, "lpc55xxA1.json")) as f:
        return json.load(f)["trustZonePreset"]


def test_integrity():
    tz = TrustZone()
    for family in tz.get_families():
        for revision in tz.get_revisions(family):
            file_name = tz.config[family]["revisions"][revision]
            assert os.path.isfile(os.path.join(tz.PRESET_DIR, file_name))


def test_tz_types(sample_tz_data):
    # TZ is enabled by default
    tz = TrustZone()
    assert tz.type == TrustZoneType.ENABLED
    tz = TrustZone.enabled()
    assert tz.type == TrustZoneType.ENABLED
    tz = TrustZone.disabled()
    assert tz.type == TrustZoneType.DISABLED

    tz = TrustZone(family="lpc55xx", customizations=sample_tz_data)
    assert tz.type == TrustZoneType.CUSTOM
    tz = TrustZone(family="lpc55xx", customizations=sample_tz_data, tz_type=TrustZoneType.CUSTOM)
    assert tz.type == TrustZoneType.CUSTOM
    tz = TrustZone(family="lpc55xx", customizations=sample_tz_data, tz_type=TrustZoneType.ENABLED)
    assert tz.type == TrustZoneType.CUSTOM
    tz = TrustZone.custom(family="lpc55xx", customizations=sample_tz_data)
    assert tz.type == TrustZoneType.CUSTOM
    assert "TrustZone" in str(tz)


def test_errors(sample_tz_data):
    with pytest.raises(SPSDKError):
        TrustZone.custom(family="totaly_legit_family", customizations=sample_tz_data)
    # throw error when TZ is disabled, but tz data are present
    with pytest.raises(SPSDKError):
        TrustZone(tz_type=TrustZoneType.DISABLED, customizations=sample_tz_data)
    # throw error when TZ is set to CUSTOM but no data and no family are provided
    with pytest.raises(SPSDKError):
        TrustZone(tz_type=TrustZoneType.CUSTOM)
    # throw error when TZ is set to CUSTOM but no family is provided
    with pytest.raises(SPSDKError):
        TrustZone(tz_type=TrustZoneType.CUSTOM, customizations=sample_tz_data)
    # throw error when TZ is set to CUSTOM but no data are provided
    with pytest.raises(SPSDKError):
        TrustZone(tz_type=TrustZoneType.CUSTOM, family="lpc55xx")
    # throw error for invalid customization data
    with pytest.raises(SPSDKError):
        TrustZone(family="lpc55xx", customizations={"fake": "this is fake"})
    # throw error when TZ  type is custom and family is not set
    with pytest.raises(SPSDKError, match="Need to provide 'family' parameter"):
        TrustZone(tz_type=TrustZoneType.CUSTOM, family=None)


def test_simplified_export():
    assert TrustZone().export() == b""
    assert TrustZone.enabled().export() == b""
    assert TrustZone.disabled().export() == b""


def test_export_invalid(sample_tz_data):
    tz = TrustZone(family="lpc55xx", tz_type=TrustZoneType.CUSTOM, customizations=sample_tz_data)
    tz.presets = None
    with pytest.raises(SPSDKError, match="Preset data not present"):
        tz.export()
    tz = TrustZone(family="lpc55xx", tz_type=TrustZoneType.CUSTOM, customizations=sample_tz_data)
    tz.customs = None
    with pytest.raises(SPSDKError, match="Data not present"):
        tz.export()


# in data dir, there are example json config files for elftosb and their  associated binaries
# to create new datasets:
#  - create config file (as per elftosb documentation)
#  - store both config file into data_dir
#  - insert new data set into parametrize


@pytest.mark.parametrize(
    "family,json_config,binary", [("lpc55xx", "lpc55xxA1.json", "lpc55xxA1_tzFile.bin")]
)
def test_binary(data_dir, family, json_config, binary):
    with open(os.path.join(data_dir, json_config)) as json_config_file:
        json_config_data = json.load(json_config_file)

    with open(os.path.join(data_dir, binary), "rb") as binary_file:
        binary_data = binary_file.read()

    my_data = TrustZone(family=family, customizations=json_config_data["trustZonePreset"]).export()
    assert my_data == binary_data


def test_tz_incorrect_data(sample_tz_data):
    with pytest.raises(SPSDKError):
        TrustZone(
            family="lpc55xx",
            raw_data=bytes(4),
            tz_type=TrustZoneType.CUSTOM,
            customizations=sample_tz_data,
        )


def test_tz_incorrect_config(sample_tz_data):
    with pytest.raises(SPSDKError):
        TrustZone.from_config(config_data=bytes(4))


def test_tz_incorrect_family():
    with pytest.raises(SPSDKError):
        TrustZone.get_validation_schemas("nonsense")

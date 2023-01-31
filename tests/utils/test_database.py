#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import os

import pytest

from spsdk.exceptions import SPSDKTypeError, SPSDKValueError
from spsdk.utils.database import Database, Devices, Revisions
from spsdk.utils.misc import load_configuration


@pytest.mark.parametrize(
    "key,device,revision,default,value",
    [
        ("attr_1", "lpc55s6x", "0a", None, "revision_value"),
        ("attr_1", "lpc55s6x", "1b", None, "device_value"),
        ("attr_1", "lpc551x", "a", None, "global_value"),
        ("attr_1", None, None, None, "global_value"),
        ("attr_1", "lpc55s6x", "latest", None, "device_value"),
        ("attr_2", "lpc55s6x", "0a", "default_value", "default_value"),
        ("attr_2", "lpc55s6x", "1b", "default_value", "default_value"),
        ("attr_2", "lpc551x", "a", "default_value", "default_value"),
        ("attr_2", None, None, "default_value", "default_value"),
    ],
)
def test_get_device_value(data_dir, key, device, revision, default, value):
    db_path = os.path.join(data_dir, "database.yaml")
    database = Database(db_path)
    val = database.get_device_value(key=key, device=device, revision=revision, default=default)
    assert val == value


def test_devices_property(data_dir):
    db_path = os.path.join(data_dir, "database.yaml")
    config = load_configuration(db_path)
    database = Database(db_path)
    assert database.devices.device_names.sort() == list(config["devices"].keys()).sort()


def test_invalid_device(data_dir):
    db_path = os.path.join(data_dir, "database.yaml")
    devices = Devices.load_from_file(db_path)
    with pytest.raises(SPSDKValueError):
        devices.get_by_name("non-existing-name")


def test_invalid_revision(data_dir):
    db_path = os.path.join(data_dir, "database.yaml")
    devices = Devices.load_from_file(db_path)
    dev = devices.get_by_name("lpc55s6x")
    with pytest.raises(SPSDKValueError):
        dev.revisions.get_by_name("abcd")


def test_loading_invalid_database(data_dir):
    db_path = os.path.join(data_dir, "database_invalid.yaml")
    with pytest.raises(SPSDKTypeError):
        Database(db_path)


def test_load_devices_from_dictionary():
    devices = {
        "lpc55s6x": {
            "revisions": {"a": {"data_file": "lpc55s6x_0a.xml"}},
            "latest": "a",
            "device_alias": "alias_name",
        }
    }
    devs = Devices.load(devices=devices)
    assert len(devs) == 1
    assert devs[0].name == "lpc55s6x"
    assert devs[0].device_alias == "alias_name"
    assert devs[0].revisions[0].is_latest == True
    assert devs[0].attributes == {}


def test_load_revisions_from_dictionary():
    revisions = {"a": {"data_file": "lpc55s6x_0a.xml"}}
    rev = Revisions.load(revisions=revisions)
    assert len(rev) == 1
    assert rev[0].data_file == "lpc55s6x_0a.xml"
    assert rev[0].name == "a"
    assert rev[0].attributes == {}


def test_load_revisions_from_list():
    revisions = [{"a": {"data_file": "lpc55s6x_0a.xml"}}]
    with pytest.raises(SPSDKTypeError):
        Revisions.load(revisions=revisions)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import os
from typing import List

import pytest

from spsdk.exceptions import SPSDKValueError
from spsdk.utils import database
from spsdk.utils.database import Database, DatabaseManager, SPSDKErrorMissingDevice


class SPSDK_TestDatabase:
    """Main SPSDK database."""

    db: Database = None

    """List all SPSDK supported features"""
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"


@pytest.fixture
def mock_test_database(monkeypatch, data_dir):
    """Change the SPSDK Database"""
    SPSDK_TestDatabase.db = Database(os.path.join(data_dir, "test_db"))
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)


@pytest.mark.parametrize(
    "device,revision,feature,key,value,default",
    [
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_int1",
            1,
            None,
        ),  # Standard loaded defaults; integer
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_str1",
            "Database text",
            None,
        ),  # Standard loaded defaults; String
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_boolT",
            True,
            None,
        ),  # Standard loaded defaults; Boolean True
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_boolF",
            False,
            None,
        ),  # Standard loaded defaults; Boolean False
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_dict",
            {"dict_attribute_int": 1, "dict_attribute_str": "Dict text"},
            None,
        ),  # Standard loaded defaults; dict
        (
            "dev1",
            "rev1",
            "feature1",
            "atrribute_list",
            [1, 2, 3],
            None,
        ),  # Standard loaded defaults; list
        (
            "dev1",
            "rev1",
            "feature2",
            "atrribute_int1",
            3,
            None,
        ),  # Overloaded device value test
        (
            "dev1",
            "rev2",
            "feature2",
            "atrribute_int1",
            4,
            None,
        ),  # Overloaded device overloaded revision value test
        (
            "dev1",
            "rev1",
            "feature3",
            "atribute__int1",
            10,
            None,
        ),  # Non existing default
        (
            "dev1",
            "rev1",
            "feature3",
            "invalid",
            10,
            10,
        ),  # Non existing key with default value
        ("dev1_alias", "rev1", "feature1", "atrribute_int1", 1, None),  # Alias device loaded
        (
            "dev1_alias",
            "new_rev",
            "feature1",
            "atrribute_int1",
            1,
            None,
        ),  # Alias device new revision
    ],
)
def test_get_device_value(mock_test_database, device, revision, feature, key, value, default):
    db = database.get_db(device=device, revision=revision)
    val = db.get_value(feature=feature, key=key, default=default)
    assert val == value


@pytest.mark.parametrize(
    "feature,devices,sub_keys,invalid",
    [
        ("feature1", ["dev1", "dev1_alias", "dev2"], None, False),
        ("feature2", ["dev1", "dev1_alias", "dev2"], None, True),
        ("feature2", ["dev1", "dev1_alias"], None, False),
        ("feature3", ["dev1", "dev1_alias"], None, False),
        ("feature1", ["dev2"], ["sub_feature1"], False),
    ],
)
def test_supported_devices(mock_test_database, feature, devices: List[str], sub_keys, invalid):
    dev_list = database.get_families(feature, sub_keys)
    dev_list.sort()
    devices.sort()
    assert (dev_list == devices) != invalid


def test_invalid_device(mock_test_database):
    with pytest.raises(SPSDKErrorMissingDevice):
        database.DatabaseManager().db.devices.get("invalid")


def test_invalid_revision(mock_test_database):
    with pytest.raises(SPSDKValueError):
        database.DatabaseManager().db.devices.get("dev2").revisions.get("invalid")


def test_load_database():
    assert isinstance(DatabaseManager().db, Database)


def test_load_database_without_cache():
    database.SPSDK_CACHE_DISABLED = True
    assert isinstance(DatabaseManager().db, Database)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest
from attr import validate

from spsdk import SPSDKError
from spsdk.image import TZ_SCH_FILE
from spsdk.utils.misc import use_working_directory
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config


@pytest.mark.parametrize(
    "test_vector,result",
    [
        ({"n1": 1}, True),
        ({"n1": 1.1}, True),
        ({"n1": "1"}, True),
        ({"n1": "Hello"}, False),
        ({"s1": "Hello"}, True),
        ({"s1": 1}, False),
        ({"f1": "testfile.bin"}, True),
        ({"f1": 1}, False),
        ({"f1": "testfile1.bin"}, False),
        ({"f2": "testfile.bin"}, True),
        ({"f2": 1}, False),
        ({"f2": "testfile1.bin"}, False),
        ({"f2": ""}, True),
        ({"d1": "testdir"}, True),
        ({"d1": "testdir_invalid"}, False),
    ],
)
def test_schema_validator(tmpdir, test_vector, result):
    """Basic test of scheme validator."""
    schema = {
        "type": "object",
        "properties": {
            "n1": {"type": ["number", "string"], "format": "number"},
            "s1": {"type": "string"},
            "f1": {"type": "string", "format": "file"},
            "f2": {"type": "string", "format": "optional_file"},
            "d1": {"type": "string", "format": "dir"},
        },
    }
    # Create temporary test file
    with open(os.path.join(tmpdir, "testfile.bin"), "wb") as f:
        f.write(bytes(16))

    os.mkdir(os.path.join(tmpdir, "testdir"))

    with use_working_directory(tmpdir):
        if result:
            check_config(test_vector, [schema])
        else:
            with pytest.raises(SPSDKError):
                check_config(test_vector, [schema])


@pytest.mark.parametrize(
    "test_vector,result",
    [
        ({"n1": 1}, True),
        ({"n1": "1", "n2": "Hello"}, True),
        ({"n2": "Hello"}, False),
    ],
)
def test_schema_validator_required(test_vector, result):
    """Basic test of scheme validator."""
    schema = {
        "type": "object",
        "properties": {
            "n1": {"type": ["number", "string"], "format": "number"},
            "n2": {"type": "string"},
        },
        "required": ["n1"],
    }

    if result:
        check_config(test_vector, [schema])
    else:
        with pytest.raises(SPSDKError):
            check_config(test_vector, [schema])


def test_schema_invalid_validator():
    """Basic test of scheme validator."""
    schema = {
        "type": "object",
        "properties": {
            "n1": {"type": "invalid_type"},
        },
    }
    with pytest.raises(SPSDKError):
        check_config({}, [schema])


def _is_yaml_comment(yaml_data: str, comment: str, key: str = None) -> bool:
    """Check if this text is in comment."""
    str_lines = yaml_data.splitlines()

    for line in str_lines:
        ix = line.find(comment)
        if ix > 0 and line.find("#", 0, ix) >= 0:
            if not key or line.find(key, 0, ix) >= 0:
                return True
    return False


def test_config_template():

    schema = {
        "type": "object",
        "title": "main_title",
        "description": "main_description",
        "properties": {
            "n1": {
                "type": "bool",
                "title": "n1_title",
                "description": "n1_description",
                "template_value": "false",
            },
            "n2": {
                "type": "string",
                "title": "n2_title",
                "description": "n2_description",
                "template_value": "n2_value",
            },
            "n3": {
                "type": "string",
                "title": "n3_title",
                "description": "n3_description",
                "template_value": "n3_value",
            },
        },
        "required": ["n2"],
        "if": {"properties": {"n1": "true"}},
        "then": {"required": ["n3"]},
    }

    my_yml_template = ConfigTemplate("Super Main Title", [schema]).export_to_yaml()

    assert _is_yaml_comment(my_yml_template, "main_description")
    assert _is_yaml_comment(my_yml_template, "n1_description", "n1")
    assert _is_yaml_comment(my_yml_template, "n2_description", "n2")
    assert _is_yaml_comment(my_yml_template, "n3_description", "n3")
    assert _is_yaml_comment(my_yml_template, "[Optional]", "n1")
    assert _is_yaml_comment(my_yml_template, "[Required]", "n2")
    assert _is_yaml_comment(my_yml_template, "[Conditionally required]", "n3")


def test_validate_oneof():
    schema = {
        "type": "array",
        "items": {
            "oneOf": [
                {
                    "type": "object",
                    "required": ["object1"],
                    "properties": {"object1": {"type": "string"}},
                },
                {
                    "type": "object",
                    "required": ["object2"],
                    "properties": {"object2": {"type": "number"}},
                },
            ]
        },
    }

    test_vector = [{"object1": "Hello"}, {"object2": 123}]

    check_config(test_vector, [schema])


def test_load_schema_file():
    """Test class ValidationSchemas"""

    assert isinstance(ValidationSchemas.get_schema_file(TZ_SCH_FILE), dict)

    with pytest.raises(SPSDKError):
        ValidationSchemas.get_schema_file("total_invalid_name")

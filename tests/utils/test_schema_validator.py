#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from typing import Any, Dict, Optional

import pytest
import yaml

from spsdk import SPSDKError
from spsdk.image import TZ_SCH_FILE
from spsdk.utils.misc import use_working_directory
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas, check_config

# schema for testing commented YAML configuration
_TEST_CONFIG_SCHEMA = {
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
        "n4": {
            "type": "string",
            "title": "n4_title",
            "description": "n4_description",
            "skip_in_template": True,
        },
        "n5": {
            "type": "string",
            "title": "n5_title",
            "description": "n5_description",
            "template_value": "n5_value",
        },
        "n6": {
            "type": "string",
            "title": "n6_title",
            "description": "n6_description",
            "template_value": "n6_value",
        },
        "arr": {
            "type": "array",
            "title": "arr_title",
            "description": "arr description",
            "items": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["itm1"],
                        "properties": {
                            "itm1": {
                                "type": ["string", "number"],
                                "title": "itm1_title",
                                "description": "itm1 description",
                                "format": "number",
                                "template_value": "0x0",
                            }
                        },
                    },
                    {
                        "type": "object",
                        "required": ["itm2"],
                        "properties": {
                            "itm2": {
                                "type": ["string", "number"],
                                "title": "itm2_title",
                                "description": "itm2 description",
                                "format": "number",
                                "template_value": "0x1",
                            }
                        },
                    },
                ]
            },
        },
    },
    "required": ["n2", "arr"],
    "if": {"properties": {"n1": "true"}},
    "then": {"required": ["n3"]},
    "anyOf": [{"required": ["n5"]}, {"required": ["n6"]}],
}


# tested configuration
_TEST_CONFIG = {
    "n1": False,
    "n2": "test value #2",
    "n5": "test value",
    "arr": [{"itm1": 1}, {"itm1": 2}, {"itm2": "0x3"}],
}

# expected commented output for the tested configuration
_EXP_CONFIG_RESULT = (
    "# ===========  Super Main Title  ===========\n"
    "# ----------------------------------------------------------------------------------------------------\n"
    "#                                           == main_title ==                                          \n"
    "#                                           main_description                                          \n"
    "# ----------------------------------------------------------------------------------------------------\n"
    "n1: false  # [Optional], n1_title; n1_description\n"
    "n2: 'test value #2' # [Required], n2_title; n2_description\n"
    "n5: test value # [Conditionally required], n5_title; n5_description\n"
    "arr: # [Required], arr_title; arr description\n"
    "  - itm1: 1  # [Required], itm1_title; itm1 description\n"
    "  - itm1: 2  # [Required], itm1_title; itm1 description\n"
    "  - itm2: '0x3'  # [Required], itm2_title; itm2 description\n"
)


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
def test_schema_validator(tmpdir, test_vector, result) -> None:
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
def test_schema_validator_required(test_vector, result) -> None:
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


def test_schema_invalid_validator() -> None:
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


@pytest.mark.parametrize("override_values", [None, {"n2": "override"}])
def test_config_template(override_values: Optional[Dict[str, Any]]) -> None:
    """Test export of commented configuration template"""
    my_yml_template = CommentedConfig(
        "Super Main Title", [_TEST_CONFIG_SCHEMA], values=override_values, export_template=True
    ).export_to_yaml()

    assert _is_yaml_comment(my_yml_template, "main_description")
    assert _is_yaml_comment(my_yml_template, "n1_description", "n1")
    assert _is_yaml_comment(my_yml_template, "n2_description", "n2")
    assert _is_yaml_comment(my_yml_template, "n3_description", "n3")
    assert _is_yaml_comment(my_yml_template, "[Optional]", "n1")
    assert _is_yaml_comment(my_yml_template, "[Required]", "n2")
    assert _is_yaml_comment(my_yml_template, "[Conditionally required]", "n3")
    yaml_config = yaml.safe_load(my_yml_template)
    assert "n4" not in yaml_config
    assert _is_yaml_comment(my_yml_template, "[Conditionally required]", "n5")
    assert _is_yaml_comment(my_yml_template, "[Conditionally required]", "n6")
    assert _is_yaml_comment(my_yml_template, "[Required]", "arr")
    assert _is_yaml_comment(my_yml_template, "[Required]", "itm1")
    assert _is_yaml_comment(my_yml_template, "[Required]", "itm2")


def test_config() -> None:
    """Test export of custom commented configuration"""
    c_cfg = CommentedConfig(
        "Super Main Title", [_TEST_CONFIG_SCHEMA], _TEST_CONFIG, export_template=False
    )
    yml_cfg_str = c_cfg.export_to_yaml()

    assert yml_cfg_str == _EXP_CONFIG_RESULT


def test_validate_oneof() -> None:
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


def test_load_schema_file() -> None:
    """Test class ValidationSchemas"""

    assert isinstance(ValidationSchemas.get_schema_file(TZ_SCH_FILE), dict)

    with pytest.raises(SPSDKError):
        ValidationSchemas.get_schema_file("total_invalid_name")

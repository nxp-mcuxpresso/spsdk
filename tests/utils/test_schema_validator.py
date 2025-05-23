#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from unittest import mock
import warnings
import os

import pytest
import yaml

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import use_working_directory
from spsdk.utils.schema_validator import CommentedConfig, check_config

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
            "description": "n5_description. N5 has really long description to test wrapping text.",
            "enum": ["test value", "test value2", "test value3", "test value4"],
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
    "# =================================================  Super Main Title  =================================================\n"
    "\n"
    "# ======================================================================================================================\n"
    "#                                                    == main_title ==                                                   \n"
    "#                                                    main_description                                                   \n"
    "# ======================================================================================================================\n"
    "# -------------------------------------------===== n1_title [Optional] =====--------------------------------------------\n"
    "# Description: n1_description\n"
    "n1: false\n"
    "# -------------------------------------------===== n2_title [Required] =====--------------------------------------------\n"
    "# Description: n2_description\n"
    "n2: 'test value #2'\n"
    "# ------------------------------------===== n5_title [Conditionally required] =====-------------------------------------\n"
    "# Description: n5_description. N5 has really long description to test wrapping text.\n"
    "# Possible options: <test value, test value2, test value3, test value4>\n"
    "n5: test value\n"
    "# -------------------------------------------===== arr_title [Required] =====-------------------------------------------\n"
    "# Description: arr description\n"
    "arr:\n"
    "  -\n"
    "    # ----------------------------------------===== itm1_title [Required] =====-----------------------------------------\n"
    "    # Description: itm1 description\n"
    "    itm1: 1\n"
    "  -\n"
    "    # ----------------------------------------===== itm1_title [Required] =====-----------------------------------------\n"
    "    # Description: itm1 description\n"
    "    itm1: 2\n"
    "  -\n"
    "    # ----------------------------------------===== itm2_title [Required] =====-----------------------------------------\n"
    "    # Description: itm2 description\n"
    "    itm2: '0x3'\n"
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

    for i, line in enumerate(str_lines):
        ix = line.find(comment)
        if ix > 0 and line.find("#", 0, ix) >= 0:
            if not key:
                return True
            # Found comment, and know it must be found also the key
            for line in str_lines[i:]:
                if line.find("# ") >= 0:
                    continue
                if line.find(key + ":") >= 0:
                    return True
    return False


def test_config_template() -> None:
    """Test export of commented configuration template"""
    my_yml_template = CommentedConfig("Super Main Title", [_TEST_CONFIG_SCHEMA]).get_template()

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
    c_cfg = CommentedConfig("Super Main Title", [_TEST_CONFIG_SCHEMA])
    yml_cfg_str = c_cfg.get_config(_TEST_CONFIG)

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

    assert isinstance(get_schema_file(DatabaseManager.TZ), dict)

    with pytest.raises(SPSDKError):
        get_schema_file("total_invalid_name")


@pytest.mark.parametrize(
    "schema,config,expected_warnings",
    [
        # Basic unknown property detection
        (
            {"type": "object", "properties": {"known": {"type": "string"}}},
            {"known": "value", "unknown": "should trigger warning"},
            ["unknown"],
        ),
        # Nested properties
        (
            {
                "type": "object",
                "properties": {
                    "level1": {"type": "object", "properties": {"known": {"type": "string"}}}
                },
            },
            {"level1": {"known": "value", "unknown_nested": "should trigger warning"}},
            ["level1.unknown_nested"],
        ),
        # Arrays with objects
        (
            {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"id": {"type": "number"}, "name": {"type": "string"}},
                        },
                    }
                },
            },
            {
                "items": [
                    {"id": 1, "name": "Item 1"},
                    {"id": 2, "name": "Item 2", "extra": "unknown field"},
                    {"id": 3, "unknown_prop": "should trigger warning", "name": "Item 3"},
                ]
            },
            ["items[1].extra", "items[2].unknown_prop"],
        ),
        # Multiple unknown at root level
        (
            {
                "type": "object",
                "properties": {"name": {"type": "string"}, "age": {"type": "number"}},
            },
            {"name": "John", "age": 30, "address": "123 Main St", "phone": "555-1234"},
            ["address", "phone"],
        ),
        # Empty configuration (no warnings)
        (
            {"type": "object", "properties": {"name": {"type": "string"}}},
            {},
            [],
        ),
        # Configuration with only valid properties (no warnings)
        (
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "data": {"type": "object", "properties": {"value": {"type": "number"}}},
                },
            },
            {"name": "test", "data": {"value": 42}},
            [],
        ),
        # oneOf with unknown properties
        (
            {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "object",
                        "oneOf": [
                            {
                                "properties": {
                                    "type": {"type": "string", "enum": ["type1"]},
                                    "value1": {"type": "string"},
                                },
                            },
                            {
                                "properties": {
                                    "type": {"type": "string", "enum": ["type2"]},
                                    "value2": {"type": "number"},
                                },
                            },
                        ],
                    }
                },
            },
            {
                "data": {
                    "type": "type1",
                    "value1": "test",
                    "unknown_field": "this should trigger a warning",
                }
            },
            ["data.unknown_field"],
        ),
        (
            {
                "type": "object",
                "properties": {
                    "options": {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "required": ["a_option"],
                                    "properties": {
                                        "a_option": {"type": "string", "enum": ["A"]},
                                        "a_value": {"type": "string"},
                                        "a_extra_value": {"type": "string"},
                                    },
                                },
                                {
                                    "type": "object",
                                    "required": ["b_option"],
                                    "properties": {
                                        "b_option": {"type": "string", "enum": ["B"]},
                                        "b_value": {"type": "number"},
                                    },
                                },
                            ]
                        },
                    }
                },
            },
            {
                "options": [
                    {"a_option": "A", "a_value": "test"},
                    {"a_option": "A", "a_value": "test2", "a_extra_value": "extra_a_value"},
                    {"b_option": "B", "b_value": 42, "b_extra_value": "unknown"},
                ]
            },
            ["options[2].b_extra_value"],
        ),
    ],
)
def test_unknown_properties_warning(caplog, schema, config, expected_warnings) -> None:
    """Test that warnings are generated for unknown properties in configuration.

    :param schema: JSON schema to test against
    :param config: Configuration to check
    :param expected_warnings: Strings that should appear in warnings
    """
    caplog.set_level(logging.WARNING)
    caplog.clear()

    # Run the validation with unknown property checking enabled
    check_config(config, [schema], check_unknown_props=True)

    warning_messages = [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ]

    if not expected_warnings:
        assert len(warning_messages) == 0

        # Check for expected warnings
    for expected in expected_warnings:
        assert any(
            msg
            for msg in warning_messages
            if msg == f"Unknown property found in configuration: '{expected}'"
        ), f"Expected warning containing '{expected}' not found in: {warning_messages}"
    # when checking the unknown properties is disabled, no warnings should be generated
    caplog.clear()
    check_config(config, [schema], check_unknown_props=False)
    warning_messages = [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ]
    assert len(warning_messages) == 0


@mock.patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", True)
def test_check_unknown_properties_strict_mode():
    schema = {"type": "object", "properties": {"known": {"type": "string"}}}
    config = {"known": "value", "unknown": "should trigger warning"}
    with pytest.raises(SPSDKError) as exc:
        check_config(config, [schema], check_unknown_props=True)
    assert "Unknown property found in configuration" in str(exc.value)



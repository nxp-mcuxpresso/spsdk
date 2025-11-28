#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SB3.1 command validators test suite.

This module contains comprehensive tests for the SB3.1 command validation system,
including rule validators that ensure proper command sequencing and constraints
in Secure Binary files.
"""

from typing import cast

import pytest

from spsdk.sbfile.sb31.commands import BaseCmd, CmdErase, CmdExecute, CmdLoad
from spsdk.sbfile.sb31.commands_validator import (
    COMMAND_VALIDATORS_MAP,
    BaseRuleValidator,
    MaxOccurrencesValidator,
    MustAppearAfterValidator,
    MustFollowValidator,
    ResultType,
    SPSDKValidationError,
)


def test_command_rule_validator_base() -> None:
    """Test the base CommandRuleValidator class functionality.

    This test validates the BaseRuleValidator class methods including command class
    retrieval, command tag extraction, command name extraction, and ensures that
    the validate method raises NotImplementedError as expected for the base class.

    :raises NotImplementedError: When validate method is called on base class.
    """
    rule = {"command": "load"}
    validator = BaseRuleValidator(rule)

    # Test get_command_class method
    assert validator.get_command_class("load") == CmdLoad
    assert validator.get_command_class("execute") == CmdExecute
    assert validator.get_command_class("ERASE") == CmdErase
    assert validator.get_command_class("nonexistent") is None

    # Test get_command_tags method
    commands = [CmdLoad(address=0, data=b"test"), CmdExecute(address=0x1000)]
    tags = validator.get_command_tags(commands)
    assert len(tags) == 2
    assert tags[0] == CmdLoad.CMD_TAG
    assert tags[1] == CmdExecute.CMD_TAG

    # Test get_command_names method
    names = validator.get_command_names(commands)
    assert len(names) == 2
    assert names[0] == "CmdLoad"
    assert names[1] == "CmdExecute"

    with pytest.raises(NotImplementedError):
        validator.validate([])


def test_must_follow_validator() -> None:
    """Test the MustFollowValidator class functionality.

    This test validates the MustFollowValidator behavior with various command sequences
    and rule configurations. It tests valid sequences where commands follow the required
    order, invalid sequences that violate the rules, unknown commands that should be
    skipped, and incomplete rule configurations.
    """
    # Test with valid command sequence
    rule = {"command": "erase", "following_cmd": "load"}
    validator = MustFollowValidator(rule)

    # Valid sequence: erase followed by load
    valid_commands = [
        CmdErase(address=0, length=0x1000),
        CmdLoad(address=0, data=b"test"),
        CmdExecute(address=0x1000),
    ]
    result = validator.validate(valid_commands)
    assert result.result == ResultType.PASSED
    result.check()

    invalid_commands = [CmdErase(address=0, length=0x1000), CmdExecute(address=0x1000)]
    result = validator.validate(invalid_commands)
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="load command must follow erase command"):
        result.check()

    invalid_end_commands = [CmdLoad(address=0, data=b"test"), CmdErase(address=0, length=0x1000)]
    result = validator.validate(invalid_end_commands)
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="load command must follow erase command"):
        result.check()

    unknown_rule = {"command": "unknown", "following_cmd": "load"}
    unknown_validator = MustFollowValidator(unknown_rule)
    result = unknown_validator.validate(valid_commands)
    assert result.result == ResultType.SKIPPED

    unknown_rule2 = {"command": "erase", "following_cmd": "unknown"}
    unknown_validator2 = MustFollowValidator(unknown_rule2)
    result = unknown_validator2.validate(valid_commands)
    assert result.result == ResultType.SKIPPED

    incomplete_rule = {"command": "erase"}
    incomplete_validator = MustFollowValidator(incomplete_rule)
    result = incomplete_validator.validate(valid_commands)
    assert result.result == ResultType.SKIPPED


def test_max_occurrences_validator() -> None:
    """Test the MaxOccurrencesValidator class functionality.

    Validates that the MaxOccurrencesValidator correctly enforces command occurrence limits
    in SB3.1 command sequences. Tests include default single occurrence validation,
    custom count validation, error handling for exceeded limits, and proper handling
    of unknown commands and incomplete rules.
    """
    rule = {"command": "execute"}
    validator = MaxOccurrencesValidator(rule)

    valid_commands = [
        CmdErase(address=0, length=0x1000),
        CmdLoad(address=0, data=b"test"),
        CmdExecute(address=0x1000),
    ]
    result = validator.validate(valid_commands)
    assert result.result == ResultType.PASSED
    result.check()

    invalid_commands = [CmdExecute(address=0x1000), CmdExecute(address=0x2000)]

    result = validator.validate(cast(list[BaseCmd], invalid_commands))
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="execute command can only be used 1 time"):
        result.check()

    custom_rule = {"command": "load", "count": 2}
    custom_validator = MaxOccurrencesValidator(custom_rule)
    valid_custom_commands: list[BaseCmd] = [
        CmdLoad(address=0, data=b"test1"),
        CmdLoad(address=0x1000, data=b"test2"),
    ]
    result = validator.validate(valid_custom_commands)
    assert result.result == ResultType.PASSED
    result.check()

    invalid_custom_commands = [
        CmdLoad(address=0, data=b"test1"),
        CmdLoad(address=0x1000, data=b"test2"),
        CmdLoad(address=0x2000, data=b"test3"),
    ]
    result = custom_validator.validate(cast(list[BaseCmd], invalid_custom_commands))
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="load command can only be used 2 time"):
        result.check()

    unknown_rule = {"command": "unknown"}
    unknown_validator = MaxOccurrencesValidator(unknown_rule)
    result = unknown_validator.validate(valid_commands)
    assert result.result == ResultType.SKIPPED

    incomplete_rule = {"count": 1}
    incomplete_validator = MaxOccurrencesValidator(incomplete_rule)
    result = incomplete_validator.validate(valid_commands)
    assert result.result == ResultType.SKIPPED


def test_must_appear_after_validator() -> None:
    """Test the MustAppearAfterValidator class functionality.

    Validates command sequence ordering rules where one command must appear after another.
    Tests include valid sequences, invalid sequences, multiple command occurrences,
    unknown commands, and incomplete validation rules.
    """
    # Test with valid command sequence
    rule = {"command": "erase", "target_command": "load"}
    validator = MustAppearAfterValidator(rule)

    # Valid sequence: erase followed by load
    valid_commands = [
        CmdErase(address=0, length=0x1000),
        CmdLoad(address=0, data=b"test"),
        CmdExecute(address=0x1000),
    ]
    result = validator.validate(valid_commands)
    assert result.result == ResultType.PASSED
    result.check()

    # Valid sequence: load without erase (source command not present)
    valid_no_source_commands = [CmdLoad(address=0, data=b"test"), CmdExecute(address=0x1000)]
    result = validator.validate(valid_no_source_commands)
    assert result.result == ResultType.PASSED
    result.check()

    # Invalid sequence: load appears before erase
    invalid_commands = [
        CmdLoad(address=0, data=b"test"),
        CmdErase(address=0, length=0x1000),
        CmdExecute(address=0x1000),
    ]
    result = validator.validate(invalid_commands)
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="load command must appear after erase command"):
        result.check()

    # Test with multiple occurrences of both commands
    multiple_commands = [
        CmdErase(address=0, length=0x1000),
        CmdLoad(address=0, data=b"test1"),
        CmdErase(address=0x2000, length=0x1000),
        CmdLoad(address=0x2000, data=b"test2"),
    ]
    result = validator.validate(multiple_commands)
    assert result.result == ResultType.PASSED
    result.check()

    # Invalid with multiple occurrences - last erase followed by no load
    invalid_multiple_commands = [
        CmdErase(address=0, length=0x1000),
        CmdLoad(address=0, data=b"test1"),
        CmdLoad(address=0x1000, data=b"test2"),
        CmdErase(address=0x2000, length=0x1000),
        CmdExecute(address=0x1000),
    ]
    result = validator.validate(invalid_multiple_commands)
    assert result.result == ResultType.FAILED
    with pytest.raises(SPSDKValidationError, match="load command must appear after erase command"):
        result.check()

    # Test with unknown commands
    unknown_rule = {"command": "unknown", "target_command": "load"}
    unknown_validator = MustAppearAfterValidator(unknown_rule)
    result = unknown_validator.validate(valid_commands)
    assert result.result == ResultType.WARNING

    unknown_rule2 = {"command": "erase", "target_command": "unknown"}
    unknown_validator2 = MustAppearAfterValidator(unknown_rule2)
    result = unknown_validator2.validate(valid_commands)
    assert result.result == ResultType.WARNING

    # Test with incomplete rule
    incomplete_rule = {"command": "erase"}
    incomplete_validator = MustAppearAfterValidator(incomplete_rule)
    result = incomplete_validator.validate(valid_commands)
    assert result.result == ResultType.WARNING

    incomplete_rule2 = {"target_command": "load"}
    incomplete_validator2 = MustAppearAfterValidator(incomplete_rule2)
    result = incomplete_validator2.validate(valid_commands)
    assert result.result == ResultType.WARNING


def test_command_validators_map() -> None:
    """Test the COMMAND_VALIDATORS_MAP dictionary.

    Validates that the command validators mapping dictionary contains all expected
    validator keys and that each key maps to the correct validator class. This ensures
    the validator registry is properly configured for SB3.1 command validation.
    """
    assert "must_follow" in COMMAND_VALIDATORS_MAP
    assert "max_occurrences" in COMMAND_VALIDATORS_MAP
    assert "must_appear_after" in COMMAND_VALIDATORS_MAP

    assert COMMAND_VALIDATORS_MAP["must_follow"] == MustFollowValidator
    assert COMMAND_VALIDATORS_MAP["max_occurrences"] == MaxOccurrencesValidator
    assert COMMAND_VALIDATORS_MAP["must_appear_after"] == MustAppearAfterValidator

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for validation of commands."""

import logging
from typing import Any, Optional, Type

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, BaseCmd
from spsdk.sbfile.sb31.constants import EnumCmdTag
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class SPSDKValidationError(SPSDKError):
    """SPSDK command validation error."""


class ResultType(SpsdkEnum):
    """Validation result status."""

    PASSED = (0, "Passed")
    SKIPPED = (1, "Skipped")
    WARNING = (1, "Warning")
    FAILED = (2, "Failed")


class CommandsValidator:
    """Commands validator."""

    def __init__(self, family: FamilyRevision, command_rules: list[dict]):
        """Commands validator init."""
        self.family = family
        self.command_rules = command_rules
        self.db = get_db(family=self.family)

    def validate_commands(self, commands: list[BaseCmd]) -> None:
        """Validate commands against device-specific rules.

        :raises SPSDKError: When command validation rules are violated
        """
        if not self.family:
            return

        if not self.command_rules:
            return

        for rule in self.command_rules:
            rule_type = rule.get("type")
            if not rule_type:
                continue
            validator_class = COMMAND_VALIDATORS_MAP.get(rule_type)

            if not validator_class:
                logger.warning(f"Unknown rule type: {rule_type}")
                continue

            # Create and run the validator
            validator = validator_class(rule=rule)
            validator.validate(commands).check()


class ValidationResult:
    """Validation result object."""

    def __init__(self, rule: "BaseRuleValidator", result: ResultType, reason: Optional[str] = None):
        """Constructor for validation result.

        :param result: Result type
        :param reason: Optional reason text
        """
        self.rule = rule
        self.reason = reason
        self.result = result

    def check(self) -> None:
        """Check if the validation result indicates a pass."""
        if self.result == ResultType.FAILED:
            raise SPSDKValidationError(
                f"Validation rule '{str(self.rule)}' failed.{self.reason or ''}"
            )
        if self.result == ResultType.WARNING:
            logger.warning(
                f"Validation rule '{str(self.rule)}' finished with warning.{self.reason or ''}"
            )
        if self.result == ResultType.SKIPPED:
            logger.info(f"Validation rule '{str(self.rule)}' was skipped.{self.reason or ''}")
        if self.result == ResultType.PASSED:
            logger.info(f"Validation rule '{str(self.rule)}' passed.{self.reason or ''}")


class BaseRuleValidator:
    """Base class for command rule validators."""

    def __init__(self, rule: dict) -> None:
        """Initialize the rule validator.

        :param rule: The rule configuration dictionary
        :param commands: List of commands to validate
        :param command_map: Mapping of command names to command classes
        """
        self.rule = rule

    def __str__(self) -> str:
        """Return a string representation of the validator with its rule.

        :return: A formatted string representation
        """
        validator_name = self.__class__.__name__

        if not self.rule:
            return f"{validator_name}: No rule specified"

        formatted_items = [f"{k}={repr(v)}" for k, v in self.rule.items()]
        return f"<{validator_name}: {', '.join(formatted_items)}>"

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate the rule against the commands.

        :raises SPSDKError: When validation fails
        """
        raise NotImplementedError("Subclasses must implement validate()")

    def get_command_class(self, command_name: str) -> Optional[type[BaseCmd]]:
        """Get command class by name.

        :param command_name: Name of the command
        :return: Command class or None if not found
        """
        for cmd_name, cmd_cls in CFG_NAME_TO_CLASS.items():
            if cmd_name.lower() == command_name.lower():
                return cmd_cls
        return None

    def get_command_tags(self, commands: list[BaseCmd]) -> list[EnumCmdTag]:
        """Get list of command tags."""
        return [cmd.CMD_TAG for cmd in commands]

    def get_command_names(self, commands: list[BaseCmd]) -> list[str]:
        """Get list of command names."""
        return [cmd.__class__.__name__ for cmd in commands]


class MustFollowValidator(BaseRuleValidator):
    """Validator for 'must_follow' rule type.

    This rule means: If the prerequisite command exists, then the specified command must follow it.
    The command can be used independently if the prerequisite is not present.
    """

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate that if prerequisite exists, command must follow it.

        :param commands: List of commands to validate
        :raises SPSDKError: When validation fails
        """
        command_name: Optional[str] = self.rule.get("command")
        following_command: Optional[str] = self.rule.get("following_cmd")

        if not command_name or not following_command:
            return ValidationResult(
                self,
                ResultType.WARNING,
                "Incomplete must_follow_rule validation rule. "
                f"Missing {'command' if not command_name else 'following_cmd'} attribute",
            )

        command_class = self.get_command_class(command_name)
        following_command_class = self.get_command_class(following_command)

        if not command_class:
            return ValidationResult(
                self, ResultType.WARNING, f"Unknown command in validation rule: {command_name}"
            )

        if not following_command_class:
            return ValidationResult(
                self,
                ResultType.WARNING,
                f"Unknown following command in validation rule: {command_name}",
            )

        command_tags = self.get_command_tags(commands)

        for idx, cmd_tag in enumerate(command_tags):
            if cmd_tag == command_class.CMD_TAG:
                # last command is not allowed
                if (
                    idx + 1 == len(command_tags)
                    or command_tags[idx + 1] != following_command_class.CMD_TAG
                ):
                    return ValidationResult(
                        self,
                        ResultType.FAILED,
                        f"{following_command} command must follow {command_name} command according to device rules",
                    )

        return ValidationResult(self, ResultType.PASSED)


class MaxOccurrencesValidator(BaseRuleValidator):
    """Validator for 'max_occurrences' rule type."""

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate that a command doesn't appear more than allowed times.

        :raises SPSDKError: When validation fails
        """
        command_name = self.rule.get("command")
        max_count = self.rule.get("count", 1)

        if not command_name:
            return ValidationResult(
                self,
                ResultType.WARNING,
                "Incomplete max_occurrences validation rule. Missing 'command' attribute",
            )

        command_class = self.get_command_class(command_name)

        if not command_class:
            return ValidationResult(
                self, ResultType.WARNING, f"Unknown command in validation rule: {command_name}"
            )

        command_tag = command_class.CMD_TAG
        command_tags = self.get_command_tags(commands)
        occurrences = command_tags.count(command_tag)
        if occurrences > max_count:
            return ValidationResult(
                self,
                ResultType.FAILED,
                f"{command_name} command can only be used {max_count} time(s) according to device rules",
            )
        return ValidationResult(self, ResultType.PASSED)


class MustAppearAfterValidator(BaseRuleValidator):
    """Validator for 'must_appear_after' rule type.

    This rule means: If both the source and target commands exist in the sequence,
    then the target command must appear after the source command.
    """

    @staticmethod
    def _find_max_index(lst: list, element: Any) -> int:
        # Find all indices where the element appears
        indices = [i for i, x in enumerate(lst) if x == element]
        # Return the last index or -1 if not found
        return max(indices) if indices else -1

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate that if both commands exist, target command appears after source command.

        :param commands: List of commands to validate
        :return: ValidationResult indicating success or failure
        """
        source_command: Optional[str] = self.rule.get("command")
        target_command: Optional[str] = self.rule.get("target_command")

        if not source_command or not target_command:
            return ValidationResult(
                self,
                ResultType.WARNING,
                "Incomplete must_appear_after validation rule. "
                f"Missing {'command' if not source_command else 'target_command'} attribute",
            )

        source_class = self.get_command_class(source_command)
        target_class = self.get_command_class(target_command)

        if not source_class:
            return ValidationResult(
                self,
                ResultType.WARNING,
                f"Unknown source command in validation rule: {source_command}",
            )

        if not target_class:
            return ValidationResult(
                self,
                ResultType.WARNING,
                f"Unknown target command in validation rule: {target_command}",
            )

        command_tags = self.get_command_tags(commands)
        src_max_index = self._find_max_index(command_tags, source_class.CMD_TAG)
        if src_max_index == -1:
            # Source command not present, validation passes
            return ValidationResult(self, ResultType.PASSED)
        tgt_max_index = self._find_max_index(command_tags, target_class.CMD_TAG)
        if tgt_max_index < src_max_index:
            return ValidationResult(
                self,
                ResultType.FAILED,
                f"{target_command} command must appear after {source_command} command according to device rules",
            )
        return ValidationResult(self, ResultType.PASSED)


COMMAND_VALIDATORS_MAP: dict[str, Type[BaseRuleValidator]] = {
    "must_follow": MustFollowValidator,
    "max_occurrences": MaxOccurrencesValidator,
    "must_appear_after": MustAppearAfterValidator,
}

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SB3.1 commands validation framework.

This module provides a comprehensive validation system for SB3.1 secure boot file commands,
including rule-based validators for command sequences, occurrence limits, and ordering
constraints to ensure proper command structure and dependencies.
"""

import logging
from typing import Any, Optional, Type

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, BaseCmd
from spsdk.sbfile.sb31.constants import EnumCmdTag
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class SPSDKValidationError(SPSDKError):
    """SPSDK command validation error exception.

    This exception is raised when validation of SB3.1 commands fails during
    processing or verification operations.
    """


class ResultType(SpsdkEnum):
    """Enumeration for SB3.1 command validation result types.

    This enum defines the possible outcomes when validating SB3.1 commands,
    providing standardized result codes and human-readable descriptions for
    validation operations.
    """

    PASSED = (0, "Passed")
    SKIPPED = (1, "Skipped")
    WARNING = (1, "Warning")
    FAILED = (2, "Failed")


class CommandsValidator:
    """SB3.1 commands validator for device-specific rule enforcement.

    This class validates sequences of SB3.1 commands against device-specific rules
    to ensure compatibility and proper execution on target hardware. It uses a
    rule-based validation system that can be configured per device family.
    """

    def __init__(self, family: FamilyRevision, command_rules: list[dict]):
        """Initialize the commands validator.

        Sets up the validator with family-specific configuration and command rules
        for validating SB3.1 commands.

        :param family: Target MCU family and revision information.
        :param command_rules: List of dictionaries containing validation rules for commands.
        """
        self.family = family
        self.command_rules = command_rules
        self.db = get_db(family=self.family)

    def validate_commands(self, commands: list[BaseCmd]) -> None:
        """Validate commands against device-specific rules.

        This method iterates through all configured command validation rules for the
        current device family and applies each rule to the provided command list.
        If no family is set or no rules are configured, validation is skipped.

        :param commands: List of commands to validate against device rules.
        :raises SPSDKError: When command validation rules are violated.
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
    """Validation result container for SB3.1 command validation operations.

    This class encapsulates the outcome of a validation rule execution, including
    the result status, associated rule, and optional reason for the result. It provides
    functionality to check and handle validation results with appropriate logging
    and error handling.
    """

    def __init__(self, rule: "BaseRuleValidator", result: ResultType, reason: Optional[str] = None):
        """Initialize validation result with rule, result type and optional reason.

        :param rule: The rule validator instance that produced this result.
        :param result: The type of validation result.
        :param reason: Optional descriptive text explaining the validation outcome.
        """
        self.rule = rule
        self.reason = reason
        self.result = result

    def check(self) -> None:
        """Check if the validation result indicates a pass.

        The method processes validation results and takes appropriate actions based on the result type.
        For failed validations, it raises an exception. For warnings, skipped, and passed validations,
        it logs appropriate messages with the rule information and optional reason.

        :raises SPSDKValidationError: When validation result indicates failure.
        """
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
    """Base class for command rule validators in SB3.1 files.

    This abstract class provides the foundation for implementing specific validation rules
    that can be applied to sequences of SB3.1 commands. Validators check command patterns,
    dependencies, and constraints to ensure proper command structure and execution order.
    """

    def __init__(self, rule: dict) -> None:
        """Initialize the rule validator.

        :param rule: The rule configuration dictionary containing validation rules.
        """
        self.rule = rule

    def __str__(self) -> str:
        """Return a string representation of the validator with its rule.

        The method formats the validator class name along with its rule dictionary
        in a readable format. If no rule is specified, it returns a message indicating
        the absence of rules.

        :return: A formatted string showing validator name and rule parameters, or
                 a message if no rule is specified.
        """
        validator_name = self.__class__.__name__

        if not self.rule:
            return f"{validator_name}: No rule specified"

        formatted_items = [f"{k}={repr(v)}" for k, v in self.rule.items()]
        return f"<{validator_name}: {', '.join(formatted_items)}>"

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate the rule against the commands.

        :param commands: List of commands to validate against the rule.
        :return: Result of the validation process.
        :raises SPSDKError: When validation fails.
        """
        raise NotImplementedError("Subclasses must implement validate()")

    def get_command_class(self, command_name: str) -> Optional[type[BaseCmd]]:
        """Get command class by name.

        Retrieves the command class associated with the specified command name from the
        configuration mapping. The search is case-insensitive.

        :param command_name: Name of the command to search for.
        :return: Command class if found, None otherwise.
        """
        for cmd_name, cmd_cls in CFG_NAME_TO_CLASS.items():
            if cmd_name.lower() == command_name.lower():
                return cmd_cls
        return None

    def get_command_tags(self, commands: list[BaseCmd]) -> list[EnumCmdTag]:
        """Get list of command tags from provided commands.

        :param commands: List of command objects to extract tags from.
        :return: List of command tags corresponding to the input commands.
        """
        return [cmd.CMD_TAG for cmd in commands]

    def get_command_names(self, commands: list[BaseCmd]) -> list[str]:
        """Get list of command names from provided commands.

        Extracts the class names from a list of command objects to create a list of
        command name strings.

        :param commands: List of command objects to extract names from.
        :return: List of command class names as strings.
        """
        return [cmd.__class__.__name__ for cmd in commands]


class MustFollowValidator(BaseRuleValidator):
    """Validator for 'must_follow' rule type in SB3.1 command sequences.

    This validator enforces conditional command ordering where if a prerequisite command exists
    in the sequence, then a specified command must immediately follow it. The command can be
    used independently if the prerequisite is not present in the sequence.
    """

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate that if prerequisite exists, command must follow it.

        Checks if a specified command is properly followed by its required subsequent command
        according to device validation rules. Returns appropriate validation results for
        missing rules, unknown commands, or rule violations.

        :param commands: List of commands to validate for proper sequencing
        :return: ValidationResult indicating success, failure, or warnings with details
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
    """SB3.1 command occurrence validator.

    This validator ensures that specific commands do not exceed their maximum
    allowed occurrences within a command sequence according to device-specific
    rules and constraints.
    """

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate that a command doesn't appear more than allowed times.

        Checks if any command in the provided list exceeds the maximum allowed occurrences
        as defined by the validation rule configuration.

        :param commands: List of commands to validate against occurrence limits.
        :return: ValidationResult indicating whether validation passed, failed, or had warnings.
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
    """Validator for command ordering rules in SB3.1 files.

    This validator enforces 'must_appear_after' rules which ensure that if both
    a source and target command exist in the command sequence, the target command
    must appear after the source command in the execution order.
    </response>
    """

    @staticmethod
    def _find_max_index(lst: list, element: Any) -> int:
        """Find the maximum (last) index of an element in a list.

        This method searches for all occurrences of the specified element in the list
        and returns the index of the last occurrence.

        :param lst: List to search in.
        :param element: Element to find in the list.
        :return: Last index where element appears, or -1 if element is not found.
        """
        # Find all indices where the element appears
        indices = [i for i, x in enumerate(lst) if x == element]
        # Return the last index or -1 if not found
        return max(indices) if indices else -1

    def validate(self, commands: list[BaseCmd]) -> ValidationResult:
        """Validate command ordering according to must_appear_after rule.

        Checks that if both source and target commands exist in the command list,
        the target command appears after the source command as required by device rules.

        :param commands: List of BaseCmd objects to validate for proper ordering
        :return: ValidationResult with PASSED if ordering is correct, FAILED if target appears
                 before source, or WARNING if validation rule is incomplete or contains unknown commands
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

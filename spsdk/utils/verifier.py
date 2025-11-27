#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK verification and validation utilities.

This module provides a comprehensive framework for performing verification
and validation operations across SPSDK components. It includes result tracking,
record management, and formatted output capabilities for verification processes.
"""

import textwrap
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Type, Union

import colorama
import prettytable

from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.utils.misc import check_range, value_to_int, wrap_text
from spsdk.utils.spsdk_enum import SpsdkEnum


class VerifierResult(SpsdkEnum):
    """Verifier result enumeration for SPSDK validation operations.

    This enumeration defines the possible outcomes of verification processes with
    associated color codes for console output formatting.

    :cvar SUCCEEDED: Verification completed successfully (green).
    :cvar WARNING: Verification completed with warnings (yellow).
    :cvar ERROR: Verification failed with errors (red).
    """

    SUCCEEDED = (0, "Succeeded", colorama.Fore.GREEN)
    WARNING = (1, "Warning", colorama.Fore.YELLOW)
    ERROR = (2, "Error", colorama.Fore.RED)

    @classmethod
    def draw(cls, res: "VerifierResult", colorize: bool = True) -> str:
        """Get string representation with optional color formatting.

        Formats the verifier result as a string, optionally adding ANSI color codes for enhanced
        visual output in terminals that support colored text.

        :param res: Verifier result object containing label and description.
        :param colorize: Whether to add ANSI escape characters for colored output.
        :return: Formatted string representation of the verifier result.
        """
        if not res.description or not colorize:
            return res.label
        return res.description + res.label + colorama.Fore.RESET


@dataclass
class VerifierRecord:
    """SPSDK verification record for storing verification results.

    This class represents a single record in the verification process, containing
    the verification name, result status, optional value, and formatting options.
    Each record captures the outcome of a specific verification step and provides
    control over how the result is displayed in verification reports.
    """

    # Name of the verification
    name: str
    # Strictly defined result
    result: VerifierResult = VerifierResult.ERROR
    # String / Integer / Boolean value of result representation
    value: Optional[Union[str, int, bool]] = None
    # Important - In case of succeeded result this record won't be printed
    important: bool = True
    # Raw record without any formatting
    raw: bool = False


########################################################################################################################
# Class data general verifier info class.
########################################################################################################################
class Verifier:
    """SPSDK data verification and formatting utility.

    This class provides structured verification reporting with hierarchical organization,
    colorized output, and flexible formatting options for SPSDK operations.

    :cvar MAX_LINE_LENGTH: Maximum line length for formatted output.
    :cvar TITLE_FG_COLOR: Default foreground color for title blocks.
    """

    MAX_LINE_LENGTH = 120
    TITLE_FG_COLOR = colorama.Fore.CYAN

    def __init__(
        self,
        name: str,
        indent: int = 2,
        description: Optional[str] = None,
        important: bool = True,
        raw: bool = False,
    ) -> None:
        """Initialize a general verifier instance.

        Creates a new verifier object for validation and verification operations
        with configurable formatting and importance settings.

        :param name: Name of the verifier instance.
        :param indent: Indentation level for nested verifying blocks, defaults to 2.
        :param description: Optional description of the verifier's purpose, defaults to None.
        :param important: Flag indicating if this is an important verifier, defaults to True.
        :param raw: Flag for raw verifier output without formatting, defaults to False.
        """
        self.name = name
        self.records: list[Union[VerifierRecord, "Verifier"]] = []
        self.description = description
        self.indent = indent
        self.level = 1
        self.important = important
        self.raw = raw

    @property
    def max_line(self) -> int:
        """Get maximal line length with current indentation level.

        Calculates the maximum allowed line length by subtracting the current
        indentation from the base maximum line length.

        :return: Maximum line length adjusted for current indentation level.
        """
        return self.MAX_LINE_LENGTH - self.indent * self.level

    def __repr__(self) -> str:
        """Get string representation of the verifier object.

        :return: String representation containing the verifier name and type.
        """
        return f"{self.name} verifier object"

    def __str__(self) -> str:
        """Get string representation of verifier output.

        Returns the verifier output in a non-colorized string format by calling the draw method
        with colorization disabled.

        :return: String representation of the verifier output without color formatting.
        """
        return self.draw(colorize=False)

    def _get_title_block(self, colorize: bool = True) -> str:
        """Get unified title block for verification result display.

        Creates a formatted ASCII art title block with the verifier name, result status,
        and optional description. The block includes decorative borders and proper spacing
        for consistent display formatting.

        :param colorize: Enable ANSI color escape sequences for colored output.
        :return: Formatted ASCII art title block string.
        """
        fg_color = self.TITLE_FG_COLOR if colorize else ""
        rst_color = colorama.Fore.RESET if colorize else ""
        delimiter = fg_color + "=" * self.max_line
        line_length = len(self.name + "  () " + self.result.label)
        rest_len = self.max_line - line_length
        odd = rest_len % 2
        fill_len = rest_len // 2
        title_str = (
            f"{fg_color}{'='*fill_len}{rst_color} {self.name} "
            f"({VerifierResult.draw(self.result, colorize=colorize)}) {fg_color}"
            f"{'='*fill_len }{'=' if odd else ''}{rst_color}"
        )

        ret = title_str + "\n" + fg_color
        if self.description:
            ret += wrap_text(self.description, self.max_line) + "\n" + delimiter + rst_color + "\n"
        return ret

    def draw(self, results: Optional[list[VerifierResult]] = None, colorize: bool = True) -> str:
        """Draw the results of the verifier with optional formatting and filtering.

        The method generates a formatted string representation of the verifier results,
        with support for colorized output and selective result filtering. For successful
        results, it may provide a shortened overview when appropriate.

        :param results: Filter for selected results to display, defaults to None for all results.
        :param colorize: Enable colored text output using ANSI escape characters.
        :return: Formatted string representation of the verifier results.
        """

        def could_shorten_to() -> Optional[VerifierRecord]:
            """Check if this verifier could be shortened to a single record.

            A verifier can be shortened if it has no description and contains at most one
            important record, with no nested Verifier instances.

            :return: The single important record if shortening is possible, None otherwise.
            """
            if self.description is not None:
                return None
            ret = None
            for rec in self.records:
                if isinstance(rec, Verifier):
                    return None
                if rec.important:
                    if ret:
                        return None
                    ret = rec
            return ret

        fg_color = self.TITLE_FG_COLOR if colorize else ""
        rst_color = colorama.Fore.RESET if colorize else ""
        if results and self.result not in results:
            return ""

        if self.result == VerifierResult.SUCCEEDED:
            ret = f"{fg_color}{self.name}{rst_color}({VerifierResult.draw(self.result, colorize)})"
            if not self.important:
                return ret + "\n"
            # print just overview
            shorten_rec = could_shorten_to()
            if shorten_rec:
                if shorten_rec.value is not None:
                    ret += ": " + str(shorten_rec.value)
                return ret + "\n"

        if self.description is not None:
            ret = self._get_title_block(colorize)
        else:
            ret = (
                f"{fg_color}{self.name}{rst_color}({VerifierResult.draw(self.result, colorize)}) \n"
            )
        # Print all important records
        for record in self.records:
            if isinstance(record, VerifierRecord):
                if (record.result == VerifierResult.SUCCEEDED and not record.important) or (
                    results and record.result not in results
                ):
                    continue
                item = self._draw_record(record, colorize) + "\n"
            else:
                record.level = self.level + 1
                item = record.draw(results=results, colorize=colorize)
            ret += textwrap.indent(item, " " * self.indent)
        return ret

    def _draw_record(self, record: VerifierRecord, colorize: bool = True) -> str:
        """Draw one record in string format.

        The method formats a verification record into a human-readable string representation,
        with optional ANSI color coding and proper text wrapping.

        :param record: Record to be converted to string format.
        :param colorize: Make the text colored with ANSI escape characters.
        :return: Formatted string representation of the record.
        """
        ret = f"{record.name}({VerifierResult.draw(record.result, colorize)}): "
        if record.value is not None:
            ret += str(record.value)
        if record.raw:
            return ret
        subsequent_indent = len(record.name + "(): " + record.result.label)
        tw = textwrap.wrap(
            text=ret,
            width=self.max_line,
            subsequent_indent=" " * subsequent_indent,
        )
        return "\n".join(tw)

    def add_record(
        self,
        name: str,
        result: Union[VerifierResult, bool],
        value: Optional[Union[str, int, bool]] = None,
        important: bool = True,
        raw: bool = False,
    ) -> None:
        """Add one verifying record to verifier.

        Creates a new verification record with the specified parameters and appends it to the
        internal records list. Boolean results are automatically converted to VerifierResult enum values.

        :param name: Name of verifying condition/expression.
        :param result: Result of verifying condition/expression, boolean values are converted
            (True == SUCCEEDED, False == ERROR).
        :param value: Optional value associated with the verification result.
        :param important: Flag indicating if this record should be marked as important.
        :param raw: Flag indicating if record should be stored without formatting.
        """
        if isinstance(result, bool):
            result = VerifierResult.SUCCEEDED if result else VerifierResult.ERROR
        record = VerifierRecord(name=name, result=result, value=value, important=important, raw=raw)
        self.records.append(record)

    def add_record_bit_range(
        self, name: str, value: Optional[int], bit_range: int = 32, important: bool = True
    ) -> None:
        """Add verifier check for bit range validation of a record.

        Validates that the provided integer value fits within the specified bit range
        and adds the verification result to the verifier.

        :param name: Name of the record to be verified.
        :param value: Integer value to be checked for bit range compliance.
        :param bit_range: Maximum bit range the value should fit within, defaults to 32.
        :param important: Flag indicating if this is an important record for verification.
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
        elif not check_range(value, end=(1 << bit_range) - 1):
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Out of {bit_range} bit range: {value}",
            )
        else:
            fmt = f"0{bit_range//4}X"
            self.add_record(name, VerifierResult.SUCCEEDED, f"0x{value:{fmt}}", important)

    def add_record_range(
        self,
        name: str,
        value: Optional[Union[int, str]],
        min_val: int = 0,
        max_val: int = (1 << 32) - 1,
    ) -> None:
        """Add range validation record to verifier.

        Validates that the provided value falls within the specified range and adds
        the verification result to the verifier records.

        :param name: Name of the record for identification.
        :param value: Integer value or hex string to be validated, None if record doesn't exist.
        :param min_val: Minimal allowed value, defaults to 0.
        :param max_val: Maximal allowed value, defaults to full 32-bit range.
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
            return

        # Convert hex string to int for validation, keep original for display
        display_value = value
        if isinstance(value, str):
            try:
                value = value_to_int(value)
            except ValueError:
                self.add_record(name, VerifierResult.ERROR, f"Invalid hex format: {value}")
                return

        if value < min_val:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Lower than allowed: {display_value} < {min_val}",
            )
        elif value > max_val:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Higher than allowed: {display_value} > {max_val}",
            )
        else:
            self.add_record(name, VerifierResult.SUCCEEDED, display_value)

    def add_record_contains(self, name: str, value: Optional[Any], collection: Iterable) -> None:
        """Add to verifier check the presence of item in collection.

        The method validates whether a given value exists within the specified collection.
        If the value is None, it records an error indicating the item doesn't exist.
        If the value is not found in the collection, it records an error with details.
        Otherwise, it records a successful verification.

        :param name: Name of the verification record.
        :param value: Item to be checked for presence in collection.
        :param collection: Collection of items to search within.
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
        elif value not in collection:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Value {value} is not in collection: {collection}",
            )
        else:
            self.add_record(
                name,
                VerifierResult.SUCCEEDED,
                f"Value {value} is in collection: {collection}",
            )

    def add_record_bytes(
        self,
        name: str,
        value: Optional[bytes],
        min_length: int = 0,
        max_length: Optional[int] = None,
    ) -> None:
        """Add bytes record validation to verifier.

        Validates a bytes value against specified length constraints and adds
        the verification result to the verifier records.

        :param name: Name of the record to be verified.
        :param value: Bytes value to be validated, None if record doesn't exist.
        :param min_length: Minimal allowed value length, defaults to 0.
        :param max_length: Maximal allowed value length, defaults to None (no limit).
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
        elif len(value) < min_length:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Not enough bytes: Minimal length ({min_length}) > Current length({len(value)}),  {value.hex()}",
            )
        elif max_length is not None and len(value) > max_length:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Too much bytes: Current length({len(value)}) > Maximal length ({max_length}),  {value.hex()}",
            )
        else:
            self.add_record(
                name, VerifierResult.SUCCEEDED, f"First bytes up to 64:{value[:64].hex()}"
            )

    def add_record_enum(
        self, name: str, value: Optional[Union[SpsdkEnum, int, str]], enum: Type[SpsdkEnum]
    ) -> None:
        """Add to verifier check of the value into enum record.

        The method validates if a given value belongs to a specified enumeration type and adds
        the verification result to the verifier. It handles different input types including
        SpsdkEnum instances, integers, and strings.

        :param name: Name of the verification record.
        :param value: Value to be checked against the enumeration (can be SpsdkEnum, int, str, or None).
        :param enum: Type of the enumeration class to verify against.
        :raises SPSDKError: When value cannot be converted to the specified enumeration type.
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
            return

        if isinstance(value, enum):
            value_enum = value
        elif isinstance(value, SpsdkEnum):
            self.add_record(
                name,
                VerifierResult.WARNING,
                value.label + f", {value.description}" if value.description else "",
            )
            return
        else:
            try:
                assert isinstance(value, (int, str))
                value_enum = enum.from_attr(value)
            except SPSDKError:
                self.add_record(
                    name, VerifierResult.ERROR, f"{value} not fit to known enumeration {str(enum)}"
                )
                return

        self.add_record(
            name,
            VerifierResult.SUCCEEDED,
            value_enum.label + f", {value_enum.description}" if value_enum.description else "",
        )

    def add_child(self, child: "Verifier", prefix_name: Optional[str] = None) -> None:
        """Add child Verifier object to this verifier.

        The child verifier will be appended to the records list and optionally
        prefixed with a custom name.

        :param child: Child verifier object to be added.
        :param prefix_name: Optional prefix to prepend to the child's name.
        """
        if prefix_name:
            child.name = f"{prefix_name}: {child.name}"
        self.records.append(child)

    def get_count(self, results: Optional[list[VerifierResult]] = None) -> int:
        """Get count of records of requested result state.

        The method recursively counts verification records that match the specified result types.
        For nested Verifier objects, it calls get_count recursively to include their records.

        :param results: List of types of result to count, defaults to None (get all)
        :return: Count of records matching the specified result types.
        """
        ret = 0
        for record in self.records:
            if isinstance(record, VerifierRecord):
                if results is None or record.result in results:
                    ret += 1
            else:
                assert isinstance(record, Verifier)
                ret += record.get_count(results=results)
        return ret

    @property
    def has_errors(self) -> bool:
        """Check if the verifier contains any error.

        :return: True if verifier contains at least one error, False otherwise.
        """
        return bool(self.get_count([VerifierResult.ERROR]))

    @property
    def result(self) -> VerifierResult:
        """Get the overall verification result from all records.

        Iterates through all verification records and sub-verifiers to determine the highest
        severity result. Returns immediately if an ERROR is encountered.

        :return: The most severe verification result found across all records.
        """
        ret = VerifierResult.SUCCEEDED
        for record in self.records:
            if isinstance(record, VerifierRecord):
                res = record.result
            else:
                assert isinstance(record, Verifier)
                res = record.result
            if res.tag > ret.tag:
                ret = res
                if ret == VerifierResult.ERROR:
                    break
        return ret

    def validate(self, colorize: bool = False) -> None:
        """Validate the object for errors.

        Checks if the verification result contains any errors and raises an exception
        if errors are found.

        :param colorize: Make the text colored with ANSI escape characters.
        :raises SPSDKVerificationError: If validation errors are found in the object.
        """
        if self.result is VerifierResult.ERROR:
            raise SPSDKVerificationError(
                self.draw(results=[VerifierResult.ERROR], colorize=colorize)
            )

    def get_summary_table(self, colorize: bool = True) -> str:
        """Get the summary table with verification results.

        Creates a formatted table displaying counts for each verification result type,
        with optional colorization using ANSI escape characters for better readability.

        :param colorize: Enable colored text output using ANSI escape characters, defaults to True
        :return: Formatted string table containing summary of verification results
        """
        header: list[str] = []
        row: list[int] = []
        for res in VerifierResult:
            header.append(VerifierResult.draw(res, colorize=colorize))
            row.append(self.get_count([res]))
        pt = prettytable.PrettyTable(header)
        pt.align = "c"
        pt.header = True
        pt.border = True
        pt.add_row(row)
        return str(pt)

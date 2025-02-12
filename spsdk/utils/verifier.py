#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""General verifier module."""

import textwrap
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Type, Union

import colorama
import prettytable

from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.utils.misc import check_range, wrap_text
from spsdk.utils.spsdk_enum import SpsdkEnum


class VerifierResult(SpsdkEnum):
    """Verifier result enumeration."""

    SUCCEEDED = (0, "Succeeded", colorama.Fore.GREEN)
    WARNING = (1, "Warning", colorama.Fore.YELLOW)
    ERROR = (2, "Error", colorama.Fore.RED)

    @classmethod
    def draw(cls, res: "VerifierResult", colorize: bool = True) -> str:
        """Get string also with colors.

        :param res: Verifier result
        :param colorize: Make the text colored with ANSI escape characters
        """
        if not res.description or not colorize:
            return res.label
        return res.description + res.label + colorama.Fore.RESET


@dataclass
class VerifierRecord:
    """Record of verification process."""

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
    """Class data general verifier info class."""

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
        """General verifier class.

        :param name: name of verifier
        :param indent: Indent of the nested verifying blocks, defaults to 2
        :param description: Description of verifier, defaults to None
        :param important: Mark of important verifier, defaults to True
        :param raw: Raw verifier without any formatting
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
        """Maximal line with current indent."""
        return self.MAX_LINE_LENGTH - self.indent * self.level

    def __repr__(self) -> str:
        """Object representation in string format."""
        return f"{self.name} verifier object"

    def __str__(self) -> str:
        """Verifier output in string format."""
        return self.draw(colorize=False)

    def _get_title_block(self, colorize: bool = True) -> str:
        """Get unified title blob.

        :param colorize: Make the text colored with ANSI escape characters
        :return: ASCII art block
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
        """Draw the results.

        :param colorize: Make the text colored with ANSI escape characters
        :param results: Filter for selected results, default is None
        :return: Stringified output of whole verifier object
        """

        def could_shorten_to() -> Optional[VerifierRecord]:
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
        """Draw one record in string.

        :param colorize: Make the text colored with ANSI escape characters
        :param record: Record to be rewritten to string.
        :return: Stringified record
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

        :param name: Name of verifying condition/expression
        :param result: Result of verifying condition/expression,
            it could be also used boolean type as assert (True == SUCCEEDED, False == ERROR)
        :param value: Result of verifying condition/expression
        :param important: Mark of important record
        :param raw: Raw record without any formatting
        """
        if isinstance(result, bool):
            result = VerifierResult.SUCCEEDED if result else VerifierResult.ERROR
        record = VerifierRecord(name=name, result=result, value=value, important=important, raw=raw)
        self.records.append(record)

    def add_record_bit_range(
        self, name: str, value: Optional[int], bit_range: int = 32, important: bool = True
    ) -> None:
        """Add to verifier check of the bit range record.

        :param name: Name of record
        :param value: Integer value to be checked
        :param bit_range: BIt range to the value should fit, defaults to 32
        :param important: Mark of important record
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
        self, name: str, value: Optional[int], min_val: int = 0, max_val: int = (1 << 32) - 1
    ) -> None:
        """Add to verifier check of the range record.

        :param name: Name of record
        :param value: Integer value to be checked
        :param min_val: Minimal allowed value, defaults to 0
        :param max_val: Maximal allowed value, defaults to full 32 bit variable
        """
        if value is None:
            self.add_record(name, VerifierResult.ERROR, "Doesn't exists")
        elif value < min_val:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Lower than allowed: {value} < {min_val}",
            )
        elif value > max_val:
            self.add_record(
                name,
                VerifierResult.ERROR,
                f"Higher than allowed: {value} > {max_val}",
            )
        else:
            self.add_record(name, VerifierResult.SUCCEEDED, value)

    def add_record_contains(self, name: str, value: Optional[Any], collection: Iterable) -> None:
        """Add to verifier check the presence of item in collection.

        :param name: Name of record
        :param value: Item to be checked
        :param collection: Collection of items
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
        """Add to verifier check of the bytes record.

        :param name: Name of record
        :param value: Bytes value to be checked
        :param min_length: Minimal allowed value length, defaults to 0
        :param max_length: Optional Maximal allowed value length, defaults to not tested
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

        :param name: Name of record
        :param value: Integer value to be checked
        :param enum: Type of the enumeration class to verify
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
        """Add children Verifier object.

        :param child: Children verifier object
        :param prefix_name: Optional addition prefix to child name.
        """
        if prefix_name:
            child.name = f"{prefix_name}: {child.name}"
        self.records.append(child)

    def get_count(self, results: Optional[list[VerifierResult]] = None) -> int:
        """Get count of records of requested result state.

        :param results: List of types of result to count, defaults to None (get all)
        :return: Count of records.
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
        """Check if the verifier contains any error."""
        return bool(self.get_count([VerifierResult.ERROR]))

    @property
    def result(self) -> VerifierResult:
        """Overall verifier result."""
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
        """Check the errors in the object.

        :param colorize: Make the text colored with ANSI escape characters
        :raises SPSDKVerificationError: In case of any error it raises Whole source of errors.
        """
        if self.result is VerifierResult.ERROR:
            raise SPSDKVerificationError(
                self.draw(results=[VerifierResult.ERROR], colorize=colorize)
            )

    def get_summary_table(self, colorize: bool = True) -> str:
        """Get the summary table with verify results.

        :param colorize: Make the text colored with ANSI escape characters
        :return: String table with summary results.
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

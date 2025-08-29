#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB abstract classes.

This module provides abstract base classes for AHAB (Advanced High-Assurance Boot)
containers used in secure boot implementations. It defines the common interfaces
for serialization, parsing, and validation of container structures.
"""

import textwrap
from dataclasses import dataclass
from struct import calcsize, unpack
from typing import Optional, Union

import colorama
from typing_extensions import Self

from spsdk.exceptions import SPSDKLengthError, SPSDKParsingError
from spsdk.image.ahab.ahab_data import LITTLE_ENDIAN, UINT8, UINT16
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import bytes_to_print
from spsdk.utils.verifier import Verifier, VerifierResult


class Container(BaseClass):
    """Base class for any container.

    Provides common interface for container operations including parsing,
    exporting and length calculations.
    """

    _parser_verifier: Optional[Verifier]

    @classmethod
    def fixed_length(cls) -> int:
        """Returns the length of a container which is fixed.

        Fixed length refers to the part of a container that holds fixed values,
        whereas some entries may have variable length.

        :return: Fixed length in bytes
        """
        return calcsize(cls.format())

    def __len__(self) -> int:
        """Returns the total length of a container.

        The length includes both the fixed and the variable length parts.

        :return: Total container length in bytes
        """
        return self.fixed_length()

    def __repr__(self) -> str:
        return "Base AHAB Container class: " + self.__class__.__name__

    def __str__(self) -> str:
        raise NotImplementedError("__str__() is not implemented in base AHAB container class")

    def export(self) -> bytes:
        """Export the container to bytes.

        :return: Bytes representation of the container
        :raises NotImplementedError: If export is not implemented in derived class
        """
        raise NotImplementedError("export() is not implemented in base AHAB container class")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into a container object.

        :param data: Binary input data to parse
        :return: Parsed container object
        :raises SPSDKParsingError: If parsing fails
        """
        raise NotImplementedError("parse() is not implemented in base AHAB container class")

    @classmethod
    def format(cls) -> str:
        """Returns the container data format as defined by struct package.

        The base returns only endianness (LITTLE_ENDIAN).

        :return: Format string for struct operations
        """
        return LITTLE_ENDIAN

    @classmethod
    def _check_fixed_input_length(cls, binary: bytes) -> Verifier:
        """Checks the data length and container fixed length.

        This is just a helper function used throughout the code.

        :param binary: Binary input data
        :return: The verifier object with checked minimal container length
        """
        data_len = len(binary)
        fixed_input_len = cls.fixed_length()
        ret = Verifier("Minimal input length of container block")
        ret.add_record_range("Length", data_len, min_val=fixed_input_len)
        return ret


@dataclass
class HeaderContainerData:
    """Holder for Container header data.

    Contains the basic attributes found in container headers.
    """

    tag: int
    length: int
    version: int

    @classmethod
    def parse(cls, binary: bytes, inverted: bool = False) -> Self:
        """Parse binary header.

        :param binary: Binary data to parse
        :param inverted: Whether the header fields are in inverted order
        :return: Parsed header container data
        :raises SPSDKParsingError: If header length is insufficient
        """
        fmt = LITTLE_ENDIAN + UINT8 + UINT16 + UINT8
        if len(binary) < 4:
            raise SPSDKParsingError("AHAB header length is not sufficient")
        if inverted:
            (tag, length, version) = unpack(fmt, binary[:4])
        else:
            (version, length, tag) = unpack(fmt, binary[:4])
        return cls(tag, length, version)


class HeaderContainer(Container):
    """A container with first byte defined as header - tag, length and version.

    Every "container" in AHAB consists of a header - tag, length and version.
    The only exception is the 'image array' or 'image array entry' respectively
    which has no header at all and SRK record, which has 'signing algorithm'
    instead of version. But this can be considered as a sort of SRK record
    'version'.
    """

    TAG: Union[int, list[int]] = 0x00
    VERSION: Union[int, list[int]] = 0x00

    DIFF_ATTRIBUTES_VALUES: list[str] = []
    DIFF_ATTRIBUTES_OBJECTS: list[str] = []

    def __init__(self, tag: int, length: int, version: int):
        """Initialize container with header values.

        :param tag: Container tag
        :param length: Container length
        :param version: Container version
        """
        self.length = length
        self.tag = tag
        self.version = version
        self._parsed_header: Optional[HeaderContainerData] = None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (HeaderContainer, HeaderContainerInverted)):
            if (
                self.tag == other.tag
                and self.length == other.length
                and self.version == other.version
            ):
                return True

        return False

    @classmethod
    def format(cls) -> str:
        """Format of binary representation.

        :return: Format string for struct operations
        """
        return super().format() + UINT8 + UINT16 + UINT8

    def verify_header(self) -> Verifier:
        """Verifies the header of container properties.

        Validates tag, length and version against constraints.

        :return: Verifier object with validation results
        :raises SPSDKValueError: If any mandatory field has invalid value
        """
        return self._verify_header(self.tag, self.length, self.version, len(self))

    def verify_parsed_header(self) -> Verifier:
        """Verifies the parsed header of container properties.

        Validates parsed tag, length and version against constraints.

        :return: Verifier object with validation results
        :raises SPSDKValueError: If any mandatory field has invalid value
        """
        ret = Verifier(f"Parsed header ({self.__class__.__name__})", important=False)
        if self._parsed_header:
            ret.add_child(
                self._verify_header(
                    self._parsed_header.tag,
                    self._parsed_header.length,
                    self._parsed_header.version,
                    len(self),
                )
            )
        else:
            ret.add_record("Availability", VerifierResult.WARNING, "Not included")
        return ret

    @classmethod
    def _verify_header(
        cls, tag: int, length: int, version: int, object_length: Optional[int] = None
    ) -> Verifier:
        """Verifies the header of container properties.

        Validates tag, length and version against constraints.

        :param tag: Container tag value
        :param length: Container length value
        :param version: Container version value
        :param object_length: Actual object length for comparison with header length
        :return: Verifier object with validation results
        :raises SPSDKValueError: If any mandatory field has invalid value
        """
        ret = Verifier("Header")
        ver_tag = Verifier("Tag")
        ver_tag.add_record_bit_range("Range", tag, 8, False)
        if tag is not None:
            if isinstance(cls.TAG, int) and tag != cls.TAG:
                ver_tag.add_record(
                    "Value",
                    VerifierResult.ERROR,
                    f"Invalid: {hex(tag)}, " f"expected {hex(cls.TAG)}!",
                )
            elif isinstance(cls.TAG, list) and tag not in cls.TAG:
                ver_tag.add_record(
                    "Value",
                    VerifierResult.ERROR,
                    f"Invalid: {hex(tag)}, " f"expected one of those {[hex(x) for x in cls.TAG]}!",
                )
            else:
                ver_tag.add_record("Value", VerifierResult.SUCCEEDED, hex(tag))
        ret.add_child(ver_tag)
        ver_length = Verifier("Length")
        ver_length.add_record_bit_range("Range", length, 16, False)
        if object_length is not None:
            if object_length > length:
                ver_length.add_record(
                    "Computed length",
                    VerifierResult.ERROR,
                    f"The length must be at least {object_length} and is {length}",
                )
            elif object_length < length:
                ver_length.add_record(
                    "Computed length",
                    VerifierResult.WARNING,
                    f"The length of object {object_length} is smaller than container size {length}",
                )
            else:
                ver_length.add_record("Computed length", VerifierResult.SUCCEEDED, object_length)
        ret.add_child(ver_length)

        ver_version = Verifier("Version")
        ver_version.add_record_bit_range("Range", version, 8, False)
        if version is not None:
            if (
                isinstance(cls.VERSION, int)
                and version != cls.VERSION
                or isinstance(cls.VERSION, list)
                and version not in cls.VERSION
            ):
                ver_version.add_record(
                    "Value",
                    VerifierResult.ERROR,
                    f"Invalid VERSION {version} loaded, expected {cls.VERSION}!",
                )
            else:
                ver_version.add_record("Value", VerifierResult.SUCCEEDED, hex(version))
        ret.add_child(ver_version)
        return ret

    @classmethod
    def parse_head(cls, binary: bytes) -> tuple[int, int, int]:
        """Parse binary data to get head members.

        :param binary: Binary data
        :return: Tuple with TAG, LENGTH, VERSION
        :raises SPSDKLengthError: If binary data length is not enough
        """
        if len(binary) < 4:
            raise SPSDKLengthError(
                f"Parsing error in {cls.__name__} container head data!\n"
                "Input data must be at least 4 bytes!"
            )
        (version, length, tag) = unpack(HeaderContainer.format(), binary[:4])
        return tag, length, version

    @classmethod
    def check_container_head(cls, binary: bytes) -> Verifier:
        """Validate container header and ensure sufficient data length.

        Performs multiple validation steps on the container header:
        1. Checks if input data has sufficient length for the fixed header
        2. Parses header fields (tag, length, version)
        3. Verifies header field values against expected constraints
        4. Ensures input data is long enough to contain the entire container

        :param binary: Input data containing the container header
        :return: Verification results for all container header checks
        """
        ret = Verifier(f"Container({cls.__name__}) header")
        ret.add_child(cls._check_fixed_input_length(binary))
        if not ret.has_errors:
            data_len = len(binary)
            (tag, length, version) = cls.parse_head(binary[: HeaderContainer.fixed_length()])
            ret.add_child(cls._verify_header(tag, length, version))

        if not ret.has_errors:
            if data_len < length:
                ret.add_record(
                    "Binary length",
                    VerifierResult.ERROR,
                    f"Parsing error of {cls.__name__} data!\n"
                    f"At least {length} bytes expected, got {data_len} bytes!",
                )
        return ret

    def diff(self, other: object) -> dict[str, dict]:
        """Get difference of a container with another container.

        :param other: Another container to compare
        :return: Dictionary containing differences between containers
        """
        diff_dict = {}

        def compare_objects(
            self_obj: Optional[Union[dict, list]], other_obj: Optional[Union[dict, list]]
        ) -> dict:
            """Helper method to recursively compare objects."""
            sub_diff = {}
            if isinstance(self_obj, list):
                min_length = min(len(self_obj), len(other_obj)) if other_obj is not None else 0
                if min_length:
                    assert self_obj and other_obj is not None
                    for i, (self_item, other_item) in enumerate(
                        zip(self_obj[:min_length], other_obj[:min_length])
                    ):
                        if self_item != other_item:
                            sub_diff[f"[{i}]"] = (
                                self_item.diff(other_item)
                                if hasattr(self_item, "diff")
                                else {"original": self_item, "new": other_item}
                            )
                else:
                    sub_diff = {
                        "original": f"Array len:{len(self_obj)}",
                        "new": f"Array len:{len(other_obj) if other_obj is not None else 0}",
                    }
            else:
                if other_obj is None or self_obj is None:
                    sub_diff = {"original": self_obj, "new": other_obj}
                elif hasattr(self_obj, "diff"):
                    sub_diff = self_obj.diff(other_obj)
                else:
                    sub_diff = {"original": self_obj, "new": other_obj}

            return sub_diff

        for attr in self.DIFF_ATTRIBUTES_VALUES:
            if getattr(self, attr) != getattr(other, attr):
                diff_dict[attr] = {"original": getattr(self, attr), "new": getattr(other, attr)}

        for attr in self.DIFF_ATTRIBUTES_OBJECTS:
            if getattr(self, attr) != getattr(other, attr):
                possible_diff = (
                    compare_objects(getattr(self, attr), getattr(other, attr))
                    if hasattr(self, attr)
                    and hasattr(other, attr)
                    and hasattr(getattr(self, attr), "diff")
                    else {"original": getattr(self, attr), "new": getattr(other, attr)}
                )
                if possible_diff:
                    diff_dict[attr] = possible_diff

        return diff_dict

    @staticmethod
    def print_diff(diff: dict) -> str:
        """Helper method to format and print differences between containers.

        :param diff: Dictionary containing differences from diff() method
        :return: Formatted string representation of differences
        """
        max_line = 120

        def format_dict(d: dict, intend: int = 0) -> str:
            sub_diff = ""
            for k, v in d.items():
                if isinstance(v, dict):
                    sub_diff += f"{' '*intend*2}{colorama.Fore.CYAN}{k}:\n" + format_dict(
                        v, intend + 1
                    )
                else:
                    colors = {"original": colorama.Fore.YELLOW, "new": colorama.Fore.GREEN}
                    color = colors.get(k, colorama.Fore.RESET)
                    if isinstance(v, int):
                        value_raw = hex(v)
                    elif isinstance(v, bytes):
                        value_raw = bytes_to_print(v)
                    else:
                        value_raw = str(v)
                    value = f"{color}{k}:{colorama.Fore.LIGHTBLACK_EX} {value_raw}\n"
                    for src_line in value.splitlines():
                        intended_value = textwrap.wrap(
                            text=src_line,
                            width=max_line,
                            subsequent_indent=" " * intend * 2,
                            fix_sentence_endings=True,
                        )
                        for line in intended_value:
                            sub_diff += f"{' '*intend*2}{line}\n"
                    sub_diff += f"{colorama.Fore.RESET}"
            return sub_diff

        return format_dict(diff, 0)


class HeaderContainerInverted(HeaderContainer):
    """A container with inverted header field order.

    Same as "HeaderContainer" only the tag/length/version are in reverse order in binary form.
    """

    @classmethod
    def parse_head(cls, binary: bytes) -> tuple[int, int, int]:
        """Parse binary data to get head members from inverted header.

        :param binary: Binary data
        :return: Tuple with TAG, LENGTH, VERSION
        :raises SPSDKLengthError: If binary data length is not enough
        """
        if len(binary) < 4:
            raise SPSDKLengthError(
                f"Parsing error in {cls.__name__} container head data!\n"
                "Input data must be at least 4 bytes!"
            )
        # Only SRK Table has splitted tag and version in binary format
        (tag, length, version) = unpack(HeaderContainer.format(), binary)
        return tag, length, version

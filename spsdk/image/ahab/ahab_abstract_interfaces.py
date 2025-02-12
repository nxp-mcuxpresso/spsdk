#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB abstract classes."""

from dataclasses import dataclass
from struct import calcsize, unpack
from typing import Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKLengthError, SPSDKParsingError
from spsdk.image.ahab.ahab_data import LITTLE_ENDIAN, UINT8, UINT16
from spsdk.utils.abstract import BaseClass
from spsdk.utils.verifier import Verifier, VerifierResult


class Container(BaseClass):
    """Base class for any container."""

    _parser_verifier: Optional[Verifier]

    @classmethod
    def fixed_length(cls) -> int:
        """Returns the length of a container which is fixed.

        i.e. part of a container holds fixed values, whereas some entries have
        variable length.
        """
        return calcsize(cls.format())

    def __len__(self) -> int:
        """Returns the total length of a container.

        The length includes the fixed as well as the variable length part.
        """
        return self.fixed_length()

    def __repr__(self) -> str:
        return "Base AHAB Container class: " + self.__class__.__name__

    def __str__(self) -> str:
        raise NotImplementedError("__str__() is not implemented in base AHAB container class")

    def export(self) -> bytes:
        """Serialize object into bytes array."""
        raise NotImplementedError("export() is not implemented in base AHAB container class")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array."""
        raise NotImplementedError("parse() is not implemented in base AHAB container class")

    @classmethod
    def format(cls) -> str:
        """Returns the container data format as defined by struct package.

        The base returns only endianness (LITTLE_ENDIAN).
        """
        return LITTLE_ENDIAN

    @classmethod
    def _check_fixed_input_length(cls, binary: bytes) -> Verifier:
        """Checks the data length and container fixed length.

        This is just a helper function used throughout the code.

        :param Binary: Binary input data.
        :return: The verifier object with checked minimal container length.
        """
        data_len = len(binary)
        fixed_input_len = cls.fixed_length()
        ret = Verifier("Minimal input length of container block")
        ret.add_record_range("Length", data_len, min_val=fixed_input_len)
        return ret


@dataclass
class HeaderContainerData:
    """Holder for Container header data."""

    tag: int
    length: int
    version: int

    @classmethod
    def parse(cls, binary: bytes, inverted: bool = False) -> Self:
        """Parse binary header."""
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

    def __init__(self, tag: int, length: int, version: int):
        """Class object initialized.

        :param tag: container tag.
        :param length: container length.
        :param version: container version.
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
        """Format of binary representation."""
        return super().format() + UINT8 + UINT16 + UINT8

    def verify_header(self) -> Verifier:
        """Verifies the header of container properties...

        i.e. tag e <0; 255>, otherwise an exception is raised.
        :raises SPSDKValueError: Any MAndatory field has invalid value.
        """
        return self._verify_header(self.tag, self.length, self.version, len(self))

    def verify_parsed_header(self) -> Verifier:
        """Verifies the parsed header of container properties...

        i.e. tag e <0; 255>, otherwise an exception is raised.
        :raises SPSDKValueError: Any MAndatory field has invalid value.
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
        """Verifies the header of container properties...

        i.e. tag e <0; 255>, otherwise an exception is raised.
        :raises SPSDKValueError: Any MAndatory field has invalid value.
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
            if object_length != length:
                ver_length.add_record(
                    "Computed length",
                    VerifierResult.ERROR,
                    f"The length should be {object_length} and is {length}",
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

        :param binary: Binary data.
        :raises SPSDKLengthError: Binary data length is not enough.
        :return: Tuple with TAG, LENGTH, VERSION
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
        """Compares the data length and container length.

        This is just a helper function used throughout the code.

        :param binary: Binary input data
        :return: Verifier object of parsed header
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


class HeaderContainerInverted(HeaderContainer):
    """A container with first byte defined as header - tag, length and version.

    It same as "HeaderContainer" only the tag/length/version are in reverse order in binary form.
    """

    @classmethod
    def parse_head(cls, binary: bytes) -> tuple[int, int, int]:
        """Parse binary data to get head members.

        :param binary: Binary data.
        :raises SPSDKLengthError: Binary data length is not enough.
        :return: Tuple with TAG, LENGTH, VERSION
        """
        if len(binary) < 4:
            raise SPSDKLengthError(
                f"Parsing error in {cls.__name__} container head data!\n"
                "Input data must be at least 4 bytes!"
            )
        # Only SRK Table has splitted tag and version in binary format
        (tag, length, version) = unpack(HeaderContainer.format(), binary)
        return tag, length, version

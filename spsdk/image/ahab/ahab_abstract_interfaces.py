#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB abstract classes."""

from abc import ABC
from struct import calcsize, unpack
from typing import Tuple

from spsdk.exceptions import SPSDKLengthError, SPSDKParsingError, SPSDKValueError
from spsdk.utils.misc import check_range

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0


class Container(ABC):
    """Base class for any container."""

    @classmethod
    def fixed_length(cls) -> int:
        """Returns the length of a container which is fixed.

        i.e. part of a container holds fixed values, whereas some entries have
        variable length.
        """
        return calcsize(cls._format())

    def __len__(self) -> int:
        """Returns the total length of a container.

        The length includes the fixed as well as the variable length part.
        """
        return self.fixed_length()

    @classmethod
    def _format(cls) -> str:
        """Returns the container data format as defined by struct package.

        The base returns only endianness (LITTLE_ENDIAN).
        """
        return LITTLE_ENDIAN

    def export(self) -> bytes:
        """Exports container to final bytes array.

        :return: Bytes representation of container object.
        """
        raise NotImplementedError

    @classmethod
    def _check_fixed_input_length(cls, binary: bytes) -> None:
        """Checks the data length and container fixed length.

        This is just a helper function used throughout the code.

        :param Binary: Binary input data.
        :raises SPSDKLengthError: If containers length is larger than data length.
        """
        data_len = len(binary)
        fixed_input_len = cls.fixed_length()
        if data_len < fixed_input_len:
            raise SPSDKLengthError(
                f"Parsing error in fixed part of {cls.__name__} data!\n"
                f"Input data must be at least {fixed_input_len} bytes!"
            )


class HeaderContainer(Container):
    """A container with first byte defined as header - tag, length and version.

    Every "container" in AHAB consists of a header - tag, length and version.

    The only exception is the 'image array' or 'image array entry' respectively
    which has no header at all and SRK record, which has 'signing algorithm'
    instead of version. But this can be considered as a sort of SRK record
    'version'.
    """

    TAG = 0x00
    VERSION = 0x00

    def __init__(self, tag: int, length: int, version: int):
        """Class object initialized.

        :param tag: container tag.
        :param length: container length.
        :param version: container version.
        """
        self.length = length
        self.tag = tag
        self.version = version

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (HeaderContainer, HeaderContainerInversed)):
            if (
                self.tag == other.tag
                and self.length == other.length
                and self.version == other.version
            ):
                return True

        return False

    @classmethod
    def _format(cls) -> str:
        return super()._format() + UINT8 + UINT16 + UINT8

    def validate_header(self) -> None:
        """Validates the header of container properties...

        i.e. tag e <0; 255>, otherwise an exception is raised.
        :raises SPSDKValueError: Any MAndatory field has invalid value.
        """
        if self.tag is None or not check_range(self.tag, end=0xFF):
            raise SPSDKValueError(f"AHAB: Head of Container: Invalid TAG Value: {self.tag}")
        if self.length is None or not check_range(self.length, end=0xFFFF):
            raise SPSDKValueError(f"AHAB: Head of Container: Invalid Length Value: {self.length}")
        if self.version is None or not check_range(self.version, end=0xFF):
            raise SPSDKValueError(f"AHAB: Head of Container: Invalid Version Value: {self.version}")

    @classmethod
    def parse_head(cls, binary: bytes) -> Tuple[int, int, int]:
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
        (version, length, tag) = unpack(HeaderContainer._format(), binary)
        return tag, length, version

    @classmethod
    def _check_container_head(cls, binary: bytes) -> None:
        """Compares the data length and container length.

        This is just a helper function used throughout the code.

        :param Binary: Binary input data.
        :raises SPSDKLengthError: If containers length is larger than data length.
        :raises SPSDKParsingError: If containers header value doesn't match.
        """
        cls._check_fixed_input_length(binary)
        data_len = len(binary)
        (tag, length, version) = cls.parse_head(binary[: HeaderContainer.fixed_length()])

        if (
            isinstance(cls.TAG, int)
            and tag != cls.TAG
            or isinstance(cls.TAG, list)
            and not tag in cls.TAG
        ):
            raise SPSDKParsingError(
                f"Parsing error of {cls.__name__} data!\n"
                f"Invalid TAG 0x{hex(tag)} loaded, expected 0x{hex(cls.TAG)}!"
            )

        if data_len < length:
            raise SPSDKLengthError(
                f"Parsing error of {cls.__name__} data!\n"
                f"At least {length} bytes expected, got {data_len} bytes!"
            )

        if (
            isinstance(cls.VERSION, int)
            and version != cls.VERSION
            or isinstance(cls.VERSION, list)
            and not version in cls.VERSION
        ):
            raise SPSDKParsingError(
                f"Parsing error of {cls.__name__} data!\n"
                f"Invalid VERSION {version} loaded, expected {cls.VERSION}!"
            )


class HeaderContainerInversed(HeaderContainer):
    """A container with first byte defined as header - tag, length and version.

    It same as "HeaderContainer" only the tag/length/version are in reverse order in binary form.
    """

    @classmethod
    def parse_head(cls, binary: bytes) -> Tuple[int, int, int]:
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
        (tag, length, version) = unpack(HeaderContainer._format(), binary)
        return tag, length, version

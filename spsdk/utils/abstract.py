#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK abstract base classes for common functionality.

This module provides foundational abstract classes that define common interfaces
and patterns used throughout the SPSDK library for consistent implementation
across different components.
"""

from abc import ABC, abstractmethod
from typing import Any

from typing_extensions import Self


########################################################################################################################
# Abstract Class for Data Classes
########################################################################################################################
class RawBaseClass(ABC):
    """SPSDK abstract base class for common object operations.

    This class provides a foundation for SPSDK classes with standardized equality
    comparison and string representation methods. It ensures consistent behavior
    across the SPSDK library by defining common object operations that derived
    classes must implement.
    """

    def __eq__(self, obj: Any) -> bool:
        """Check object equality.

        Compare this object with another object for equality by checking if they are
        instances of the same class and have identical attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(obj, self.__class__) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        """Check if this object is not equal to another object.

        This method implements the inequality comparison by negating the equality comparison.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    @abstractmethod
    def __repr__(self) -> str:
        """Get string representation of the object.

        :return: String representation of the object.
        """

    @abstractmethod
    def __str__(self) -> str:
        """Get string representation of the object.

        :return: Object description in string format.
        """


class BaseClass(RawBaseClass):
    """SPSDK abstract base class for serializable data objects.

    This class provides a common interface for data classes that need to be
    exported to and parsed from binary formats. It defines the essential
    methods for binary serialization and deserialization operations.
    """

    @abstractmethod
    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Object representation as bytes.
        """

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Byte array containing the serialized object data.
        :return: Parsed object instance.
        """

    def post_export(self, output_path: str) -> list[str]:
        """Post export method to handle additional operations after data export.

        This method is called after the main export process to perform any additional
        file operations or data processing that may be required.

        :param output_path: Path to store the data files of configuration.
        :return: List of created file paths.
        """
        return []

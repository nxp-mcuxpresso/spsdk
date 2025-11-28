#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK custom enumeration extensions with enhanced functionality.

This module provides extended enumeration classes that offer additional features
beyond standard Python enums, including flexible member lookup, soft enums for
dynamic values, and enhanced error handling tailored for SPSDK applications.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Type, Union, cast

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKTypeError


@dataclass(frozen=True)
class SpsdkEnumMember:
    """SPSDK Enum member representation.

    This class represents a single member of an SPSDK enumeration, containing
    the numeric tag, human-readable label, and optional description for the
    enumeration value.
    """

    tag: int
    label: str
    description: Optional[str] = None


class SpsdkEnum(SpsdkEnumMember, Enum):
    """SPSDK enhanced enumeration with extended functionality.

    This class extends Python's standard Enum to provide additional features
    for SPSDK operations including tag-based identification, label management,
    and flexible member lookup capabilities. It supports equality comparison
    by both tag and label values, and provides utility methods for member
    introspection and validation.
    """

    def __eq__(self, __value: object) -> bool:
        """Check equality of enum value with another object.

        Compares the enum instance with another object by checking if the object
        matches either the tag or label attribute of this enum value.

        :param __value: Object to compare with this enum value.
        :return: True if the object equals tag or label, False otherwise.
        """
        return self.tag == __value or self.label == __value

    def __hash__(self) -> int:
        """Calculate hash value for the enum instance.

        The hash is computed based on the combination of tag, label, and description
        attributes to ensure unique identification of enum instances.

        :return: Hash value as integer.
        """
        return hash((self.tag, self.label, self.description))

    @classmethod
    def labels(cls) -> list[str]:
        """Get list of labels of all enum members.

        :return: List of all labels.
        """
        return [value.label for value in cls.__members__.values()]

    @classmethod
    def tags(cls) -> list[int]:
        """Get list of tags of all enum members.

        :return: List of all tags.
        """
        return [value.tag for value in cls.__members__.values()]

    @classmethod
    def contains(cls, obj: Union[int, str]) -> bool:
        """Check if given member with given tag/label exists in enum.

        :param obj: Label or tag of enum member to check for existence.
        :raises SPSDKTypeError: Object must be either string or integer.
        :return: True if member exists, False otherwise.
        """
        if not isinstance(obj, (int, str)):
            raise SPSDKTypeError("Object must be either string or integer")
        try:
            cls.from_attr(obj)
            return True
        except SPSDKKeyError:
            return False

    @classmethod
    def get_tag(cls, label: str) -> int:
        """Get tag of enum member with given label.

        :param label: Label to be used for searching.
        :raises SPSDKValueError: If enum member with given label is not found.
        :return: Tag of found enum member.
        """
        value = cls.from_label(label)
        return value.tag

    @classmethod
    def get_label(cls, tag: int) -> str:
        """Get label of enum member with given tag.

        :param tag: Tag to be used for searching.
        :return: Label of found enum member.
        """
        value = cls.from_tag(tag)
        return value.label

    @classmethod
    def get_description(cls, tag: int, default: Optional[str] = None) -> Optional[str]:
        """Get description of enum member with given tag.

        :param tag: Tag to be used for searching.
        :param default: Default value if member contains no description.
        :return: Description of found enum member or default value if no description exists.
        """
        value = cls.from_tag(tag)
        return value.description or default

    @classmethod
    def from_attr(cls, attribute: Union[int, str]) -> Self:
        """Get enum member with given tag/label attribute.

        The method automatically determines whether to use tag (for int) or label (for str)
        based on the attribute type and delegates to the appropriate method.

        :param attribute: Tag value (int) or label value (str) of the enum member to find.
        :return: Found enum member matching the given attribute.
        """
        # Let's make MyPy happy, see https://github.com/python/mypy/issues/10740
        from_tag: Callable = cls.from_tag
        from_label: Callable = cls.from_label
        from_method: Callable = from_tag if isinstance(attribute, int) else from_label
        return from_method(attribute)

    @classmethod
    def from_tag(cls, tag: int) -> Self:
        """Get enum member with given tag.

        :param tag: Tag to be used for searching
        :raises SPSDKKeyError: If enum with given tag is not found
        :return: Found enum member
        """
        for item in cls.__members__.values():
            if item.tag == tag:
                return item
        raise SPSDKKeyError(f"There is no {cls.__name__} item in with tag {tag} defined")

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Get enum member with given label.

        The method performs case-insensitive search through all enum members to find
        the one with matching label.

        :param label: Label to be used for searching
        :raises SPSDKKeyError: If enum with given label is not found or label is not string
        :return: Found enum member
        """
        if not isinstance(label, str):
            raise SPSDKKeyError("Label must be string")
        for item in cls.__members__.values():
            if item.label.upper() == label.upper():
                return item
        raise SPSDKKeyError(f"There is no {cls.__name__} item with label {label} defined")

    @classmethod
    def create_from_dict(cls, name: str, config: dict[str, Union[tuple, list]]) -> Type[Self]:
        """Create the Enum in runtime from the Dictionary configuration.

        The method dynamically creates an Enum class using the provided name and configuration
        dictionary. All dictionary values are converted to tuples before creating the Enum.

        :param name: Name of the new Enum class to be created.
        :param config: Configuration dictionary containing enum definitions where values can be
            tuples or lists.
        :return: Dynamically created Enum class.
        """
        updated_config = {}
        for k, v in config.items():
            updated_config[k] = tuple(v)
        return cls(name, updated_config)  # type:ignore # pylint: disable=too-many-function-args


class SpsdkSoftEnum(SpsdkEnum):
    """SPSDK Soft Enum with graceful error handling.

    This enum variant provides default fallback values for labels and descriptions
    when accessing non-existing enum members, preventing exceptions during lookup
    operations and returning descriptive "Unknown" values instead.
    """

    @classmethod
    def get_label(cls, tag: int) -> str:
        """Get label of enum member with given tag.

        If member not found, returns a formatted string with the unknown tag value
        instead of raising an exception.

        :param tag: Tag value to search for in enum members.
        :return: Label of found enum member or "Unknown (tag)" if not found.
        """
        try:
            return super().get_label(tag)
        except SPSDKKeyError:
            return f"Unknown ({tag})"

    @classmethod
    def get_description(cls, tag: int, default: Optional[str] = None) -> Optional[str]:
        """Get description of enum member with given tag.

        The method searches for an enum member by tag and returns its description.
        If the member is not found, returns a formatted unknown message with the tag.

        :param tag: Tag to be used for searching the enum member.
        :param default: Default value if member contains no description.
        :return: Description of found enum member or formatted unknown message.
        """
        try:
            return super().get_description(tag, default)
        except SPSDKKeyError:
            return f"Unknown ({tag})"

    @classmethod
    def from_tag(cls, tag: int) -> Self:
        """Get enum member with given tag.

        This method attempts to find an enum member by its tag value. If the tag is not found
        in the current enum, it creates a dynamic UnknownEnum placeholder to handle the
        unrecognized value gracefully while maintaining enum structure integrity.

        :param tag: Integer tag value to search for in the enum.
        :raises SPSDKKeyError: If enum with given tag is not found in parent implementation.
        :return: Found enum member or dynamically created UnknownEnum placeholder.
        """
        try:
            return super().from_tag(tag)
        except SPSDKKeyError:

            class UnknownEnum(SpsdkEnum):
                """SPSDK Enum placeholder for unknown enumeration values.

                This class represents a dynamically created enum entry that serves as a fallback
                when encountering unrecognized enumeration tags, providing a standardized way to
                handle unknown values while maintaining enum structure integrity.

                :cvar UNKNOWN: Placeholder enum entry for unrecognized tag values.
                """

                UNKNOWN = (
                    tag,
                    f"{cls.__name__}:Unknown_{hex(tag)}",
                    f"This is non-existing tag({hex(tag)}) from enum: {cls.__name__}",
                )

            return cast(Self, UnknownEnum).from_tag(tag)

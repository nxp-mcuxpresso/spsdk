#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK custom enumeration extensions with enhanced functionality.

This module provides extended enumeration classes that offer additional features
beyond standard Python enums, including flexible member lookup, soft enums for
dynamic values, and enhanced error handling tailored for SPSDK applications.
"""

from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional, Sequence, Type, Union, cast

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKTypeError

if TYPE_CHECKING:
    from spsdk.utils.database import Features


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
        return cls(name, updated_config)  # type: ignore # pylint: disable=too-many-function-args


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


class SpsdkDynamicEnum:
    """SPSDK Dynamic Enumeration loader from database.

    This class provides functionality for dynamically loading enumeration classes
    from database configurations at runtime. It acts as a factory and proxy for
    dynamically created enum types, supporting lazy loading and caching.
    """

    def __init__(
        self,
        db: "Features",
        feature: str,
        enum_key: str,
        enum_name: str,
        base_key: Optional[list[str]] = None,
        fallback_enum: Optional[Type[SpsdkEnum]] = None,
    ):
        """Initialize dynamic enum loader.

        :param db: Database instance to load from
        :param feature: Database feature identifier
        :param enum_key: Key in database where enum data is stored
        :param enum_name: Name for the dynamically created enum class
        :param base_key: Optional hierarchical keys for nested database access
        :param fallback_enum: Optional fallback enum class if database load fails
        """
        self._db = db
        self._feature = feature
        self._enum_key = enum_key
        self._enum_name = enum_name
        self._base_key = base_key
        self._fallback_enum = fallback_enum
        self._cached_enum: Optional[Type[SpsdkEnum]] = None

    def _make_key(self, key: str) -> Union[str, list[str]]:
        """Create a composite key from base key and provided key.

        :param key: The key to be combined with base key.
        :return: Original key if no base key exists, otherwise list with base key elements and new key.
        """
        if self._base_key is None:
            return key
        ret = []
        ret.extend(self._base_key)
        ret.append(key)
        return ret

    def _get_enum_class(self) -> Type[SpsdkEnum]:
        """Get or create the dynamic enum class.

        Loads enum data from database and creates a SpsdkSoftEnum class. Results are
        cached to avoid repeated database queries. Falls back to fallback_enum if
        database load fails.

        :return: Dynamically created or fallback enum class
        """
        if self._cached_enum is not None:
            return self._cached_enum

        try:
            enum_data = self._db.get_dict(self._feature, self._make_key(self._enum_key))
            self._cached_enum = cast(
                Type[SpsdkEnum],
                SpsdkSoftEnum.create_from_dict(self._enum_name, enum_data),
            )
            return self._cached_enum
        except Exception:
            if self._fallback_enum:
                self._cached_enum = self._fallback_enum
                return self._cached_enum
            raise

    @classmethod
    def create_from_db(
        cls,
        db: "Features",
        feature: str,
        enum_key: str,
        enum_name: str,
        base_key: Optional[list[str]] = None,
        fallback_enum: Optional[Type[SpsdkEnum]] = None,
    ) -> Type[SpsdkEnum]:
        """Create a dynamic enum class from database configuration.

        This is a convenience class method that creates an instance and immediately
        returns the loaded enum class.

        :param db: Database instance to load from
        :param feature: Database feature identifier
        :param enum_key: Key in database where enum data is stored
        :param enum_name: Name for the dynamically created enum class
        :param base_key: Optional hierarchical keys for nested database access
        :param fallback_enum: Optional fallback enum class if database load fails
        :return: Dynamically created enum class
        """
        instance = cls(
            db=db,
            feature=feature,
            enum_key=enum_key,
            enum_name=enum_name,
            base_key=base_key,
            fallback_enum=fallback_enum,
        )
        return instance._get_enum_class()

    def __iter__(self) -> Iterator:
        """Make the dynamic enum iterable by delegating to the underlying enum class.

        :return: Iterator over enum members
        """
        return iter(self._get_enum_class())

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the underlying enum class.

        :param name: Attribute name to access
        :return: Attribute value from the enum class
        """
        return getattr(self._get_enum_class(), name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Make the instance callable by delegating to the underlying enum class.

        :return: Result of calling the enum class
        """
        return self._get_enum_class()(*args, **kwargs)


class SpsdkIntFlag(IntFlag):
    """SPSDK enhanced integer flag enumeration with extended functionality.

    This class extends Python's standard IntFlag to provide additional features
    for SPSDK operations including flexible flag creation from various input types,
    validation of unknown flags, and enhanced flag manipulation capabilities.

    SpsdkIntFlag supports bitwise operations and provides utility methods for:
    - Creating flags from labels, values, or mixed lists
    - Converting flag combinations back to individual components
    - Validating flag values against defined enum members
    - Case-insensitive label lookup

    Example:
        >>> class HouseFeatures(SpsdkIntFlag):
        ...     HEATING = 1
        ...     AC = 2
        ...     ELECTRICITY = 4
        ...     GAS = 8

        >>> # Create from labels
        >>> features = HouseFeatures.from_labels(["HEATING", "AC"])
        >>> print(features.value)  # 3

        >>> # Create from mixed list
        >>> features = HouseFeatures.from_list(["heating", 4, HouseFeatures.GAS])
        >>> print(features.value)  # 13

        >>> # Convert back to individual flags
        >>> individual = features.to_list()
        >>> print([f.name for f in individual])  # ['HEATING', 'ELECTRICITY', 'GAS']

        >>> # Check for unknown flags
        >>> unknown_flags = HouseFeatures(1000)
        >>> print(unknown_flags.has_unknown_flags())  # True

    Note:
        Unlike standard IntFlag, this class provides enhanced error handling
        and validation capabilities specifically designed for SPSDK applications.
        All label-based operations are case-insensitive for improved usability.
    """

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Get flag by label name."""
        # Case-insensitive search through members
        label_upper = label.upper()
        for name, item in cls.__members__.items():
            if name == label_upper:
                return item

        raise SPSDKKeyError(f"There is no {cls.__name__} item with label {label} defined")

    @classmethod
    def from_labels(cls, labels: list[str]) -> Self:
        """Get flag by label name."""
        combined = cls(0)
        for label in labels:
            combined |= cls.from_label(label)
        return combined

    @classmethod
    def from_values(cls, values: list[int]) -> Self:
        """Get flag by label name."""
        result = cls(0)
        for value in values:
            result |= cls(value)
        return result

    @classmethod
    def from_list(cls, items: Sequence[Union[str, int, "Self"]]) -> Self:
        """Get flag from mixed list of labels and values.

        :param items: List containing label strings and/or integer values
        :return: Combined flag value
        """
        result = cls(0)
        for item in items:
            if isinstance(item, str):
                result |= cls.from_label(item)
            elif isinstance(item, cls):
                result |= item
            else:
                result |= cls(item)
        return result

    def to_list(self) -> list[Self]:
        """Get list of SMR items from the map.

        :return: List of SMR items (0-31) that are set in the map
        """
        items = []
        for member in self.__class__.__members__.values():
            if member.value == 0:
                # Special case: if there's a zero-valued flag and self is zero, include it
                if self.value == 0:
                    items.append(member)
            else:
                # Check if this member is a single bit flag (power of 2) and is set in self
                if (member & (member - 1)) == 0 and (self & member):
                    items.append(member)
        return items

    @property
    def has_unknown_flags(self) -> bool:
        """Check if this flag combination contains any undefined/unknown flags.

        This method verifies whether the current flag value contains any bits
        that are not defined as valid enum members. This can happen when creating
        a flag instance with arbitrary integer values that don't correspond to
        defined enum members.

        :return: True if unknown flags are present, False if all flags are defined

        Example:
            >>> class MyFlags(SpsdkIntFlag):
            ...     FLAG_A = 1
            ...     FLAG_B = 2
            >>> valid_flags = MyFlags(3)  # FLAG_A | FLAG_B
            >>> valid_flags.has_unknown_flags()
            False
            >>> invalid_flags = MyFlags(1000)  # Contains undefined bits
            >>> invalid_flags.has_unknown_flags()
            True
        """
        if self.value == 0:
            return False

        # Get all valid flag values (powers of 2) from enum members
        valid_flags = 0
        for member in self.__class__.__members__.values():
            if member != 0:
                valid_flags |= member.value

        # Check if current value has any bits set that are not in valid_flags
        return (self.value & ~valid_flags) != 0

# Copyright 2019 Martin Olejar
# Copyright 2020-2021 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0

"""EasyEnum allows numerical value, string tag and description to an enum element."""

__author__ = "Martin Olejar"
__contact__ = "martin.olejar@gmail.com"
__version__ = "0.4.0"
__license__ = "Apache 2.0"
__status__ = "Development"
__all__ = ["Enum"]

from typing import Sequence, Union

EnumKeyType = Union[str, int]


class MetaEnum(type):
    """Meta Class for Enum Type."""

    def __new__(mcs, name, bases, attrs):
        cls = super().__new__(mcs, name, bases, attrs)
        cls._items_ = list()
        for attr, value in attrs.items():
            if attr in set(dir(type(name, (object,), {}))) or (
                attr.startswith("_") and attr.endswith("_")
            ):
                continue
            if isinstance(value, (classmethod, staticmethod)):
                continue
            if isinstance(value, tuple):
                if len(value) == 2:
                    cls._items_.append((attr, value[0], value[1]))
                else:
                    cls._items_.append((value[1], value[0], value[2]))
                setattr(cls, attr, value[0])
            else:
                assert isinstance(value, int)
                cls._items_.append((attr, value, ""))
        return cls

    def __getitem__(cls, key):
        if isinstance(key, str):
            for name, value, _ in cls._items_:
                if key.upper() == name.upper():
                    return value
            raise KeyError("'%s' has no item with name '%s'" % (cls.__name__, key))

        if isinstance(key, int):
            for name, value, _ in cls._items_:
                if key == value:
                    return name
            raise KeyError("'%s' has no item with value '%d'" % (cls.__name__, key))

        raise TypeError("'%s' has no item with type '%r'" % (cls.__name__, type(key)))

    def __iter__(cls):
        return (item for item in cls._items_)

    def __contains__(cls, item):
        if isinstance(item, str) and item in (item[0] for item in cls._items_):
            return True
        if isinstance(item, int) and item in (item[1] for item in cls._items_):
            return True
        return False

    def __len__(cls):
        return len(cls._items_)


class Enum(metaclass=MetaEnum):
    """Enum Type Class."""

    @classmethod
    def get(cls, key: EnumKeyType, default: EnumKeyType = None) -> str:
        """Converts enumeration value to name OR name to enumeration value.

        :param key: either value or name (name is case INSENSITIVE)
        :param default: value in case key does not exist
        :return: name for value; value for name
        """
        try:
            return cls[key]
        except KeyError:
            return default

    @classmethod
    def desc(cls, key: EnumKeyType, default: str = "") -> str:
        """Description of the specified value.

        :param key: either value or name (name is case INSENSITIVE)
        :param default: value in case key does not exist
        :return: description of the value; empty string if description was not specified
        :raises TypeError: Key is nor string or int
        """
        # pylint: disable=no-member
        if isinstance(key, str):
            for name, _, desc in cls._items_:
                if key.upper() == name.upper():
                    return desc
            return default

        if isinstance(key, int):
            for _, value, desc in cls._items_:
                if key == value:
                    return desc
            return default

        raise TypeError("'%s' has no item with type '%r'" % (cls.__name__, type(key)))

    @classmethod
    def name(cls, key: int, default: str = None) -> str:
        """Returns name of selected enumeration tag.

        :param key: enumeration tag
        :param default: value to return of tag not found; if not defined, KeyError exception will be raised
        :return: name of the corresponding enumeration tag
        :raise KeyError: if tag not supported and default value not provided
        """
        # pylint: disable=no-member
        for name, value, _ in cls._items_:
            if key == value:
                return name

        if default is None:
            raise KeyError("Enumeration not supported: " + str(key))

        return default

    @classmethod
    def tags(cls) -> Sequence[int]:
        """Return sequence of all enumerations tags."""
        # pylint: disable=no-member
        return [tag for _, tag, _ in cls._items_]

    @classmethod
    def from_int(cls, value: int) -> "Enum":
        """Converts integer value into enumeration.

        Note: the method does two things:
        - checks whether given integer value is defined within the enumeration
        - formally converts value into enumeration (for type hints), even the returned value is same as input
        :param value: integer value to be converted
        :return: corresponding enumeration
        :raises ValueError: if specified value does not match any enumeration value
        """
        if value not in cls.tags():
            raise ValueError(
                f"the following integer value is not defined within the enumeration: {str(value)}"
            )

        return value

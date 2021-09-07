# Copyright 2020-2021 NXP
# This is stub for Enum class implemented in easy_enum, to provide info about differences implemented in Meta class

from enum import IntEnum
from typing import Iterator, Optional, Sequence, Tuple, Type, TypeVar, Union

# type that represents a key for enum: either integer or string (name)
EnumKeyType = Union[str, int]

# forward for Enum type
TEnumType = TypeVar("TEnumType", bound="Enum")

class Enum(IntEnum):
    @classmethod
    def get(
        cls: Type[TEnumType], key: EnumKeyType, default: Optional[EnumKeyType] = None
    ) -> Optional[EnumKeyType]:
        """Converts enumeration value to name OR name to enumeration value

        :param key: either value or name (name is case INSENSITIVE)
        :param default: value in case key does not exist
        :return: name for value; value for name
        """
        pass
    @classmethod
    def desc(cls: Type[TEnumType], key: EnumKeyType, default: str = "") -> str:
        """Description of the specified value

        :param key: either value or name (name is case INSENSITIVE)
        :param default: value in case key does not exist
        :return: description of the value; empty string if description was not specified
        """
        pass
    # noinspection PyMethodOverriding
    @classmethod
    def name(cls: Type[TEnumType], key: int, default: Optional[str] = None) -> str:  # type: ignore
        """Name of the specified value

        :param key: enumeration value (integer)
        :param default: value in case key does not exist
        :return: description of the value; empty string if description was not specified
        """
        pass
    @classmethod
    def tags(cls: Type[TEnumType]) -> Sequence[TEnumType]:
        pass
    @classmethod
    def from_int(cls: Type[TEnumType], value: int) -> TEnumType:
        pass
    def __iter__(self) -> Iterator[Tuple[str, int, str]]:
        """Deprecated, use self.tags() instead"""
        pass
    def __contains__(self, tag: EnumKeyType) -> bool:
        pass

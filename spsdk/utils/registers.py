#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK register configuration and management utilities.

This module provides comprehensive functionality for handling register descriptions,
configurations, and operations within the SPSDK framework. It includes support for
register bit fields, access control, enumeration handling, and configuration processing
with validation capabilities.
"""

import json
import logging
from typing import Any, Generic, Iterator, Mapping, Optional, Type, TypeVar, Union, cast

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.binary_image import BinaryImage, BinaryPattern
from spsdk.utils.config import Config, PreValidationHook
from spsdk.utils.database import get_whole_db
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import (
    Endianness,
    format_value,
    get_bytes_cnt_of_int,
    load_configuration,
    value_to_bool,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

HTMLDataElement = Mapping[str, Union[str, dict, list]]
HTMLData = list[HTMLDataElement]

logger = logging.getLogger(__name__)


class Access(SpsdkEnum):
    """Register access mode enumeration for SPSDK operations.

    Defines access permissions for register and bitfield operations including
    read-only, write-only, read-write, and special access modes. Provides
    utility methods to check readability and writability of access modes.
    """

    NONE = (0, "none", "Not applicable")
    RO = (1, "RO", "Read-only")
    RW = (2, "RW", "Read/Write")
    WO = (3, "WO", "Write-only")
    WRITE_CONST = (4, "WRITE_CONST", "Accepts only default value")

    @property
    def is_readable(self) -> bool:
        """Check if the access mode allows read operations.

        :return: True if the object has read access (RO or RW), False otherwise.
        """
        return self in [Access.RO, Access.RW]

    @property
    def is_writable(self) -> bool:
        """Check if the access mode allows write operations.

        :return: True if the access mode is write-only, read-write, or write-constant, False otherwise.
        """
        return self in [Access.WO, Access.RW, Access.WRITE_CONST]

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Get enum member with given label.

        The method accepts labels with forward slashes (like R/W, R/O) by removing
        the slash characters before searching for the enum member.

        :param label: Label to be used for searching the enum member.
        :return: Found enum member matching the processed label.
        """
        return super().from_label(label.replace("/", ""))  # accept also R/W, R/O etc.


class RegsEnum:
    """Register enumeration value container for SPSDK register operations.

    This class represents a single enumeration value within a register bitfield,
    storing the name, numeric value, description, and formatting information.
    It provides functionality to create enumerations from specifications and
    convert between different value representations.
    """

    def __init__(
        self,
        name: str,
        value: Any,
        description: str,
        max_width: int = 0,
        deprecated_names: Optional[list[str]] = None,
    ) -> None:
        """Initialize RegsEnum with enumeration information for bitfield.

        Used to store enumeration data including name, value, description and formatting options.

        :param name: Name of enumeration.
        :param value: Value of enumeration.
        :param description: Text description of enumeration.
        :param max_width: Maximal width of enum value used to format output.
        :param deprecated_names: Optional list of deprecated names for this enum.
        :raises SPSDKRegsError: Invalid input value.
        """
        self.name = name or "N/A"
        try:
            self.value = value_to_int(value)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {value}") from exc
        self.description = description or ""
        self.max_width = max_width
        self.deprecated_names = [x for x in deprecated_names] if deprecated_names else []

    @classmethod
    def create_from_spec(cls, spec: dict[str, Any], maxwidth: int = 0) -> Self:
        """Create Enum instance from specification dictionary.

        The method parses enumeration specification data and creates a new Enum instance
        with validated name, value, description, and optional deprecated names.

        :param spec: Input specification dictionary containing enumeration data including 'name',
                     'value', 'description', and optionally 'deprecated_names'.
        :param maxwidth: The maximal width of bitfield for this enum (used for formatting).
        :return: The instance of this class.
        :raises SPSDKRegsError: Error during JSON data parsing or invalid enum value.
        """
        name = spec.get("name", "N/A")
        if "value" not in spec:
            raise SPSDKRegsError(f"Missing Enum Value Key for {name}.")

        raw_val = spec["value"]
        try:
            value = value_to_int(raw_val)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {raw_val}") from exc

        description = spec.get("description", "N/A")
        deprecated_names = spec.get("deprecated_names", [])

        return cls(name, value, description, maxwidth, deprecated_names=deprecated_names)

    def create_spec(self) -> dict[str, Union[str, int]]:
        """Creates the enumeration specification.

        The method builds a dictionary containing the enumeration's name, value, description,
        and optionally deprecated names if they exist.

        :return: The specification dictionary containing enum properties.
        """
        spec: dict[str, Union[str, int, list[str]]] = {}
        spec["name"] = self.name
        spec["value"] = self.value
        spec["description"] = self.description
        if self.deprecated_names:
            spec["deprecated_names"] = self.deprecated_names
        return cast(dict[str, Union[str, int]], spec)

    def get_value_int(self) -> int:
        """Get integer value of the enum.

        :return: Integer value of the enum.
        """
        return self.value

    def get_value_str(self) -> str:
        """Get formatted string representation of the register value.

        The method formats the current register value using the maximum width
        specification to ensure consistent string representation.

        :return: Formatted string with the register value.
        """
        return format_value(self.value, self.max_width)

    def __str__(self) -> str:
        """Return string representation of the register.

        Provides a formatted string containing the register's name, current value,
        and description for debugging and display purposes.

        :return: Formatted string with register information including name, value, and description.
        """
        output = ""
        output += f"Name:        {self.name}\n"
        output += f"Value:       {self.get_value_str()}\n"
        output += f"Description: {self.description}\n"

        return output


class ConfigProcessor:
    """SPSDK Configuration Processor base class.

    This class provides a foundation for processing configuration data with support for
    value transformation, parameter parsing, and configuration string handling. It serves
    as a base class for implementing specific configuration processors that can pre-process
    and post-process values during configuration operations.

    :cvar NAME: Processor identifier name used for registration and identification.
    """

    NAME = "NOP"

    def __init__(self, description: str = "") -> None:
        """Initialize the processor.

        :param description: Description of the processor, defaults to empty string.
        """
        self.description = description

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file.

        :param value: Integer value from configuration file to be processed.
        :return: Processed integer value.
        """
        return value

    def post_process(self, value: int) -> int:
        """Post-process value going to config file.

        :param value: The integer value to be post-processed.
        :return: The post-processed integer value.
        """
        return value

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file.

        :param value: The input value to be processed.
        :return: The processed value with updated bit-width.
        """
        return value

    @classmethod
    def get_method_name(cls, config_string: str) -> str:
        """Get config processor method name from configuration string.

        Extracts the method name portion from a configuration string by splitting
        on the first colon separator.

        :param config_string: Configuration string containing method name and parameters.
        :return: Method name extracted from the configuration string.
        """
        return config_string.split(":")[0]

    @classmethod
    def get_params(cls, config_string: str) -> dict[str, int]:
        """Parse configuration string to extract processor method parameters.

        Extracts parameters from a configuration string in the format 'method:param1=value1,param2=value2'.
        The method name and parameters are separated by colon, individual parameters are separated by
        commas, and each parameter follows the 'name=value' format.

        :param config_string: Configuration string containing method and parameters
        :raises SPSDKRegsError: Invalid parameter format in configuration string
        :return: Dictionary with parameter names as keys and integer values
        """

        def split_params(param: str) -> tuple[str, str]:
            """Split key=value pair into a tuple.

            Parse a parameter string in the format 'key=value' and return the key and value
            as separate strings in a tuple.

            :param param: Parameter string in format 'key=value' to be split.
            :raises SPSDKRegsError: Invalid parameter format (not exactly one '=' separator).
            :return: Tuple containing the key and value as separate strings.
            """
            parts = param.split("=")
            if len(parts) != 2:
                raise SPSDKRegsError(
                    f"Invalid param setting: '{param}'. Expected format '<name>=<value>'"
                )
            return (parts[0], parts[1])

        parts = config_string.split(";", maxsplit=1)[0].split(":")
        if len(parts) == 1:
            return {}
        params = parts[1].split(",")
        params_dict: dict[str, str] = dict(split_params(p) for p in params)
        return {key.lower(): value_to_int(value) for key, value in params_dict.items()}

    @classmethod
    def get_description(cls, config_string: str) -> str:
        """Extract description from configuration string.

        Parses a configuration string to extract the description part that follows
        the DESC= prefix after a semicolon separator.

        :param config_string: Configuration string containing description after semicolon.
        :return: Extracted description with DESC= prefix removed.
        """
        parts = config_string.partition(";")
        return parts[2].replace("DESC=", "")

    @classmethod
    def from_str(cls, config_string: str) -> "ConfigProcessor":
        """Create config processor instance from configuration string.

        :param config_string: Configuration string to process.
        :return: New ConfigProcessor instance.
        """
        return cls(config_string)

    @classmethod
    def from_spec(cls, spec: Optional[str]) -> Optional["ConfigProcessor"]:
        """Create config processor from JSON data entry.

        Factory method that creates appropriate ConfigProcessor subclass instance based on
        the method name extracted from the specification string.

        :param spec: JSON specification string containing processor configuration, None if not specified.
        :return: ConfigProcessor instance of appropriate subclass, or None if spec is None or no
            matching processor found.
        """
        if spec is None:
            return None
        method_name = cls.get_method_name(config_string=spec)
        for klass in cls.__subclasses__():
            if klass.NAME == method_name:
                return klass.from_str(config_string=spec)
        return None


class ShiftRightConfigProcessor(ConfigProcessor):
    """SPSDK Configuration Processor for right-shift bit operations.

    This processor handles bit-shifting operations on register values, shifting bits to the right
    during pre-processing and to the left during post-processing. It automatically adjusts bit
    width calculations to accommodate the shift operations.

    :cvar NAME: Processor identifier string for configuration parsing.
    """

    NAME = "SHIFT_RIGHT"

    def __init__(self, count: int, description: str = "") -> None:
        """Initialize the right-shift config processor.

        :param count: Count of bits for shift operation.
        :param description: Extra description for config processor, defaults to empty string.
        """
        super().__init__(
            description=description or f"Actual binary value is shifted by {count} bits to right."
        )
        self.count = count

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file.

        Performs a right bit shift operation on the input value by the count of bits
        specified in the register field configuration.

        :param value: The integer value to be pre-processed from config file.
        :return: The pre-processed value after right bit shift operation.
        """
        return value >> self.count

    def post_process(self, value: int) -> int:
        """Post-process value going to config file.

        Shifts the input value left by the count of bits specified in the register configuration.

        :param value: The integer value to be post-processed.
        :return: The value shifted left by self.count bits.
        """
        return value << self.count

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file.

        :param value: The input value to be updated.
        :return: Updated value with count added to it.
        """
        return value + self.count

    @classmethod
    def from_str(cls, config_string: str) -> "ShiftRightConfigProcessor":
        """Create config processor instance from configuration string.

        Parses the configuration string to extract method name, parameters, and description,
        then creates a new ShiftRightConfigProcessor instance with the specified count value.

        :param config_string: Configuration string containing method name, parameters and description.
        :raises SPSDKRegsError: Invalid method name or missing COUNT parameter.
        :return: New ShiftRightConfigProcessor instance configured with parsed parameters.
        """
        name = cls.get_method_name(config_string=config_string)
        if name != cls.NAME:
            raise SPSDKRegsError(f"Invalid method name '{name}' expected {cls.NAME}")
        params = cls.get_params(config_string=config_string)
        if "count" not in params:
            raise SPSDKRegsError(f"{cls.NAME} requires the COUNT parameter")
        description = cls.get_description(config_string=config_string)
        return cls(count=value_to_int(params["count"]), description=description)


class RegsBitField:
    """Register bitfield representation and management.

    This class represents a single bitfield within a register, providing
    functionality to manage bitfield properties such as offset, width,
    access permissions, and enumerated values. It handles bitfield
    configuration, validation, and value operations within the SPSDK
    register framework.
    """

    def __init__(
        self,
        parent: "Register",
        name: str,
        offset: int,
        width: int,
        uid: str,
        description: Optional[str] = None,
        access: Access = Access.RW,
        reserved: bool = False,
        config_processor: Optional[ConfigProcessor] = None,
        no_yaml_comments: bool = False,
        deprecated_names: Optional[list[str]] = None,
    ) -> None:
        """Initialize RegsBitField instance.

        Constructor for RegsBitField class used to store and manage bitfield information
        within a register structure.

        :param parent: Parent register containing this bitfield.
        :param name: Name identifier of the bitfield.
        :param offset: Bit offset position within the register.
        :param width: Width of the bitfield in bits.
        :param uid: Unique identifier for the bitfield.
        :param description: Optional text description of the bitfield functionality.
        :param access: Access permissions for the bitfield (read/write/etc).
        :param reserved: Flag to hide bitfield from standard searches if True.
        :param config_processor: Optional processor for configuration handling.
        :param no_yaml_comments: Flag to disable YAML comments generation if True.
        :param deprecated_names: Optional list of deprecated names for this bitfield.
        """
        self.parent = parent
        self.name = name or "N/A"
        self.offset = offset
        self.width = width
        self.uid = uid
        self.description = description or "N/A"
        self.access = access
        self.reserved = reserved
        self._enums: list[RegsEnum] = []
        self.config_processor = config_processor or ConfigProcessor()
        self.config_width = self.config_processor.width_update(width)
        self.no_yaml_comments = no_yaml_comments
        self.deprecated_names = deprecated_names or []

    @classmethod
    def create_from_spec(
        cls,
        spec: dict[str, Any],
        offset: int,
        parent: "Register",
        bitfield_mods: Optional[dict[str, Any]] = None,
    ) -> "RegsBitField":
        """Create register bitfield from specification dictionary.

        The method parses the specification dictionary to extract bitfield properties
        and creates a new RegsBitField instance with optional modifications applied.

        :param spec: Dictionary containing bitfield specification data including width, name, description.
        :param offset: Bit offset position within the parent register.
        :param parent: Parent Register object that contains this bitfield.
        :param bitfield_mods: Optional dictionary with modifications to override spec values.
        :return: New RegsBitField instance created from the specification.
        """
        width = value_to_int(spec.get("width", 0))
        uid = spec.get("id", cls._create_uid(parent.uid, offset, width))
        name = spec.get("name")
        reserved = bool(name is None or name.lower().startswith("reserved"))
        description = spec.get("description", "N/A")
        access = Access.from_label(spec.get("access", "RW"))
        deprecated_names = spec.get("deprecated_names", [])
        config_processor = ConfigProcessor()
        no_yaml_comments = False
        # Apply bitfield modifications if available
        if bitfield_mods:
            if "reserved" in bitfield_mods:
                reserved = value_to_bool(bitfield_mods["reserved"])
            if "config_processor" in bitfield_mods:
                config_processor = (
                    ConfigProcessor.from_spec(bitfield_mods["config_processor"])
                    or ConfigProcessor()
                )
            if "no_yaml_comments" in bitfield_mods:
                no_yaml_comments = value_to_bool(bitfield_mods["no_yaml_comments"])

        bitfield = cls(
            parent,
            name or f"reserved_{uid}",
            offset,
            width,
            uid,
            description,
            access,
            reserved,
            config_processor,
            no_yaml_comments,
            deprecated_names=deprecated_names,
        )

        for enum_spec in spec.get("values", []):
            bitfield.add_enum(RegsEnum.create_from_spec(enum_spec, width))

        return bitfield

    @staticmethod
    def _create_uid(reg_uid: str, offset: int, width: int) -> str:
        """Generate a consistent UID for bitfields based on parent register and bitfield properties.

        :param reg_uid: Parent register's UID
        :param offset: Bitfield offset within the register
        :param width: Bitfield width in bits
        :return: Generated unique identifier string
        """
        if width == 1:
            bitfield_id = f"-bit{offset}"
        else:
            bitfield_id = f"-bits{offset}-{offset+width-1}"
        return reg_uid + bitfield_id

    def _get_uid(self) -> str:
        """Get UID of register.

        Returns the unique identifier for this register. If the register already has
        a UID assigned, it returns that value. Otherwise, it creates a new UID based
        on the parent's UID, offset, and width.

        :return: Unique identifier string for the register.
        """
        if self.uid:
            return self.uid

        return self._create_uid(self.parent._get_uid(), self.offset, self.width)

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        The method builds a dictionary containing all register bitfield properties including
        offset, width, access type, description, and optional enumeration values.

        :return: Dictionary with register bitfield specification containing id, offset, width,
            access type, description and optional values/deprecated_names.
        """
        spec: dict[str, Any] = {}
        spec["id"] = self._get_uid()
        spec["offset"] = hex(self.offset)
        spec["width"] = str(self.width)
        if not self.reserved:
            spec["name"] = self.name
        spec["access"] = self.access.label
        spec["description"] = self.description
        enums = []
        for enum in self._enums:
            enums.append(enum.create_spec())
        if enums:
            spec["values"] = enums
        if self.deprecated_names:
            spec["deprecated_names"] = self.deprecated_names
        return spec

    def has_enums(self) -> bool:
        """Check if the bitfield has enumeration values defined.

        :return: True if enums are defined, False otherwise.
        """
        return len(self._enums) > 0

    def get_enums(self) -> list[RegsEnum]:
        """Get bitfield enums.

        :return: List of bitfield enumeration values.
        """
        return self._enums

    def add_enum(self, enum: RegsEnum) -> None:
        """Add bitfield enum.

        :param enum: New enumeration value for bitfield.
        """
        self._enums.append(enum)

    def get_value(self) -> int:
        """Get integer value of the bitfield.

        Extracts and returns the current value of this bitfield from its parent register.
        The method retrieves the parent register value, applies bit shifting and masking
        to extract the relevant bits, and processes the result through the configuration
        processor.

        :return: Current integer value of the bitfield after post-processing.
        """
        reg_val = self.parent.get_value(raw=False)
        value = reg_val >> self.offset
        mask = (1 << self.width) - 1
        value = value & mask
        value = self.config_processor.post_process(value)
        return value

    def get_reset_value(self) -> int:
        """Get reset value of the bitfield.

        Extracts and returns the reset value for this specific bitfield from the parent register's
        reset value. The method applies bit shifting, masking, and post-processing to isolate the
        bitfield's portion of the register.

        :return: Reset value of the bitfield as an integer.
        """
        reg_val = self.parent.get_reset_value()
        value = reg_val >> self.offset
        mask = (1 << self.width) - 1
        value = value & mask
        value = self.config_processor.post_process(value)
        return value

    def set_value(self, new_val: Any, raw: bool = False, no_preprocess: bool = False) -> None:
        """Updates the value of the bitfield.

        The method modifies the bitfield value within its parent register by applying proper masking
        and bit shifting operations. The value can be preprocessed and automatically modified unless
        explicitly disabled.

        :param new_val: New value to set for the bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :param no_preprocess: If set, no pre-processing of value is applied.
        :raises SPSDKValueError: The input value is out of bitfield range.
        """
        new_val_int = value_to_int(new_val)
        if not no_preprocess:
            new_val_int = self.config_processor.pre_process(new_val_int)
        if new_val_int > 1 << self.width:
            raise SPSDKValueError("The input value is out of bitfield range")
        reg_val = self.parent.get_value(raw=raw)

        mask = ((1 << self.width) - 1) << self.offset
        reg_val = reg_val & ~mask
        value = (new_val_int << self.offset) & mask
        reg_val = reg_val | value
        self.parent.set_value(reg_val, raw)

    def set_enum_value(self, new_val: Union[str, int], raw: bool = False) -> None:
        """Update bitfield value using enum value or integer.

        The input value can be either string enum or integer. If string is used, the method tries to decode it.
        Special RAW unprocessed values can be passed as string prefixed with RAW:.

        :param new_val: New enum value of bitfield (string enum name or integer value).
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKRegsErrorEnumNotFound: Input value cannot be decoded.
        """
        no_preprocess = False
        try:
            val_int = self.get_enum_constant(new_val)
        except SPSDKRegsErrorEnumNotFound:
            # Special scenario for passing raw values when the value is prefixed with RAW
            if isinstance(new_val, str) and new_val.startswith("RAW:"):
                new_val = new_val[4:]
                no_preprocess = True
                raw = True
                logger.debug(f"Passing RAW value without pre-processing {new_val} to {self.name}")
            # Try to decode standard input
            try:
                val_int = value_to_int(new_val)
            except TypeError:
                raise SPSDKRegsErrorEnumNotFound  # pylint: disable=raise-missing-from
        self.set_value(val_int, raw, no_preprocess)

    def get_enum_value(self) -> Union[str, int]:
        """Get enum value of the bitfield.

        Retrieves the enumerated value corresponding to the current bitfield value.
        If the current value matches an enumeration entry, returns the enum name,
        otherwise returns the hexadecimal representation of the value.

        :return: Enum name if value matches enumeration, otherwise hex value.
        """
        value = self.get_value()
        for enum in self._enums:
            if enum.get_value_int() == value:
                return enum.name
        # return value
        return self.get_hex_value()

    def get_hex_value(self) -> str:
        """Get the value of register in string hex format.

        The method formats the register value as a hexadecimal string with proper width
        based on the register's configuration width and '0x' prefix.

        :return: Hexadecimal value of register as formatted string.
        """
        fmt = f"0{self.config_width // 4}X"
        val = f"0x{format(self.get_value(), fmt)}"
        return val

    def get_enum_constant(self, enum_name: Union[str, int]) -> int:
        """Get constant representation of enum by its name or value.

        The method searches through available enums to find a match by name (case-insensitive)
        or integer value. It also supports deprecated enum names with warning logging.

        :param enum_name: Name of the enum (string) or its integer value to search for.
        :raises SPSDKRegsErrorEnumNotFound: The enum has not been found.
        :return: Integer constant value of the found enum.
        """
        if isinstance(enum_name, int):
            for enum in self._enums:
                if enum.get_value_int() == enum_name:
                    return enum_name
        if not isinstance(enum_name, str):
            raise SPSDKRegsErrorEnumNotFound(f"The enum for {enum_name} has not been found.")
        enum_name = enum_name.upper()
        for enum in self._enums:
            if enum.name.upper() == enum_name:
                return enum.get_value_int()
            if enum_name in enum.deprecated_names:
                logger.warning(
                    f"Using deprecated enum name: {enum_name}, "
                    f"updated configuration to use: {enum.name}"
                )
                return enum.get_value_int()

        raise SPSDKRegsErrorEnumNotFound(f"The enum for {enum_name} has not been found.")

    def get_enum_names(self) -> list[str]:
        """Get list of enumeration names.

        :return: List of enum names as strings.
        """
        return [x.name for x in self._enums]

    def __str__(self) -> str:
        """Return string representation of the bitfield.

        Provides a formatted string containing all bitfield properties including name,
        offset, width, access type, reset value, description, reserved status, and
        associated enums.

        :return: Formatted string describing the bitfield properties.
        """
        output = ""
        output += f"Name:     {self.name}\n"
        output += f"Offset:   {self.offset} bits\n"
        output += f"Width:    {self.width} bits\n"
        output += f"Access:   {self.access.label} bits\n"
        output += f"Reset val:{self.get_reset_value()}\n"
        output += f"Description: \n {self.description}\n"
        if self.reserved:
            output += "This is reserved bitfield!\n"

        i = 0
        for enum in self._enums:
            output += f"Enum             #{i}: \n" + str(enum)
            i += 1

        return output

    def __repr__(self) -> str:
        """Return string representation of the BitField object.

        The representation includes the BitField name and its current hexadecimal value,
        formatted for debugging and logging purposes.

        :return: String representation in format "<BitField name = 0x(value)>".
        """
        return f"<BitField {self.name} = {self.get_hex_value()}>"

    def find_config_key(self, cfg: Config) -> Optional[str]:
        """Find which bitfield name (current or deprecated) is in the config and return its key.

        The method searches for the bitfield name in the configuration dictionary using multiple
        strategies: exact match, case-insensitive match, and deprecated names matching.

        :param cfg: Configuration dictionary to search in.
        :return: Configuration key found in the dictionary, or None if not found.
        """
        # Check for exact match first
        if self.name in cfg:
            return self.name
        # Check for case-insensitive match with the register name
        for config_key in cfg:
            if isinstance(config_key, str) and config_key.lower() == self.name.lower():
                return config_key

        # Check deprecated names (both exact and case-insensitive)
        for dep_name in self.deprecated_names:
            if dep_name in cfg:
                return dep_name

            for config_key in cfg:
                if isinstance(config_key, str) and config_key.lower() == dep_name.lower():
                    return config_key
        return None


class Register:
    """SPSDK Register representation for hardware register management.

    This class represents a hardware register with configurable properties including
    bit width, access permissions, endianness, and sub-register management. It provides
    functionality for register value manipulation, bitfield operations, and configuration
    export/import capabilities.
    """

    def __init__(
        self,
        name: str,
        offset: int,
        width: int,
        uid: str,
        description: Optional[str] = None,
        default_value: Optional[int] = None,
        reverse: bool = False,
        access: Access = Access.RW,
        config_as_hexstring: bool = False,
        reverse_subregs_order: bool = False,
        base_endianness: Endianness = Endianness.BIG,
        alt_widths: Optional[list[int]] = None,
        reserved: bool = False,
        no_yaml_comments: bool = False,
        deprecated_names: Optional[list[str]] = None,
    ) -> None:
        """Initialize RegsRegister instance with register configuration.

        Creates a new register object with specified properties including name, offset,
        width, and various configuration options for register behavior and display.

        :param name: Name of register.
        :param offset: Byte offset of register.
        :param width: Bit width of register.
        :param uid: Register unique ID.
        :param description: Text description of register.
        :param default_value: Default value of register.
        :param reverse: Multi byte register value could be printed in reverse order.
        :param access: Access type of register.
        :param config_as_hexstring: Config is stored as a hex string.
        :param reverse_subregs_order: Reverse order of sub registers.
        :param base_endianness: Base endianness for bytes import/export of value.
        :param alt_widths: List of alternative widths.
        :param reserved: The register will be hidden from standard searches.
        :param no_yaml_comments: Disable yaml comments for this register.
        :param deprecated_names: List of deprecated names for this register.
        :raises SPSDKValueError: Register width is not a multiple of 8 bits.
        """
        if width % 8 != 0:
            raise SPSDKValueError("Register supports only widths in multiply 8 bits.")
        self.name = name
        self.offset = offset
        self.width = width
        self.uid = uid
        self.description = description or "N/A"
        self.access = access
        self.reverse = reverse
        self._bitfields: list[RegsBitField] = []
        self._default_value = default_value or 0
        self._value = self._default_value
        self.config_as_hexstring = config_as_hexstring
        self.reverse_subregs_order = reverse_subregs_order
        self.base_endianness = base_endianness
        self.alt_widths = alt_widths
        self.reserved = reserved
        self.no_yaml_comments = no_yaml_comments
        self.deprecated_names = deprecated_names or []

        # Grouped register members
        self.sub_regs: list[Self] = []
        self._sub_regs_width_init = False
        self._sub_regs_width = 0

    def __hash__(self) -> int:
        """Get hash value for the register object.

        The hash is computed based on the unique identifier (uid) of the register,
        allowing register objects to be used in hash-based collections like sets
        and dictionaries.

        :return: Hash value of the register's uid.
        """
        return hash(self.uid)

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects have same settings.

        Checks equality by comparing name, width, reverse flag, current value,
        and default value attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects have identical settings, False otherwise.
        """
        if not isinstance(obj, self.__class__):
            return False
        if obj.name != self.name:
            return False
        if obj.width != self.width:
            return False
        if obj.reverse != self.reverse:
            return False
        if obj._value != self._value:
            return False
        if obj._default_value != self._default_value:
            return False
        return True

    @classmethod
    def create_from_spec(
        cls, spec: dict[str, Any], reg_mods: Optional[dict[str, Any]] = None
    ) -> Self:
        """Create register instance from specification dictionary.

        This class method creates a new register instance by parsing the provided
        specification dictionary and applying optional modifications. It handles
        register properties, bitfield creation, and default value initialization.

        :param spec: Dictionary containing register specification with keys like 'id',
                     'name', 'offset_int', 'reg_width', 'description', 'access', etc.
        :param reg_mods: Optional dictionary with register-level modifications that
                         override specification values.
        :return: New register instance configured according to the specification.
        """
        uid = spec.get("id", "")
        name = spec.get("name", "N/A")
        offset = value_to_int(spec.get("offset_int", 0))
        width = value_to_int(spec.get("reg_width", 32))
        description = spec.get("description", "N/A")
        access = Access.from_label(spec.get("access", "RW"))
        reserved = value_to_bool(spec.get("is_reserved", False))
        no_yaml_comments = value_to_bool(spec.get("no_yaml_comments", False))

        # Apply register level modifications if available
        reverse = value_to_bool(spec.get("reverse", False))
        config_as_hexstring = value_to_bool(spec.get("config_as_hexstring", False))
        alt_widths = spec.get("alt_widths")
        deprecated_names = [x.upper() for x in spec.get("deprecated_names", [])]

        if reg_mods:
            if "reverse" in reg_mods:
                reverse = value_to_bool(reg_mods["reverse"])
            if "config_as_hexstring" in reg_mods:
                config_as_hexstring = value_to_bool(reg_mods["config_as_hexstring"])
            if "alt_widths" in reg_mods:
                alt_widths = reg_mods["alt_widths"]
            if "no_yaml_comments" in reg_mods:
                no_yaml_comments = value_to_bool(reg_mods["no_yaml_comments"])

        reg = cls(
            name=name,
            offset=offset,
            width=width,
            uid=uid,
            description=description,
            reverse=reverse,
            access=access,
            reserved=reserved,
            no_yaml_comments=no_yaml_comments,
            config_as_hexstring=config_as_hexstring,
            alt_widths=alt_widths,
            deprecated_names=deprecated_names,
        )
        reg._default_value = value_to_int(spec.get("default_value_int", 0))
        if reg._default_value:
            reg.set_value(reg._default_value, True)

        spec_bitfields = spec.get("bitfields", [])
        offset = 0
        for bitfield_spec in spec_bitfields:
            # Get bitfield modifications if available
            bitfield_uid = bitfield_spec.get("id", "")
            bitfield_mods = None
            if reg_mods and "bitfields" in reg_mods and bitfield_uid in reg_mods["bitfields"]:
                bitfield_mods = reg_mods["bitfields"].get(bitfield_uid)

            bitfield = RegsBitField.create_from_spec(bitfield_spec, offset, reg, bitfield_mods)
            offset += bitfield.width
            reg.add_bitfield(bitfield)

        return reg

    def _get_uid(self) -> str:
        """Get unique identifier of the register field.

        Returns the UID if explicitly set, otherwise generates a default identifier
        based on whether the field is reserved and its offset position.

        :return: Unique identifier string for the register field.
        """
        if self.uid:
            return self.uid
        if self.reserved:
            return f"reserved{self.offset:03X}"

        return f"field{self.offset:03X}"

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        The method generates a dictionary containing all register information including ID, offset,
        width, name, description, default value, and bitfields. Gaps between bitfields are
        automatically filled to maintain proper structure.

        :return: Dictionary containing the complete register specification with all metadata
            and bitfield definitions.
        """
        spec: dict[str, Union[str, list]] = {}
        spec["id"] = self._get_uid()
        spec["offset_int"] = hex(self.offset)
        spec["reg_width"] = str(self.width)
        spec["name"] = self.name
        spec["description"] = self.description
        spec["default_value_int"] = hex(self.get_reset_value())
        bitfields = []
        bitfields_offset = 0
        for bitfield in sorted(self._bitfields, key=lambda x: x.offset):
            if bitfield.offset != bitfields_offset:
                gap_width = bitfield.offset - bitfields_offset
                bitfields.append({"width": gap_width})
                bitfields_offset += gap_width

            bitfields.append(bitfield.create_spec())
            bitfields_offset += bitfield.width

        if bitfields:
            spec["bitfields"] = bitfields
        if self.deprecated_names:
            spec["deprecated_names"] = self.deprecated_names
        return spec

    def has_group_registers(self) -> bool:
        """Check if register is compounded from sub-registers.

        :return: True if register has sub-registers, False otherwise.
        """
        return len(self.sub_regs) > 0

    def _add_group_reg(self, reg: Self) -> None:
        """Add group element for this register.

        Validates consistency rules for register groups including memory layout,
        width, and access permissions. For the first member, initializes group
        properties from the register. For subsequent members, enforces that
        registers must be contiguous in memory and have matching properties.

        :param reg: Register member to add to this register group.
        :raises SPSDKRegsErrorRegisterGroupMishmash: When any inconsistency is detected.
        """
        first_member = not self.has_group_registers()
        if first_member:
            if self.offset == 0:
                self.offset = reg.offset
            if self.width == 0:
                self.width = reg.width
            else:
                self._sub_regs_width_init = True
                self._sub_regs_width = reg.width
            if self.access == Access.RW:
                self.access = reg.access
        else:
            # There is strong rule that supported group MUST be in one row in memory! But in case that
            # this is just description of OTP fuses, the rule is disabled
            if not self._sub_regs_width_init:
                if self.offset + self.width // 8 != reg.offset:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} doesn't follow the previous one."
                    )
                self.width += reg.width
            else:
                self._sub_regs_width += reg.width
                if self._sub_regs_width > self.width:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} bigger width than is defined."
                    )
            if self.sub_regs[0].width != reg.width:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} has different width."
                )
            # The access validation is skipped for reserved
            if not reg.reserved and self.access != reg.access:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} has different access type."
                )

        reg.base_endianness = self.base_endianness
        self.sub_regs.append(reg)

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register.

        The method validates the input value fits within the register width and handles
        endianness conversion if reverse mode is enabled. For group registers, it also
        updates all sub-registers with appropriate bit portions of the value.

        :param val: The new value to set (integer or convertible to integer).
        :param raw: Do not use any modification hooks if True.
        :raises SPSDKError: When invalid value is loaded into register or value exceeds
            register width.
        """
        try:
            value = value_to_int(val)
            if value >= 1 << self.width:
                raise SPSDKError(
                    f"Input value {value} doesn't fit into register of width {self.width}."
                )

            alt_width = self.get_alt_width(value)

            if not raw and self.reverse:
                # The value_to_int internally is using BIG endian
                val_bytes = value_to_bytes(
                    value,
                    align_to_2n=False,
                    byte_cnt=alt_width // 8,
                    endianness=Endianness.BIG,
                )
                value = value.from_bytes(val_bytes, Endianness.LITTLE.value)

            if self.has_group_registers():
                # Update also values in sub registers
                subreg_width = self.sub_regs[0].width
                sub_regs = self.sub_regs[: alt_width // subreg_width]
                for index, sub_reg in enumerate(sub_regs, start=1):
                    if self.reverse_subregs_order:
                        bit_pos = alt_width - index * subreg_width
                    else:
                        bit_pos = (index - 1) * subreg_width

                    sub_reg.set_value((value >> bit_pos) & ((1 << subreg_width) - 1), raw=raw)
            else:
                self._value = value

        except SPSDKError as exc:
            raise SPSDKError(f"Loaded invalid value {str(val)}") from exc

    def reset_value(self, raw: bool = False) -> None:
        """Reset the value of register to its default reset value.

        :param raw: Do not use any modification hooks, defaults to False.
        """
        self.set_value(self.get_reset_value(), raw)

    def get_alt_width(self, value: int) -> int:
        """Get alternative width of register based on input value.

        Determines the appropriate register width by analyzing the input value's byte requirements
        and selecting the smallest suitable width from available alternatives.

        :param value: Input integer value used to determine the required register width.
        :return: Register width in bits, either the default width or smallest suitable alternative.
        """
        alt_width = self.width
        if self.alt_widths:
            real_byte_cnt = get_bytes_cnt_of_int(value, align_to_2n=False)
            self.alt_widths.sort()
            for alt in self.alt_widths:
                if real_byte_cnt <= alt // 8:
                    alt_width = alt
                    break
        return alt_width

    def get_value(self, raw: bool = False) -> int:
        """Get the value of register.

        Retrieves the register value, handling sub-registers if present and applying
        endianness conversion when needed.

        :param raw: Do not use any modification hooks, defaults to False.
        :return: The register value as integer.
        """
        if self.has_group_registers():
            # Update local value, by the sub register values
            subreg_width = self.sub_regs[0].width
            sub_regs_value = 0
            for index, sub_reg in enumerate(self.sub_regs, start=1):
                if self.reverse_subregs_order:
                    bit_pos = self.width - index * subreg_width
                else:
                    bit_pos = (index - 1) * subreg_width
                sub_regs_value |= sub_reg.get_value(raw=raw) << (bit_pos)
            value = sub_regs_value
        else:
            value = self._value

        alt_width = self.get_alt_width(value)

        if not raw and self.reverse:
            val_bytes = value_to_bytes(
                value,
                align_to_2n=False,
                byte_cnt=alt_width // 8,
                endianness=self.base_endianness,
            )
            value = value.from_bytes(
                val_bytes,
                (
                    Endianness.BIG.value
                    if self.base_endianness == Endianness.LITTLE
                    else Endianness.LITTLE.value
                ),
            )

        return value

    def get_bytes_value(self, raw: bool = False) -> bytes:
        """Get the bytes value of register.

        Converts the register value to bytes representation using the register's
        endianness and appropriate byte count based on the value's bit width.

        :param raw: Do not use any modification hooks when getting the value.
        :return: Register value converted to bytes.
        """
        value = self.get_value(raw=raw)
        return value_to_bytes(
            value,
            align_to_2n=False,
            byte_cnt=self.get_alt_width(value) // 8,
            endianness=self.base_endianness,
        )

    def get_hex_value(self, raw: bool = False) -> str:
        """Get the value of register in string hex format.

        :param raw: Do not use any modification hooks.
        :return: Hexadecimal value of register.
        """
        val_int = self.get_value(raw=raw)
        count = "0" + str(self.get_alt_width(val_int) // 4)
        value = f"{val_int:{count}X}"
        if not self.config_as_hexstring:
            value = "0x" + value
        return value

    def get_reset_value(self) -> int:
        """Get reset value of the register.

        :return: Reset value of register.
        """
        return self._default_value

    def add_bitfield(self, bitfield: RegsBitField) -> None:
        """Add register bitfield to the register.

        :param bitfield: New bitfield value for register.
        """
        self._bitfields.append(bitfield)

    def get_bitfields(self, exclude: Optional[list[str]] = None) -> list[RegsBitField]:
        """Get register bitfields with optional exclusion filtering.

        Method allows excluding specific bitfields by their names using prefix matching.
        Non-reserved bitfields are included by default.

        :param exclude: List of bitfield name prefixes to exclude from results.
        :return: List of non-reserved register bitfields, filtered by exclusion criteria.
        """
        ret = []
        for bitf in self._bitfields:
            if bitf.reserved:
                continue
            if exclude and bitf.name.startswith(tuple(exclude)):
                continue
            ret.append(bitf)
        return ret

    def get_bitfield_names(self, exclude: Optional[list[str]] = None) -> list[str]:
        """Get list of bitfield names.

        :param exclude: List of bitfield names to exclude from the result, defaults to None.
        :return: List of bitfield names.
        """
        return [x.name for x in self.get_bitfields(exclude)]

    def get_bitfield(self, uid: str) -> RegsBitField:
        """Get bitfield instance by its unique identifier.

        The method performs case-insensitive search through all bitfields in the register
        to find the one matching the provided UID.

        :param uid: The unique identifier of the bitfield to retrieve.
        :return: Instance of the bitfield matching the provided UID.
        :raises SPSDKRegsErrorBitfieldNotFound: The bitfield with given UID doesn't exist.
        """
        for bitfield in self._bitfields:
            if uid.upper() == bitfield.uid.upper():
                return bitfield

        raise SPSDKRegsErrorBitfieldNotFound(
            f" The UID:{uid} is not found in register {self.name}."
        )

    def find_bitfield(self, name: str) -> RegsBitField:
        """Find bitfield by name in the register.

        The method searches for a bitfield using its name, UID, or deprecated names.
        Case-insensitive matching is performed. A warning is logged when deprecated
        names are used.

        :param name: The name of the bitfield (case insensitive).
        :return: Instance of the bitfield.
        :raises SPSDKRegsErrorBitfieldNotFound: The bitfield doesn't exist.
        """
        for bitfield in self._bitfields:
            if name.upper() == bitfield.name.upper():
                return bitfield
            if name.upper() == bitfield.uid.upper():
                return bitfield
            if name.upper() in bitfield.deprecated_names:
                logger.warning(
                    f"Bitfield name is deprecated, use the new name: {bitfield.name}."
                    "Deprecated names will be removed in the next major version of SPSDK."
                )
                return bitfield
        raise SPSDKRegsErrorBitfieldNotFound(f" The {name} is not found in register {self.name}.")

    def __str__(self) -> str:
        """Get string representation of the register.

        Provides a formatted string containing register details including name, offset,
        width, access permissions, description, and all associated bitfields.

        :return: Formatted string describing the register and its bitfields.
        """
        output = ""
        output += f"Name:   {self.name}\n"
        output += f"Offset: 0x{self.offset:04X}\n"
        output += f"Width:  {self.width} bits\n"
        output += f"Access:   {self.access.label}\n"
        output += f"Description: \n {self.description}\n"
        i = 0
        for bitfield in self._bitfields:
            output += f"Bitfield #{i}: \n" + str(bitfield)
            i += 1

        return output

    def __repr__(self) -> str:
        """Return string representation of the register object.

        The representation includes the class name, register name, and current hexadecimal value
        in a readable format suitable for debugging and logging purposes.

        :return: String representation in format '<ClassName name = 0x(value)>'.
        """
        return f"<{self.__class__.__name__} {self.name} = {self.get_hex_value()}>"

    @property
    def has_reset_value(self) -> bool:
        """Test if the current value is reset value.

        :return: True if the value has not been changed, False otherwise.
        """
        return self.get_reset_value() == self.get_value(raw=True)

    def find_config_key(self, cfg: Config) -> Optional[str]:
        """Find which register name (current or deprecated) is in the config and return its key.

        The method searches for the register name in the configuration dictionary using multiple
        strategies: exact match, case-insensitive match for current name, and then the same
        approaches for deprecated names.

        :param cfg: Configuration dictionary to search in.
        :return: Configuration key if found, None otherwise.
        """
        # Check for exact match first
        if self.name in cfg:
            return self.name
        # Check for case-insensitive match with the register name
        for config_key in cfg:
            if isinstance(config_key, str) and config_key.lower() == self.name.lower():
                return config_key

        # Check deprecated names (both exact and case-insensitive)
        for dep_name in self.deprecated_names:
            if dep_name in cfg:
                return dep_name

            for config_key in cfg:
                if isinstance(config_key, str) and config_key.lower() == dep_name.lower():
                    return config_key
        return None


RegisterClassT = TypeVar("RegisterClassT", bound=Register)


class _RegistersBase(Generic[RegisterClassT]):
    """SPSDK base class for managing hardware register collections.

    This generic class provides a foundation for handling register specifications
    across NXP MCU families. It manages register loading from database specifications,
    supports grouped registers, and provides common operations for register manipulation.

    :cvar register_class: Type of register class to instantiate.
    :cvar TEMPLATE_NOTE: Documentation note about register value definitions.
    """

    register_class: Type[RegisterClassT]
    TEMPLATE_NOTE = (
        "All registers is possible to define also as one value although the bitfields are used. "
        "Instead of bitfields: ... field, the value: ... definition works as well."
    )

    def __init__(
        self,
        family: FamilyRevision,
        feature: str,
        base_key: Optional[Union[list[str], str]] = None,
        base_endianness: Endianness = Endianness.BIG,
        just_standard_library_data: bool = False,
        do_not_raise_exception: bool = False,
    ) -> None:
        """Initialize Registers class for managing device register specifications.

        Loads register specifications from the device database, including grouped registers,
        modifications, and deprecated register names. Handles both standard library data
        and restricted data sources.

        :param family: Family revision object specifying the target device family.
        :param feature: Feature name to identify the register set.
        :param base_key: Base item key or key path as list like ['grp1', 'grp2', 'key'].
        :param base_endianness: The base endianness of registers in binary form.
        :param just_standard_library_data: If True, uses only embedded library data,
            otherwise includes restricted data.
        :param do_not_raise_exception: Enable debug mode to suppress exceptions during
            database load errors.
        :raises SPSDKError: When database loading fails and do_not_raise_exception is False.
        """
        self._registers: list[RegisterClassT] = []
        self.family = family
        self.base_endianness = base_endianness
        self.feature = feature
        self.base_key = base_key

        try:
            self.db = get_db(family)
            spec_file_name = self.db.get_file_path(
                self.feature,
                self._create_key("reg_spec"),
                just_standard_lib=just_standard_library_data,
            )
            grouped_registers = self.db.get_list(
                self.feature, self._create_key("grouped_registers"), []
            )
            # Get additional register specifications from database
            reg_spec_modifications = self.db.get_value(
                self.feature, self._create_key("reg_spec_modification"), {}
            )
            # Handle potential modifications to register specifications stored in configuration file
            if isinstance(reg_spec_modifications, str):
                reg_spec_modifications = load_configuration(
                    self.db.device.create_file_path(reg_spec_modifications)
                )

            self._load_spec(
                spec_file=spec_file_name,
                grouped_regs=grouped_registers,
                reg_spec_modifications=reg_spec_modifications,
                deprecated_regs=self._load_deprecated_names(),
            )
        except SPSDKError as exc:
            if do_not_raise_exception:
                # Only path for testing and internal tools
                logger.info(
                    f"Loading of database failed, inform SPSDK team about this error: {str(exc)}"
                    f"\n Family: {self.family}, Feature: {feature}"
                )
            else:
                raise exc

    def __iter__(self) -> Iterator[RegisterClassT]:
        """Return an iterator over the registers in the collection.

        :return: Iterator that yields register objects from the internal registers collection.
        """
        return iter(self._registers)

    def __len__(self) -> int:
        """Get the number of registers in the collection.

        :return: Number of registers stored in this collection.
        """
        return len(self._registers)

    def _create_key(self, key: str) -> Union[str, list[str]]:
        """Create the final key path for database access.

        The method combines the base key path with the requested key to form
        a complete path. If no base key exists, returns the key as-is. If base
        key is a string, creates a list with base key and the new key. If base
        key is already a list, appends the new key to it.

        :param key: The requested final key to be added to the path.
        :return: Complete key path as string or list of strings for database access.
        """
        if not self.base_key:
            return key
        if isinstance(self.base_key, str):
            return [self.base_key, key]
        return self.base_key + [key]

    def __eq__(self, obj: Any) -> bool:
        """Compare if two register objects have identical settings.

        Compares the family, base endianness, and internal register configurations
        to determine if two register objects are equivalent.

        :param obj: Object to compare against this register instance.
        :return: True if objects have same family, endianness and registers, False otherwise.
        """
        if not (
            isinstance(obj, self.__class__)
            and obj.family == self.family
            and obj.base_endianness == self.base_endianness
        ):
            return False
        ret = obj._registers == self._registers
        return ret

    def find_reg(self, name: str, include_group_regs: bool = False) -> RegisterClassT:
        """Find register instance by name or identifier.

        The method searches through loaded registers to find a match by name, UID, or deprecated names.
        When include_group_regs is enabled, it also searches within group sub-registers.

        :param name: The name, UID, or deprecated name of the register to find.
        :param include_group_regs: Whether to include group sub-registers in the search.
        :return: Instance of the found register.
        :raises SPSDKRegsErrorRegisterNotFound: The register doesn't exist in loaded registers.
        """

        def check_reg(reg: RegisterClassT) -> bool:
            """Check if register matches the given name.

            Compares the provided name against register's name, UID, and deprecated names.
            Issues a warning if a deprecated name is used.

            :param reg: Register object to check against the name.
            :return: True if register matches the name, False otherwise.
            """
            if name.upper() == reg.name.upper():
                return True
            if name.upper() == reg.uid.upper():
                return True
            if name.upper() in reg.deprecated_names:
                logger.warning(
                    f"Register name is deprecated, use the new name: {reg.name}."
                    "Deprecated names will be removed in the next major version of SPSDK."
                )
                return True
            return False

        for reg in self._registers:
            if check_reg(reg):
                return reg
            if include_group_regs and reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    if check_reg(sub_reg):
                        return sub_reg

        raise SPSDKRegsErrorRegisterNotFound(
            f"The {name} is not found in loaded registers for {self.family} device."
        )

    def get_reg(self, uid: str) -> RegisterClassT:
        """Get register instance by unique identifier.

        Searches through all loaded registers and their sub-registers to find a match
        for the provided UID. The search is case-insensitive.

        :param uid: The unique identifier of the register to retrieve.
        :return: Instance of the register matching the provided UID.
        :raises SPSDKRegsErrorRegisterNotFound: The register with specified UID
            doesn't exist in loaded registers.
        """
        for reg in self._registers:
            if uid.upper() == reg.uid.upper():
                return reg
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    if uid.upper() == sub_reg.uid.upper():
                        return sub_reg

        raise SPSDKRegsErrorRegisterNotFound(
            f"The UID:{uid} is not found in loaded registers for {self.family} device."
        )

    def add_register(self, reg: RegisterClassT) -> None:
        """Adds register into register list.

        The method validates the register type and ensures no conflicts with existing
        registers by name or offset before adding it to the internal register collection.

        :param reg: Register instance to add to the register list.
        :raises SPSDKError: Invalid register type has been provided.
        :raises SPSDKRegsError: Cannot add register with same name or existing offset.
        """
        if not isinstance(reg, self.register_class):
            raise SPSDKError(f"The register has invalid type: {type(reg)}.")

        if reg.name in self.get_reg_names():
            raise SPSDKRegsError(f"Cannot add register with same name: {reg.name}.")

        for register in self._registers:
            # TODO solve problem with group register that are always at 0 offset
            if register.offset == reg.offset != 0:
                logger.error(
                    f"Found register at the same offset {hex(reg.offset)}"
                    f"cannot add register instead of {register.name}"
                )
                raise SPSDKRegsError(f"Cannot add register on existing offset: {hex(reg.offset)}.")
        # update base endianness for all registers in group
        reg.base_endianness = self.base_endianness
        self._registers.append(reg)

    def remove_registers(self) -> None:
        """Remove all registers.

        This method clears all registers from the internal registers collection,
        effectively resetting the register container to an empty state.
        """
        self._registers.clear()

    def remove_register(self, name: str) -> None:
        """Remove a register from the list.

        :param name: Name of the register to remove.
        :raises SPSDKValueError: If register with given name is not found.
        """
        self._registers.remove(self.find_reg(name, True))

    def get_registers(
        self,
        exclude: Optional[list[str]] = None,
        include_group_regs: bool = False,
        include_reserved: bool = False,
    ) -> list[RegisterClassT]:
        """Get list of registers with optional filtering.

        Method allows excluding registers by their names and optionally including group registers
        and reserved registers in the result.

        :param exclude: List of register name prefixes to exclude from the result.
        :param include_group_regs: Include group registers (sub-registers) in the result.
        :param include_reserved: Include reserved registers in the result.
        :return: List of registers matching the specified criteria.
        """
        if exclude:
            regs = [r for r in self._registers if not r.name.startswith(tuple(exclude))]
        else:
            regs = self._registers
        if include_group_regs:
            sub_regs = []
            for reg in regs:
                if reg.has_group_registers():
                    sub_regs.extend(reg.sub_regs)
            regs.extend(sub_regs)

        if include_reserved:
            return regs

        return [x for x in regs if not x.reserved]

    def get_reg_names(
        self, exclude: Optional[list[str]] = None, include_group_regs: bool = False
    ) -> list[str]:
        """Get list of register names.

        Retrieves names of all registers, with optional filtering capabilities
        and support for including group registers in the search.

        :param exclude: List of register names to exclude from the result.
        :param include_group_regs: Include group registers in the search algorithm.
        :return: List of register names.
        """
        return [x.name for x in self.get_registers(exclude, include_group_regs)]

    def reset_values(self, exclude: Optional[list[str]] = None) -> None:
        """Reset all register values to their default state.

        This method iterates through all registers and resets each one to its
        default value, with an option to exclude specific registers from the reset.

        :param exclude: List of register names to exclude from reset operation.
        """
        for reg in self.get_registers(exclude):
            reg.reset_value(True)

    def __repr__(self) -> str:
        """Get string representation of the Registers class.

        :return: String containing family and feature information for this Registers instance.
        """
        return f"Registers class for {self.family}, feature: {self.feature} "

    def __str__(self) -> str:
        """Return string representation of the registers collection.

        Provides a human-readable format showing the device family name
        and detailed information for all registers in the collection.

        :return: Formatted string containing device name and register details.
        """
        output = ""
        output += "Device name:        " + str(self.family) + "\n"
        for reg in self._registers:
            output += str(reg) + "\n"

        return output

    def image_info(
        self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")
    ) -> BinaryImage:
        """Export registers into binary image format.

        Creates a binary image containing all registers with their current values,
        properly positioned at their respective offsets.

        :param size: Result size of image in bytes, 0 means automatic minimal size.
        :param pattern: Pattern used to fill gaps between registers.
        :return: Binary image containing all registers data.
        """
        image = BinaryImage(self.family.name, size=size, pattern=pattern)
        for reg in self._registers:
            image.add_image(
                BinaryImage(
                    reg.name,
                    reg.width // 8,
                    offset=reg.offset,
                    description=reg.description,
                    binary=reg.get_bytes_value(raw=True),
                )
            )

        return image

    def export(self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")) -> bytes:
        """Export Registers into binary.

        :param size: Result size of Image, 0 means automatic minimal size.
        :param pattern: Pattern of gaps, defaults to "zeros".
        :return: Binary representation of the registers.
        """
        return self.image_info(size, pattern).export()

    def parse(self, binary: bytes) -> None:
        """Parse the binary data values into loaded registers.

        The method extracts register values from binary data based on each register's
        offset and width. If the binary data is shorter than expected, parsing stops
        at the first register that cannot be fully read.

        :param binary: Binary data to parse into register values.
        """
        bin_len = len(binary)
        if bin_len < len(self.image_info()):
            logger.info(
                f"Input binary is smaller than registers supports: {bin_len} != {len(self.image_info())}"
            )
        for reg in self._registers:
            if bin_len < reg.offset + reg.width // 8:
                logger.debug(f"Parsing of binary block ends at {reg.name}")
                break
            binary_value = binary[reg.offset : reg.offset + reg.width // 8]
            reg.set_value(int.from_bytes(binary_value, self.base_endianness.value), raw=True)

    def get_base_offset(self) -> int:
        """Get the minimal offset from all registers in the collection.

        This method finds the smallest offset value among all registers contained
        in this register collection.

        :raises ValueError: If no registers are available in the collection.
        :return: The minimal offset value found among all registers.
        """
        return min(r.offset for r in self.get_registers())

    def normalize_offsets(self) -> None:
        """Normalize (shift) register offsets, so the first register's offset is zero.

        This method adjusts all register offsets by subtracting the base offset (minimum offset
        among all registers) from each register's offset, effectively making the first register
        start at offset zero while maintaining relative positioning.

        :raises SPSDKError: If no registers are available to normalize.
        """
        base_offset = self.get_base_offset()
        for r in self.get_registers():
            r.offset -= base_offset

    def get_diff(
        self, other: Self
    ) -> list[Union[tuple[RegsBitField, RegsBitField], tuple[Register, Register]]]:
        """Compare registers and bitfields between two register collections.

        The tuples contain "expected" and "actual" value respectively.
        If a register doesn't contain bitfields the whole register is included.
        If a register contains bitfields, only non-matching bitfields are included.

        :param other: Another register collection to compare against.
        :return: List of tuples containing differing registers or bitfields.
        """
        diffs: list[Union[tuple[RegsBitField, RegsBitField], tuple[Register, Register]]] = []
        for r1, r2 in zip(self.get_registers(), other.get_registers()):
            if len(r1.get_bitfields()) == 0:
                if r1.get_value() != r2.get_value():
                    diffs.append((r1, r2))
            else:
                for b1, b2 in zip(r1.get_bitfields(), r2.get_bitfields()):
                    if b1.get_value() != b2.get_value():
                        diffs.append((b1, b2))
        return diffs

    def _get_bitfield_yaml_description(self, bitfield: RegsBitField) -> str:
        """Create the valuable comment for bitfield.

        Generates a comprehensive YAML description string for a register bitfield including
        offset, width, description, processor notes, and enumeration values if present.

        :param bitfield: Bitfield object used to generate description.
        :return: Formatted bitfield description string for YAML output.
        """
        description = f"Offset: {bitfield.offset}b, Width: {bitfield.config_width}b"
        if bitfield.description not in ("", "."):
            description += ", " + bitfield.description
        if bitfield.config_processor.description:
            description += ".\n NOTE: " + bitfield.config_processor.description
        if bitfield.has_enums():
            for enum in bitfield.get_enums():
                descr = enum.description if enum.description != "." else enum.name
                enum_description = descr
                description += f"\n- {enum.name}, ({enum.get_value_int()})"
                if enum_description:
                    description += f": {enum_description}"
        return description

    def get_validation_schema(self) -> dict[str, Any]:
        """Get JSON schema for register validation and template generation.

        Generates a comprehensive JSON schema that includes validation rules for all registers,
        their bitfields, and alternative naming conventions. The schema supports multiple
        input formats including direct values, bitfield objects, and deprecated naming.

        :return: JSON schema dictionary with validation rules for all registers.
        """
        properties: dict[str, Any] = {}
        # pattern_properties: dict[str, Any] = {}  # For case-insensitive matching

        def add_reg_validation_schema(reg: RegisterClassT, is_subreg: bool = False) -> None:
            """Add register validation schema for a given register.

            Creates and adds validation schema entries for the register including support for
            bitfields, deprecated names, and sub-registers. The schema supports multiple formats
            including direct value assignment and bitfield-based configuration.

            :param reg: Register object to create validation schema for.
            :param is_subreg: Whether this register is a sub-register, defaults to False.
            """
            bitfields = reg._bitfields
            bitfields_in_template = len([b for b in bitfields if not b.reserved]) > 0
            reg_schema = [
                {
                    "type": ["string", "number"],
                    "skip_in_template": bitfields_in_template,
                    # "format": "number", # TODO add option to hexstring
                    "template_value": f"{reg.get_hex_value()}",
                    "no_yaml_comments": reg.no_yaml_comments,
                },
                {  # Obsolete type
                    "type": "object",
                    "required": ["value"],
                    "skip_in_template": True,
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "type": ["string", "number"],
                            # "format": "number", # TODO add option to hexstring
                            "template_value": f"{reg.get_hex_value()}",
                        }
                    },
                },
            ]

            if bitfields:
                bitfields_schema = {}

                for bitfield in bitfields:
                    if not bitfield.has_enums():
                        bitfield_sch = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "template_value": bitfield.get_value(),
                            "skip_in_template": bitfield.reserved,
                            "no_yaml_comments": bitfield.no_yaml_comments,
                        }
                    else:
                        bitfield_sch = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "enum_template": bitfield.get_enum_names(),
                            "minimum": 0,
                            "maximum": (1 << bitfield.width) - 1,
                            "template_value": bitfield.get_enum_value(),
                            "skip_in_template": bitfield.reserved,
                            "no_yaml_comments": bitfield.no_yaml_comments,
                        }
                    # Add the main bitfield name
                    bitfields_schema[bitfield.name] = bitfield_sch
                    if bitfield.name.upper() not in bitfields_schema:
                        # add upper-case format for validation, not for a template
                        bitfields_schema[bitfield.name.upper()] = {
                            **bitfield_sch,
                            "skip_in_template": True,
                        }

                    # Add deprecated names
                    for alt_name in bitfield.deprecated_names:
                        bitfields_schema[alt_name] = {
                            **bitfield_sch,
                            "skip_in_template": True,
                        }
                        if alt_name.upper() not in bitfields_schema:
                            bitfields_schema[alt_name.upper()] = {
                                **bitfield_sch,
                                "skip_in_template": True,
                            }

                # Extend register schema by obsolete style
                reg_schema.append(
                    {
                        "type": "object",
                        "required": ["bitfields"],
                        "skip_in_template": True,
                        "additionalProperties": False,
                        "no_yaml_comments": reg.no_yaml_comments,
                        "properties": {
                            "bitfields": {
                                "type": "object",
                                "properties": bitfields_schema,
                            }
                        },
                    }
                )
                # Extend by new style of bitfields
                reg_schema.append(
                    {
                        "type": "object",
                        "skip_in_template": not bitfields_in_template,
                        "required": [],
                        "additionalProperties": False,
                        "no_yaml_comments": reg.no_yaml_comments,
                        "properties": bitfields_schema,
                    },
                )
            # we show only group registers in template, but we keep sub-registers for validation in case user define it
            reg_properties = {
                "title": f"{reg.name}",
                "description": f"Offset: 0x{reg.offset:08X}, Width: {reg.width}b; {reg.description}",
                "no_yaml_comments": reg.no_yaml_comments,
                "skip_in_template": is_subreg,
                "oneOf": reg_schema,
            }
            # Add the main register name to properties
            properties[reg.name] = reg_properties
            if reg.name.upper() not in properties:
                # add upper-case format for validation, not for a template
                properties[reg.name.upper()] = {**reg_properties, "skip_in_template": True}

            # also register UID is accepted as valid schema key
            if reg.uid != reg.name:
                properties[reg.uid] = {**reg_properties, "skip_in_template": True}
            # Add deprecated register names to schema but skip them in template
            for deprecated_name in reg.deprecated_names:
                properties[deprecated_name] = {**reg_properties, "skip_in_template": True}
                if deprecated_name.upper() not in properties:
                    properties[deprecated_name.upper()] = {
                        **reg_properties,
                        "skip_in_template": True,
                    }

            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    add_reg_validation_schema(sub_reg, is_subreg=True)

        for reg in self.get_registers():
            add_reg_validation_schema(reg)

        return {
            "type": "object",
            "title": self.family.name,
            "properties": properties,
        }

    @classmethod
    def _get_register_group(
        cls, reg: RegisterClassT, grouped_regs: Optional[list[dict]] = None
    ) -> Optional[dict]:
        """Help function to recognize if the register should be part of group.

        :param reg: Register object to check for group membership.
        :param grouped_regs: List of register group dictionaries containing sub_regs.
        :return: Group dictionary if register belongs to a group, None otherwise.
        """
        if grouped_regs:
            for group in grouped_regs:
                if reg.uid in group["sub_regs"]:
                    return group
        return None

    def _load_from_spec(
        self,
        config: dict[str, Any],
        grouped_regs: Optional[list[dict]] = None,
        reg_spec_modifications: Optional[dict[str, dict]] = None,
        deprecated_reg_names: Optional[dict[str, dict[str, Any]]] = None,
    ) -> None:
        """Load registers from specification configuration.

        Parses the configuration dictionary to create and add registers to the collection.
        Handles register grouping, modifications, and deprecated names during the loading process.

        :param config: Configuration dictionary containing register groups and specifications.
        :param grouped_regs: Optional list of grouped register definitions for organizing
            registers into hierarchical structures.
        :param reg_spec_modifications: Optional dictionary of register-specific modifications
            to apply during register creation, keyed by register UID.
        :param deprecated_reg_names: Optional dictionary mapping register UIDs to their
            deprecated names and bitfield alternatives.
        """
        for spec_group in config.get("groups", []):
            for spec_reg in spec_group.get("registers", []):
                reg_uid = spec_reg.get("id", "")
                reg_mods = None
                if reg_spec_modifications and reg_uid in reg_spec_modifications:
                    reg_mods = reg_spec_modifications.get(reg_uid)

                reg = self.register_class.create_from_spec(spec_reg, reg_mods)
                if deprecated_reg_names and reg.uid in deprecated_reg_names:
                    reg.deprecated_names.extend(deprecated_reg_names[reg.uid]["alt_names"])
                    for bf in reg.get_bitfields():
                        if bf.uid in deprecated_reg_names[reg.uid]["bitfields"]:
                            bf.deprecated_names.extend(
                                deprecated_reg_names[reg.uid]["bitfields"][bf.uid]
                            )

                group = self._get_register_group(reg, grouped_regs)
                if group:
                    try:
                        group_reg = self.get_reg(group["uid"])
                    except SPSDKRegsErrorRegisterNotFound:
                        group_reg = self.register_class(
                            name=group["name"],
                            offset=value_to_int(group.get("offset", 0)),
                            width=value_to_int(group.get("width", 0)),
                            uid=group["uid"],
                            description=group.get(
                                "description", f"Group of {group['name']} registers."
                            ),
                            reverse=value_to_bool(group.get("reversed", False)),
                            access=Access.from_label(group.get("access", "RW")),
                            config_as_hexstring=group.get("config_as_hexstring", False),
                            reverse_subregs_order=group.get("reverse_subregs_order", False),
                            alt_widths=group.get("alternative_widths"),
                        )
                        self.add_register(group_reg)
                    group_reg._add_group_reg(reg)
                else:
                    self.add_register(reg)

    def _load_spec(
        self,
        spec_file: str,
        grouped_regs: Optional[list[dict]] = None,
        reg_spec_modifications: Optional[dict[str, dict]] = None,
        deprecated_regs: Optional[dict[str, dict[str, Any]]] = None,
    ) -> None:
        """Load registers from JSON specification file.

        Parses the JSON specification file and loads register definitions into the current
        instance. Supports grouping of registers and specification modifications.

        :param spec_file: Path to the JSON specification file.
        :param grouped_regs: List of register prefix names to be grouped into one register.
        :param reg_spec_modifications: Dictionary with additional register specifications to apply.
        :param deprecated_regs: Dictionary containing deprecated register definitions.
        :raises SPSDKError: JSON parsing error occurs or file cannot be read.
        """
        try:
            with open(spec_file, "r", encoding="utf-8") as f:
                spec = json.load(f)
        except json.JSONDecodeError as exc:
            raise SPSDKError(
                f"Cannot load register specification: {spec_file}. {str(exc)}"
            ) from exc
        self._load_from_spec(spec, grouped_regs, reg_spec_modifications, deprecated_regs)

    def write_spec(self, file_name: str) -> None:
        """Write loaded register structures into JSON file.

        The method exports all loaded registers into a JSON specification file format
        that can be used for register configuration and documentation purposes.

        :param file_name: The name of JSON file that should be created.
        """
        spec: dict[str, Any] = {}
        spec["cpu"] = self.family.name

        regs = []
        for reg in self._registers:
            regs.append(reg.create_spec())
        group = {"name": "General regs", "description": "General register generated by SPSDK"}
        spec["groups"] = [{"group": group, "registers": regs}]

        write_file(json.dumps(spec, indent=4), file_name)

    def load_from_config(self, config: Config) -> None:
        """Load registers configuration from config data.

        The method handles restricted data sources and converts between standard and
        restricted data library names when necessary. If loading fails with standard
        names, it attempts conversion using the standard library data.

        :param config: Configuration data containing register values and settings.
        :raises SPSDKRegsErrorRegisterNotFound: When register is not found in database.
        :raises SPSDKRegsErrorBitfieldNotFound: When bitfield is not found in register.
        :raises SPSDKRegsErrorEnumNotFound: When enum value is not found in bitfield.
        """
        try:
            self._load_from_config(config)
        except (
            SPSDKRegsErrorRegisterNotFound,
            SPSDKRegsErrorBitfieldNotFound,
            SPSDKRegsErrorEnumNotFound,
        ) as exc:
            if not get_whole_db()._data.restricted_data_path:
                raise exc

            # Try to load the configuration with standard database names and convert it to restricted data names
            std_regs = self.__class__(
                family=self.family,
                feature=self.feature,
                base_key=self.base_key,
                base_endianness=self.base_endianness,
                just_standard_library_data=True,
            )
            std_regs._load_from_config(config)
            self.parse(std_regs.export())
            logger.warning(
                "The input YAML configuration file has been converted from standard"
                " library names to restricted data library extension."
            )

    def _load_from_config(self, config: Config) -> None:
        """Load register configuration from YAML data.

        The method processes YAML configuration data to set register values. It supports
        both direct value assignment and bitfield-based configuration. The method handles
        hexadecimal string conversion, enum value assignment, and provides backward
        compatibility for older register data formats.

        :param config: The YAML configuration data containing register names and their
            corresponding values or bitfield configurations.
        :raises SPSDKRegsErrorRegisterNotFound: When specified register is not found.
        :raises SPSDKError: When bitfield value is out of range or invalid.
        """
        for reg_name in config.keys():
            try:
                register = self.find_reg(reg_name, include_group_regs=True)
            except SPSDKRegsErrorRegisterNotFound as exc:
                logger.error(str(exc))
                raise exc
            reg_value = config[reg_name]

            if isinstance(reg_value, dict):
                if "value" in reg_value:
                    raw_val = reg_value["value"]
                    val = (
                        int(raw_val, 16)
                        if register.config_as_hexstring and isinstance(raw_val, str)
                        else value_to_int(raw_val)
                    )
                    register.set_value(val, False)
                else:
                    bitfields = reg_value["bitfields"] if "bitfields" in reg_value else reg_value
                    for bitfield_name in bitfields:
                        bitfield_val = bitfields[bitfield_name]
                        bitfield = register.find_bitfield(bitfield_name)
                        try:
                            bitfield.set_enum_value(bitfield_val, True)
                        except SPSDKValueError as e:
                            bitfield_val = (
                                hex(bitfield_val) if isinstance(bitfield_val, int) else bitfield_val
                            )
                            raise SPSDKError(
                                f"Bitfield value: {bitfield_val} of {bitfield.name} is out of range."
                                + f"\nBitfield width is {bitfield.width} bits"
                            ) from e
                        except SPSDKError:
                            # New versions of register data do not contain register and bitfield value in enum
                            old_bitfield = bitfield_val
                            bitfield_val = bitfield_val.replace(bitfield.name + "_", "").replace(
                                register.name + "_", ""
                            )
                            logger.warning(
                                f"Bitfield {old_bitfield} not found, trying backward"
                                f" compatibility mode with {bitfield_val}"
                            )
                            bitfield.set_enum_value(bitfield_val, True)

                    # Run the processing of loaded register value
                    register.set_value(register.get_value(True), False)
            elif isinstance(reg_value, (int, str)):
                val = (
                    int(reg_value, 16)
                    if register.config_as_hexstring and isinstance(reg_value, str)
                    else value_to_int(reg_value)
                )
                register.set_value(val, False)

            else:
                logger.error(f"There are no data for {reg_name} register.")

            logger.debug(f"The register {reg_name} has been loaded from configuration.")

    def _load_deprecated_names(self) -> dict[str, dict[str, Any]]:
        """Parse the deprecated_reg_names dictionary into a structured format.

        The structure separates register names and bitfield names for easier lookup.
        Supports both simplified list format for register names only and detailed
        dictionary format with bitfields configuration.

        :raises SPSDKError: Invalid register configuration format.
        :return: Dictionary with structured deprecated names containing 'alt_names'
                 and 'bitfields' keys for each register.
        """
        ret = {}
        registers = self.db.get_dict(self.feature, self._create_key("deprecated_reg_names"), {})
        for reg, value in registers.items():
            # if no bitfields are defined, allow simplified configuration
            if isinstance(value, list):
                ret[reg] = {"alt_names": value, "bitfields": {}}
            elif isinstance(value, dict):
                ret[reg] = {
                    "alt_names": value.get("alt_names", []),
                    "bitfields": {
                        bf_name: bf_details
                        for bf_name, bf_details in value.get("bitfields", {}).items()
                    },
                }
            else:
                raise SPSDKError(f"Invalid register configuration for {reg}")
        return ret

    def get_config(self, data_path: str = "./", diff: bool = False) -> Config:
        """Get the whole configuration in dictionary.

        The method extracts register configurations, optionally filtering to show only
        registers that differ from their reset values. For registers with bitfields,
        it returns a nested structure with bitfield values.

        :param data_path: Path to store the data files of configuration.
        :param diff: Get only configuration with difference value to reset state.
        :return: Configuration object containing registers values.
        """
        ret = Config()
        for reg in self._registers:
            if diff and reg.get_value(raw=True) == reg.get_reset_value():
                continue
            bitfields = reg._bitfields
            if bitfields:
                btf = {}
                for bitfield in bitfields:
                    if (
                        diff or bitfield.reserved
                    ) and bitfield.get_value() == bitfield.get_reset_value():
                        continue
                    btf[bitfield.name] = bitfield.get_enum_value()
                ret[reg.name] = btf
            else:
                ret[reg.name] = reg.get_hex_value()

        return ret

    @property
    def has_reset_value(self) -> bool:
        """Test if the current value is reset value.

        :return: True if the value has not been changed, False otherwise.
        """
        return all(x.has_reset_value for x in self._registers)

    @property
    def size(self) -> int:
        """Get the size of registers in bytes.

        Calculates the total size by finding the register with the highest offset
        and adding its width to determine the overall memory footprint.

        :return: Total size of all registers in bytes, or 0 if no registers exist.
        """
        if not self._registers:
            return 0

        last_reg = max(self._registers, key=lambda r: r.offset)
        return last_reg.offset + last_reg.width // 8


class Registers(_RegistersBase[Register]):
    """SPSDK Registers container for hardware register management.

    This class provides a specialized container for managing Register objects,
    extending the base registers functionality with specific register handling
    capabilities for NXP MCU register operations.

    :cvar register_class: The Register class used for creating register instances.
    """

    register_class = Register


class RegistersPreValidationHook(PreValidationHook):
    """Pre-validation hook for register configuration processing.

    This class handles the preprocessing of register configurations before validation,
    specifically converting register and bitfield keys to uppercase format to ensure
    consistency across different configuration formats and legacy compatibility.
    """

    def process_registers(self, config: dict) -> None:
        """Process register keys in a dictionary, converting them to uppercase.

        The method processes both top-level register keys and nested bitfield keys within register
        configurations. It handles both old format with 'bitfields' key and direct bitfield format.
        Registers with 'value' key are skipped from bitfield processing.

        :param config: Dictionary containing register configurations to be processed in-place
        """
        # Process top-level register keys
        for reg_key in list(config.keys()):
            if isinstance(reg_key, str) and reg_key != reg_key.upper():
                # Move the value to the uppercase key and remove the original key
                config[reg_key.upper()] = config.pop(reg_key)

        # Process bitfield keys within register dictionaries
        for reg_key, reg_value in config.items():
            if isinstance(reg_value, dict):
                if "value" in reg_value:
                    continue
                # Check if this is the old format with a 'bitfields' key
                if "bitfields" in reg_value and isinstance(reg_value["bitfields"], dict):
                    # Process bitfields inside the 'bitfields' key
                    bitfields_dict = reg_value["bitfields"]

                    for bf_key in list(bitfields_dict.keys()):
                        if isinstance(bf_key, str) and bf_key != bf_key.upper():
                            # Move the value to the uppercase key and remove the original key
                            bitfields_dict[bf_key.upper()] = bitfields_dict.pop(bf_key)
                else:
                    # Process direct bitfield keys
                    for bf_key in list(reg_value.keys()):
                        if isinstance(bf_key, str) and bf_key != bf_key.upper():
                            # Move the value to the uppercase key and remove the original key
                            reg_value[bf_key.upper()] = reg_value.pop(bf_key)

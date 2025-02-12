#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers descriptions."""

import json
import logging
from typing import Any, Generic, Iterator, Mapping, Optional, Type, TypeVar, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.database import get_db, get_whole_db
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.images import BinaryImage, BinaryPattern
from spsdk.utils.misc import (
    Endianness,
    format_value,
    get_bytes_cnt_of_int,
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
    """Access mode enum."""

    NONE = (0, "none", "Not applicable")
    RO = (1, "RO", "Read-only")
    RW = (2, "RW", "Read/Write")
    WO = (3, "WO", "Write-only")

    @property
    def is_readable(self) -> bool:
        """Return True if the object is readable."""
        return self in [Access.RO, Access.RW]

    @property
    def is_writable(self) -> bool:
        """Return True if the object is writeable."""
        return self in [Access.WO, Access.RW]

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Get enum member with given label.

        :param label: Label to be used for searching
        :return: Found enum member
        """
        return super().from_label(label.replace("/", ""))  # accept also R/W, R/O etc.


class RegsEnum:
    """Storage for register enumerations."""

    def __init__(self, name: str, value: Any, description: str, max_width: int = 0) -> None:
        """Constructor of RegsEnum class. Used to store enumeration information of bitfield.

        :param name: Name of enumeration.
        :param value: Value of enumeration.
        :param description: Text description of enumeration.
        :param max_width: Maximal width of enum value used to format output
        :raises SPSDKRegsError: Invalid input value.
        """
        self.name = name or "N/A"
        try:
            self.value = value_to_int(value)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {value}") from exc
        self.description = description or "N/A"
        self.max_width = max_width

    @classmethod
    def create_from_spec(cls, spec: dict[str, Any], maxwidth: int = 0) -> Self:
        """Initialization Enum from specification.

        :param spec: Input specification with enumeration data.
        :param maxwidth: The maximal width of bitfield for this enum (used for formatting).
        :return: The instance of this class.
        :raises SPSDKRegsError: Error during JSON data parsing.
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

        return cls(name, value, description, maxwidth)

    def create_spec(self) -> dict[str, Union[str, int]]:
        """Creates the enumeration specification.

        :returns: The specification dictionary of enum.
        """
        spec: dict[str, Union[str, int]] = {}
        spec["name"] = self.name
        spec["value"] = self.value
        spec["description"] = self.description
        return spec

    def get_value_int(self) -> int:
        """Method returns Integer value of enum.

        :return: Integer value of Enum.
        """
        return self.value

    def get_value_str(self) -> str:
        """Method returns formatted value.

        :return: Formatted string with enum value.
        """
        return format_value(self.value, self.max_width)

    def __str__(self) -> str:
        """Overrides 'ToString()' to print register.

        :return: Friendly string with enum information.
        """
        output = ""
        output += f"Name:        {self.name}\n"
        output += f"Value:       {self.get_value_str()}\n"
        output += f"Description: {self.description}\n"

        return output


class ConfigProcessor:
    """Base class for processing configuration data."""

    NAME = "NOP"

    def __init__(self, description: str = "") -> None:
        """Initialize the processor."""
        self.description = description

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file."""
        return value

    def post_process(self, value: int) -> int:
        """Post-process value going to config file."""
        return value

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file."""
        return value

    @classmethod
    def get_method_name(cls, config_string: str) -> str:
        """Return config processor method name."""
        return config_string.split(":")[0]

    @classmethod
    def get_params(cls, config_string: str) -> dict[str, int]:
        """Return config processor method parameters."""

        def split_params(param: str) -> tuple[str, str]:
            """Split key=value pair into a tuple."""
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
        """Return extra description for config processor."""
        parts = config_string.partition(";")
        return parts[2].replace("DESC=", "")

    @classmethod
    def from_str(cls, config_string: str) -> "ConfigProcessor":
        """Create config processor instance from configuration string."""
        return cls(config_string)

    @classmethod
    def from_spec(cls, spec: Optional[str]) -> Optional["ConfigProcessor"]:
        """Create config processor from JSON data entry."""
        if spec is None:
            return None
        method_name = cls.get_method_name(config_string=spec)
        for klass in cls.__subclasses__():
            if klass.NAME == method_name:
                return klass.from_str(config_string=spec)
        return None


class ShiftRightConfigProcessor(ConfigProcessor):
    """Config processor performing the right-shift operation."""

    NAME = "SHIFT_RIGHT"

    def __init__(self, count: int, description: str = "") -> None:
        """Initialize the right-shift config processor.

        :param count: Count of bit for shift operation
        :param description: Extra description for config processor, defaults to ""
        """
        super().__init__(
            description=description or f"Actual binary value is shifted by {count} bits to right."
        )
        self.count = count

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file."""
        return value >> self.count

    def post_process(self, value: int) -> int:
        """Post-process value going to config file."""
        return value << self.count

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file."""
        return value + self.count

    @classmethod
    def from_str(cls, config_string: str) -> "ShiftRightConfigProcessor":
        """Create config processor instance from configuration string."""
        name = cls.get_method_name(config_string=config_string)
        if name != cls.NAME:
            raise SPSDKRegsError(f"Invalid method name '{name}' expected {cls.NAME}")
        params = cls.get_params(config_string=config_string)
        if "count" not in params:
            raise SPSDKRegsError(f"{cls.NAME} requires the COUNT parameter")
        description = cls.get_description(config_string=config_string)
        return cls(count=value_to_int(params["count"]), description=description)


class RegsBitField:
    """Storage for register bitfields."""

    def __init__(
        self,
        parent: "Register",
        name: str,
        offset: int,
        width: int,
        uid: str,
        description: Optional[str] = None,
        reset_val: Optional[Any] = None,
        access: Access = Access.RW,
        hidden: bool = False,
        config_processor: Optional[ConfigProcessor] = None,
        no_yaml_comments: bool = False,
    ) -> None:
        """Constructor of RegsBitField class. Used to store bitfield information.

        :param parent: Parent register of bitfield.
        :param name: Name of bitfield.
        :param offset: Bit offset of bitfield.
        :param width: Bit width of bitfield.
        :param uid: Bitfield unique ID
        :param description: Text description of bitfield.
        :param reset_val: Reset value of bitfield if available.
        :param access: Access type of bitfield.
        :param hidden: The bitfield will be hidden from standard searches.
        :param no_yaml_comments: Disable yaml comments for this register.
        """
        self.parent = parent
        self.name = name or "N/A"
        self.offset = offset
        self.width = width
        self.uid = uid
        self.description = description or "N/A"
        self.access = access
        self.hidden = hidden
        self._enums: list[RegsEnum] = []
        self.config_processor = config_processor or ConfigProcessor()
        self.config_width = self.config_processor.width_update(width)
        self.reset_value = value_to_int(reset_val) if reset_val else self.get_value()
        self.no_yaml_comments = no_yaml_comments
        if reset_val:
            self.set_value(self.reset_value, raw=True)

    @classmethod
    def create_from_spec(
        cls, spec: dict[str, Any], offset: int, parent: "Register"
    ) -> "RegsBitField":
        """Initialization bitfield by specification.

        :param spec: Input subelement with bitfield data.
        :param offset: Bitfield offset.
        :param parent: Reference to parent Register object.
        :return: The instance of this class.
        """
        hidden_name = f"HIDDEN_BITFIELD_{offset:03X}"
        uid = spec.get("id", "")
        width = value_to_int(spec.get("width", 0))
        name = spec.get("name", hidden_name)
        hidden = bool(name == hidden_name)
        description = spec.get("description", "N/A")
        access = Access.from_label(spec.get("access", "RW"))
        reset_value = value_to_int(spec.get("reset_value_int", 0))
        config_processor = ConfigProcessor.from_spec(spec.get("config_preprocess"))
        no_yaml_comments = value_to_bool(spec.get("no_yaml_comments", False))
        bitfield = cls(
            parent,
            name,
            offset,
            width,
            uid,
            description,
            reset_value,
            access,
            hidden,
            config_processor,
            no_yaml_comments,
        )

        for enum_spec in spec.get("values", []):
            bitfield.add_enum(RegsEnum.create_from_spec(enum_spec, width))

        return bitfield

    def _get_uid(self) -> str:
        """Get UID of register."""
        if self.width == 1:
            bitfield_id = f"-bit{self.offset}"
        else:
            bitfield_id = f"-bits{self.offset}-{self.offset+self.width-1}"
        return self.uid or self.parent._get_uid() + bitfield_id

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        :returns: The specification of Register bitfield.
        """
        spec: dict[str, Union[str, list[dict[str, Union[str, int]]]]] = {}
        spec["id"] = self._get_uid()
        spec["offset"] = hex(self.offset)
        spec["width"] = str(self.width)
        if not self.hidden:
            spec["name"] = self.name
        spec["access"] = self.access.label
        spec["reset_value_int"] = hex(self.get_reset_value())
        spec["description"] = self.description
        enums = []
        for enum in self._enums:
            enums.append(enum.create_spec())
        if enums:
            spec["values"] = enums
        return spec

    def has_enums(self) -> bool:
        """Returns if the bitfields has enums.

        :return: True is has enums, False otherwise.
        """
        return len(self._enums) > 0

    def get_enums(self) -> list[RegsEnum]:
        """Returns bitfield enums.

        :return: List of bitfield enumeration values.
        """
        return self._enums

    def add_enum(self, enum: RegsEnum) -> None:
        """Add bitfield enum.

        :param enum: New enumeration value for bitfield.
        """
        self._enums.append(enum)

    def get_value(self) -> int:
        """Returns integer value of the bitfield.

        :return: Current value of bitfield.
        """
        reg_val = self.parent.get_value(raw=False)
        value = reg_val >> self.offset
        mask = (1 << self.width) - 1
        value = value & mask
        value = self.config_processor.post_process(value)
        return value

    def get_reset_value(self) -> int:
        """Returns integer reset value of the bitfield.

        :return: Reset value of bitfield.
        """
        return self.reset_value

    def set_value(self, new_val: Any, raw: bool = False, no_preprocess: bool = False) -> None:
        """Updates the value of the bitfield.

        :param new_val: New value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :param no_preprocess: If set, no pre-processing of value is applied.
        :raises SPSDKValueError: The input value is out of range.
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
        """Updates the value of the bitfield by its enum value.

        NOTE: The input value can be either string enum or integer. If string is used, the method tries to decode it
        Special RAW unprocessed values can be passed as string prefixed with RAW:.

        :param new_val: New enum value of bitfield.
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
        """Returns enum value of the bitfield.

        :return: Current value of bitfield.
        """
        value = self.get_value()
        for enum in self._enums:
            if enum.get_value_int() == value:
                return enum.name
        # return value
        return self.get_hex_value()

    def get_hex_value(self) -> str:
        """Get the value of register in string hex format.

        :return: Hexadecimal value of register.
        """
        fmt = f"0{self.config_width // 4}X"
        val = f"0x{format(self.get_value(), fmt)}"
        return val

    def get_enum_constant(self, enum_name: Union[str, int]) -> int:
        """Returns constant representation of enum by its name.

        :return: Constant of enum.
        :raises SPSDKRegsErrorEnumNotFound: The enum has not been found.
        """
        for enum in self._enums:
            if enum.name == enum_name:
                return enum.get_value_int()

        raise SPSDKRegsErrorEnumNotFound(f"The enum for {enum_name} has not been found.")

    def get_enum_names(self) -> list[str]:
        """Returns list of the enum strings.

        :return: List of enum names.
        """
        return [x.name for x in self._enums]

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the bitfield.
        """
        output = ""
        output += f"Name:     {self.name}\n"
        output += f"Offset:   {self.offset} bits\n"
        output += f"Width:    {self.width} bits\n"
        output += f"Access:   {self.access.label} bits\n"
        output += f"Reset val:{self.reset_value}\n"
        output += f"Description: \n {self.description}\n"
        if self.hidden:
            output += "This is hidden bitfield!\n"

        i = 0
        for enum in self._enums:
            output += f"Enum             #{i}: \n" + str(enum)
            i += 1

        return output

    def __repr__(self) -> str:
        return f"<BitField {self.name} = {self.get_hex_value()}>"


class Register:
    """Initialization register by input information."""

    def __init__(
        self,
        name: str,
        offset: int,
        width: int,
        uid: str,
        description: Optional[str] = None,
        reverse: bool = False,
        access: Access = Access.RW,
        config_as_hexstring: bool = False,
        reverse_subregs_order: bool = False,
        base_endianness: Endianness = Endianness.BIG,
        alt_widths: Optional[list[int]] = None,
        hidden: bool = False,
        no_yaml_comments: bool = False,
    ) -> None:
        """Constructor of RegsRegister class. Used to store register information.

        :param name: Name of register.
        :param offset: Byte offset of register.
        :param width: Bit width of register.
        :param uid: Register unique ID.
        :param description: Text description of register.
        :param reverse: Multi byte register value could be printed in reverse order.
        :param access: Access type of register.
        :param config_as_hexstring: Config is stored as a hex string.
        :param reverse_subregs_order: Reverse order of sub registers.
        :param base_endianness: Base endianness for bytes import/export of value.
        :param alt_widths: List of alternative widths.
        :param hidden: The register will be hidden from standard searches.
        :param no_yaml_comments: Disable yaml comments for this register.
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
        self._value = 0
        self._reset_value = 0
        self.config_as_hexstring = config_as_hexstring
        self.reverse_subregs_order = reverse_subregs_order
        self.base_endianness = base_endianness
        self.alt_widths = alt_widths
        self._alias_names: list[str] = []
        self.hidden = hidden
        self.no_yaml_comments = no_yaml_comments

        # Grouped register members
        self.sub_regs: list[Self] = []
        self._sub_regs_width_init = False
        self._sub_regs_width = 0

    def __hash__(self) -> int:
        return hash(self.uid)

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
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
        if obj._reset_value != self._reset_value:
            return False
        return True

    @classmethod
    def create_from_spec(cls, spec: dict[str, Any]) -> Self:
        """Initialization register by specification.

        :param spec: Input specification with register data.
        :return: The instance of this class.
        """
        uid = spec.get("id", "")
        name = spec.get("name", "N/A")
        offset = value_to_int(spec.get("offset_int", 0))
        width = value_to_int(spec.get("reg_width", 32))
        description = spec.get("description", "N/A")
        access = Access.from_label(spec.get("access", "RW"))
        reserved = value_to_bool(spec.get("is_reserved", False))
        no_yaml_comments = value_to_bool(spec.get("no_yaml_comments", False))
        reg = cls(
            name=name,
            offset=offset,
            width=width,
            uid=uid,
            description=description,
            reverse=False,
            access=access,
            hidden=reserved,
            no_yaml_comments=no_yaml_comments,
        )
        reg._reset_value = value_to_int(spec.get("reset_value_int", 0))
        if reg._reset_value:
            reg.set_value(reg._reset_value, True)
        spec_bitfields = spec.get("bitfields", [])
        offset = 0
        for bitfield_spec in spec_bitfields:
            bitfield = RegsBitField.create_from_spec(bitfield_spec, offset, reg)
            offset += bitfield.width
            reg.add_bitfield(bitfield)
        return reg

    def _get_uid(self) -> str:
        """Get UID of register."""
        if self.uid:
            return self.uid
        if self.hidden:
            return f"reserved{self.offset:03X}"

        return f"field{self.offset:03X}"

    def create_spec(self) -> dict[str, Any]:
        """Creates the register specification structure.

        :returns: The register specification.
        """
        spec: dict[str, Union[str, list]] = {}
        spec["id"] = self._get_uid()
        spec["offset_int"] = hex(self.offset)
        spec["reg_width"] = str(self.width)
        spec["name"] = self.name
        spec["description"] = self.description
        spec["reset_value_int"] = hex(self.get_reset_value())
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
        return spec

    def add_alias(self, alias: str) -> None:
        """Add alias name to register.

        :param alias: Register name alias.
        """
        if alias not in self._alias_names:
            self._alias_names.append(alias)

    def has_group_registers(self) -> bool:
        """Returns true if register is compounded from sub-registers.

        :return: True if register has sub-registers, False otherwise.
        """
        return len(self.sub_regs) > 0

    def _add_group_reg(self, reg: Self) -> None:
        """Add group element for this register.

        :param reg: Register member of this register group.
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
            if self.access != reg.access:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} has different access type."
                )

        reg.base_endianness = self.base_endianness
        self.sub_regs.append(reg)

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register.

        :param val: The new value to set.
        :param raw: Do not use any modification hooks.
        :raises SPSDKError: When invalid values is loaded into register
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
        """Reset the value of register.

        :param raw: Do not use any modification hooks.
        """
        self.set_value(self.get_reset_value(), raw)

    def get_alt_width(self, value: int) -> int:
        """Get alternative width of register.

        :param value: Input value to recognize width
        :return: Current width
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

        :param raw: Do not use any modification hooks.
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

        :param raw: Do not use any modification hooks.
        :return: Register value in bytes.
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
        """Returns reset value of the register.

        :return: Reset value of register.
        """
        value = self._reset_value
        for bitfield in self._bitfields:
            width = bitfield.width
            offset = bitfield.offset
            val = bitfield.reset_value
            value |= (val & ((1 << width) - 1)) << offset

        return value

    def add_bitfield(self, bitfield: RegsBitField) -> None:
        """Add register bitfield.

        :param bitfield: New bitfield value for register.
        """
        self._bitfields.append(bitfield)

    def get_bitfields(self, exclude: Optional[list[str]] = None) -> list[RegsBitField]:
        """Returns register bitfields.

        Method allows exclude some bitfields by their names.
        :param exclude: Exclude list of bitfield names if needed.
        :return: Returns List of register bitfields.
        """
        ret = []
        for bitf in self._bitfields:
            if bitf.hidden:
                continue
            if exclude and bitf.name.startswith(tuple(exclude)):
                continue
            ret.append(bitf)
        return ret

    def get_bitfield_names(self, exclude: Optional[list[str]] = None) -> list[str]:
        """Returns list of the bitfield names.

        :param exclude: Exclude list of bitfield names if needed.
        :return: List of bitfield names.
        """
        return [x.name for x in self.get_bitfields(exclude)]

    def get_bitfield(self, uid: str) -> RegsBitField:
        """Returns the instance of the bitfield by its UID.

        :param uid: The uid of the bitfield.
        :return: Instance of the bitfield.
        :raises SPSDKRegsErrorBitfieldNotFound: The bitfield doesn't exist.
        """
        for bitfield in self._bitfields:
            if uid == bitfield.uid:
                return bitfield

        raise SPSDKRegsErrorBitfieldNotFound(
            f" The UID:{uid} is not found in register {self.name}."
        )

    def find_bitfield(self, name: str) -> RegsBitField:
        """Returns the instance of the bitfield by its name.

        :param name: The name of the bitfield.
        :return: Instance of the bitfield.
        :raises SPSDKRegsErrorBitfieldNotFound: The bitfield doesn't exist.
        """
        for bitfield in self._bitfields:
            if name == bitfield.name:
                return bitfield
            if name == bitfield.uid:
                return bitfield

        raise SPSDKRegsErrorBitfieldNotFound(f" The {name} is not found in register {self.name}.")

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the register.
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
        return f"<{self.__class__.__name__} {self.name} = {self.get_hex_value()}>"


RegisterClassT = TypeVar("RegisterClassT", bound=Register)


class _RegistersBase(Generic[RegisterClassT]):
    """SPSDK Generic class for registers handling."""

    register_class: Type[RegisterClassT]
    TEMPLATE_NOTE = (
        "All registers is possible to define also as one value although the bitfields are used. "
        "Instead of bitfields: ... field, the value: ... definition works as well."
    )

    def __init__(
        self,
        family: str,
        feature: str,
        base_key: Optional[Union[list[str], str]] = None,
        revision: str = "latest",
        base_endianness: Endianness = Endianness.BIG,
        just_standard_library_data: bool = False,
    ) -> None:
        """Initialization of Registers class.

        :param family: Chip family
        :param feature: Feature name
        :param base_key: Base item key or key path in list like ['grp1', 'grp2', 'key']
        :param revision: Optional Chip family revision
        :param base_endianness: The base endianness of registers in binary form
        :param just_standard_library_data: The specification is gets from embedded library if True,
            otherwise Restricted data takes in count
        """
        self._registers: list[RegisterClassT] = []
        self.family = family
        self.revision = revision
        self.base_endianness = base_endianness
        self.feature = feature
        self.base_key = base_key

        try:
            self.db = get_db(device=family, revision=revision)
            spec_file_name = self.db.get_file_path(
                self.feature,
                self._create_key("reg_spec"),
                just_standard_lib=just_standard_library_data,
            )
            grouped_registers = self.db.get_list(
                self.feature, self._create_key("grouped_registers"), []
            )
            self._load_spec(spec_file=spec_file_name, grouped_regs=grouped_registers)
        except SPSDKError as exc:
            # Only path for testing and internal tools
            logger.error(
                f"Loading of database failed, inform SPSDK team about this error: {str(exc)}"
                f"\n Family: {family}, Feature: {feature}, Revision: {revision}"
            )

    def __iter__(self) -> Iterator[RegisterClassT]:
        """Return an iterator."""
        return iter(self._registers)

    def __len__(self) -> int:
        """Number of registers."""
        return len(self._registers)

    def _create_key(self, key: str) -> Union[str, list[str]]:
        """Create the final key path.

        :param key: requested final key
        :return: Full key path to database
        """
        if not self.base_key:
            return key
        if isinstance(self.base_key, str):
            return [self.base_key, key]
        return self.base_key + [key]

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        if not (
            isinstance(obj, self.__class__)
            and obj.family == self.family
            and obj.base_endianness == self.base_endianness
        ):
            return False
        ret = obj._registers == self._registers
        return ret

    def find_reg(self, name: str, include_group_regs: bool = False) -> RegisterClassT:
        """Returns the instance of the register by its name.

        :param name: The name of the register.
        :param include_group_regs: The algorithm will check also group registers.
        :return: Instance of the register.
        :raises SPSDKRegsErrorRegisterNotFound: The register doesn't exist.
        """

        def check_reg(reg: RegisterClassT) -> bool:
            if name == reg.name:
                return True
            if name in reg._alias_names:
                return True
            if name == reg.uid:
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
        """Returns the instance of the register by its UID.

        :param uid: The unique ID of the register.
        :return: Instance of the register.
        :raises SPSDKRegsErrorRegisterNotFound: The register doesn't exist.
        """
        for reg in self._registers:
            if uid == reg.uid:
                return reg
            if reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    if uid == sub_reg.uid:
                        return sub_reg

        raise SPSDKRegsErrorRegisterNotFound(
            f"The UID:{uid} is not found in loaded registers for {self.family} device."
        )

    def add_register(self, reg: RegisterClassT) -> None:
        """Adds register into register list.

        :param reg: Register to add to the class.
        :raises SPSDKError: Invalid type has been provided.
        :raises SPSDKRegsError: Cannot add register with same name
        """
        if not isinstance(reg, self.register_class):
            raise SPSDKError(f"The register has invalid type: {type(reg)}.")

        if reg.name in self.get_reg_names():
            raise SPSDKRegsError(f"Cannot add register with same name: {reg.name}.")

        for idx, register in enumerate(self._registers):
            # TODO solve problem with group register that are always at 0 offset
            if register.offset == reg.offset != 0:
                logger.debug(
                    f"Found register at the same offset {hex(reg.offset)}"
                    f", adding {reg.name} as an alias to {register.name}"
                )
                self._registers[idx].add_alias(reg.name)
                self._registers[idx]._bitfields.extend(reg._bitfields)
                return
        # update base endianness for all registers in group
        reg.base_endianness = self.base_endianness
        self._registers.append(reg)

    def remove_registers(self) -> None:
        """Remove all registers."""
        self._registers.clear()

    def remove_register(self, name: str) -> None:
        """Remove a register from the list."""
        self._registers.remove(self.find_reg(name, True))

    def get_registers(
        self, exclude: Optional[list[str]] = None, include_group_regs: bool = False
    ) -> list[RegisterClassT]:
        """Returns list of the registers.

        Method allows exclude some register by their names.
        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
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

        return [x for x in regs if not x.hidden]

    def get_reg_names(
        self, exclude: Optional[list[str]] = None, include_group_regs: bool = False
    ) -> list[str]:
        """Returns list of the register names.

        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
        """
        return [x.name for x in self.get_registers(exclude, include_group_regs)]

    def reset_values(self, exclude: Optional[list[str]] = None) -> None:
        """The method reset values in registers.

        :param exclude: The list of register names to be excluded.
        """
        for reg in self.get_registers(exclude):
            reg.reset_value(True)

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the registers.
        """
        output = ""
        output += "Device name:        " + self.family + "\n"
        for reg in self._registers:
            output += str(reg) + "\n"

        return output

    def image_info(
        self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")
    ) -> BinaryImage:
        """Export Registers into  binary information.

        :param size: Result size of Image, 0 means automatic minimal size.
        :param pattern: Pattern of gaps, defaults to "zeros"
        """
        image = BinaryImage(self.family, size=size, pattern=pattern)
        for reg in self._registers:
            description = reg.description
            if reg._alias_names:
                description += f"\n Alias names: {', '.join(reg._alias_names)}"
            image.add_image(
                BinaryImage(
                    reg.name,
                    reg.width // 8,
                    offset=reg.offset,
                    description=description,
                    binary=reg.get_bytes_value(raw=True),
                )
            )

        return image

    def export(self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")) -> bytes:
        """Export Registers into binary.

        :param size: Result size of Image, 0 means automatic minimal size.
        :param pattern: Pattern of gaps, defaults to "zeros"
        """
        return self.image_info(size, pattern).export()

    def parse(self, binary: bytes) -> None:
        """Parse the binary data values into loaded registers.

        :param binary: Binary data to parse.
        """
        bin_len = len(binary)
        if bin_len < len(self.image_info()):
            logger.info(
                f"Input binary is smaller than registers supports: {bin_len} != {len(self.image_info())}"
            )
        for reg in self.get_registers():
            if bin_len < reg.offset + reg.width // 8:
                logger.debug(f"Parsing of binary block ends at {reg.name}")
                break
            binary_value = binary[reg.offset : reg.offset + reg.width // 8]
            reg.set_value(int.from_bytes(binary_value, self.base_endianness.value), raw=True)

    def get_base_offset(self) -> int:
        """Return minimal offset from registers."""
        return min(r.offset for r in self.get_registers())

    def normalize_offsets(self) -> None:
        """Normalize (shift) register offsets, so the first register's offset is zero."""
        base_offset = self.get_base_offset()
        for r in self.get_registers():
            r.offset -= base_offset

    def get_diff(
        self, other: Self
    ) -> list[Union[tuple[RegsBitField, RegsBitField], tuple[Register, Register]]]:
        """Return registers and bitfields containing different value.

        The tuples contain "expected" and "actual" value respectively.
        If a register doesn't contain bitfields the whole register is included.
        If a register contains bitfields, only non-matching bitfields are included.
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

        :param bitfield: Bitfield used to generate description.
        :return: Bitfield description.
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
                description += f"\n- {enum.name}, ({enum.get_value_int()}): {enum_description}"
        return description

    def get_validation_schema(self) -> dict:
        """Get the JSON SCHEMA for registers.

        :return: JSON SCHEMA.
        """
        properties: dict[str, Any] = {}
        for reg in self.get_registers():
            bitfields = reg._bitfields
            reg_schema = [
                {
                    "type": ["string", "number"],
                    "skip_in_template": len(bitfields) > 0,
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
                        bitfields_schema[bitfield.name] = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "template_value": bitfield.get_value(),
                            "skip_in_template": bitfield.hidden,
                            "no_yaml_comments": bitfield.no_yaml_comments,
                        }
                    else:
                        bitfields_schema[bitfield.name] = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "enum_template": bitfield.get_enum_names(),
                            "minimum": 0,
                            "maximum": (1 << bitfield.width) - 1,
                            "template_value": bitfield.get_enum_value(),
                            "skip_in_template": bitfield.hidden,
                            "no_yaml_comments": bitfield.no_yaml_comments,
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
                            "bitfields": {"type": "object", "properties": bitfields_schema}
                        },
                    }
                )
                # Extend by new style of bitfields
                reg_schema.append(
                    {
                        "type": "object",
                        "skip_in_template": False,
                        "required": [],
                        "additionalProperties": False,
                        "no_yaml_comments": reg.no_yaml_comments,
                        "properties": bitfields_schema,
                    },
                )

            properties[reg.name] = {
                "title": f"{reg.name}",
                "description": f"Offset: 0x{reg.offset:08X}, Width: {reg.width}b; {reg.description}",
                "no_yaml_comments": reg.no_yaml_comments,
                "oneOf": reg_schema,
            }

        return {"type": "object", "title": self.family, "properties": properties}

    @classmethod
    def _get_register_group(
        cls, reg: RegisterClassT, grouped_regs: Optional[list[dict]] = None
    ) -> Optional[dict]:
        """Help function to recognize if the register should be part of group."""
        if grouped_regs:
            for group in grouped_regs:
                if reg.uid in group["sub_regs"]:
                    return group
        return None

    def _load_from_spec(
        self, config: dict[str, Any], grouped_regs: Optional[list[dict]] = None
    ) -> None:
        for spec_group in config.get("groups", []):
            for spec_reg in spec_group.get("registers", []):
                reg = self.register_class.create_from_spec(spec_reg)
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

    def _load_spec(self, spec_file: str, grouped_regs: Optional[list[dict]] = None) -> None:
        """Function loads the registers from the given JSON.

        :param spec_file: Input JSON file path.
        :param grouped_regs: List of register prefixes names to be grouped into one.
        :raises SPSDKError: JSON parse problem occurs.
        """
        try:
            with open(spec_file, "r", encoding="utf-8") as f:
                spec = json.load(f)
        except json.JSONDecodeError as exc:
            raise SPSDKError(
                f"Cannot load register specification: {spec_file}. {str(exc)}"
            ) from exc
        self._load_from_spec(spec, grouped_regs)

    def write_spec(self, file_name: str) -> None:
        """Write loaded register structures into JSON file.

        :param file_name: The name of JSON file that should be created.
        """
        spec: dict[str, Any] = {}
        spec["cpu"] = self.family

        regs = []
        for reg in self._registers:
            regs.append(reg.create_spec())
        group = {"name": "General regs", "description": "General register generated by SPSDK"}
        spec["groups"] = [{"group": group, "registers": regs}]

        write_file(json.dumps(spec, indent=4), file_name)

    def load_yml_config(self, yml_data: dict[str, Any]) -> None:
        """The function loads the configuration from YML file.

        Note: It takes in count the restricted data and different names to standard data
        in embedded database.

        :param yml_data: The YAML commented data with register values.
        """
        try:
            self._load_yml_config(yml_data)
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
                revision=self.revision,
                base_endianness=self.base_endianness,
                just_standard_library_data=True,
            )
            std_regs._load_yml_config(yml_data)
            self.parse(std_regs.export())
            logger.warning(
                "The input YAML configuration file has been converted from standard"
                " library names to restricted data library extension."
            )

    def _load_yml_config(self, yml_data: dict[str, Any]) -> None:
        """The function loads the configuration from YML file.

        :param yml_data: The YAML commented data with register values.
        """
        if not isinstance(yml_data, dict):
            raise SPSDKError("The configuration does not contain any register settings.")
        for reg_name in yml_data.keys():
            reg_value = yml_data[reg_name]
            try:
                register = self.find_reg(reg_name, include_group_regs=True)
            except SPSDKRegsErrorRegisterNotFound as exc:
                logger.error(str(exc))
                raise exc
            if isinstance(reg_value, dict):
                if "value" in reg_value.keys():
                    raw_val = reg_value["value"]
                    val = (
                        int(raw_val, 16)
                        if register.config_as_hexstring and isinstance(raw_val, str)
                        else value_to_int(raw_val)
                    )
                    register.set_value(val, False)
                else:
                    bitfields = (
                        reg_value["bitfields"] if "bitfields" in reg_value.keys() else reg_value
                    )
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

    def get_config(self, diff: bool = False) -> dict[str, Any]:
        """Get the whole configuration in dictionary.

        :param diff: Get only configuration with difference value to reset state.
        :return: Dictionary of registers values.
        """
        ret: dict[str, Any] = {}
        for reg in self._registers:
            if diff and reg.get_value(raw=True) == reg.get_reset_value():
                continue
            bitfields = reg._bitfields
            if bitfields:
                btf = {}
                for bitfield in bitfields:
                    if (
                        diff or bitfield.hidden
                    ) and bitfield.get_value() == bitfield.get_reset_value():
                        continue
                    btf[bitfield.name] = bitfield.get_enum_value()
                ret[reg.name] = btf
            else:
                ret[reg.name] = reg.get_hex_value()

        return ret


class Registers(_RegistersBase[Register]):
    """SPSDK class for registers handling."""

    register_class = Register

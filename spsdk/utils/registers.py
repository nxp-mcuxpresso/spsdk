#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers descriptions with support for XML files."""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Mapping, Union
from xml.dom import minidom

from jinja2 import Environment, FileSystemLoader
from ruamel.yaml.comments import CommentedMap as CM

from spsdk import SPSDK_YML_INDENT, SPSDKError, utils
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.misc import format_value, value_to_bool, value_to_bytes, value_to_int

HTMLDataElement = Mapping[str, Union[str, dict, list]]
HTMLData = List[HTMLDataElement]

logger = logging.getLogger(__name__)


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
    def from_xml_element(cls, xml_element: ET.Element, maxwidth: int = 0) -> "RegsEnum":
        """Initialization Enum by XML ET element.

        :param xml_element: Input XML subelement with enumeration data.
        :param maxwidth: The maximal width of bitfield for this enum (used for formating).
        :return: The instance of this class.
        :raises SPSDKRegsError: Error during enum XML parsing.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        if "value" not in xml_element.attrib:
            raise SPSDKRegsError(f"Missing Enum Value Key for {name}.")

        raw_val = xml_element.attrib["value"]
        try:
            value = value_to_int(raw_val)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {raw_val}") from exc

        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"

        return cls(name, value, descr, maxwidth)

    def get_value_int(self) -> int:
        """Method returns Integer value of enum.

        :return: Integer value of Enum.
        """
        return self.value

    def get_value_str(self) -> str:
        """Method returns formated value.

        :return: Formatted string with enum value.
        """
        return format_value(self.value, self.max_width)

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "bit_field_value")
        element.set("name", self.name)
        element.set("value", self.get_value_str())
        element.set("description", self.description)

    def __str__(self) -> str:
        """Overrides 'ToString()' to print register.

        :return: Friendly string with enum information.
        """
        output = ""
        output += f"Name:        {self.name}\n"
        output += f"Value:       {self.get_value_str()}\n"
        output += f"Description: {self.description}\n"

        return output


class RegsBitField:
    """Storage for register bitfields."""

    def __init__(
        self,
        parent: "RegsRegister",
        name: str,
        offset: int,
        width: int,
        description: str = None,
        reset_val: Any = "0",
        access: str = "RW",
        hidden: bool = False,
    ) -> None:
        """Constructor of RegsBitField class. Used to store bitfield information.

        :param parent: Parent register of bitfield.
        :param name: Name of bitfield.
        :param offset: Bit offset of bitfield.
        :param width: Bit width of bitfield.
        :param description: Text description of bitfield.
        :param reset_val: Reset value of bitfield.
        :param access: Access type of bitfield.
        :param hidden: The bitfield will be hidden from standard searches.
        """
        self.parent = parent
        self.name = name or "N/A"
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.reset_value = value_to_int(reset_val, 0)
        self.access = access
        self.hidden = hidden
        self._enums: List[RegsEnum] = []
        self._update_reset_value()
        self.set_value(self.reset_value, raw=True)

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element, parent: "RegsRegister") -> "RegsBitField":
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :param parent: Reference to parent RegsRegister object.
        :return: The instance of this class.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        offset = value_to_int(xml_element.attrib["offset"]) if "offset" in xml_element.attrib else 0
        width = value_to_int(xml_element.attrib["width"]) if "width" in xml_element.attrib else 0
        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"
        access = xml_element.attrib["access"] if "access" in xml_element.attrib else "R/W"
        reset_value = (
            value_to_int(xml_element.attrib["reset_value"])
            if "reset_value" in xml_element.attrib
            else 0
        )
        hidden = False if xml_element.tag == "bit_field" else True
        bitfield = cls(parent, name, offset, width, descr, reset_value, access, hidden)

        if xml_element.text:
            xml_enums = xml_element.findall("bit_field_value")
            for xml_enum in xml_enums:
                bitfield.add_enum(RegsEnum.from_xml_element(xml_enum, width))
        return bitfield

    def has_enums(self) -> bool:
        """Returns if the bitfields has enums.

        :return: True is has enums, False otherwise.
        """
        return len(self._enums) > 0

    def get_enums(self) -> List[RegsEnum]:
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
        reg_val = self.parent.get_value()
        value = reg_val >> self.offset
        mask = (1 << self.width) - 1
        value = value & mask
        return value

    def get_reset_value(self) -> int:
        """Returns integer reset value of the bitfield.

        :return: Reset value of bitfield.
        """
        return self.reset_value

    def set_value(self, new_val: Any, raw: bool = False) -> None:
        """Updates the value of the bitfield.

        :param new_val: New value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKError: The input value is out of range.
        """
        new_val_int = value_to_int(new_val)
        if new_val_int > 1 << self.width:
            raise SPSDKError("The input value is out of bitfield range")
        reg_val = self.parent.get_value()
        mask = ((1 << self.width) - 1) << self.offset
        reg_val = reg_val & ~mask
        value = (new_val_int << self.offset) & mask
        reg_val = reg_val | value
        self.parent.set_value(reg_val, raw)

    def _update_reset_value(self) -> None:
        """Updates the reset value of the bitfield in register."""
        reg_val = self.parent.get_value()
        mask = ((1 << self.width) - 1) << self.offset
        reg_val = reg_val & ~mask
        value = (self.reset_value << self.offset) & mask
        reg_val = reg_val | value
        self.parent._reset_value = reg_val  # pylint: disable=protected-access

    def set_enum_value(self, new_val: str, raw: bool = False) -> None:
        """Updates the value of the bitfield by its enum value.

        :param new_val: New enum value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKRegsErrorEnumNotFound: Input value cannot be decoded.
        """
        try:
            val_int = self.get_enum_constant(new_val)
        except SPSDKRegsErrorEnumNotFound as exc:
            # Try to decode standard input
            try:
                val_int = value_to_int(new_val)
            except TypeError:
                raise exc
        self.set_value(val_int, raw)

    def get_enum_value(self) -> Union[str, int]:
        """Returns enum value of the bitfield.

        :return: Current value of bitfield.
        """
        value = self.get_value()
        if len(self._enums) > 0:
            for enum in self._enums:
                if enum.get_value_int() == value:
                    return enum.name
        return value

    def get_enum_constant(self, enum_name: str) -> int:
        """Returns constant representation of enum by its name.

        :return: Constant of enum.
        :raises SPSDKRegsErrorEnumNotFound: The enum has not been found.
        """
        for enum in self._enums:
            if enum.name == enum_name:
                return enum.get_value_int()

        raise SPSDKRegsErrorEnumNotFound(f"The enum for {enum_name} has not been found.")

    def get_enum_names(self) -> List[str]:
        """Returns list of the enum strings.

        :return: List of enum names.
        """
        return [x.name for x in self._enums]

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "reserved_bit_field" if self.hidden else "bit_field")
        element.set("offset", hex(self.offset))
        element.set("width", str(self.width))
        element.set("name", self.name)
        element.set("access", self.access)
        element.set("reset_value", format_value(self.reset_value, self.width))
        element.set("description", self.description)
        for enum in self._enums:
            enum.add_et_subelement(element)

    def get_html_data_element(self) -> HTMLDataElement:
        """Returns HTML element of bitfield.

        :return: HTML element.
        """
        enum_desc = {}
        for enum in self.get_enums():
            enum_desc[enum.get_value_str()] = enum.description

        return {
            "name": self.name,
            "desc": self.description,
            "width": str(self.width),
            "offset": str(self.offset),
            "bit_values": enum_desc,
        }

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the bitfield.
        """
        output = ""
        output += f"Name:     {self.name}\n"
        output += f"Offset:   {self.offset} bits\n"
        output += f"Width:    {self.width} bits\n"
        output += f"Access:   {self.access} bits\n"
        output += f"Reset val:{self.reset_value}\n"
        output += f"Description: \n {self.description}\n"
        if self.hidden:
            output += f"This is hidden bitfield!\n"

        i = 0
        for enum in self._enums:
            output += f"Enum             #{i}: \n" + str(enum)
            i += 1

        return output


class RegsRegister:
    """Initialization register by input information."""

    def __init__(
        self,
        name: str,
        offset: int,
        width: int,
        description: str = None,
        reverse: bool = False,
        access: str = None,
        config_as_hexstring: bool = False,
    ) -> None:
        """Constructor of RegsRegister class. Used to store register information.

        :param name: Name of register.
        :param offset: Byte offset of register.
        :param width: Bit width of register.
        :param description: Text description of register.
        :param reverse: Multi  register value is stored in reverse order.
        :param access: Access type of register.
        :param config_as_hexstring: Config is stored as a hex string.
        """
        self.name = name
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.access = access or "RW"
        self.reverse = reverse
        self._bitfields: List[RegsBitField] = []
        self._set_value_hooks: list = []
        self._value = 0
        self._reset_value = 0
        self.config_as_hexstring = config_as_hexstring

        # Grouped register members
        self.sub_regs: List["RegsRegister"] = []
        self._sub_regs_width_init = False
        self._sub_regs_width = 0

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element) -> "RegsRegister":
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :return: The instance of this class.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        offset = value_to_int(xml_element.attrib["offset"]) if "offset" in xml_element.attrib else 0
        width = value_to_int(xml_element.attrib["width"]) if "width" in xml_element.attrib else 0
        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"
        reverse = (
            xml_element.attrib["reversed"] if "reversed" in xml_element.attrib else "False"
        ) == "True"
        access = xml_element.attrib["access"] if "access" in xml_element.attrib else "N/A"

        reg = cls(name, offset, width, descr, reverse, access)
        if xml_element.text:
            xml_bitfields = xml_element.findall("bit_field")
            xml_bitfields.extend(xml_element.findall("reserved_bit_field"))
            xml_bitfields_len = len(xml_bitfields)
            for xml_bitfield in xml_bitfields:
                bitfield = RegsBitField.from_xml_element(xml_bitfield, reg)
                if xml_bitfields_len == 1 and bitfield.width == reg.width:
                    if len(reg.description) < len(bitfield.description):
                        reg.description = bitfield.description
                    reg.access = bitfield.access
                else:
                    if reg.access == "N/A":
                        reg.access = "Bitfields depended"
                    reg.add_bitfield(bitfield)
        return reg

    def has_group_registers(self) -> bool:
        """Returns true if register is compounded from sub-registers.

        :return: True if register has sub-registers, False otherwise.
        """
        return len(self.sub_regs) > 0

    def add_group_reg(self, reg: "RegsRegister") -> None:
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
            if reg.reverse:
                self.reverse = True
            if self.access == "RW":
                self.access = reg.access
        else:
            # There is strong rule that supported group MUST be in one row in memory!
            if not self._sub_regs_width_init:
                if self.offset + self.width // 8 != reg.offset:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} doesn't follow the previous one."
                    )
                self.width += reg.width
            else:
                if self.offset + self.width // 8 <= reg.offset:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} doesn't follow the previous one."
                    )
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

        if self.reverse:
            reg.reverse = True

        self.sub_regs.append(reg)

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "register")
        element.set("offset", hex(self.offset))
        element.set("width", str(self.width))
        element.set("name", self.name)
        element.set("reversed", str(self.reverse))
        element.set("description", self.description)
        for bitfield in self._bitfields:
            bitfield.add_et_subelement(element)

    def get_html_data_element(self, exclude: List[str] = None) -> HTMLDataElement:
        """Returns HTML element of register.

        :return: HTML element.
        """
        bitfield_desc = []
        for bitfield in self.get_bitfields(exclude):
            bitfield_desc.append(bitfield.get_html_data_element())

        return {
            "name": self.name,
            "desc": self.description,
            "width": str(self.width),
            "offset": hex(self.offset),
            "bitfields": bitfield_desc,
        }

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register.

        :param val: The new value to set.
        :param raw: Do not use any modification hooks.
        :raises SPSDKError: When invalid values is loaded into register
        """
        try:
            value = value_to_int(val)
            if not raw and len(self._set_value_hooks) > 0:
                for hook in self._set_value_hooks:
                    value = hook[0](value, hook[1])

            self._value = value

            if self.has_group_registers():
                # Update also values in sub registers
                subreg_width = self.sub_regs[0].width
                for index, sub_reg in enumerate(self.sub_regs, start=1):
                    # sub_reg.set_value((value >> (index * subreg_width)) & ((1 << subreg_width) - 1))
                    sub_reg.set_value(
                        (value >> (self.width - index * subreg_width)) & ((1 << subreg_width) - 1)
                    )

        except SPSDKError:
            logger.error(f"Loaded invalid value {str(val)}")
            raise SPSDKError(f"Loaded invalid value {str(val)}")

    def reset_value(self, raw: bool = False) -> None:
        """Reset the value of register.

        :param raw: Do not use any modification hooks.
        """
        value = 0
        for bitfield in self.get_bitfields():
            width = bitfield.width
            offset = bitfield.offset
            val = bitfield.reset_value
            value |= (val & ((1 << width) - 1)) << offset

        self.set_value(value, raw)

    def get_value(self) -> int:
        """Get the value of register."""
        if self.has_group_registers():
            # Update local value, by the sub register values
            subreg_width = self.sub_regs[0].width
            sub_regs_value = 0
            for index, sub_reg in enumerate(self.sub_regs, start=1):
                sub_regs_value |= sub_reg.get_value() << (self.width - index * subreg_width)
            if sub_regs_value != self._value:
                self.set_value(sub_regs_value, raw=True)

        return self._value

    def get_bytes_value(self) -> bytes:
        """Get the bytes value of register.

        The value endianism is returned by 'reversed' member.
        :return: Register value in bytes.
        """
        endianism = "little" if not self.reverse else "big"
        return value_to_bytes(
            self.get_value(), align_to_2n=False, byte_cnt=self.width // 8, endianism=endianism
        )

    def get_hex_value(self) -> str:
        """Get the value of register in string hex format."""
        use_prefix = not self.config_as_hexstring
        return format_value(self.get_value(), self.width, delimeter="", use_prefix=use_prefix)

    def get_reset_value(self) -> int:
        """Returns reset value of the register.

        :return: Reset value of register.
        """
        return self._reset_value

    def add_bitfield(self, bitfield: RegsBitField) -> None:
        """Add register bitfield.

        :param bitfield: New bitfield value for register.
        """
        self._bitfields.append(bitfield)

    def get_bitfields(self, exclude: List[str] = None) -> List[RegsBitField]:
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

    def get_bitfield_names(self, exclude: List[str] = None) -> List[str]:
        """Returns list of the bitfield names.

        :param exclude: Exclude list of bitfield names if needed.
        :return: List of bitfield names.
        """
        return [x.name for x in self.get_bitfields(exclude)]

    def find_bitfield(self, name: str) -> RegsBitField:
        """Returns the instance of the bitfield by its name.

        :param name: The name of the bitfield.
        :return: The bitfield instance.
        :raises SPSDKRegsErrorBitfieldNotFound: The register doesn't exists.
        """
        for bitfield in self._bitfields:
            if name == bitfield.name:
                return bitfield

        raise SPSDKRegsErrorBitfieldNotFound(f" The {name} is not found in register {self.name}.")

    def add_setvalue_hook(self, hook: Callable, context: Any = None) -> None:
        """Set the value hook for write operation.

        :param hook: Callable hook for set value operation.
        :param context: Context data for this hook.
        """
        self._set_value_hooks.append((hook, context))

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the register.
        """
        output = ""
        output += f"Name:   {self.name}\n"
        output += f"Offset: 0x{self.offset:04X}\n"
        output += f"Width:  {self.width} bits\n"
        output += f"Access:   {self.access}\n"
        output += f"Description: \n {self.description}\n"

        i = 0
        for bitfield in self._bitfields:
            output += f"Bitfield #{i}: \n" + str(bitfield)
            i += 1

        return output


class Registers:
    """SPSDK Class for registers handling."""

    def __init__(self, device_name: str) -> None:
        """Initialization of Registers class."""
        self._registers: List[RegsRegister] = []
        self.dev_name = device_name

    def find_reg(self, name: str, include_group_regs: bool = False) -> RegsRegister:
        """Returns the instance of the register by its name.

        :param name: The name of the register.
        :param include_group_regs: The algorithm will check also group registers.
        :return: The register instance.
        :raises SPSDKRegsErrorRegisterNotFound: The register doesn't exists.
        """
        for reg in self._registers:
            if name == reg.name:
                return reg
            elif include_group_regs and reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    if name == sub_reg.name:
                        return sub_reg

        raise SPSDKRegsErrorRegisterNotFound(
            f"The {name} is not found in loaded registers for {self.dev_name} device."
        )

    def add_register(self, reg: RegsRegister) -> None:
        """Adds register into register list.

        :param reg: Register to add to the class.
        :raises SPSDKError: Invalid type has been provided.
        :raise SPSDKRegsError: Cannot add register with same name
        """
        if not isinstance(reg, RegsRegister):
            raise SPSDKError("The 'reg' has invalid type.")

        if reg.name in self.get_reg_names():
            raise SPSDKRegsError(f"Cannot add register with same name: {reg.name}.")

        self._registers.append(reg)

    def remove_register(self, reg: RegsRegister) -> None:
        """Remove register from register list by its instance reference.

        :reg: Instance of register that should be removed.
        :raises SPSDKError: Invalid type has been provided.
        """
        if not isinstance(reg, RegsRegister):
            raise SPSDKError("The 'reg' has invalid type.")

        self._registers.remove(reg)

    def remove_register_by_name(self, reg_names: List[str]) -> None:
        """Removes register from register list by List of its names.

        :reg_names: List of names of registers that should be removed.
        """
        for reg in self._registers:
            if any(reg.name in name for name in reg_names):
                self._registers.remove(reg)

    def get_registers(
        self, exclude: List[str] = None, include_group_regs: bool = False
    ) -> List[RegsRegister]:
        """Returns list of the registers.

        Method allows exclude some register by their names.
        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
        """
        if exclude:
            regs = [r for r in self._registers if not r.name.startswith(tuple(exclude))]
        else:
            regs = self._registers.copy()
        if include_group_regs:
            sub_regs = []
            for reg in regs:
                if reg.has_group_registers():
                    sub_regs.extend(reg.sub_regs)
            regs.extend(sub_regs)

        return regs

    def get_reg_names(
        self, exclude: List[str] = None, include_group_regs: bool = False
    ) -> List[str]:
        """Returns list of the register names.

        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
        """
        return [x.name for x in self.get_registers(exclude, include_group_regs)]

    def run_hooks(self, exclude: List[str] = None) -> None:
        """The method run hooks on all regular registers.

        :param exclude: The list of register names to be excluded.
        """
        for reg in self.get_registers(exclude):
            reg.set_value(reg.get_value(), False)

    def reset_values(self, exclude: List[str] = None) -> None:
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
        output += "Device name:        " + self.dev_name + "\n"
        for reg in self._registers:
            output += str(reg) + "\n"

        return output

    def write_xml(self, file_name: str) -> None:
        """Write loaded register structures into XML file.

        :param file_name: The name of XML file that should be created.
        """
        xml_root = ET.Element("regs")
        for reg in self._registers:
            reg.add_et_subelement(xml_root)

        with open(file_name, "w", encoding="utf-8") as xml_file:
            no_pretty_data = minidom.parseString(
                ET.tostring(xml_root, encoding="unicode", short_empty_elements=False)
            )
            xml_file.write(no_pretty_data.toprettyxml())

    def generate_html(
        self,
        heading1: str,
        heading2: str,
        regs_exclude: List[str] = None,
        fields_exclude: List[str] = None,
    ) -> str:
        """Generate describing HTML file with registers.

        :param heading1: The main title in HTML.
        :param heading2: The sub-title in HTML.
        :param regs_exclude: The exclude registers list.
        :param fields_exclude: The exclude bitfield list.
        :return: The content of HTML file.
        """
        data: HTMLData = []
        for reg in self.get_registers(regs_exclude):
            data.append(reg.get_html_data_element(fields_exclude))

        jinja_env = Environment(loader=FileSystemLoader(utils.REGS_DATA_FOLDER))
        template = jinja_env.get_template("regs_desc_template.html")
        return template.render(heading1=heading1, heading2=heading2, data=data)

    # pylint: disable=no-self-use   #It's better to have this function visually close to callies
    def _filter_by_names(self, items: List[ET.Element], names: List[str]) -> List[ET.Element]:
        """Filter out all items in the "items" tree,whose name starts with one of the strings in "names" list.

        :param items: Items to be filtered out.
        :param names: Names to filter out.
        :return: Filtered item elements list.
        """
        return [item for item in items if not item.attrib["name"].startswith(tuple(names))]

    # pylint: disable=dangerous-default-value
    def load_registers_from_xml(
        self, xml: str, filter_reg: List[str] = None, grouped_regs: List[dict] = None
    ) -> None:
        """Function loads the registers from the given XML.

        :param xml: Input XML data in string format.
        :param filter_reg: List of register names that should be filtered out.
        :param grouped_regs: List of register prefixes names to be grouped int one.
        :raises SPSDKRegsError: XML parse problem occuress.
        """

        def is_reg_in_group(reg: str) -> Union[dict, None]:
            """Help function to recognize if the register should be part of group."""
            if grouped_regs:
                for group in grouped_regs:
                    if reg.startswith(group["name"]):
                        return group
            return None

        try:
            xml_elements = ET.parse(xml)
        except ET.ParseError as exc:
            raise SPSDKRegsError(f"Cannot Parse XML data: {str(exc)}") from exc
        xml_registers = xml_elements.findall("register")
        xml_registers = self._filter_by_names(xml_registers, filter_reg or [])
        # Load all registers into the class
        for xml_reg in xml_registers:
            group = is_reg_in_group(xml_reg.attrib["name"])
            if group:
                try:
                    group_reg = self.find_reg(group["name"])
                except SPSDKRegsErrorRegisterNotFound:
                    group_reg = RegsRegister(
                        name=group["name"],
                        offset=value_to_int(group.get("offset", 0)),
                        width=value_to_int(group.get("width", 0)),
                        description=group.get(
                            "description", f"Group of {group['name']} registers."
                        ),
                        reverse=value_to_bool(group.get("reverse", False)),
                        access=group.get("access", None),
                        config_as_hexstring=group.get("config_as_hexstring", False),
                    )

                    self.add_register(group_reg)
                group_reg.add_group_reg(RegsRegister.from_xml_element(xml_reg))
            else:
                self.add_register(RegsRegister.from_xml_element(xml_reg))

    def load_yml_config(
        self,
        yml_data: Any,
        exclude_regs: List[str] = None,
        exclude_fields: Dict[str, Dict[str, str]] = None,
    ) -> None:
        """The function loads the configuration from YML file.

        :param yml_data: The YAML commented data with register values.
        :param exclude_regs: List of excluded registers
        :param exclude_fields: Dictionary with lists of excluded bitfields
        """
        for reg_name in yml_data.keys():
            reg_dict = yml_data[reg_name]
            register = self.find_reg(reg_name, include_group_regs=True)
            if "value" in reg_dict.keys():
                raw_val = reg_dict["value"]
                val = int(raw_val, 16) if register.config_as_hexstring else value_to_int(raw_val)
                register.set_value(val, True)
            elif "bitfields" in reg_dict.keys():
                for bitfield_name in reg_dict["bitfields"]:
                    bitfield_val = reg_dict["bitfields"][bitfield_name]
                    bitfield = register.find_bitfield(bitfield_name)
                    if (
                        exclude_fields
                        and reg_name in exclude_fields.keys()
                        and bitfield_name in exclude_fields[reg_name]
                    ):
                        continue

                    bitfield.set_enum_value(bitfield_val, True)
            else:
                logger.error(f"There are no data for {reg_name} register.")

            logger.debug(f"The register {reg_name} has been loaded from configuration.")

    def _get_bitfield_yaml_description(self, bitfield: RegsBitField, indent: int) -> str:
        """Create the valuable comment for bitfield.

        :param bitfield: Bitfield used to generate description.
        :param indent: Indent for multiline comment.
        :return: Bitfield YAML description.
        """

        def new_line(comment: str) -> str:
            return f"\n{' '*indent}# {comment}"

        description = f"Width: {bitfield.width}b[0-{(1<<bitfield.width)-1}]"
        if bitfield.description not in ("", "."):
            description += ", Description: " + bitfield.description.replace(
                "&#10;", f"\n{' '*indent}# "
            )
        if bitfield.has_enums():
            for enum in bitfield.get_enums():
                descr = enum.description if enum.description != "." else enum.name
                enum_description = descr.replace("&#10;", f"\n{' '*indent}# ")
                description += new_line(
                    f"- {enum.name}, ({enum.get_value_int()}): {enum_description}"
                )
        return description

    def create_yml_config_white_list(
        self, white_list: Dict[str, Any] = None, diff: bool = False, indent: int = 0
    ) -> Any:
        """The function creates the configuration YML file.

        :param white_list: Dictionary with lists of registers and its bitfields
        :param diff: Get only configuration with difference value to reset state.
        :param indent: Indent in space to generate YML.
        :return: YAML commented map of registers value.
        """
        data = CM()
        ix = 0
        for reg in self.get_registers():
            if white_list and reg.name not in white_list.keys():
                continue
            reg_yml = CM()
            if diff and reg.get_value() == reg.get_reset_value():
                continue
            descr = reg.description if reg.description != "." else reg.name
            descr = descr.replace("&#10;", "\n# ")
            data.insert(
                ix,
                reg.name,
                reg_yml,
                comment=descr,
            )
            ix += 1
            bitfields = reg.get_bitfields()
            if len(bitfields) > 0 and white_list and white_list[reg.name]:
                btf_yml = CM()
                for i, bitfield in enumerate(bitfields):
                    if diff and bitfield.get_value() == bitfield.get_reset_value():
                        continue
                    if (
                        white_list
                        and isinstance(white_list[reg.name], list)
                        and bitfield.name not in white_list[reg.name]
                    ):
                        continue
                    btf_yml.insert(
                        pos=i,
                        key=bitfield.name,
                        value=bitfield.get_enum_value(),
                        comment=self._get_bitfield_yaml_description(
                            bitfield, indent + SPSDK_YML_INDENT + SPSDK_YML_INDENT
                        ),
                    )
                reg_yml.insert(1, "bitfields", btf_yml, comment="The register bitfields")
            else:
                reg_yml.insert(
                    1,
                    "value",
                    reg.get_hex_value(),
                    comment=f"The value width: {reg.width}b",
                )

        return data

    # pylint: disable=(useless-param-doc, useless-type-doc)
    def create_yml_config(
        self,
        exclude_regs: List[str] = None,
        exclude_fields: Dict[str, Dict[str, str]] = None,
        ignored_fields: List[str] = None,
        diff: bool = False,
        indent: int = 0,
    ) -> Any:
        """The function creates the configuration YML file.

        :param exclude_regs: List of excluded registers
        :param exclude_fields: Dictionary with lists of excluded bitfields per register
        :param ignored_fields: List of ignored names in fields.
        :param diff: Get only configuration with difference value to reset state.
        :param indent: Indent in space to generate YML.
        :return: YAML commented map of registers value.
        """
        white_list = {}
        for reg in self._registers:
            if exclude_regs and reg.name.startswith(tuple(exclude_regs)):
                continue
            value = []
            for bitfield in reg.get_bitfields():
                if ignored_fields and bitfield.name.startswith(tuple(ignored_fields)):
                    continue
                if (
                    exclude_fields
                    and reg.name in exclude_fields.keys()
                    and exclude_fields[reg.name]
                ):
                    if bitfield.name.startswith(tuple(exclude_fields[reg.name])):
                        continue
                value.append(bitfield.name)
            white_list[reg.name] = value if len(value) > 0 else None

        return self.create_yml_config_white_list(white_list if white_list else None, diff, indent)

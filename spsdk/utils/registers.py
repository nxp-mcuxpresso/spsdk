#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers descriptions with support for XML files."""

import os
import logging
from math import log, ceil
from typing import List, Dict, Any
import json

import xml.etree.ElementTree as ET
from xml.dom import minidom

from spsdk.exceptions import SPSDKError

logger = logging.getLogger(__name__)

class RegisterNotFound(SPSDKError):
    """Register has not found."""
    pass

class BitfieldNotFound(SPSDKError):
    """Bitfield has not found."""
    pass

class EnumNotFound(SPSDKError):
    """Enum has not found."""
    pass

def value_to_bytes(value: Any, align_to_2n: bool = True) -> bytes:
    """Function loads value from lot of formats.

    :param value: Input value.
    :param align_to_2n: When is set, the function aligns legth of return array to 1,2,4,8,12 etc.
    :return: Value in bytes.
    :raise TypeError: Unsupported input type.
    """
    def bytes_cnt(value: int, align_to_2n: bool = True) -> int:
        val = 1 if value == 0 else int(log(value, 256)) + 1
        if align_to_2n and val > 2:
            val = int(ceil(val / 4)) * 4

        return val

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, int):
        return value.to_bytes(bytes_cnt(value, align_to_2n), "big")

    if isinstance(value, str):
        if value.lower().find('0x') >= 0:
            val = int(value, 16)
            return val.to_bytes(bytes_cnt(val, align_to_2n), "big")
        if value.lower().find('0b') >= 0:
            val = int(value, 2)
            return val.to_bytes(bytes_cnt(val, align_to_2n), "big")
        if value.lower().find("b'") >= 0:
            value = value.replace("b'", "0b")
            val = int(value, 2)
            return val.to_bytes(bytes_cnt(val, align_to_2n), "big")
        if value.isdecimal():
            val = int(value)
            return val.to_bytes(bytes_cnt(val, align_to_2n), "big")

    raise TypeError(f"Invalid input number type({type(value)})")


class RegsEnum():
    """Storage for register enumerations."""
    def __init__(self, name: str, value: Any, description: str, max_width: int = 0) -> None:
        """Constructor of RegsEnum class. Used to store enumeration information of bitfield.

        :param name: Name of enumeration.
        :param value: Value of enumeration.
        :param description: Text description of enumeration.
        :param max_width: Maximal width of enum value used to format output
        """
        self.name = name or "N/A"
        try:
            self.value = value_to_bytes(value)
        except TypeError:
            self.value = b''
        self.description = description or "N/A"
        self.max_width = max_width

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element, maxwidth: int = 0) -> 'RegsEnum':
        """Initialization Enum by XML ET element.

        :param xml_element: Input XML subelement with enumeration data.
        :param maxwidth: The maximal width of bitfield for this enum (used for formating).
        :return: The instance of this class.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        try:
            value = value_to_bytes(xml_element.attrib["value"] if "value" in xml_element.attrib else b'')
        except TypeError:
            value = b''
        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"

        return cls(name, value, descr, maxwidth)

    def get_value_int(self) -> int:
        """Method returns Integer value of enum.

        :return: Integer value of Enum.
        """
        return int.from_bytes(self.value, "big")

    def _get_value_str(self) -> str:
        """Method returns formated value.

        :return: Formatted string with enum value.
        """
        if self.value == b'':
            return "N/A"

        val = self.get_value_int()
        if self.max_width == 0:
            return bin(val)

        return f"0b{val:0{self.max_width}b}"

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "bit_field_value")
        element.set("name", self.name)
        element.set("value", self._get_value_str())
        element.set("description", self.description)


    def __str__(self) -> str:
        """Overrided 'ToString()' to print register.

        :return: Friendly string with enum information.
        """
        output = ""
        output += f"Name:        {self.name}\n"
        output += f"Value:       {self._get_value_str()}\n"
        output += f"Description: {self.description}\n"

        return output

class RegsBitField():
    """Storage for register bitfields."""
    def __init__(self,
                 parent: "RegsRegister",
                 name: str,
                 offset: int,
                 width: int,
                 description: str = None,
                 reset_val: str = "N/A",
                 access: str = "RW") -> None:
        """Constructor of RegsBitField class. Used to store bitfield information.

        :param parent: Parent register of bitfield.
        :param name: Name of bitfield.
        :param offset: Bit offset of bitfield.
        :param width: Bit width of bitfield.
        :param description: Text description of bitfield.
        :param reset_val: Reset value of bitfield.
        :param access: Access type of bitfield.
        """
        self.parent = parent
        self.name = name or "N/A"
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.reset_value = reset_val
        self.access = access
        self._enums: List[RegsEnum] = []

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element, parent: 'RegsRegister') -> 'RegsBitField':
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :param parent: Reference to parent RegsRegister object.
        :return: The instance of this class.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        offset = int(xml_element.attrib["offset"], 16) if "offset" in xml_element.attrib else 0
        width = int(xml_element.attrib["width"]) if "width" in xml_element.attrib else 0
        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"
        access = xml_element.attrib["access"] if "access" in xml_element.attrib else "N/A"
        reset_value = xml_element.attrib["reset_value"] \
                                if "reset_value" in xml_element.attrib else "N/A"
        bitfield = cls(parent,
                       name,
                       offset,
                       width,
                       descr,
                       reset_value,
                       access)

        if xml_element.text:
            xml_enums = xml_element.findall(f"bit_field_value")
            for xml_enum in xml_enums:
                bitfield.add_enum(RegsEnum.from_xml_element(xml_enum, width))
        return bitfield

    def has_enums(self) -> bool:
        """Returns if the bitfileds has enums.

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

        :param enum: New enumeration value for bitfiled.
        """
        self._enums.append(enum)

    def get_value(self) -> int:
        """Returns integer value of the bitfield.

        :return: Current value of bitfield.
        """
        reg_val = int.from_bytes(self.parent.get_value(), "big")
        value = reg_val >> self.offset
        mask = ((1<<self.width)-1)
        value = value & mask
        return value

    def set_value(self, new_val: int) -> None:
        """Updates the value of the bitfield.

        :param new_val: New value of bitfield.
        :raise ValueError: The input value is out of range.
        """
        if new_val > 1<<self.width:
            raise ValueError("The input value is out of bitfield range")
        reg_val = int.from_bytes(self.parent.get_value(), "big")
        mask = ((1<<self.width)-1) << self.offset
        reg_val = reg_val & ~mask
        value = (new_val << self.offset) & mask
        reg_val = reg_val | value
        reg_val_bytes = reg_val.to_bytes(length=ceil(self.parent.width / 8), byteorder="big")
        self.parent.set_value(reg_val_bytes)

    def set_enum_value(self, new_val: str) -> None:
        """Updates the value of the bitfield by its enum value.

        :param new_val: New enum value of bitfield.
        """
        self.set_value(self.get_enum_constant(new_val))

    def get_enum_value(self) -> Any:
        """Returns enum value of the bitfield.

        :return: Current value of bitfield.
        """
        value = self.get_value()
        if len(self._enums) > 0:
            for enum in self._enums:
                if enum.get_value_int() == value:
                    return enum.name
        return int(value)

    def get_enum_constant(self, enum_name: str) -> int:
        """Returns constant representation of enum by its name.

        :return: Constant of enum.
        :raises EnumNotFound: The enum has not been found.
        """
        for enum in self._enums:
            if enum.name == enum_name:
                return enum.get_value_int()

        raise EnumNotFound("The enum for {enum_name} has not been found.")

    def get_enum_names(self) -> List[str]:
        """Returns list of the enum strings.

        :return: List of enum names.
        """
        return [x.name for x in self._enums]

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "bit_field")
        element.set("offset", hex(self.offset))
        element.set("width", str(self.width))
        element.set("name", self.name)
        element.set("access", self.access)
        element.set("reset_value", str(self.reset_value))
        element.set("description", self.description)
        for enum in self._enums:
            enum.add_et_subelement(element)

    def __str__(self) -> str:
        """Overrided 'ToString()' to print register.

        :return: Friendly looking string that describes the bitfield.
        """
        output = ""
        output += f"Name:     {self.name}\n"
        output += f"Offset:   {self.offset} bits\n"
        output += f"Width:    {self.width} bits\n"
        output += f"Access:   {self.access} bits\n"
        output += f"Reset val:{self.reset_value}\n"
        output += f"Description: \n {self.description}\n"

        i = 0
        for enum in self._enums:
            output += f"Enum             #{i}: \n" + str(enum)
            i += 1

        return output

class RegsRegister():
    """Initialization register by input information."""
    def __init__(self,
                 name: str,
                 offset: int,
                 width: int,
                 description: str = None,
                 reverse: bool = False,
                 access: str = None) -> None:
        """Constructor of RegsRegister class. Used to store register information.

        :param name: Name of register.
        :param offset: Byte offset of register.
        :param width: Bit width of register.
        :param description: Text description of register.
        :param reverse: Multi  register value is stored in reverse order.
        :param access: Access type of register.
        """
        self.name = name
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.access = access or "N/A"
        self.reverse = reverse
        self._bitfields: List[RegsBitField] = []
        self.value = bytes([0])

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element) -> 'RegsRegister':
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :return: The instance of this class.
        """
        name = xml_element.attrib["name"] if "name" in xml_element.attrib else "N/A"
        offset = int(xml_element.attrib["offset"], 16) if "offset" in xml_element.attrib else 0
        width = int(xml_element.attrib["width"]) if "width" in xml_element.attrib else 0
        descr = xml_element.attrib["description"] if "description" in xml_element.attrib else "N/A"
        reverse = (xml_element.attrib["reversed"] if "reversed" in xml_element.attrib else "False") == "True"
        access = "RW" #TODO solve this

        reg = cls(name, offset, width, descr, reverse, access)
        if xml_element.text:
            xml_bitfields = xml_element.findall(f"bit_field")
            for xml_bitfield in xml_bitfields:
                reg.add_bitfield(RegsBitField.from_xml_element(xml_bitfield, reg))
        return reg

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

    def set_value(self, val: Any) -> None:
        """Set the new value of register."""
        try:
            self.value = value_to_bytes(val)
        except TypeError:
            logger.error("Loaded invalid value {str(val)}")
            self.value = b''

    def get_value(self) -> bytes:
        """Get the value of register."""
        return self.value

    def get_hex_value(self) -> str:
        """Get the value of register in string hex format."""
        return "0x"+ self.value.hex().replace("'", "")

    def add_bitfield(self, bitfield: RegsBitField) -> None:
        """Add register bitfield.

        :param bitfield: New bitfield value for register.
        """
        self._bitfields.append(bitfield)

    def get_bitfields(self) -> List[RegsBitField]:
        """Returns register bitfields.

        :return: Returns List of added register bitfields.
        """
        return self._bitfields

    def find_bitfield(self, name: str) -> RegsBitField:
        """Returns the instance of the bitfield by its name.

        :param name: The name of the bitfield.
        :return: The bitfield instance.
        :raises BitfieldNotFound: The register doesn't exists.
        """
        for bitf in self._bitfields:
            if name == bitf.name:
                return bitf

        raise BitfieldNotFound(f" The {name} is not found in register {self.name}.")

    def __str__(self) -> str:
        """Overrided 'ToString()' to print register.

        :return: Friendly looking string that describes the register.
        """
        output = ""
        output += f"Name:   {self.name}\n"
        # if isinstance(self.alias, str) and self.alias != "":
        #     output += f"Alias:  {self.alias}\n"
        # if isinstance(self.type, str) and self.type != "":
        #     output += f"Type:   {self.type}\n"
        output += f"Offset: 0x{self.offset:04X}\n"
        output += f"Width:  {self.width} bits\n"
        output += f"Access:   {self.access}\n"
        output += f"Description: \n {self.description}\n"

        i = 0
        for bitfiled in self._bitfields:
            output += f"Bitfield #{i}: \n" + str(bitfiled)
            i += 1

        return output

class Registers():
    """SPSDK Class for registers handling."""
    def __init__(self, device_name: str) -> None:
        """Initialization of Registr class."""
        self.registers: List[RegsRegister] = []
        self.dev_name = device_name

    def find_reg(self, name: str) -> RegsRegister:
        """Returns the instance of the register by its name.

        :param name: The name of the register.
        :return: The register instance.
        :raises RegisterNotFound: The register doesn't exists.
        """
        for reg in self.registers:
            if name == reg.name:
                return reg

        raise RegisterNotFound(f" The {name} is not found in loaded registers for {self.dev_name} device.")

    def add_register(self, reg: RegsRegister) -> None:
        """Adds register into register list.

        :param reg: Register to add to the class.
        :raise TypeError: Invalid type has been provided.
        """
        if not isinstance(reg, RegsRegister):
            raise TypeError("The 'reg' has invalid type.")

        if reg.name not in self.get_reg_names():
            self.registers.append(reg)
        else:
            logger.warning(f"Cannot add register with same name: {reg.name}.")

    def remove_register(self, reg: RegsRegister) -> None:
        """Remove register from register list by its instance reference.

        :reg: Instance of register that should be removed.
        :raise TypeError: Invalid type has been provided.
        """
        if not isinstance(reg, RegsRegister):
            raise TypeError("The 'reg' has invalid type.")

        self.registers.remove(reg)

    def remove_register_by_name(self, reg_names: List[str]) -> None:
        """Removes register from register list by List of its names.

        :reg_names: List of names of registers that should be removed.
        """
        for reg in self.registers:
            if any(reg.name in name for name in reg_names):
                self.registers.remove(reg)

    def get_reg_names(self) -> List[str]:
        """Returns list of the register names.

        :return: List of register names.
        """
        return [x.name for x in self.registers]

    def clear(self) -> None:
        """Method clears the regs class."""
        self.registers.clear()

    def __str__(self) -> str:
        """Overrided 'ToString()' to print register.

        :return: Friendly looking string that describes the registers.
        """
        output = ""
        output += "Device name:        " + self.dev_name + "\n"
        for reg in self.registers:
            output += str(reg) + "\n"

        return output

    def write_xml(self, file_name: str) -> None:
        """Write loaded register structures into XML file.

        :param file_name: The name of XML file that should be created.
        """
        xml_root = ET.Element("regs")
        for reg in self.registers:
            reg.add_et_subelement(xml_root)

        with open(file_name, 'w', encoding="utf-8") as xml_file:
            no_pretty_data = minidom.parseString(ET.tostring(xml_root, encoding="unicode", short_empty_elements=False))
            xml_file.write(no_pretty_data.toprettyxml())

    # pylint: disable=no-self-use   #It's better to have this function visually close to callies
    def _filter_by_names(self, items: List[ET.Element], names: List[str]) -> List[ET.Element]:
        """Filter out all items in the "items" tree,whose name starts with one of the strings in "names" list.

        :param items: Items to be filtered out.
        :param names: Names to filter out.
        :return: Filtered item elements list.
        """
        return [item for item in items if not item.attrib["name"].startswith(tuple(names))]

# pylint: disable=dangerous-default-value
    def load_registers_from_xml(self, xml: str, filter_reg: List[str] = None) -> None:
        """Function loads the registers from the given XML.

        :param xml: Input XML data in string format.
        :param filter_reg: List of register names that should be filtered out.
        """
        xml_elements = ET.parse(xml)
        xml_registers = xml_elements.findall("register")
        xml_registers = self._filter_by_names(xml_registers, filter_reg or [])
        # Load all registers into the class
        for xml_reg in xml_registers:
            self.add_register(RegsRegister.from_xml_element(xml_reg))

class RegConfig():
    """Class that helps manage the registers configuration."""

    def __init__(self, path: str):
        """Register Configuration class consructor.

        :param path: The path to configuration JSON file.
        """
        self.path = path
        self.config = RegConfig.load_config(path)

    @classmethod
    def load_config(cls, path: str) -> dict:
        """Load config file."""
        with open(path) as config_file:
            return json.load(config_file)

    @classmethod
    def devices(cls, path: str) -> List[str]:
        """Classmethod to get list of supppoted devices."""
        config = cls.load_config(path)
        return list(config['devices'].keys())

    def get_latest_revision(self, device: str) -> str:
        """Get latest revision for device."""
        return self.config["devices"][device]["latest"]

    def get_devices(self) -> List[str]:
        """Get list of supported devices."""
        return list(self.config["devices"].keys())

    def get_revisions(self, device: str) -> List[str]:
        """Get list of revisions for given device."""
        return list(self.config["devices"][device]["revisions"].keys())

    def get_address(self, device: str, remove_underscore: bool = False) -> str:
        """Get the area address in chip memory."""
        address = self.config["devices"][device]["address"]
        if remove_underscore:
            return address.replace("_", "")
        return address

    def get_data_file(self, device: str, revision: str) -> str:
        """Return the full path to data file (xml)."""
        file_name = self.config["devices"][device]["revisions"][revision]
        dir_path = os.path.dirname(os.path.abspath(self.path))
        return os.path.join(dir_path, file_name)

    def get_antipole_regs(self, device: str) -> Dict[str, str]:
        """Return the list of inverted registers."""
        inverted_regs = self.config["devices"][device]["inverted_regs"]
        return inverted_regs

    def get_computed_fields(self, device: str) -> Dict[str, Dict[str, str]]:
        """Return the list of computed fileds (not used in config YML files)."""
        inverted_regs = self.config["devices"][device]["computed_fields"]
        return inverted_regs

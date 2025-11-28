#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK FCB header to JSON conversion utility.

This module provides functionality to convert FCB (Flexspi Configuration Block)
register descriptions from C header file structures into JSON format for SPSDK usage.
"""

import logging
import re
import sys
from copy import deepcopy

import click

from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.exceptions import SPSDKError
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_file, value_to_int
from spsdk.utils.registers import Register, Registers, RegsBitField

logger = logging.getLogger(__name__)


def get_struct(text: str, name: str) -> str:
    """Extract C structure definition from header file text.

    Parses the input text to find and extract the content of a specific C structure
    definition, including all fields between the opening brace and the structure name.

    :param text: Header file content as string containing C structure definitions.
    :param name: Name of the target structure to extract.
    :raises SPSDKError: When the structure name is not found or has invalid format.
    :return: Structure content between braces as string, excluding typedef and name parts.
    """
    struct_end_re = re.findall(rf"}}\s*{name}\s*;", text)
    if not struct_end_re:
        raise SPSDKError(f"Invalid structure name to find: {name}")
    end_i = text.find(struct_end_re[0])
    struct_start_re = re.findall(r"typedef\s*struct\s*\w*\n*{\s*\b", text[:end_i])
    if not struct_start_re:
        raise SPSDKError(f"Invalid structure name to find: {name}")
    struct_head = struct_start_re[len(struct_start_re) - 1]
    start_i = text.find(struct_head)
    return text[start_i + len(struct_head) : end_i]


class StructMember:
    """C struct member representation for SPSDK configuration parsing.

    This class represents a single member of a C structure, providing functionality
    to parse, validate, and calculate sizes of C data types commonly used in
    embedded systems and NXP MCU configurations.

    :cvar STANDARD_TYPES_SIZES: Mapping of standard C types to their byte sizes.
    """

    STANDARD_TYPES_SIZES = {
        "uint8_t": 1,
        "int8_t": 1,
        "uint16_t": 2,
        "int16_t": 2,
        "uint32_t": 4,
        "int32_t": 4,
        "uint64_t": 8,
        "int64_t": 8,
    }

    def __init__(self, mem_type: str, cnt: int, name: str, description: str = "") -> None:
        """Initialize structure member with type, count, name and description.

        :param mem_type: Type of the structure member.
        :param cnt: Length of repetition for arrays (defaults to 1 if None or 0).
        :param name: Name of the structure member.
        :param description: Additional description or comment for the member, defaults to "".
        """
        self.mem_type = mem_type
        self.name = name
        self.description = description
        self.cnt = cnt or 1

    def __str__(self) -> str:
        """Return string representation of the object.

        Provides a formatted string containing the memory type, array count, name, and description
        of the object for debugging and logging purposes.

        :return: Formatted string with object details including type, count, name and comment.
        """
        return f"Type: {self.mem_type}, Array of: {self.cnt}, Name: {self.name}, Comment: {self.description}"

    def is_standard_type(self) -> bool:
        """Check if the memory type is a standard type.

        Determines whether the current memory type belongs to the predefined
        standard types based on the STANDARD_TYPES_SIZES collection.

        :return: True if the memory type is a standard type, False otherwise.
        """
        return self.mem_type in self.STANDARD_TYPES_SIZES

    def get_size(self) -> int:
        """Get variable size.

        Calculates the total size of the variable by multiplying the type size by the count.

        :return: Total size in bytes of the variable.
        """
        return self.get_type_size() * self.cnt

    def get_type_size(self) -> int:
        """Get the size of the memory type in bytes.

        Returns the size in bytes for standard memory types, or 0 for non-standard types.

        :return: Size of the memory type in bytes, or 0 if not a standard type.
        """
        if self.is_standard_type():
            return self.STANDARD_TYPES_SIZES[self.mem_type]
        return 0


class StructMemberIter:
    """SPSDK iterator for parsing C struct members from text.

    This class provides iteration capabilities for extracting structured information
    about C struct members including their types, names, array dimensions, and
    associated comments from raw text input. It uses regular expressions to parse
    the text and yields StructMember objects for each found member definition.
    """

    def __init__(self, text: str) -> None:
        """Initialize the iteration member with input text.

        :param text: Input string to work with.
        The docstring needed minor improvements:
        1. Added a period after the parameter description for consistency
        2. The structure is already correct with the brief description and proper parameter documentation
        3. Correctly omits return documentation since `__init__` returns None
        4. The indentation and format follow SPSDK standards
        """
        self.text = text
        self.last_ix = 0

    def __iter__(self) -> "StructMemberIter":
        """Return iterator for struct members.

        This method implements the iterator protocol by returning self, allowing
        the object to be used in for loops and other iteration contexts.

        :return: The iterator object itself.
        """
        return self

    def __next__(self) -> StructMember:
        """Get the next struct member from the parsed text.

        Parses C-style struct member declarations including type, name, array size,
        and associated comments. The method uses regular expressions to extract
        member information and handles both block comments (/* */) and line comments (//).

        :raises StopIteration: When no more struct members are found in the text.
        :return: Parsed struct member with type, array size, name and description.
        """
        re_type_name = r"\s*(?P<mem_type>\w*)\s*(?P<mem_name>\w*)(?P<mem_array>\[\d*\])?\s*;"
        re_description = (
            r"\s*\/\*.!?<?(?P<description>[\w\d \t\/\(\)\.\,\+\?\^\$\[\]\{\}\|\-\/\:\;\']*)\*\/"
        )
        re_description_line = (
            r"\s*\/\/!?<?(?P<description>[\w\d \t\/\(\)\.\,\+\?\^\$\[\]\{\}\|\-\/\:\;\']*)"
        )
        match = re.match(re_type_name, self.text[self.last_ix :])
        if not match:
            raise StopIteration
        self.last_ix += match.end()
        mem_type = match.group("mem_type")
        mem_name = match.group("mem_name")
        mem_array_raw = match.group("mem_array")
        mem_array = (
            value_to_int(mem_array_raw.replace("[", "").replace("]", "")) if mem_array_raw else 1
        )
        # try to find all description
        mem_descr = ""
        while True:
            match_descr = re.match(re_description, self.text[self.last_ix :])
            if not match_descr:
                match_descr = re.match(re_description_line, self.text[self.last_ix :])
                if not match_descr:
                    break
            mem_descr += match_descr.group("description")
            self.last_ix += match_descr.end()
        mem_descr.strip()
        return StructMember(mem_type, mem_array, mem_name, mem_descr)


def get_reg(member: StructMember, offset: int, header: str) -> Register:
    """Create register from structure member.

    Converts a StructMember into a Register object, handling both standard data types
    and complex structures with bitfields. For standard types, creates a simple register
    with basic properties. For complex structures, parses the structure definition to
    create individual bitfields within the register.

    :param member: Structure member to convert to register.
    :param offset: Memory offset where the register is located.
    :param header: Header content containing C structure definitions.
    :return: Register object with appropriate configuration and bitfields.
    """
    if member.is_standard_type():
        return Register(
            name=member.name,
            offset=offset,
            width=member.get_type_size() * 8,
            uid=f"reg{hex(offset)}",
            description=member.description,
        )
    # Get bitfields
    fields_struct = get_struct(header, member.mem_type)
    reg = Register(
        name=member.name,
        offset=offset,
        width=0,
        uid=f"reg{hex(offset)}",
        description=member.description,
    )
    for gen_mem in StructMemberIter(fields_struct):
        bitfield_size = gen_mem.get_size() * 8
        reg.add_bitfield(
            RegsBitField(
                reg,
                name=gen_mem.name,
                offset=reg.width,
                width=bitfield_size,
                uid=f"reg{hex(offset)}_bit{reg.width}",
                description=gen_mem.description,
            )
        )
        reg.width += bitfield_size
    return reg


def add_to_regs(regs: Registers, reg: Register) -> None:
    """Add a register to registers group.

    Handles name conflicts by automatically renaming duplicates with incremented
    suffixes or appending index numbers to ensure unique register names.

    :param regs: The registers group to add the register to.
    :param reg: The register to be added to the group.
    """
    if reg.name in regs.get_reg_names():
        index = re.match(r"\d+$", reg.name)
        if index:
            val = value_to_int(str(index))
            val += 1
            reg.name = reg.name.replace(str(index), str(val))
        else:
            reg.name = reg.name + f"_{0}"
    regs.add_register(reg)


def process_struct_member(regs: Registers, member: StructMember, offset: int, header: str) -> int:
    """Process structure member and add it to registers.

    This method processes a single structure member by creating register(s) from it.
    If the member count is 1, it adds a single register. If the member count is greater
    than 1, it creates multiple registers with indexed names and appropriate offsets.

    :param regs: Registers object to add the processed member to.
    :param member: Structure member to process.
    :param offset: Current offset in bits where the member starts.
    :param header: Header string identifier for the register.
    :return: Total width in bits consumed by this member (count * register width).
    """
    logger.debug((str(member)))
    logger.debug(f"Offset:{hex(offset // 8)}")
    reg = get_reg(member, offset, header)
    if member.cnt == 1:
        add_to_regs(regs, reg)
    else:
        for i in range(member.cnt):
            loc_reg = deepcopy(reg)
            loc_reg.name = f"{reg.name}_{i}"
            loc_reg.offset = offset + i * loc_reg.width
            add_to_regs(regs, loc_reg)

    return member.cnt * reg.width


@click.command()
@click.option("-h", "--header", type=str, required=True)
@click.option("-f", "--fcb", type=str, required=True, help="FCB structure name")
@click.option("-m", "--json", type=str, required=True)
@spsdk_apps_common_options
def main(header: str, fcb: str, json: str, log_level: int) -> int:
    """Main CLI function for converting FCB header to JSON configuration.

    Processes a C header file containing FCB (Flash Configuration Block) structure
    definitions and converts them to a JSON register specification file. The function
    parses the structure members, creates register definitions, and validates the
    resulting configuration to ensure it matches the expected 512-byte FCB size.

    :param header: Path to the C header file containing FCB structure definitions.
    :param fcb: Name of the FCB structure to process from the header file.
    :param json: Output path for the generated JSON register specification file.
    :param log_level: Logging level for the operation (e.g., logging.WARNING).
    :raises SPSDKError: Invalid length of result loaded structure (not 512 bytes).
    :return: Exit code (0 for success).
    """
    logging.basicConfig(level=log_level or logging.WARNING)
    header_file = load_file(header)
    assert isinstance(header_file, str)
    sp_struct = get_struct(header_file, fcb)

    offset = 0
    regs = Registers(
        family=FamilyRevision("FCB"), feature="PlaceHolder", do_not_raise_exception=True
    )
    for member in StructMemberIter(sp_struct):
        if member.name == "memConfig":
            gen_struct = get_struct(header_file, member.mem_type)
            for gen_mem in StructMemberIter(gen_struct):
                offset += process_struct_member(regs, gen_mem, offset, header_file)
        else:
            offset += process_struct_member(regs, member, offset, header_file)

    print(str(regs.image_info()))
    if len(regs.image_info()) != 512:
        logger.error("Invalid length of result loaded structure!")
        raise SPSDKError(f"Invalid length of result loaded structure! {len(regs.image_info())}B")

    regs.write_spec(json)

    return 0


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function and exit with its return code.

    This function serves as a safe wrapper around the main function,
    ensuring proper system exit handling.

    :raises SystemExit: Always exits with the return code from main().
    """
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

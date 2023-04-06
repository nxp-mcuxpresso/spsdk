#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to covert FCB Register description from C header file structure."""

import logging
import re
import sys
from copy import deepcopy

import click

from spsdk import SPSDKError
from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.utils.misc import load_file, value_to_int
from spsdk.utils.registers import Registers, RegsBitField, RegsRegister

logger = logging.getLogger(__name__)


def get_struct(text: str, name: str) -> str:
    """Get sub list with structure content.

    :param text_lines: Input lines with header file.
    :param name: name of structure
    :raises SPSDKError: When there is invalid structure name to find
    :return: Subset of lines with structure content.
    """
    # pylint: disable=anomalous-backslash-in-string  # \s is a part of the regular expression
    struct_end_re = re.findall(f"}}\s*{name}\s*;", text)
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
    """C struct member"""

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
        self.mem_type = mem_type
        self.name = name
        self.description = description
        self.cnt = cnt or 1

    def __str__(self) -> str:
        return f"Type: {self.mem_type}, Array of: {self.cnt}, Name: {self.name}, Comment: {self.description}"

    def is_standard_type(self) -> bool:
        return self.mem_type in self.STANDARD_TYPES_SIZES

    def get_size(self) -> int:
        return self.get_type_size() * self.cnt

    def get_type_size(self) -> int:
        if self.is_standard_type():
            return self.STANDARD_TYPES_SIZES[self.mem_type]
        return 0


class StructMemberIter:
    """Iterator for class struct members."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.last_ix = 0

    def __iter__(self) -> "StructMemberIter":
        return self

    def __next__(self) -> StructMember:
        re_type_name = r"\s*(?P<mem_type>\w*)\s*(?P<mem_name>\w*)(?P<mem_array>\[\d*\])?\s*;"
        re_description = (
            r"\s*\/\*.!?<?(?P<description>[\w\d \t\/\(\)\.\,\+\?\^\$\[\]\{\}\|\-\/\:\;\']*)\*\/"
        )
        re_description_line = (
            r"\s*\/\/!?<?(?P<description>[\w\d \t\/\(\)\.\,\+\?\^\$\[\]\{\}\|\-\/\:\;\']*)"
        )
        match = re.match(re_type_name, self.text[self.last_ix :])
        if not match:
            raise SPSDKError()
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


def get_reg(member: StructMember, offset: int, header: str) -> RegsRegister:
    if member.is_standard_type():
        return RegsRegister(
            name=member.name,
            offset=offset,
            width=member.get_type_size() * 8,
            description=member.description,
        )
    # Get bitfields
    fields_struct = get_struct(header, member.mem_type)
    reg = RegsRegister(name=member.name, offset=offset, width=0, description=member.description)
    for gen_mem in StructMemberIter(fields_struct):
        bitfield_size = gen_mem.get_size() * 8
        reg.add_bitfield(
            RegsBitField(
                reg,
                name=gen_mem.name,
                offset=reg.width,
                width=bitfield_size,
                description=gen_mem.description,
            )
        )
        reg.width += bitfield_size
    return reg


def add_to_regs(regs: Registers, reg: RegsRegister) -> None:
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
@click.option("-m", "--xml", type=str, required=True)
@spsdk_apps_common_options
def main(header: str, fcb: str, xml: str, log_level: int) -> int:
    """Main CLI function."""
    logging.basicConfig(level=log_level or logging.WARNING)
    header_file = load_file(header)
    assert isinstance(header_file, str)
    sp_struct = get_struct(header_file, fcb)

    offset = 0
    regs = Registers("FCB")
    for member in StructMemberIter(sp_struct):
        if member.name == "memConfig":
            gen_struct = get_struct(header_file, member.mem_type)
            for gen_mem in StructMemberIter(gen_struct):
                offset += process_struct_member(regs, gen_mem, offset, header_file)
        else:
            offset += process_struct_member(regs, member, offset, header_file)

    print(regs.image_info().info())
    if len(regs.image_info()) != 512:
        logger.error("Invalid length of result loaded structure!")
        raise SPSDKError(f"Invalid length of result loaded structure! {len(regs.image_info())}B")

    regs.write_xml(xml)

    return 0


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

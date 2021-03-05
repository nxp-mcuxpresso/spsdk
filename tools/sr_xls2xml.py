#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to covert Shadow register description EXCEL file to XML."""


from typing import Any
import re
import sys
import os

import click

import openpyxl
import openpyxl.utils as utils
import openpyxl.utils.cell as cell_utils

from spsdk.utils.registers import (Registers, RegsRegister, RegsBitField, RegsEnum)


XLS_COLUMN_NAMES = ("Block Name", "OTP Word", "Register Name", "Field Name", "Enum Name",
                    "Description", "Shadow Register Offset/bit offset", "Register Width / Field width",
                    "Value", "Access rw = has shadow register")


@click.group()
@click.option('-x', '--xls', type=str)
@click.option('-m', '--xml', type=str)
@click.option('-t', '--xls_type', type=int, default=1)
@click.help_option('--help')
@click.pass_context
def main(ctx: click.Context, xls: str, xml: str, xls_type: int=1) -> int:

    if not isinstance(xls, str):
        return -1

    if not isinstance(xml, str):
        xml = ""
    try:
        xls2xml_class = XLS_TYPES[str(xls_type)]
        xls2xml_class(xls, xml, xls_type)
    except Exception as exc:
        print(str(exc))
        return -1

    return 0

@main.command()
@click.pass_obj
def convert(pass_obj: dict) -> None:
    """List supported Devices."""
    print("convert")

class ShadowRegsXlsToXml():
    "Class to convert XLSX to XML with shadow register description"
    def __init__(self, xls_file: str, xml_file: str = "", xls_type: int=1) -> None:
        self.registers = Registers("Unknown")
        self.xls_type = xls_type
        self.header_cells = {}
        self.xml_file_name = xml_file if xml_file != "" else xls_file.replace(".xlsx", ".xml")
        self.wb = None
        print(os.path.dirname(os.path.realpath(__file__)))
        self.wb = openpyxl.load_workbook(xls_file)
        print(f"Loaded XLSX file ({xls_file})")
        self.convert()
        self.registers.write_xml(self.xml_file_name)
        print(f"Written XML file ({self.xml_file_name})")
        print(str(self.registers))

    def convert(self) -> None:
        raise NotImplementedError

    def _get_worksheet(self) -> Any:
        """Find the valid worksheet with the fuse map."""
        raise NotImplementedError

    def _get_header(self) -> None:
        """Returns the dictionary with cells of header."""
        raise NotImplementedError

    def _get_registers(self) -> None:
        """Function finds all registers in XLS sheet and store them."""
        raise NotImplementedError

    def __del__(self) -> None:
        """Just close all open files."""
        if self.wb:
            self.wb.close()

class ShadowRegsXlsToXml_Type1(ShadowRegsXlsToXml):

    def convert(self) -> None:
        self.ws = self._get_worksheet()
        #Get all merged cells
        self.merged_cells = self.ws.merged_cells.ranges
        self._get_header()
        self._get_registers()

    def _get_worksheet(self) -> Any:
        """Find the valid worksheet with the fuse map."""
        return self.wb.active

    def _get_header(self) -> None:
        """Returns the dictionary with cells of header."""
        ret = {}
        for head in XLS_COLUMN_NAMES:
            self.header_cells[head] = self._find_cell_coor_by_val(head)

    def _filterout_bitrange(self, name: str) -> (str, bool):
        """Function filter out the bit ranges in various shapes from register name."""
        bits_rev1 = re.search(r"_\d{1,4}_\d{1,4}$", name)
        bits_rev2 = re.search(r"\[\d{1,4}:\d{1,4}\]$", name)
        reverse = False
        if bits_rev1 or bits_rev2:
            bits = bits_rev1 if bits_rev1 else bits_rev2
            name = name.replace(bits.group(0), "")
            # Determine the order of the multiple registers.
            # Just find if the first multiple register contains zero
            bit_numbers = re.findall(r"(\d{1,4})+", bits.group(0))
            reverse = bit_numbers[len(bit_numbers) - 1] != "0"

        return name, reverse

    def _get_registers(self) -> None:
        """Function finds all registers in XLS sheet and store them."""
        regname_cr = cell_utils.coordinate_from_string(self.header_cells["Register Name"])
        sr_access_cr = cell_utils.coordinate_from_string(self.header_cells["Access rw = has shadow register"])
        desc_cr = cell_utils.coordinate_from_string(self.header_cells["Description"])
        offset_cr = cell_utils.coordinate_from_string(self.header_cells["Shadow Register Offset/bit offset"])
        width_cr = cell_utils.coordinate_from_string(self.header_cells["Register Width / Field width"])

        s = 1 + regname_cr[1]
        skip = 0
        for r in range(s, self.ws.max_row + 1):
            cell = regname_cr[0] + str(r)
            if skip > 0:
                skip -= 1
            elif isinstance(self.ws[cell].value, str):
                # We have a register, just Mask out the Fuse register only
                access = self.ws[sr_access_cr[0] + str(r)].value \
                         if isinstance(self.ws[sr_access_cr[0] + str(r)].value, str) else ""
                if any(x in access for x in ["rw", "ro", "wo"]):
                    # Now we have just Shadow registers only
                    # Some registers are defined multiply to store bigger data
                    # those could be detected by merged description field
                    reg_name = self.ws[cell].value
                    # Now, normalize the name
                    reg_name, reg_reverse = self._filterout_bitrange(reg_name)
                    cells = self._get_merged_by_first_cell(desc_cr[0] + str(r))
                    if cells is not None:
                        # set the skip for next search
                        cells = cells.split(':')
                        skip = cell_utils.coordinate_from_string(cells[1])[1] - \
                               cell_utils.coordinate_from_string(cells[0])[1]

                    reg_offset = int(self.ws[offset_cr[0] + str(r)].value, 16)
                    reg_width = int(self.ws[width_cr[0] + str(r)].value) * (skip + 1)
                    reg_descr = self.ws[desc_cr[0] + str(r)].value
                    reg_name = reg_name.strip()

                    register = RegsRegister(reg_name, reg_offset, reg_width, reg_descr, reg_reverse, access)

                    self.registers.add_register(register)

                    cells = self._get_merged_by_first_cell(regname_cr[0] + str(r))
                    if cells is not None:
                        # find the number of rows of the register description
                        cells = cells.split(':')
                        reg_lines = cell_utils.coordinate_from_string(cells[1])[1] - cell_utils.coordinate_from_string(cells[0])[1]
                    self._get_bitfields(register, r, reg_lines + 1)

    def _get_bitfields(self, reg: Any, excel_row: int, excel_row_cnt: int) -> None:
        """Tried to find and fill up all register bitfields."""
        if excel_row_cnt <= 1:
            # There is no bitfields
            return

        bitfieldname_cr = cell_utils.coordinate_from_string(self.header_cells["Field Name"])
        desc_cr = cell_utils.coordinate_from_string(self.header_cells["Description"])
        offset_cr = cell_utils.coordinate_from_string(self.header_cells["Shadow Register Offset/bit offset"])
        width_cr = cell_utils.coordinate_from_string(self.header_cells["Register Width / Field width"])
        rv_cr = cell_utils.coordinate_from_string(self.header_cells["Value"])

        excel_row += 1
        excel_row_cnt -= 1

        for r in range(excel_row, excel_row + excel_row_cnt):
            cell = bitfieldname_cr[0] + str(r)
            if isinstance(self.ws[cell].value, str):
                bitfield_name = self.ws[cell].value
                bitfield_offset = int(self.ws[offset_cr[0] + str(r)].value)
                bitfield_width = int(self.ws[width_cr[0] + str(r)].value)
                bitfield_descr = self.ws[desc_cr[0] + str(r)].value
                bitfield_rv = self.ws[rv_cr[0] + str(r)].value
                bitfield_rv = bitfield_rv if bitfield_rv is not None else "N/A"
                bitf = RegsBitField(reg,
                                    bitfield_name,
                                    bitfield_offset,
                                    bitfield_width,
                                    bitfield_descr,
                                    reset_val=bitfield_rv)
                reg.add_bitfield(bitf)

                cells = self._get_merged_by_first_cell(bitfieldname_cr[0] + str(r))
                if cells is not None:
                    # find the number of rows of the register description
                    cells = cells.split(':')
                    reg_lines = cell_utils.coordinate_from_string(cells[1])[1] - \
                                cell_utils.coordinate_from_string(cells[0])[1]
                    self._get_enums(bitf, r, reg_lines + 1)

    def _get_enums(self, bitfield: Any, excel_row: int, excel_row_cnt: int) -> None:
        """Tried to find and fill up all register bitfields enumerations."""
        if excel_row_cnt <= 1:
            # There is no enums
            return

        enumname_cr = cell_utils.coordinate_from_string(self.header_cells["Enum Name"])
        desc_cr = cell_utils.coordinate_from_string(self.header_cells["Description"])
        value_cr = cell_utils.coordinate_from_string(self.header_cells["Value"])

        excel_row += 1
        excel_row_cnt -= 1

        for r in range(excel_row, excel_row + excel_row_cnt):
            cell = enumname_cr[0] + str(r)
            if isinstance(self.ws[cell].value, str):
                enum_name = self.ws[cell].value
                enum_descr = self.ws[desc_cr[0] + str(r)].value
                enum_value: str = self.ws[value_cr[0] + str(r)].value
                if enum_value is None:
                    print(f"Warning: The Enum {enum_name} is missing and it will be skipped.")
                else:
                    bitfield.add_enum(RegsEnum(enum_name, enum_value, enum_descr, bitfield.width))

    def _get_merged_by_first_cell(self, cell:str) -> str:
        """ Function returns the merged range by first cell."""
        for merged in self.merged_cells:
            if merged.coord.find(cell+":") >= 0:
                return merged.coord
        return None


    def _find_cell_coor_by_val(self, value:Any, start:str = "", end:str = "") -> str:
        """Search engine for the cell values"""
        if start == "" or start == None:
            start = "A1"
        if end == "" or end == None:
            end = utils.get_column_letter(self.ws.max_column) + str(self.ws.max_row)

        s = cell_utils.coordinate_from_string(start)
        e = cell_utils.coordinate_from_string(end)
        sc = utils.column_index_from_string(s[0])
        sr = s[1]
        ec = utils.column_index_from_string(e[0])
        er = e[1]

        for r in range(sr, er+1):
            for c in range(sc, ec+1):
                val = self.ws[utils.get_column_letter(c) + str(r)].value
                if isinstance(val, str):
                    val = val.replace("\n", " ")
                    val = val.replace("  ", " ")
                if value == val:
                    return utils.get_column_letter(c) + str(r)

        return None


class ShadowRegsXlsToXml_Type2(ShadowRegsXlsToXml):

    def convert(self) -> None:
        self.ws = self._get_worksheet()
        #Get all merged cells
        self._get_header()
        self._get_registers()

    def _get_worksheet(self) -> None:
        """Find the valid worksheet with the fuse map."""
        return self.wb["Fuse Definitions"]

    def _get_header(self) -> None:
        self.header_cells["reg_base"] = "A"
        self.header_cells["fuse_address"] = "B"
        self.header_cells["fuse_index"] = "D"
        self.header_cells["fuse_name"] = "E"
        self.header_cells["fuse_width"] = "F"
        self.header_cells["fuse_descr"] = "G"
        self.header_cells["fuse_sett"] = "H"
        self.header_cells["burned_value"] = "J"
        self.header_cells["customer_visible"] = "L"

    def _get_regbase(self, line: int) -> int:
        try:
            base = int(self.ws[self.header_cells["reg_base"] + str(line)].value, 16)
        except Exception as exc:
            base = -1
        return base

    def _get_fusename(self, line: int) -> int:
        try:
            name = self.ws[self.header_cells["fuse_name"] + str(line)].value
        except Exception as exc:
            name = "Unknown name :-("
        return name

    def _get_fuseoffset(self, line: int) -> int:

        try:
            reg_offset_bits = (self._get_regbase(line) - 0x400)
            fuse_offset = self.ws[self.header_cells["fuse_index"] + str(line)].value
            fuse_offset = fuse_offset - reg_offset_bits
        except Exception as exc:
            fuse_offset = -1
        return fuse_offset

    def _get_fusewidth(self, line: int) -> int:

        try:
            fuse_width = self.ws[self.header_cells["fuse_width"] + str(line)].value
        except Exception as exc:
            fuse_width = -1
        return fuse_width

    def _get_fusedescription(self, line: int) -> int:
        try:
            fuse_description = self.ws[self.header_cells["fuse_descr"] + str(line)].value
        except Exception as exc:
            fuse_description = "There is no any special description"
        return fuse_description

    def _get_fuse_resetvalue(self, line: int) -> int:
        try:
            fuse_resetvalue = self.ws[self.header_cells["burned_value"] + str(line)].value
        except Exception as exc:
            fuse_resetvalue = "N/A"
        return fuse_resetvalue

    def _get_fuse_bitfield_info(self, line: int) -> (int,int):
        try:
            fuse_width = self._get_fusewidth(line)
            fuse_address = self.ws[self.header_cells["fuse_address"] + str(line)].value
            pattern = re.compile(r'\[([^)]*)\]')
            offsets = pattern.findall(fuse_address)[0]
            if offsets.count(":") > 0:
                offsets = offsets.split(":")
                offsets.reverse()
                offset = int(offsets[0])
            else:
                offset = int(offsets)
        except Exception as exc:
            print(f"Issue with get the getting bitfield info ({str(exc)})")

        return offset, fuse_width

    def _get_registers(self) -> None:
        # Start line in excel style 2 is 3!
        reg_base = 0
        try:
            for r in range(3, self.ws.max_row + 1):
                new_reg_base = self._get_regbase(r)
                if new_reg_base == -1:
                    break
                if new_reg_base != reg_base:
                    # This is new register, just create it
                    reg_base = new_reg_base
                    reg_name = f"REG_0x{reg_base:04X}"
                    reg_offset = 0x400 - reg_base
                    reg_width = 32 # TODO solve that fields
                    reg_dscr = f"This is description string of {reg_name} register"
                    reg_reverse = False
                    reg_access = "RW"
                    reg = RegsRegister(reg_name, reg_offset, reg_width, reg_dscr, reg_reverse, reg_access)
                    self.registers.add_register(reg)

                # we have added register, so this is about a adding of bitfield
                bitfield_name = self._get_fusename(r)
                bitfield_offset, bitfield_width = self._get_fuse_bitfield_info(r)
                bitfield_descr = self._get_fusedescription(r)
                bitfield_rv = self._get_fuse_resetvalue(r)
                bitf = RegsBitField(reg,
                                    bitfield_name,
                                    bitfield_offset,
                                    bitfield_width,
                                    bitfield_descr,
                                    reset_val=bitfield_rv)
                reg.add_bitfield(bitf)
        except Exception as exc:
            print(f"Unwanted exception during getting registers({str(exc)})")




XLS_TYPES = {"1": ShadowRegsXlsToXml_Type1,
            "2": ShadowRegsXlsToXml_Type2}

if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover # pylint: disable=no-value-for-parameter
#     xls = ShadowRegsXlsToXml("tools/OTP6.xlsx")
    # regs = Registers("pokus 685", None)
    # regs.load_registers_from_xml("tools/OTP.xml")
    # regs.write_xml("tools/OPT2.xml")

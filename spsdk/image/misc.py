#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Misc."""
import io
import re
from io import SEEK_CUR
from typing import Union

from .header import Header


def size_fmt(num: Union[float, int], use_kibibyte: bool = True) -> str:
    """Size format."""
    base, suffix = [(1000., 'B'), (1024., 'iB')][use_kibibyte]
    i = 'B'
    for i in ['B'] + [i + suffix for i in list('kMGTP')]:
        if not -base < num < base:
            num /= base
    return "{0:3.1f} {1:s}".format(num, i)


def modulus_fmt(modulus: bytes, tab: int = 4, length: int = 15, sep: str = ':') -> str:
    """Modulus format."""
    text = ' ' * tab
    data = b'\0' + modulus
    for i, j in enumerate(data):
        text += "{:02x}{}".format(j, sep)
        if ((i + 1) % length) == 0:
            text += '\n' + ' ' * tab
    return text


def read_raw_data(stream: Union[io.BufferedReader, io.BytesIO], length: int, index: int = None,
                  no_seek: bool = False) -> bytes:
    """Read raw data."""
    if index is not None:
        if index < 0:
            raise ValueError(" Index must be non-negative, found {}".format(index))
        if index != stream.tell():
            stream.seek(index)

    if length < 0:
        raise ValueError(" Length must be non-negative, found {}".format(length))

    try:
        data = stream.read(length)
    except Exception:
        raise Exception(" stream.read() failed, requested {} bytes".format(length))

    if len(data) != length:
        raise Exception(" Could not read enough bytes, expected {}, found {}".format(length, len(data)))

    if no_seek:
        stream.seek(-length, SEEK_CUR)

    return data


def read_raw_segment(buffer: Union[io.BufferedReader, io.BytesIO], segment_tag: int, index: int = None) -> bytes:
    """Read raw segmement."""
    hrdata = read_raw_data(buffer, Header.SIZE, index)
    length = Header.parse(hrdata, 0, segment_tag).length - Header.SIZE
    return hrdata + read_raw_data(buffer, length)


NUMBER_FORMAT = re.compile(r'(?P<prefix>0[bx])?(?P<number>[0-9a-fA-F_]+)(?P<suffix>[ulUL]{0,3})$')


def parse_int(number: str) -> int:
    """Convert string in HEX or DEC format into integer number.

    :param number: input string
    :return: corresponding integer value
    :raise ValueError: if parameter is not valid number
    """
    match = NUMBER_FORMAT.match(number)
    if match is None:
        raise ValueError('invalid number')
    base = {
        '0b': 2,
        '0x': 16,
        None: 10
    }[match.group('prefix')]
    return int(match.group('number'), base=base)


def format_value(value: int, size: int) -> str:
    """Convert the 'value' into either BIN or HEX string, depending on 'size'.

    if 'size' is divisible by 8, function returns HEX, BIN otherwise
    digits in result string are grouped by 4 using '_' (underscore)
    """
    padding = size if size % 8 else (size // 8) * 2
    infix = 'b' if size % 8 else 'x'
    parts = re.findall(".{1,4}", f"{value:0{padding}{infix}}"[::-1])
    rev = "_".join(parts)[::-1]
    return f"0{infix}{rev}"


def dict_diff(main: dict, mod: dict) -> dict:
    """Return a difference between two dictionaries if key is not present in main, it's skipped."""
    diff = {}
    for key, value in mod.items():
        if isinstance(value, dict):
            sub = dict_diff(main[key], value)
            if sub != dict():
                diff[key] = sub
        else:
            if key not in main:
                continue
            main_value = main[key] if isinstance(main, dict) else main
            if parse_int(main_value) != parse_int(value):
                diff[key] = value
    return diff

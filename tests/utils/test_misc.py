#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import filecmp
import os

from typing import Union

import pytest

from spsdk.utils.misc import (
    align, align_block, align_block_fill_random, extend_block, find_first,
    load_binary, load_file, write_file, format_value, reverse_bytes_in_longs,
    get_bytes_cnt_of_int, change_endianism, value_to_int, value_to_bytes,
    value_to_bool)


@pytest.mark.parametrize(
    "test_input,alignment,expected",
    [
        (0, 4, 0),
        (1, 4, 4),
        (2, 4, 4),
        (3, 4, 4),
        (4, 4, 4),
        (5, 4, 8),
        (1, 255, 255),
        (256, 255, 2 * 255),
        (1, 65535, 65535),
        (1, 65536, 65536),
        (65535, 65536, 65536),
        (0x7FFFFFFF, 0x80000000, 0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ]
)
def test_align(test_input: int, alignment: int, expected: int):
    assert align(test_input, alignment) == expected


@pytest.mark.parametrize(
    "test_input,alignment,padding,expected",
    [
        # no change in empty data
        (b'', 4, 0, b''),
        (b'', 1024, 0, b''),
        # no change for alignment == 1
        (b'\x00', 1, 0, b'\x00'),
        (b'\x00\x01\x02\x03', 2, 0xFF, b'\x00\x01\x02\x03'),
        (b'\x00\x01\x02\x03', 4, 0xFF, b'\x00\x01\x02\x03'),
        # align to 3
        (b'\x00', 3, 1, b'\x00\x01\x01'),
        # align to 4
        (b'\x00', 4, 0, b'\x00\x00\x00\x00'),
        (b'\x00', 4, 0xFF, b'\x00\xff\xff\xff'),
        # align to 16
        (b'\x02', 16, 2, b'\x02' * 16),
    ],
)
def test_align_block(test_input: bytes, alignment: int, padding: int, expected: bytes):
    """Test misc.align_block()"""
    data = align_block(test_input, alignment, padding)
    assert isinstance(data, bytes)
    assert data == expected


@pytest.mark.parametrize(
    "test_input,alignment,expected",
    [
        # no change in empty data
        (b'', 4, b''),
        (b'', 1024, b''),
        # no change for alignment == 1
        (b'\x00', 1, b'\x00'),
        (b'\x00\x01\x02\x03', 2, b'\x00\x01\x02\x03'),
        (b'\x00\x01\x02\x03', 4, b'\x00\x01\x02\x03'),
        # align to 3
        (b'\x00', 3, 3),
        # align to 4
        (b'\x00', 4, 4),
        (b'\x00', 4, 4),
        # align to 16
        (b'\x02', 16, 16),
    ],
)
def test_align_block_fill_random(test_input: bytes, alignment: int, expected: Union[int, bytes]):
    """Test misc.align_block_fill_random()"""
    data1 = align_block_fill_random(test_input, alignment)
    data2 = align_block(test_input, alignment, -1)
    assert isinstance(data1, bytes)
    if isinstance(expected, int):
        assert len(data1) == expected
        assert len(data2) == expected
    else:
        assert data1 == expected
        assert data2 == expected


def test_align_block_invalid_input():
    """Test invalid inputs for misc.align_block()"""
    with pytest.raises(AssertionError):
        align_block(None)
    with pytest.raises(AssertionError):
        align_block(b'', -1)
    with pytest.raises(AssertionError):
        align_block(b'', 0)
    with pytest.raises(AssertionError):
        align_block(b'', 1, -2)
    with pytest.raises(AssertionError):
        align_block(b'', 1, 256)


@pytest.mark.parametrize(
    "test_input,length,padding,expected",
    [
        # extend empty data
        (b'', 4, 0, b'\x00\x00\x00\x00'),
        # no change for alignment == 1
        (b'\x00', 1, 0, b'\x00'),
        # align to 3
        (b'\x00', 3, 1, b'\x00\x01\x01'),
        # align to 4
        (b'\x00\x01\x02\x03', 4, 0, b'\x00\x01\x02\x03'),
        (b'\x00\x01\x02', 4, 0, b'\x00\x01\x02\x00'),
        (b'\x00\x01', 4, 255, b'\x00\x01\xFF\xFF'),
    ]
)
def test_add_padding(test_input: bytes, length: int, padding: int, expected: bytes) -> None:
    """Test misc.add_padding()"""
    data = extend_block(test_input, length, padding)
    assert data == expected


def test_add_padding_invalid_input():
    """Test invalid inputs for misc.align_block()"""
    # negative length
    with pytest.raises(AssertionError):
        extend_block(b'', -1)
    # length < current length
    with pytest.raises(AssertionError):
        extend_block(b'\x00\x00', 1)
    # padding > 255
    with pytest.raises(AssertionError):
        extend_block(b'\x00\x00', 1, 256)
    # padding < 0
    with pytest.raises(AssertionError):
        extend_block(b'\x00\x00', 1, -1)


def test_find_first():
    """Test find_first"""
    assert find_first([1, 2], lambda x: True) == 1
    assert find_first(['1', '2'], lambda x: True) == '1'
    assert find_first(['1', '2'], lambda x: x == '2') == '2'
    assert find_first((1, 2, 3, 4, 5), lambda x: True) == 1
    assert find_first((5, 4, 3, 2, 1, 0), lambda x: True) == 5
    assert find_first((5, 4, 3, 2, 1, 0), lambda x: x == 'a') is None

    class TestClass:
        def __init__(self, first: bool = False):
            self.first = first

    assert find_first((TestClass(False), TestClass(False)), lambda x: x.first) is None
    assert find_first((TestClass(False), TestClass(True)), lambda x: x.first) is not None


def test_load_binary(data_dir):
    """Test loading binary files using load_binary and load_file."""
    data = load_binary(data_dir, 'file.bin')
    data2 = load_file(data_dir, 'file.bin', mode='rb')

    assert data == data2
    assert data == bytes(i for i in range(10))


def test_load_file(data_dir):
    """Test loading text file."""
    text = load_file(data_dir, 'file.txt')
    assert text == 'Hello\nworld'


def test_write_file(data_dir, tmpdir):
    """Test writing data to data using write_file."""
    data = load_binary(data_dir, 'file.bin')
    text = load_file(data_dir, 'file.txt')

    write_file(data, tmpdir, 'file.bin', mode='wb')
    write_file(text, tmpdir, 'file.txt')

    assert filecmp.cmp(os.path.join(data_dir, 'file.bin'), os.path.join(tmpdir, 'file.bin'))
    assert filecmp.cmp(os.path.join(data_dir, 'file.txt'), os.path.join(tmpdir, 'file.txt'))

@pytest.mark.parametrize(
    "value,size,expected",
    [
        (0, 2, "0b00"), (0, 4, "0b0000"), (0, 10, "0b00_0000_0000"),
        (0, 8, "0x00"), (0, 16, "0x0000"),
        (0, 32, "0x0000_0000"),
        (0, 64, "0x0000_0000_0000_0000")
    ]
)
def test_format_value(value, size, expected):
    assert format_value(value, size) == expected

def test_reg_long_reverse():
    """Test Register Config - reverse_bytes_in_longs function."""
    test_val = b'\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34'
    test_val_ret = b'\x04\x03\x02\x01\x14\x13\x12\x11\x24\x23\x22\x21\x34\x33\x32\x31'

    assert reverse_bytes_in_longs(test_val) == test_val_ret
    assert reverse_bytes_in_longs(test_val_ret) == test_val

    test_val1 = b'\x01\x02\x03\x04\x11\x12'
    with pytest.raises(ValueError):
        reverse_bytes_in_longs(test_val1)

@pytest.mark.parametrize(
    "num, output, align_2_2n",
    [
        (0, 1, True),
        (1, 1, True),
        ((1<<8)-1, 1, True),
        ((1<<8), 2, True),
        ((1<<16)-1, 2, True),
        ((1<<16), 4, True),
        ((1<<24)-1, 4, True),
        ((1<<24), 4, True),
        ((1<<32)-1, 4, True),
        ((1<<32), 8, True),
        ((1<<64)-1, 8, True),
        ((1<<64), 12, True),
        ((1<<128)-1, 16, True),
        ((1<<128), 20, True),
        (0, 1, False),
        (1, 1, False),
        ((1<<8)-1, 1, False),
        ((1<<8), 2, False),
        ((1<<16)-1, 2, False),
        ((1<<16), 3, False),
        ((1<<24)-1, 3, False),
        ((1<<24), 4, False),
        ((1<<32)-1, 4, False),
        ((1<<32), 5, False),
        ((1<<64)-1, 8, False),
        ((1<<64), 9, False),
        ((1<<128)-1, 16, False),
        ((1<<128), 17, False),
    ]
)
def test_get_bytes_cnt(num, output, align_2_2n):
    """Test of get_bytes_cnt_of_int function."""
    assert output == get_bytes_cnt_of_int(num, align_2_2n)

@pytest.mark.parametrize(
    "value, res, exc",
    [
        (b'\x12', b'\x12', False),
        (b'\x12\x34', b'\x34\x12', False),
        (b'\x12\x34\x56', b'\x56\x34\x12', True),
        (b'\x12\x34\x56\x78', b'\x78\x56\x34\x12', False),
        (b'\x12\x34\x56\x78\x12\x34\x56\x78', b'\x78\x56\x34\x12\x78\x56\x34\x12', False),
        (b'\x12\x34\x56\x78\x12\x34\x56', b'\x78\x56\x34\x12\x78\x56\x34', True),
    ]
)
def test_change_endianism(value, res, exc):
    """Test of change_endianism function"""
    if not exc:
        assert res == change_endianism(value)
    else:
        with pytest.raises(ValueError):
            change_endianism(value)

@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, 0, False),
        ("0", 0, False),
        ("-1", -1, True),
        ("0xffff", 65535, False),
        ("ffff", 65535, False),
        ("0xff_ff", 65535, False),
        ("ff_ff", 65535, False),
        ("0b111_1", 15, False),
        ("b'111_1", 15, False),
        (b'\xff\x00', 65280, False),
        (bytearray(b'\xff\x00'), 65280, False),
        ("InvalidValue", 0, True),
    ]
)
def test_value_to_int(value, res, exc):
    """Test of value_to_int function"""
    if not exc:
        assert res == value_to_int(value)
    else:
        with pytest.raises(TypeError):
            value_to_int(value)

@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, b'\x00', False),
        ("0", b'\x00', False),
        ("-1", b'\xff', True),
        ("0xffff", b'\xff\xff', False),
        ("ffff", b'\xff\xff', False),
        ("0xff_ff", b'\xff\xff', False),
        ("0b111_1", b'\x0f', False),
        ("ff_ff", b'\xff\xff', False),
        ("b'111_1", b'\x0f', False),
        (b'\xff\x00', b'\xff\x00', False),
        (bytearray(b'\xff\x00'), b'\xff\x00', False),
        ("InvalidValue", 0, True),
    ]
)
def test_value_to_bytes(value, res, exc):
    """Test of value_to_bytes function"""
    if not exc:
        assert res == value_to_bytes(value)
    else:
        with pytest.raises(TypeError):
            value_to_bytes(value)


@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, False, False),
        (False, False, False),
        ("False", False, False),
        (1, True, False),
        (True, True, False),
        ("True", True, False),
        ("T", True, False),
        (b'\x20', True, True),        
    ]
)
def test_value_to_bool(value, res, exc):
    """Test of value_to_bool function"""
    if not exc:
        assert res == value_to_bool(value)
    else:
        with pytest.raises(TypeError):
            value_to_bool(value)

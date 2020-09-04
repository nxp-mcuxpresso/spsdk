#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import filecmp
import os

from typing import Union

import pytest

from spsdk.utils.misc import (
    align, align_block, align_block_fill_random, extend_block, find_first,
    load_binary, load_file, write_file)


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

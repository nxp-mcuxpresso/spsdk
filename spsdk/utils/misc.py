#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions used throughout the SPSDK."""
import contextlib
import os
from typing import Callable, Iterable, Iterator, Optional, TypeVar, List, Union

from .crypto.common import crypto_backend

# for generics
T = TypeVar('T')  # pylint: disable=invalid-name


def align(number: int, alignment: int = 4) -> int:
    """Align number (size or address) size to specified alignment, typically 4, 8 or 16 bytes boundary.

    :param number: input to be aligned
    :param alignment: the boundary to align; typical value is power of 2
    :return: aligned number; result is always >= size (e.g. aligned up)
    """
    assert alignment > 0 and number >= 0
    return (number + (alignment - 1)) // alignment * alignment


def align_block(data: bytes, alignment: int = 4, padding: int = 0) -> bytes:
    """Align binary data block length to specified boundary by adding padding bytes to the end.

    :param data: to be aligned
    :param alignment: boundary alignment (typically 2, 4, 16, 64 or 256 boundary)
    :param padding: byte to be added, use -1 to fill with random data
    :return: aligned block
    """
    assert isinstance(data, bytes)
    assert alignment > 0
    assert -1 <= padding <= 255
    curr_size = len(data)
    num_padding = align(curr_size, alignment) - curr_size
    if not num_padding:
        return data
    if padding == -1:
        return data + crypto_backend().random_bytes(num_padding)
    return data + bytes([padding]) * num_padding


def align_block_fill_random(data: bytes, alignment: int = 4) -> bytes:
    """Same as `align_block`, just parameter `padding` is fixed to `-1` to fill with random data."""
    return align_block(data, alignment, -1)


def extend_block(data: bytes, length: int, padding: int = 0) -> bytes:
    """Add padding to the binary data block to extend the length to specified value.

    :param data: block to be extended
    :param length: requested block length; the value must be >= current block length
    :param padding: 8-bit value value to be used as a padding
    :return: block extended with padding
    """
    curr_len = len(data)
    assert length >= curr_len
    num_padding = length - curr_len
    if not num_padding:
        return data
    return data + bytes([padding]) * num_padding


def find_first(iterable: Iterable[T], predicate: Callable[[T], bool]) -> Optional[T]:
    """Find first element from the list, that matches the condition.

    :param iterable: list of elements
    :param predicate: function for selection of the element
    :return: found element; None if not found
    """
    return next((a for a in iterable if predicate(a)), None)


def load_binary(*args: str) -> bytes:
    """Loads binary file into bytes.

    :param args: list that consists of:
        - absolute path
        - optional sub-directory (any number)
        - file name including file extension
        All the fields together represents absolute path to the file
    :return: content of the binary file as bytes
    """
    data = load_file(*args, mode='rb')
    assert isinstance(data, bytes)
    return data


def load_file(*path_segments: str, mode: str = 'r') -> Union[str, bytes]:
    """Loads a file into bytes.

    :param path_segments: list that consists of:
        - absolute path
        - optional sub-directory (any number)
        - file name including file extension
        All the fields together represents absolute path to the file
    :param mode: mode for reading the file 'r'/'rb'
    :return: content of the binary file as bytes or str (based on mode)
    """
    path = os.path.join(*path_segments)
    with open(path, mode) as f:
        return f.read()


def write_file(data: Union[str, bytes], *path_segments: str, mode: str = 'w') -> int:
    """Writes data into a file.

    :param data: data to write
    :param path_segments: pieces of path to the file, might be just a single str
    :param mode: writing mode, 'w' for text, 'wb' for binary data, defaults to 'w'
    :return: number of written elements
    """
    path = os.path.join(*path_segments)
    with open(path, mode) as f:
        return f.write(data)


@contextlib.contextmanager
def use_working_directory(path: str) -> Iterator[None]:
    # pylint: disable=missing-yield-doc
    """Execute the block in given directory.

    Cd into specific directory.
    Execute the block.
    Change the directory back into the original one.

    :param path: the path, where the current directory will be changed to
    """
    current_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(current_dir)
        assert os.getcwd() == current_dir


class DebugInfo:
    """The class is used to provide detailed information about export process and exported data.

    It is handy for analyzing content and debugging changes in the exported binary output.
    """

    @classmethod
    def disabled(cls) -> 'DebugInfo':
        """Return an instance of DebugInfo with disabled message collecting."""
        return DebugInfo(enabled=False)

    def __init__(self, enabled: bool = True):
        """Constructor.

        :param enabled: True if logging enabled; False otherwise
        """
        self._lines: Optional[List[str]] = list() if enabled else None

    @property
    def enabled(self) -> bool:
        """:return: whether debugging enabled."""
        return self._lines is not None

    def append(self, line: str) -> None:
        """Appends the line to the log.

        :param line: text to be added
        """
        if self.enabled:
            assert self._lines is not None
            self._lines.append(line)

    def append_section(self, name: str) -> None:
        """Append new section to the debug log.

        :param name: of the section
        """
        self.append(f'[{name}]')

    def append_hex_data(self, data: bytes) -> None:
        """Append binary data in HEX form.

        :param data: to be logged
        """
        self.append('hex=' + data.hex())
        self.append('len=' + str(len(data)) + '=' + hex(len(data)))

    def append_binary_section(self, section_name: str, data: bytes) -> None:
        """Append section and binary data.

        :param section_name: the name
        :param data: binary data
        """
        self.append_section(section_name)
        self.append_hex_data(data)

    def append_binary_data(self, data_name: str, data: bytes) -> None:
        """Append short section with binary data.

        :param data_name: the name
        :param data: binary data (up to 8 bytes)
        """
        assert len(data) <= 16
        self.append(data_name + '=' + data.hex())

    @property
    def lines(self) -> Iterable[str]:
        """:return: list of logged lines; empty list if nothing logged or log disabled."""
        if self._lines:
            return self._lines
        return list()

    def info(self) -> str:
        """:return: multi-line text with log; empty string if nothing logged or log disabled."""
        return "\n".join(self.lines)

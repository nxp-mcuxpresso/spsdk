#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions used throughout the SPSDK."""
import contextlib
import logging
import math
import os
import re
import time
from math import ceil
from struct import pack, unpack
from typing import Callable, Dict, Iterable, Iterator, List, Optional, TypeVar, Union

from spsdk import SPSDKError
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError

# for generics
T = TypeVar("T")  # pylint: disable=invalid-name

logger = logging.getLogger(__name__)


class BinaryPattern:
    """Binary pattern class.

    Supported patterns:
        - rand: Random Pattern
        - zeros: Filled with zeros
        - ones: Filled with all ones
        - inc: Filled with repeated numbers incremented by one 0-0xff
        - any kind of number, that will be repeated to fill up whole image.
          The format could be decimal, hexadecimal, bytes.
    """

    SPECIAL_PATTERNS = ["rand", "zeros", "ones", "inc"]

    def __init__(self, pattern: str) -> None:
        """Constructor of pattern class.

        :param pattern: Supported patterns:
                        - rand: Random Pattern
                        - zeros: Filled with zeros
                        - ones: Filled with all ones
                        - inc: Filled with repeated numbers incremented by one 0-0xff
                        - any kind of number, that will be repeated to fill up whole image.
                        The format could be decimal, hexadecimal, bytes.
        :raises SPSDKValueError: Unsupported pattern detected.
        """
        try:
            value_to_int(pattern)
        except SPSDKError:
            if not pattern in BinaryPattern.SPECIAL_PATTERNS:
                raise SPSDKValueError(  # pylint: disable=raise-missing-from
                    f"Unsupported input pattern{pattern}"
                )

        self._pattern = pattern

    def get_block(self, size: int) -> bytes:
        """Get block filled with pattern.

        :param size: Size of block to return.
        :return: Filled up block with specified pattern.
        """
        if self._pattern == "zeros":
            return bytes(size)

        if self._pattern == "ones":
            return bytes(b"\xff" * size)

        if self._pattern == "rand":
            # pylint: disable=import-outside-toplevel
            from spsdk.utils.crypto.common import crypto_backend

            return crypto_backend().random_bytes(size)

        if self._pattern == "inc":
            return bytes((x & 0xFF for x in range(size)))

        pattern = value_to_bytes(self._pattern)
        block = bytes(pattern * int((size / len(pattern))))
        return block[:size]

    @property
    def pattern(self) -> str:
        """Get the pattern.

        :return: Pattern in string representation.
        """
        try:
            return hex(value_to_int(self._pattern))
        except SPSDKError:
            return self._pattern


def align(number: int, alignment: int = 4) -> int:
    """Align number (size or address) size to specified alignment, typically 4, 8 or 16 bytes boundary.

    :param number: input to be aligned
    :param alignment: the boundary to align; typical value is power of 2
    :return: aligned number; result is always >= size (e.g. aligned up)
    :raises SPSDKError: When there is wrong alignment
    """
    if alignment <= 0 or number < 0:
        raise SPSDKError("Wrong alignment")

    return (number + (alignment - 1)) // alignment * alignment


def align_block(
    data: Union[bytes, bytearray], alignment: int = 4, padding: Union[int, BinaryPattern] = None
) -> bytes:
    """Align binary data block length to specified boundary by adding padding bytes to the end.

    :param data: to be aligned
    :param alignment: boundary alignment (typically 2, 4, 16, 64 or 256 boundary)
    :param padding: byte to be added or BinaryPattern
    :return: aligned block
    :raises SPSDKError: When there is wrong alignment
    """
    assert isinstance(data, (bytes, bytearray))

    if alignment < 0:
        raise SPSDKError("Wrong alignment")
    current_size = len(data)
    num_padding = align(current_size, alignment) - current_size
    if not num_padding:
        return bytes(data)
    if not padding:
        padding = BinaryPattern("zeros")
    elif isinstance(padding, int):
        padding = BinaryPattern(str(padding))
    return bytes(data + padding.get_block(num_padding))


def align_block_fill_random(data: bytes, alignment: int = 4) -> bytes:
    """Same as `align_block`, just parameter `padding` is fixed to `-1` to fill with random data."""
    return align_block(data, alignment, BinaryPattern("rand"))


def extend_block(data: bytes, length: int, padding: int = 0) -> bytes:
    """Add padding to the binary data block to extend the length to specified value.

    :param data: block to be extended
    :param length: requested block length; the value must be >= current block length
    :param padding: 8-bit value value to be used as a padding
    :return: block extended with padding
    :raises SPSDKError: When the length is incorrect
    """
    current_len = len(data)
    if length < current_len:
        raise SPSDKError("Incorrect length")
    num_padding = length - current_len
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


def load_binary(path: str, search_paths: List[str] = None) -> bytes:
    """Loads binary file into bytes.

    :param path: Path to the file.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: content of the binary file as bytes
    """
    data = load_file(path, mode="rb", search_paths=search_paths)
    assert isinstance(data, bytes)
    return data


def load_text(path: str, search_paths: List[str] = None) -> str:
    """Loads binary file into bytes.

    :param path: Path to the file.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: content of the binary file as bytes
    """
    text = load_file(path, mode="r", search_paths=search_paths)
    assert isinstance(text, str)
    return text


def load_file(path: str, mode: str = "r", search_paths: List[str] = None) -> Union[str, bytes]:
    """Loads a file into bytes.

    :param path: Path to the file.
    :param mode: mode for reading the file 'r'/'rb'
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: content of the binary file as bytes or str (based on mode)
    """
    path = find_file(path, search_paths=search_paths)
    logger.debug(f"Loading {'binary' if 'b' in mode else 'text'} file from {path} .")
    with open(path, mode) as f:
        return f.read()


def write_file(data: Union[str, bytes], path: str, mode: str = "w", encoding: str = None) -> int:
    # pylint: disable=missing-param-doc
    r"""Writes data into a file.

    :param data: data to write
    :param path: Path to the file.
    :param mode: writing mode, 'w' for text, 'wb' for binary data, defaults to 'w'
    :param encoding: Encoding of written file ('ascii', 'utf-8').
    :return: number of written elements
    """
    path = path.replace("\\", "/")
    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

    logger.debug(f"Storing {'binary' if 'b' in mode else 'text'} file at {path} .")
    with open(path, mode, encoding=encoding) as f:
        return f.write(data)


def get_abs_path(file_path: str, base_dir: Optional[str] = None) -> str:
    """Return a full path to the file.

    param base_dir: Base directory to create absolute path, if not specified the system CWD is used.
    return: Absolute file path.
    """
    if os.path.isabs(file_path):
        return file_path.replace("\\", "/")

    return os.path.abspath(os.path.join(base_dir or os.getcwd(), file_path)).replace("\\", "/")


def find_file(
    file_path: str,
    use_cwd: bool = True,
    search_paths: List[str] = None,
    raise_exc: bool = True,
) -> str:
    """Return a full path to the file.

    `search_paths` takes precedence over `CWD` if used (default)

    :param file_path: File name, part of file path or full path
    :param use_cwd: Try current working directory to find the file, defaults to True
    :param search_paths: List of paths where to search for the file, defaults to None
    :param raise_exc: Raise exception if file is not found, defaults to True
    :return: Full path to the file
    :raises SPSDKError: File not found
    """
    file_path = file_path.replace("\\", "/")

    if os.path.isabs(file_path):
        return file_path
    if search_paths:
        for dir_candidate in search_paths:
            if not dir_candidate:
                continue
            dir_candidate = dir_candidate.replace("\\", "/")
            path_candidate = get_abs_path(file_path, base_dir=dir_candidate)
            if os.path.isfile(path_candidate):
                return path_candidate
    if use_cwd and os.path.isfile(file_path):
        return get_abs_path(file_path)
    # list all directories in error message
    searched_in: List[str] = []
    if use_cwd:
        searched_in.append(os.path.abspath(os.curdir))
    if search_paths:
        searched_in.extend(filter(None, search_paths))
    searched_in = [s.replace("\\", "/") for s in searched_in]
    err_str = f"File '{file_path}' not found, Searched in: {', '.join(searched_in)}"
    if not raise_exc:
        logger.debug(err_str)
        return ""  # TODO Maybe, it will be better return None and solve raised MyPY recommendations
    raise SPSDKError(err_str)


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
    def disabled(cls) -> "DebugInfo":
        """Return an instance of DebugInfo with disabled message collecting."""
        return DebugInfo(enabled=False)

    def __init__(self, enabled: bool = True):
        """Constructor.

        :param enabled: True if logging enabled; False otherwise
        """
        self._lines: Optional[List[str]] = [] if enabled else None

    @property
    def enabled(self) -> bool:
        """:return: whether debugging enabled."""
        return self._lines is not None

    def append(self, line: str) -> None:
        """Appends the line to the log.

        :param line: text to be added
        :raises SPSDKError: When there is nothing to append
        """
        if self.enabled:
            if self._lines is None:
                raise SPSDKError("There is nothing to append")
            self._lines.append(line)

    def append_section(self, name: str) -> None:
        """Append new section to the debug log.

        :param name: of the section
        """
        self.append(f"[{name}]")

    def append_hex_data(self, data: bytes) -> None:
        """Append binary data in HEX form.

        :param data: to be logged
        """
        self.append("hex=" + data.hex())
        self.append("len=" + str(len(data)) + "=" + hex(len(data)))

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
        :raises SPSDKError: When the data has incorrect length
        """
        if len(data) > 16:
            raise SPSDKError("Incorrect data length")
        self.append(data_name + "=" + data.hex())

    @property
    def lines(self) -> Iterable[str]:
        """:return: list of logged lines; empty list if nothing logged or log disabled."""
        if self._lines:
            return self._lines
        return []

    def info(self) -> str:
        """:return: multi-line text with log; empty string if nothing logged or log disabled."""
        return "\n".join(self.lines)


def format_value(value: int, size: int, delimiter: str = "_", use_prefix: bool = True) -> str:
    """Convert the 'value' into either BIN or HEX string, depending on 'size'.

    if 'size' is divisible by 8, function returns HEX, BIN otherwise
    digits in result string are grouped by 4 using 'delimiter' (underscore)
    """
    padding = size if size % 8 else (size // 8) * 2
    infix = "b" if size % 8 else "x"
    parts = re.findall(".{1,4}", f"{value:0{padding}{infix}}"[::-1])
    rev = delimiter.join(parts)[::-1]
    prefix = f"0{infix}" if use_prefix else ""
    return f"{prefix}{rev}"


def get_bytes_cnt_of_int(value: int, align_to_2n: bool = True, byte_cnt: int = None) -> int:
    """Returns count of bytes needed to store handled integer.

    :param value: Input integer value.
    :param align_to_2n: The result will be aligned to standard sizes 1,2,4,8,12,16,20.
    :param byte_cnt: The result count of bytes.
    :raises SPSDKValueError: The integer input value doesn't fit into byte_cnt.
    :return: Number of bytes needed to store integer.
    """
    cnt = 0
    if value == 0:
        return byte_cnt or 1

    while value != 0:
        value >>= 8
        cnt += 1

    if align_to_2n and cnt > 2:
        cnt = int(ceil(cnt / 4)) * 4

    if byte_cnt and cnt > byte_cnt:
        raise SPSDKValueError(
            f"Value takes more bytes than required byte count{byte_cnt} after align."
        )

    cnt = byte_cnt or cnt

    return cnt


def value_to_int(value: Union[bytes, bytearray, int, str], default: int = None) -> int:
    """Function loads value from lot of formats to integer.

    :param value: Input value.
    :param default: Default Value in case of invalid input.
    :return: Value in Integer.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, int):
        return value

    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "big")

    if isinstance(value, str) and value != "":
        match = re.match(
            r"(?P<prefix>0[box])?(?P<number>[0-9a-f_]+)(?P<suffix>[ul]{0,3})$",
            value.strip().lower(),
        )
        if match:
            base = {"0b": 2, "0o": 8, "0": 10, "0x": 16, None: 10}[match.group("prefix")]
            try:
                return int(match.group("number"), base=base)
            except ValueError:
                pass

    if default is not None:
        return default
    raise SPSDKError(f"Invalid input number type({type(value)}) with value ({value})")


def value_to_bytes(
    value: Union[bytes, bytearray, int, str],
    align_to_2n: bool = True,
    byte_cnt: int = None,
    endianness: str = "big",
) -> bytes:
    """Function loads value from lot of formats.

    :param value: Input value.
    :param align_to_2n: When is set, the function aligns length of return array to 1,2,4,8,12 etc.
    :param byte_cnt: The result count of bytes.
    :param endianness: The result bytes endianness ['big', 'little'].
    :return: Value in bytes.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    value = value_to_int(value)
    return value.to_bytes(
        get_bytes_cnt_of_int(value, align_to_2n, byte_cnt=byte_cnt),
        endianness,  # type: ignore[arg-type]
    )


def value_to_bool(value: Union[bool, int, str]) -> bool:
    """Function decode bool value from various formats.

    :param value: Input value.
    :return: Boolean value.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return bool(value)

    if isinstance(value, str):
        return value in ("True", "T", "1")

    raise SPSDKError(f"Invalid input Boolean type({type(value)}) with value ({value})")


def reverse_bytes_in_longs(arr: bytes) -> bytes:
    """The function reverse byte order in longs from input bytes.

    :param arr: Input array.
    :return: New array with reversed bytes.
    :raises SPSDKError: Raises when invalid value is in input.
    """
    arr_len = len(arr)
    if arr_len % 4 != 0:
        raise SPSDKError("The input array is not in modulo 4!")

    result = bytearray()

    for x in range(0, arr_len, 4):
        word = bytearray(arr[x : x + 4])
        word.reverse()
        result.extend(word)
    return bytes(result)


def change_endianness(bin_data: bytes) -> bytes:
    """Convert binary format used in files to binary used in register object.

    :param bin_data: input binary array.
    :return: Converted array (practically little to big endianness).
    :raises SPSDKError: Invalid value on input.
    """
    data = bytearray(bin_data)
    length = len(data)
    if length == 1:
        return data

    if length == 2:
        data.reverse()
        return data

    # The length of 24 bits is not supported yet
    if length == 3:
        raise SPSDKError("Unsupported length (3) for change endianness.")

    return reverse_bytes_in_longs(data)


class Timeout:
    """Simple timeout handle class."""

    UNITS = {
        "s": 1000000,
        "ms": 1000,
        "us": 1,
    }

    def __init__(self, timeout: int, units: str = "s") -> None:
        """Simple timeout class constructor.

        :param timeout: Timeout value.
        :param units: Timeout units (MUST be from the UNITS list)
        :raises SPSDKValueError: Invalid input value.
        """
        if units not in self.UNITS:
            raise SPSDKValueError("Units are not in supported units.")
        self.enabled = timeout != 0
        self.timeout_us = timeout * self.UNITS[units]
        self.start_time_us = self._get_current_time_us()
        self.end_time = self.start_time_us + self.timeout_us
        self.units = units

    @staticmethod
    def _get_current_time_us() -> int:
        """Returns current system time in microseconds.

        :return: Current time in microseconds
        """
        return ceil(time.time() * 1_000_000)

    def _convert_to_units(self, time_us: int) -> int:
        """Converts time in us into used units.

        :param time_us: Time in micro seconds.
        :return: Time in user units.
        """
        return time_us // self.UNITS[self.units]

    def get_consumed_time(self) -> int:
        """Returns consumed time since start of timeout operation.

        :return: Consumed time in units as the class was constructed
        """
        return self._convert_to_units(self._get_current_time_us() - self.start_time_us)

    def get_consumed_time_ms(self) -> int:
        """Returns consumed time since start of timeouted operation in milliseconds.

        :return: Consumed time in milliseconds
        """
        return (self._get_current_time_us() - self.start_time_us) // 1000

    def get_rest_time(self, raise_exc: bool = False) -> int:
        """Returns rest time to timeout overflow.

        :param raise_exc: If set, the function raise SPSDKTimeoutError in case of overflow.
        :return: Rest time in units as the class was constructed
        :raises SPSDKTimeoutError: In case of overflow
        """
        if self.enabled and self._get_current_time_us() > self.end_time and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")

        return (
            self._convert_to_units(self.end_time - self._get_current_time_us())
            if self.enabled
            else 0
        )

    def get_rest_time_ms(self, raise_exc: bool = False) -> int:
        """Returns rest time to timeout overflow.

        :param raise_exc: If set, the function raise SPSDKTimeoutError in case of overflow.
        :return: Rest time in milliseconds
        :raises SPSDKTimeoutError: In case of overflow
        """
        if self.enabled and self._get_current_time_us() > self.end_time and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")

        # pylint: disable=superfluous-parens     # because PEP20: Readability counts
        return ((self.end_time - self._get_current_time_us()) // 1000) if self.enabled else 0

    def overflow(self, raise_exc: bool = False) -> bool:
        """Check the the timer has been overflowed.

        :param raise_exc: If set, the function raise SPSDKTimeoutError in case of overflow.
        :return: True if timeout overflowed, False otherwise.
        :raises SPSDKTimeoutError: In case of overflow
        """
        overflow = self.enabled and self._get_current_time_us() > self.end_time
        if overflow and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")
        return overflow


def size_fmt(num: Union[float, int], use_kibibyte: bool = True) -> str:
    """Size format."""
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][use_kibibyte]
    i = "B"
    for i in ["B"] + [i + suffix for i in list("kMGTP")]:
        if num < base:
            break
        num /= base

    return f"{int(num)} {i}" if i == "B" else f"{num:3.1f} {i}"


def numberify_version(version: str, separator: str = ".", valid_numbers: int = 3) -> int:
    """Turn version string into a number.

    Each group is weighted by a multiple of 1000

    1.2.3    -> 1  * 1_000_000 +   2 * 1_000 + 3 * 1 =  1_002_003
    21.100.9 -> 21 * 1_000_000 + 100 * 1_000 + 9 * 1 = 21_100_009

    :param version: Version string numbers separated by `separator`
    :param separator: Separator used in the version string, defaults to "."
    :param valid_numbers: Amount of numbers to sanitize to consider, defaults to 3
    :return: Number representing the version
    """
    sanitized_version = sanitize_version(
        version=version, separator=separator, valid_numbers=valid_numbers
    )
    return int(
        sum(
            int(number) * math.pow(10, 3 * order)
            for order, number in enumerate(reversed(sanitized_version.split(separator)))
        )
    )


def sanitize_version(version: str, separator: str = ".", valid_numbers: int = 3) -> str:
    """Sanitize version string.

    Append '.0' in case version string has fewer parts than `valid_numbers`
    Remove right-most version parts after `valid_numbers` amount of parts

    1.2     -> 1.2.0
    1.2.3.4 -> 1.2.3

    :param version: Original version string
    :param separator: Separator used in the version string, defaults to "."
    :param valid_numbers: Amount of numbers to sanitize, defaults to 3
    :return: Sanitized version string
    """
    version_parts = version.split(separator)
    version_parts += ["0"] * (valid_numbers - len(version_parts))
    return separator.join(version_parts[:valid_numbers])


def get_key_by_val(value: str, dictionary: Dict[str, List[str]]) -> str:
    """Return key by its value.

    :param value: Value to find.
    :param dictionary: Dictionary to find in.
    :raises SPSDKValueError: Value is not present in dictionary.
    :return: Key name
    """
    for key, item in dictionary.items():
        if value.lower() in [x.lower() for x in item]:
            return key

    raise SPSDKValueError(f"Value {value} is not in {dictionary}.")


def swap16(x: int) -> int:
    """Swap bytes in half word (16bit).

    :param x: Original number
    :return: Number with swapped bytes
    :raises SPSDKError: When incorrect number to be swapped is provided
    """
    if x < 0 or x > 0xFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)


def swap32(x: int) -> int:
    """Swap 32 bit integer.

    :param x: integer to be swapped
    :return: swapped value
    :raises SPSDKError: When incorrect number to be swapped is provided
    """
    if x < 0 or x > 0xFFFFFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return unpack("<I", pack(">I", x))[0]


def check_range(x: int, start: int = 0, end: int = (1 << 32) - 1) -> bool:
    """Check if the number is in range.

    :param x: Number to check.
    :param start: Lower border of range, default is 0.
    :param end: Upper border of range, default is unsigned 32-bit range.
    :return: True if fits, False otherwise.
    """
    if start > x > end:
        return False

    return True


def load_configuration(path: str) -> dict:
    """Load configuration from yml/json file.

    :param path: Path to configuration file
    :raises SPSDKError: When unsupported file is provided
    :return: Content of configuration as dictionary
    """
    if not os.path.exists(path):
        raise SPSDKError(f"File not found'{path}'.")

    # import YAML only if needed to save startup time
    from ruamel.yaml import YAML, YAMLError  # pylint: disable=import-outside-toplevel

    try:
        with open(path) as f:
            return YAML(typ="safe").load(f)
    except (YAMLError, UnicodeDecodeError):
        pass

    # import json only if needed to save startup time
    import commentjson as json  # pylint: disable=import-outside-toplevel

    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONLibraryException:
        pass

    raise SPSDKError(f"Unable to load '{path}'.")

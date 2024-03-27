#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os

import pytest

from spsdk.apps.utils import utils
from spsdk.apps.utils.utils import catch_spsdk_error, resolve_path_relative_to_config
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootConnectionError
from spsdk.utils.misc import load_configuration, use_working_directory


def test_split_string():
    assert ["12", "34", "5"] == utils._split_string("12345", length=2)
    assert ["123", "123"] == utils._split_string("123123", length=3)


def test_format_data():
    data = bytes(range(20))
    expect_8 = "00 01 02 03 04 05 06 07\n08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_8 == utils.format_raw_data(data, use_hexdump=False, line_length=8)
    expect_16 = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_16 == utils.format_raw_data(data, use_hexdump=False, line_length=16)


@pytest.mark.parametrize(
    "input_param,exp_path,exp_size",
    [("path", "path", -1), ("path,10", "path", 10), ("path,0x20", "path", 0x20)],
)
def test_file_size_composite(input_param, exp_path, exp_size):
    path, size = utils.parse_file_and_size(input_param)
    assert path == exp_path
    assert size == exp_size


@pytest.mark.parametrize(
    "input_hex_data,output_bytes",
    [
        ("{{11223344}}", b"\x11\x22\x33\x44"),
        ("{{11 22 33 44}}", b"\x11\x22\x33\x44"),
        (" { { 11    22 33 44}}", b"\x11\x22\x33\x44"),
        ("{{bcd}}", b"\xbc\x0d"),
        ("[[bcd]]", b"\xbc\x0d"),
        ("[[ 01 02 ]]", b"\x01\x02"),
    ],
)
def test_parse_hex_data(input_hex_data, output_bytes):
    parsed_data = utils.parse_hex_data(input_hex_data)
    assert parsed_data == output_bytes


@pytest.mark.parametrize(
    "input_hex_data",
    [
        ("{ { } }"),
        ("11223344"),
        ("{{11223344"),
        ("11223344}}"),
        ("{11223344}"),
        ("{{11 xa}}"),
        ("{{ab zz}}"),
    ],
)
def test_parse_hex_data_error(input_hex_data):
    with pytest.raises(SPSDKError):
        utils.parse_hex_data(input_hex_data)


@catch_spsdk_error
def function_under_test(to_raise: Exception = None) -> int:
    if to_raise is None:
        return 0
    raise to_raise


def test_catch_spsdk_error():
    with pytest.raises(SystemExit) as exc:
        function_under_test(AssertionError())
    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc_2:
        function_under_test(McuBootConnectionError())
    assert exc_2.value.code == 2

    with pytest.raises(SystemExit) as exc_3:
        function_under_test(IndexError())
    assert exc_3.value.code == 3

    assert function_under_test(None) == 0


@pytest.mark.parametrize("file_name", ["certgen_config.yaml", "test_config.json"])
def test_load_configuration(data_dir, file_name):
    with use_working_directory(data_dir):
        result = load_configuration(file_name)
        assert isinstance(result, dict)


@pytest.mark.parametrize("file_name", ["zeros.bin", "invalid_file.json"])
def test_load_configuration_invalid_file(data_dir, file_name):
    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            load_configuration(file_name)


@pytest.mark.parametrize("file_name", ["test_relative_config1.yaml"])
def test_resolve_path_relative_to_config(data_dir, file_name):
    path_key = "containerOutputFile"
    with use_working_directory(data_dir):
        pth = resolve_path_relative_to_config(path_key, file_name)
        assert os.path.join("tests", "apps", "output.txt") in pth

        assert "override" == resolve_path_relative_to_config(
            path_key, file_name, override_path="override"
        )

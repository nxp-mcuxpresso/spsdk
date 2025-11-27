#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO Secure Objects data splitting functionality tests.

This module contains unit tests for the EL2GO API utility functions that handle
splitting user data into required and additional Secure Object groups.
"""

from pathlib import Path

from spsdk.el2go.api_utils import split_user_data


def test_regular_data_split(data_dir: str) -> None:
    """Test regular data splitting functionality.

    Validates that the split_user_data function correctly separates full binary data
    into required and additional components by comparing against expected reference files.

    :param data_dir: Directory path containing test data files (full_data.bin, req.bin, add.bin).
    """
    full_data = Path(data_dir).joinpath("full_data.bin").read_bytes()
    req_data = Path(data_dir).joinpath("req.bin").read_bytes()
    add_data = Path(data_dir).joinpath("add.bin").read_bytes()

    required, additional = split_user_data(full_data)

    assert required == req_data
    assert additional == add_data


def test_no_add_data_split(data_dir: str) -> None:
    """Test that split_user_data function handles data without additional section correctly.

    Verifies that when input data contains only required data (no additional data section),
    the split_user_data function returns the original data as required and empty bytes
    as additional data.

    :param data_dir: Directory path containing test data files
    """
    req_data = Path(data_dir).joinpath("req.bin").read_bytes()

    required, additional = split_user_data(req_data)

    assert required == req_data
    assert additional == bytes()


def test_no_req_data_split(data_dir: str) -> None:
    """Test function for splitting user data when no required data is present.

    This test verifies that the split_user_data function correctly handles the case
    where the input data contains only additional data and no required data section.
    The function should return empty bytes for required data and the original data
    as additional data.

    :param data_dir: Directory path containing test data files
    :raises AssertionError: If the data splitting does not work as expected
    """
    add_data = Path(data_dir).joinpath("add.bin").read_bytes()

    required, additional = split_user_data(add_data)

    assert required == bytes()
    assert additional == add_data

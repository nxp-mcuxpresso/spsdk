#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for splitting Secure Objects into required and additional groups."""

from pathlib import Path

from spsdk.el2go.api_utils import split_user_data


def test_regular_data_split(data_dir: str):
    full_data = Path(data_dir).joinpath("full_data.bin").read_bytes()
    req_data = Path(data_dir).joinpath("req.bin").read_bytes()
    add_data = Path(data_dir).joinpath("add.bin").read_bytes()

    required, additional = split_user_data(full_data)

    assert required == req_data
    assert additional == add_data


def test_no_add_data_split(data_dir: str):
    req_data = Path(data_dir).joinpath("req.bin").read_bytes()

    required, additional = split_user_data(req_data)

    assert required == req_data
    assert additional == bytes()


def test_no_req_data_split(data_dir: str):
    add_data = Path(data_dir).joinpath("add.bin").read_bytes()

    required, additional = split_user_data(add_data)

    assert required == bytes()
    assert additional == add_data

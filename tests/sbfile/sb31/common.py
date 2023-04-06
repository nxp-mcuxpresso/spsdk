#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Create read file function."""

from os import path


def read_file(data_dir, file_name, mode="rb"):
    """Function to read file."""
    with open(path.join(data_dir, file_name), mode) as f:
        return f.read()


def read_file_hex(data_dir, file_name, mode="r"):
    """Function to read file. Return bytearray object initialized from hex numbers."""
    with open(path.join(data_dir, file_name), mode) as f:
        return bytes.fromhex(f.read())

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


# name if data sub-directory with logs from output generation
DEBUG_LOG_SUBDIR = "debug_logs"


def compare_bin_files(path: str, bin_data: bytes) -> None:
    """Compares generated binary content with expected content stored in the file
    If the content is not same, the generated file is stored to the disk to allow analysis of the differences

    :param path: absolute path of the file with expected content
    :param bin_data: generated binary data
    """
    with open(path, "rb") as f:
        expected = f.read()
    if expected != bin_data:
        with open(path + ".generated", "wb") as f:
            f.write(bin_data)
        assert expected == bin_data, f'file does not match: "{path}"'


class GetPassMock:
    """Mocks the get_pass functionality."""

    def __init__(self, passphrase: str) -> None:
        self.passphrase = passphrase

    def get_pass(self, prompt=None, stream=None):
        return self.passphrase

    getpass = get_pass

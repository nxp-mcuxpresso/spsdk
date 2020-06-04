#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from typing import Iterable

# name if data sub-directory with logs from output generation
DEBUG_LOG_SUBDIR = 'debug_logs'


def compare_bin_files(path: str, bin_data: bytes) -> None:
    """ Compares generated binary content with expected content stored in the file
    If the content is not same, the generated file is stored to the disk to allow analysis of the differences

    :param path: absolute path of the file with expected content
    :param bin_data: generated binary data
    """
    with open(path, 'rb') as f:
        expected = f.read()
    if expected != bin_data:
        with open(path + '.generated', 'wb') as f:
            f.write(bin_data)
        assert expected == bin_data


def write_dbg_log(data_dir: str, file_name: str, text: Iterable[str], test: bool) -> None:
    """ In production mode, this function writes log to the disk.
    In test mode, the function just compare existing log with provided text.

    :param data_dir: absolute path of the data directory
    :param file_name: of the log file, without extension
    :param text: of the log file, list of lines without line endings
    :param test: True to compare log content (e.g. unit test mode); False to-rewrite the log (e.g. production)
    """
    dbg_path = os.path.join(data_dir, DEBUG_LOG_SUBDIR, file_name + '.txt')
    text = [line + '\n' for line in text]  # add line endings
    if test:
        with open(dbg_path, 'r') as f:
            lines = f.readlines()
        if text != lines:
            with open(dbg_path + '.generated', 'w') as f:
                f.writelines(text)
            assert text == lines
    else:
        with open(dbg_path, 'w') as f:
            f.writelines(text)

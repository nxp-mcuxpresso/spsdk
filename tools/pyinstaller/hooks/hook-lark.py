# -*- mode: python ; coding: utf-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""PyInstaller hook to collect metadata for package which iis not supported by PyInstaller yet."""

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files('lark')

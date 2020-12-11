# -*- mode: python ; coding: utf-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""PyInstaller hook to collect metadata for package which iis not supported by PyInstaller yet."""

from PyInstaller.utils.hooks import copy_metadata

datas = copy_metadata('prettytable')

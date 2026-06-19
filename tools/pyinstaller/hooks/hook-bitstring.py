#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""PyInstaller hook for the bitstring package.

bitstring/__init__.py uses importlib.import_module() to pick either the
bitarray-backed or the Rust (tibs) backend at runtime. PyInstaller cannot
detect these dynamic imports automatically, so we declare them here.
"""

hiddenimports = [
    "bitstring.bitstore_bitarray",
    "bitstring.bitstore_bitarray_helpers",
    "bitstring.bitstore_tibs",
    "bitstring.bitstore_tibs_helpers",
    "bitstring.bitstore_common_helpers",
]

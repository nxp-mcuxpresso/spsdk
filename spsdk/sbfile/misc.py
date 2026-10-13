#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SBFile miscellaneous utilities and helper functions.

This module provides utility functions and classes for SBFile operations,
including version handling, block size management, and timestamp operations.
"""

# Backward compatibility re-imports
# pylint: disable=unused-import
from spsdk.sbfile.utils.misc import (
    BcdVersion3,
    BcdVersion3Format,
    SecBootBlckSize,
    pack_timestamp,
    unpack_timestamp,
)

__all__ = [
    "BcdVersion3",
    "BcdVersion3Format",
    "SecBootBlckSize",
    "pack_timestamp",
    "unpack_timestamp",
]

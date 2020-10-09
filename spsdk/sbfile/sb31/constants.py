#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""File including constants."""

from spsdk.utils.easy_enum import Enum


########################################################################################################################
# Enums version 3.1
########################################################################################################################
class EnumCmdTag(Enum):
    """Contains commands tags."""
    NONE = 0x00
    ERASE = 0x01
    LOAD = 0x02
    EXECUTE = 0x03
    CALL = 0x04
    PROGRAM_FUSES = 0x05
    PROGRAM_IFR = 0x06
    LOAD_CMAC = 0x07
    COPY = 0x08
    LOAD_HASH_LOCKING = 0x09
    LOAD_KEY_BLOB = 0x0A
    CONFIGURE_MEMORY = 0x0B
    FILL_MEMORY = 0x0C
    FW_VERSION_CHECK = 0x0D

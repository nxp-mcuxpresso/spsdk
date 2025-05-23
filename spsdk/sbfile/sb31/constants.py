#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""File including constants."""

from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# Enums version 3.1
########################################################################################################################


class EnumCmdTag(SpsdkEnum):
    """Contains commands tags."""

    NONE = (0x00, "NONE")
    ERASE = (0x01, "erase")
    LOAD = (0x02, "load")
    EXECUTE = (0x03, "execute")
    CALL = (0x04, "call")
    PROGRAM_FUSES = (0x05, "programFuses")
    PROGRAM_IFR = (0x06, "programIFR")
    LOAD_CMAC = (0x07, "loadCMAC")
    COPY = (0x08, "copy")
    LOAD_HASH_LOCKING = (0x09, "loadHashLocking")
    LOAD_KEY_BLOB = (0x0A, "loadKeyBlob")
    CONFIGURE_MEMORY = (0x0B, "configureMemory")
    FILL_MEMORY = (0x0C, "fillMemory")
    FW_VERSION_CHECK = (0x0D, "checkFwVersion")
    # RESET added in SBx
    RESET = (0x0E, "reset")


class EnumDevHSMType(SpsdkEnum):
    """Contains Types of DevHSM provisioning specification."""

    INTERNAL = (1, "INTERNAL_DEVHSM_PROVISIONING")
    EXTERNAL = (2, "EXTERNAL_DEVHSM_PROVISIONING")

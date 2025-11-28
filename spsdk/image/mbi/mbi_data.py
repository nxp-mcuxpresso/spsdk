#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK Master Boot Image data definitions and enumerations.

This module provides data structures, enumerations, and mappings for Master Boot Image
configuration and processing within the SPSDK framework.
"""

import logging

from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class MbiImageTypeEnum(SpsdkEnum):
    """MBI image type enumeration for Master Boot Image configurations.

    This enumeration defines the supported image types for Master Boot Image (MBI)
    including plain, signed, CRC-protected, and encrypted variants for both
    XIP (Execute-in-Place) and Load-to-RAM execution models.
    """

    PLAIN_IMAGE = (0x00, "PLAIN_IMAGE", "Plain Image (either XIP or Load-to-RAM)")
    SIGNED_RAM_IMAGE = (0x01, "SIGNED_RAM_IMAGE", "Plain Signed Load-to-RAM Image")
    CRC_RAM_IMAGE = (0x02, "CRC_RAM_IMAGE", "Plain CRC Load-to-RAM Image")
    ENCRYPTED_RAM_IMAGE = (0x03, "ENCRYPTED_RAM_IMAGE", "Encrypted Load-to-RAM Image")
    SIGNED_XIP_IMAGE = (0x04, "SIGNED_XIP_IMAGE", "Plain Signed XIP Image")
    CRC_XIP_IMAGE = (0x05, "CRC_XIP_IMAGE", "Plain CRC XIP Image")
    SIGNED_XIP_NXP_IMAGE = (0x08, "SIGNED_XIP_NXP_IMAGE", "Plain Signed XIP Image NXP Keys")


MAP_IMAGE_TARGETS = {
    "targets": {
        "xip": [
            "xip",
            "famode",
            "famode_nxp",
            "Internal flash (XIP)",
            "External flash (XIP)",
            "Internal Flash (XIP)",
            "External Flash (XIP)",
        ],
        "load_to_ram": ["load-to-ram", "RAM", "ram"],
    }
}

MAP_AUTHENTICATIONS = {
    "plain": ["plain", "Plain"],
    "crc": ["crc", "CRC"],
    "signed": ["signed", "Signed", "famode"],
    "nxp_signed": ["signed-nxp", "NXP Signed", "NXP signed", "nxp_signed", "famode_nxp"],
    "encrypted": ["signed-encrypted", "Encrypted + Signed", "encrypted"],
}

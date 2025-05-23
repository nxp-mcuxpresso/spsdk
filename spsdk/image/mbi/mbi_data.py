#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image data."""

import logging

from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class MbiImageTypeEnum(SpsdkEnum):
    """Enumeration of MBI image types."""

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
    "signed": ["signed", "Signed"],
    "nxp_signed": ["signed-nxp", "NXP Signed", "NXP signed", "nxp_signed"],
    "encrypted": ["signed-encrypted", "Encrypted + Signed", "encrypted"],
}

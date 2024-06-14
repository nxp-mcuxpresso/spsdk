#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB data storage classes and various constants."""
import logging
from dataclasses import dataclass
from typing import List, Optional, Type

from spsdk.utils.spsdk_enum import SpsdkEnum, SpsdkSoftEnum

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0
CONTAINER_SIZE = 0x400
CONTAINER_ALIGNMENT = 8
START_IMAGE_ADDRESS = 0x2000
START_IMAGE_ADDRESS_NAND = 0x1C00


class AhabTargetMemory(SpsdkEnum):
    """Enum of supported SPSDK target memories."""

    TARGET_MEMORY_SERIAL_DOWNLOADER = (0, "serial_downloader")
    TARGET_MEMORY_NOR = (1, "nor")
    TARGET_MEMORY_NAND_4K = (2, "nand_4k")
    TARGET_MEMORY_NAND_2K = (3, "nand_2k")
    TARGET_MEMORY_STANDARD = (4, "standard")


TARGET_MEMORY_BOOT_OFFSETS = {
    AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER: 0x400,
    AhabTargetMemory.TARGET_MEMORY_NOR: 0x1000,
    AhabTargetMemory.TARGET_MEMORY_NAND_4K: 0x400,
    AhabTargetMemory.TARGET_MEMORY_NAND_2K: 0x400,
    AhabTargetMemory.TARGET_MEMORY_STANDARD: 0,
}

BINARY_IMAGE_ALIGNMENTS = {
    AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER: 512,
    AhabTargetMemory.TARGET_MEMORY_NOR: 1024,
    AhabTargetMemory.TARGET_MEMORY_NAND_2K: 2048,
    AhabTargetMemory.TARGET_MEMORY_NAND_4K: 4096,
    AhabTargetMemory.TARGET_MEMORY_STANDARD: 1024,
}


class AHABTags(SpsdkEnum):
    """AHAB container related tags."""

    BLOB = (0x81, "Blob (Wrapped Data Encryption Key).")
    CONTAINER_HEADER = (0x87, "Container header.")
    SIGNATURE_BLOCK = (0x90, "Signature block.")
    CERTIFICATE_UUID = (0xA0, "Certificate with UUID.")
    CERTIFICATE_NON_UUID = (0xAF, "Certificate without UUID.")
    SRK_TABLE = (0xD7, "SRK table.")
    SIGNATURE = (0xD8, "Signature part of signature block.")
    SRK_RECORD = (0xE1, "SRK record.")


class AHABSignAlgorithm(SpsdkEnum):
    """AHAB signature algorithm related tags."""

    RSA = (0x21, "RSA", "Rivest–Shamir–Adleman")
    RSA_PSS = (0x22, "RSA_PSS", "Rivest–Shamir–Adleman with PSS padding")
    ECDSA = (0x27, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    SM2 = (0x28, "SM2", "Chinese national cryptography standard")


class AHABSignHashAlgorithm(SpsdkEnum):
    """AHAB signature hash algorithm related tags."""

    SHA256 = (0x00, "SHA256", "Secure Hash Algorithm 256")
    SHA384 = (0x01, "SHA384", "Secure Hash Algorithm 384")
    SHA512 = (0x02, "SHA512", "Secure Hash Algorithm 512")
    SM3 = (
        0x03,
        "SM3",
        "Cryptographic hash function used in the Chinese National Standard",
    )


class FlagsSrkSet(SpsdkSoftEnum):
    """Flags SRK Set."""

    NONE = (0x00, "none", "Image is not signed")
    NXP = (0x01, "nxp", "Signed by NXP keys")
    OEM = (0x02, "oem", "Signed by OEM keys")


@dataclass
class AhabChipConfig:
    """Holder class of common AHAB configuration regarding the used chip."""

    family: str
    revision: str
    target_memory: AhabTargetMemory
    core_ids: Type[SpsdkSoftEnum]
    image_types: Type[SpsdkSoftEnum]
    start_image_address: int
    containers_max_cnt: int
    images_max_cnt: int
    valid_offset_minimal_alignment: int
    container_size: int = CONTAINER_SIZE
    container_image_size_alignment: int = CONTAINER_ALIGNMENT

    search_paths: Optional[List[str]] = None


@dataclass
class AhabChipContainerConfig:
    """Holder class of container AHAB configuration regarding the used chip."""

    base: AhabChipConfig
    container_offset: int
    locked: bool = False

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AHAB data storage classes and various constants."""
import logging
from dataclasses import dataclass, field
from typing import Optional, Type

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.database import DatabaseManager, Features, get_db
from spsdk.utils.spsdk_enum import SpsdkEnum, SpsdkSoftEnum

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0
CONTAINER_ALIGNMENT = 8


class AhabTargetMemory(SpsdkEnum):
    """Enum of supported SPSDK target memories."""

    TARGET_MEMORY_SERIAL_DOWNLOADER = (0, "serial_downloader")
    TARGET_MEMORY_NOR = (1, "nor")
    TARGET_MEMORY_NAND_4K = (2, "nand_4k")
    TARGET_MEMORY_NAND_2K = (3, "nand_2k")
    TARGET_MEMORY_STANDARD = (4, "standard")


BINARY_IMAGE_ALIGNMENTS = {
    AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER: 512,
    AhabTargetMemory.TARGET_MEMORY_NOR: 1024,
    AhabTargetMemory.TARGET_MEMORY_NAND_2K: 2048,
    AhabTargetMemory.TARGET_MEMORY_NAND_4K: 4096,
    AhabTargetMemory.TARGET_MEMORY_STANDARD: 1024,
}


class AHABTags(SpsdkEnum):
    """AHAB container related tags."""

    SRK_TABLE_ARRAY = (0x5A, "SRK table array.")
    SRK_DATA = (0x5D, "SRK Data.")
    BLOB = (0x81, "Blob (Wrapped Data Encryption Key).")
    CONTAINER_HEADER = (0x87, "Container header.")
    SIGNATURE_BLOCK = (0x90, "Signature block.")
    CERTIFICATE = (0xAF, "Certificate.")
    SRK_TABLE = (0xD7, "SRK table.")
    SIGNATURE = (0xD8, "Signature part of signature block.")
    SRK_RECORD = (0xE1, "SRK record.")


class AHABSignAlgorithm(SpsdkEnum):
    """AHAB signature algorithm related tags."""


class AHABSignAlgorithmV1(AHABSignAlgorithm):
    """AHAB signature algorithm related tags."""

    RSA = (0x21, "RSA", "Rivest–Shamir–Adleman")
    RSA_PSS = (0x22, "RSA_PSS", "Rivest–Shamir–Adleman with PSS padding")
    ECDSA = (0x27, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    SM2 = (0x28, "SM2", "Chinese national cryptography standard")


class AHABSignAlgorithmV2(AHABSignAlgorithm):
    """AHAB signature algorithm related tags."""

    RSA = (0x21, "RSA", "Rivest–Shamir–Adleman")
    RSA_PSS = (0x22, "RSA_PSS", "Rivest–Shamir–Adleman with PSS padding")
    ECDSA = (0x27, "ECDSA", "Elliptic Curve Digital Signature Algorithm")
    SM2 = (0x28, "SM2", "Chinese national cryptography standard")
    DILITHIUM = (0xD1, "DILITHIUM", "Post quantum cryptography standard candidate")


class AHABSignHashAlgorithm(SpsdkEnum):
    """AHAB signature hash algorithm related tags."""


class AHABSignHashAlgorithmV1(AHABSignHashAlgorithm):
    """AHAB signature hash algorithm related tags."""

    SHA256 = (0x00, "SHA256", "Secure Hash Algorithm 256")
    SHA384 = (0x01, "SHA384", "Secure Hash Algorithm 384")
    SHA512 = (0x02, "SHA512", "Secure Hash Algorithm 512")
    SM3 = (
        0x03,
        "SM3",
        "Cryptographic hash function used in the Chinese National Standard",
    )


class AHABSignHashAlgorithmV2(AHABSignHashAlgorithm):
    """AHAB signature hash algorithm related tags."""

    SHA256 = (0x00, "SHA256", "Secure Hash Algorithm 256")
    SHA384 = (0x01, "SHA384", "Secure Hash Algorithm 384")
    SHA512 = (0x02, "SHA512", "Secure Hash Algorithm 512")
    SM3 = (
        0x03,
        "SM3",
        "Cryptographic hash function used in the Chinese National Standard",
    )
    SHA3_256 = (4, "SHA3_256", "Secure Hash Algorithm 3 - 256")
    SHA3_384 = (5, "SHA3_384", "Secure Hash Algorithm 3 - 384")
    SHA3_512 = (6, "SHA3_512", "Secure Hash Algorithm 3 - 512")
    SHAKE_128_OUTPUT_256 = (
        8,
        "SHAKE_128_OUTPUT_256",
        "Secure Hash Algorithm Shake 128 - with 256 bits output",
    )
    SHAKE_256_OUTPUT_512 = (
        9,
        "SHAKE_256_OUTPUT_512",
        "Secure Hash Algorithm Shake 256 - with 512 bits output",
    )


class FlagsSrkSet(SpsdkSoftEnum):
    """Flags SRK Set."""

    NONE = (0x00, "none", "Image is not signed")
    NXP = (0x01, "nxp", "Signed by NXP keys")
    OEM = (0x02, "oem", "Signed by OEM keys")


class DummyEnum(SpsdkSoftEnum):
    """Dummy core id."""

    DUMMY = (0x00, "dummy")


@dataclass
class AhabChipConfig:
    """Holder class of common AHAB configuration regarding the used chip."""

    family: str = "Unknown"
    revision: str = "latest"
    target_memory: AhabTargetMemory = AhabTargetMemory.TARGET_MEMORY_STANDARD
    core_ids: Type[SpsdkSoftEnum] = DummyEnum
    image_types: dict[str, Type[SpsdkSoftEnum]] = field(default_factory=dict)
    image_types_mapping: dict[str, list[int]] = field(default_factory=dict)
    containers_max_cnt: int = 3
    images_max_cnt: int = 8
    container_types: list[int] = field(default_factory=list)
    valid_offset_minimal_alignment: int = 4
    container_image_size_alignment: int = CONTAINER_ALIGNMENT
    allow_empty_hash: bool = False

    search_paths: Optional[list[str]] = None


@dataclass
class AhabChipContainerConfig:
    """Holder class of container AHAB configuration regarding the used chip."""

    base: AhabChipConfig = field(default_factory=AhabChipConfig)
    container_offset: int = 0
    used_srk_id: int = 0
    srk_revoke_keys: int = 0
    srk_set: FlagsSrkSet = FlagsSrkSet.NONE
    locked: bool = False


def load_images_types(db: Features) -> dict[str, Type[SpsdkSoftEnum]]:
    """Load images types.

    :param db: database to load from.
    :return: Loaded dictionary with image types.
    """
    db_image_types = db.get_dict(DatabaseManager.AHAB, "image_types")
    ret = {}
    for k, v in db_image_types.items():
        ret[k] = SpsdkSoftEnum.create_from_dict(f"AHABImageTypes_{k}", v)
    return ret


def create_chip_config(
    family: str,
    revision: str = "latest",
    target_memory: str = AhabTargetMemory.TARGET_MEMORY_STANDARD.label,
    search_paths: Optional[list[str]] = None,
) -> AhabChipConfig:
    """Create AHAB chip configuration structure.

    :param family: Name of device family.
    :param revision: Device silicon revision, defaults to "latest"
    :param target_memory: Target memory for AHAB image [serial_downloader, standard, nand], defaults to "standard"
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKValueError: Invalid input configuration.
    :return: AHAB chip configuration structure.
    """
    if target_memory not in AhabTargetMemory.labels():
        raise SPSDKValueError(
            f"Invalid AHAB target memory [{target_memory}]."
            f" The list of supported images: [{','.join(AhabTargetMemory.labels())}]"
        )
    db = get_db(family, revision)
    containers_max_cnt = db.get_int(DatabaseManager.AHAB, "containers_max_cnt")
    images_max_cnt = db.get_int(DatabaseManager.AHAB, "oem_images_max_cnt")
    core_ids = SpsdkSoftEnum.create_from_dict(
        "AHABCoreId", db.get_dict(DatabaseManager.AHAB, "core_ids")
    )
    image_types = load_images_types(db)
    image_types_mapping = db.get_dict(DatabaseManager.AHAB, "image_types_mapping")

    valid_offset_minimal_alignment = db.get_int(
        DatabaseManager.AHAB, "valid_offset_minimal_alignment", 4
    )
    container_image_size_alignment = db.get_int(
        DatabaseManager.AHAB, "container_image_size_alignment", 1
    )
    container_types = db.get_list(DatabaseManager.AHAB, "container_types")
    allow_empty_hash = db.get_bool(DatabaseManager.AHAB, "allow_empty_hash")
    return AhabChipConfig(
        family=family,
        revision=db.name,
        target_memory=AhabTargetMemory.from_label(target_memory),
        core_ids=core_ids,
        image_types=image_types,
        image_types_mapping=image_types_mapping,
        containers_max_cnt=containers_max_cnt,
        images_max_cnt=images_max_cnt,
        container_types=container_types,
        valid_offset_minimal_alignment=valid_offset_minimal_alignment,
        container_image_size_alignment=container_image_size_alignment,
        allow_empty_hash=allow_empty_hash,
        search_paths=search_paths,
    )

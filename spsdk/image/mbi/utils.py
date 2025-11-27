#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Master Boot Image utilities.

This module provides utility functions for Master Boot Image (MBI) processing,
including AHAB hash algorithm support and validation schema management.
"""


from typing import Any

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.image.ahab.ahab_data import AhabChipConfig
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db


def get_ahab_supported_hashes(family: FamilyRevision) -> list[EnumHashAlgorithm]:
    """Get list of hash algorithms supported by the specified family.

    :param family: Family revision information.
    :return: List of supported hash algorithms.
    """
    supported_labels: list[str] = get_db(family).get_list(
        DatabaseManager.MBI, ["ahab", "image_hash_types"], ["sha384"]
    )
    return [EnumHashAlgorithm.from_label(enum_label) for enum_label in supported_labels]


def get_mbi_ahab_validation_schemas(ahab_config: AhabChipConfig) -> dict[str, Any]:
    """Create the MBI AHAB validation schemas for configuration.

    The method dynamically configures validation schemas based on the AHAB chip configuration,
    including support for multiple hash types and core IDs when available.

    :param ahab_config: AHAB chip configuration containing family and core ID information.
    :return: Dictionary containing the configured validation schemas for MBI AHAB.
    """
    mbi_sch_cfg = get_schema_file(DatabaseManager.MBI)

    # if multiple hash types are supported, add hash type selection schema
    supported_hashes = get_ahab_supported_hashes(ahab_config.family)
    if len(supported_hashes) > 1:
        mbi_sch_cfg["ahab_sign_support_add_image_hash_type"]["properties"]["image_hash_type"][
            "enum"
        ] = [hash_alg.label for hash_alg in supported_hashes]
        mbi_sch_cfg["ahab_sign_support_add_image_hash_type"]["properties"]["image_hash_type"][
            "template_value"
        ] = supported_hashes[0].label
    mbi_sch_cfg["ahab_sign_support_add_image_hash_type"]["properties"]["image_hash_type"][
        "skip_in_template"
    ] = bool(len(supported_hashes) <= 1)

    # if multiple core ids are supported, add core id selection schema
    if len(ahab_config.core_ids) > 1:
        mbi_sch_cfg["ahab_sign_support_add_core_id"]["properties"]["core_id"][
            "enum"
        ] = ahab_config.core_ids.labels()
        mbi_sch_cfg["ahab_sign_support_add_core_id"]["properties"]["core_id"][
            "template_value"
        ] = ahab_config.core_ids.labels()[0]
    mbi_sch_cfg["ahab_sign_support_add_core_id"]["properties"]["core_id"]["skip_in_template"] = (
        bool(len(ahab_config.core_ids) <= 1)
    )

    return mbi_sch_cfg

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB image testing module.

This module contains unit tests for HAB (High Assurance Boot) image functionality
in SPSDK, covering image parsing, export operations, and DEK handling.
"""

import os
from typing import Any

import pytest

from spsdk.image.hab.hab_image import HabImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


@pytest.fixture()
def nxpimage_hab_data_dir(tests_root_dir: str) -> str:
    """Get HAB test data directory path.

    Constructs the absolute path to the HAB (High Assurance Boot) test data directory
    by joining the provided tests root directory with the HAB-specific subdirectory structure.

    :param tests_root_dir: Root directory path for test files.
    :return: Absolute path to the HAB test data directory.
    """
    return os.path.join(tests_root_dir, "nxpimage", "data", "hab")


@pytest.mark.parametrize(
    "configuration, family",
    [
        ("rt1050_xip_image_iar_authenticated", FamilyRevision("mimxrt1050")),
        ("rt1060_flashloader_authenticated_nocak", FamilyRevision("mimxrt1060")),
        ("rt1165_flashloader_authenticated", FamilyRevision("mimxrt1165")),
        ("rt1165_semcnand_authenticated", FamilyRevision("mimxrt1165")),
        ("rt1170_flashloader_authenticated", FamilyRevision("mimxrt1176")),
        ("rt1170_RAM_authenticated", FamilyRevision("mimxrt1176")),
        ("rt1170_semcnand_authenticated", FamilyRevision("mimxrt1176")),
        ("rt1160_xip_mdk_unsigned", FamilyRevision("mimxrt1060")),
        ("rt1170_RAM_non_xip_unsigned", FamilyRevision("mimxrt1176")),
        ("rt1170_flashloader_unsigned", FamilyRevision("mimxrt1176")),
        ("rt1170_QSPI_flash_unsigned", FamilyRevision("mimxrt1176")),
        ("rt1170_RAM_unsigned", FamilyRevision("mimxrt1176")),
    ],
)
def test_nxpimage_hab_parse_and_export(
    configuration: str, family: FamilyRevision, nxpimage_hab_data_dir: str
) -> None:
    """Test HAB image parsing and export functionality.

    This test verifies that a HAB image can be parsed from binary data and then
    exported back to the same binary format. It also validates that the length
    of the parsed image matches the original binary data.

    :param configuration: Configuration name used to locate the reference HAB file
    :param family: Family revision specification for HAB image parsing
    :param nxpimage_hab_data_dir: Base directory path containing HAB test data files
    """
    ref_hab_file = os.path.join(nxpimage_hab_data_dir, "export", configuration, "output.bin")
    ref_hab = load_binary(ref_hab_file)
    hab = HabImage.parse(ref_hab, family)
    assert hab.export() == ref_hab
    assert len(hab) == len(ref_hab)


def test_hab_dek_is_exported(tmpdir: Any, nxpimage_hab_data_dir: str) -> None:
    """Test that DEK (Data Encryption Key) is properly exported during HAB image processing.

    This test verifies that when a HAB image is configured with encryption settings,
    the DEK file is correctly exported to the specified location and matches the
    DEK stored in the CSF segment.

    :param tmpdir: Temporary directory for test file operations.
    :param nxpimage_hab_data_dir: Directory containing HAB test data files.
    """
    config = Config.create_from_file(
        os.path.join(nxpimage_hab_data_dir, "export", "rt1165_semcnand_encrypted", "config.yaml")
    )
    dek_file = os.path.join(tmpdir, "dek.bin")
    config["sections"][6]["SecretKey"]["SecretKey_Name"] = dek_file
    config["sections"][6]["SecretKey"]["SecretKey_ReuseDek"] = False
    hab = HabImage.load_from_config(config)
    hab.post_export(tmpdir)
    assert os.path.isfile(dek_file)
    assert hab.csf_segment is not None
    assert hab.csf_segment.dek == load_binary(dek_file)

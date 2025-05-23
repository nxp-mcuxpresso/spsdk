#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os

import pytest

from spsdk.image.hab.hab_image import HabImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.fixture()
def nxpimage_hab_data_dir(tests_root_dir):
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
def test_nxpimage_hab_parse_and_export(configuration, family, nxpimage_hab_data_dir):
    ref_hab_file = os.path.join(nxpimage_hab_data_dir, "export", configuration, "output.bin")
    ref_hab = load_binary(ref_hab_file)
    hab = HabImage.parse(ref_hab, family)
    assert hab.export() == ref_hab
    assert len(hab) == len(ref_hab)


def test_hab_dek_is_exported(tmpdir, nxpimage_hab_data_dir):
    config = Config.create_from_file(
        os.path.join(nxpimage_hab_data_dir, "export", "rt1165_semcnand_encrypted", "config.yaml")
    )
    dek_file = os.path.join(tmpdir, "dek.bin")
    config["sections"][6]["SecretKey"]["SecretKey_Name"] = dek_file
    config["sections"][6]["SecretKey"]["SecretKey_ReuseDek"] = False
    hab = HabImage.load_from_config(config)
    hab.post_export(tmpdir)
    assert os.path.isfile(dek_file)
    assert hab.csf_segment.dek == load_binary(dek_file)

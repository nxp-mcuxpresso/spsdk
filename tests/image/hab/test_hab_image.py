#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""HAB image testing module.

This module contains unit tests for HAB (High Assurance Boot) image functionality
in SPSDK, covering image parsing, export operations, and DEK handling.
"""

import os
from typing import Any

import pytest

from spsdk.exceptions import SPSDKParsingError
from spsdk.image.hab.hab_image import HabImage
from spsdk.image.hab.segments.seg_bdt import SegBDT
from spsdk.image.hab.segments.seg_ivt import SegIVT
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


def _build_cortex_a_hab_image(
    ivt_offset: int,
    start_address: int,
    app_offset: int,
    app: bytes,
    dcd: bytes | None = None,
    csf_reserved: int = 0,
) -> bytes:
    """Build a minimal HAB image as created by legacy tools (e.g. U-Boot mkimage).

    The application is plain Cortex-A code without Cortex-M vector table, the IVT entry point
    points directly to the application start. Optionally a DCD and an empty (unsigned) CSF
    area referenced from IVT can be added.

    :param ivt_offset: Offset of IVT from the image start (BDT start address).
    :param start_address: Image start address stored in BDT.
    :param app_offset: Offset of the application from IVT.
    :param app: Application binary.
    :param dcd: Optional DCD binary placed right after BDT.
    :param csf_reserved: Size of reserved (empty) CSF area, 0 for no CSF.
    :return: HAB image binary starting with IVT.
    """
    ivt_address = start_address + ivt_offset
    ivt = SegIVT(0x40)
    ivt.ivt_address = ivt_address
    ivt.bdt_address = ivt_address + SegIVT.SIZE
    ivt.app_address = ivt_address + app_offset
    if dcd:
        ivt.dcd_address = ivt.bdt_address + SegBDT.SIZE
    if csf_reserved:
        ivt.csf_address = ivt_address + app_offset + len(app)
    image_length = ivt_offset + app_offset + len(app) + csf_reserved
    bdt = SegBDT(app_start=start_address, app_length=image_length)
    headers = ivt.export() + bdt.export() + (dcd or b"")
    assert len(headers) <= app_offset
    return headers.ljust(app_offset, b"\x00") + app + b"\x00" * csf_reserved


# Cortex-A (ARM / AArch64) code start: branch instruction, no Cortex-M vector table
CORTEX_A_APP = bytes.fromhex("0f0000ea14f09fe514f09fe5") + bytes(range(256)) * 16


@pytest.mark.parametrize(
    "ivt_offset, start_address, app_offset, dcd, csf_reserved",
    [
        # i.MX6 style: IVT at 0x400, DCD, application at 0xC00, reserved CSF area
        (0x400, 0x907000, 0xC00, True, 0x2000),
        # i.MX6 style without DCD and CSF
        (0x400, 0x907000, 0xC00, False, 0),
        # i.MX8M Nano SPL style: IVT at image start, application right after BDT
        (0x0, 0x911FC0, 0x40, False, 0),
        # i.MX8M Nano style with reserved CSF area
        (0x0, 0x911FC0, 0x40, False, 0x2000),
    ],
)
def test_hab_parse_cortex_a_image(
    ivt_offset: int,
    start_address: int,
    app_offset: int,
    dcd: bool,
    csf_reserved: int,
    data_dir: str,
) -> None:
    """Test parsing of legacy Cortex-A HAB images (i.MX6 / i.MX8M) without Cortex-M vectors.

    :param ivt_offset: Offset of IVT from the image start.
    :param start_address: Image start address.
    :param app_offset: Offset of the application from IVT.
    :param dcd: Whether to add DCD segment.
    :param csf_reserved: Size of reserved empty CSF area.
    :param data_dir: Path to the HAB test data directory.
    """
    dcd_bin = (
        load_binary(os.path.join(data_dir, "..", "segments", "data", "dcd.bin")) if dcd else None
    )
    image = _build_cortex_a_hab_image(
        ivt_offset, start_address, app_offset, CORTEX_A_APP, dcd_bin, csf_reserved
    )
    # Trailing data (e.g. U-Boot proper behind SPL) must be ignored
    hab = HabImage.parse(image + b"\xff" * 0x1000)
    assert hab.ivt_offset == ivt_offset
    assert hab.start_address == start_address
    assert hab.app_segment.offset == app_offset
    assert hab.app_segment.binary == CORTEX_A_APP
    assert hab.csf_segment is None
    assert not hab.is_authenticated
    assert (hab.dcd_segment is not None) == dcd
    if dcd_bin:
        assert hab.dcd_segment is not None
        assert hab.dcd_segment.export() == dcd_bin
    exported = hab.export()
    assert image.startswith(exported)
    assert len(hab) == app_offset + len(CORTEX_A_APP)


def test_hab_parse_cortex_a_image_get_config(tmpdir: Any) -> None:
    """Test that configuration can be created from parsed legacy image with unknown family.

    :param tmpdir: Temporary directory for exported files.
    """
    image = _build_cortex_a_hab_image(0x400, 0x907000, 0xC00, CORTEX_A_APP)
    hab = HabImage.parse(image)
    hab.verify().validate()
    config = hab.get_config(str(tmpdir))
    assert config["options"]["ivtOffset"] == 0x400
    assert config["options"]["initialLoadSize"] == 0xC00
    assert load_binary(os.path.join(tmpdir, config["inputImageFile"])) == CORTEX_A_APP


def test_hab_parse_invalid_entry_point() -> None:
    """Test that image with entry point inside HAB headers and no vector table is rejected."""
    image = bytearray(_build_cortex_a_hab_image(0x400, 0x907000, 0xC00, CORTEX_A_APP))
    # Move entry point into the BDT
    image[4:8] = (0x907000 + 0x400 + SegIVT.SIZE).to_bytes(4, "little")
    with pytest.raises(SPSDKParsingError, match="Application offset could not be found"):
        HabImage.parse(bytes(image))


@pytest.mark.parametrize("leading_size", [0, 0x400, 0x8000])
def test_hab_find_offset_of_hab(leading_size: int) -> None:
    """Test finding the HAB container inside binary with leading data.

    :param leading_size: Size of data placed before the HAB container.
    """
    image = _build_cortex_a_hab_image(0x0, 0x911FC0, 0x40, CORTEX_A_APP)
    binary = b"\x00" * leading_size + image
    offset = HabImage.find_offset_of_hab(binary)
    assert offset == leading_size
    hab = HabImage.parse(binary[offset:])
    assert hab.app_segment.binary == CORTEX_A_APP


def test_hab_find_offset_of_hab_not_found() -> None:
    """Test that missing HAB container is reported."""
    with pytest.raises(SPSDKParsingError):
        HabImage.find_offset_of_hab(b"\xd1" * 0x1000)


@pytest.mark.parametrize(
    "ivt_offset, start_address, app_offset",
    [
        (0x0, 0x911FC0, 0x40),
        (0x400, 0x907000, 0xC00),
    ],
)
def test_hab_parse_cortex_a_image_with_address_literal(
    ivt_offset: int, start_address: int, app_offset: int
) -> None:
    """Test that Cortex-A application data resembling a Cortex-M reset vector are ignored.

    An odd in-range address literal at a known vector table offset must not override
    the IVT entry point of a Cortex-A image.

    :param ivt_offset: Offset of IVT from the image start.
    :param start_address: Image start address.
    :param app_offset: Offset of the application from IVT.
    """
    app = bytearray(CORTEX_A_APP)
    ivt_address = start_address + ivt_offset
    for vector_offset in (0x100, 0x1000, 0x2000):
        if vector_offset > app_offset:
            position = vector_offset + 4 - app_offset
            app[position : position + 4] = (ivt_address + app_offset + 0x41).to_bytes(4, "little")
    image = _build_cortex_a_hab_image(ivt_offset, start_address, app_offset, bytes(app))
    hab = HabImage.parse(image)
    assert hab.app_segment.offset == app_offset
    assert hab.app_segment.binary == bytes(app)

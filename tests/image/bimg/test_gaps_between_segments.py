#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of preserving the data stored between the bootable image segments."""

import logging
import os
from pathlib import Path
from typing import Any, Optional

import pytest

from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.utils import ahab_sign_image
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mem_type import MemoryType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

FAMILY = FamilyRevision("mimx943")
KEYS_DIR = Path(__file__).resolve().parents[2] / "_data" / "keys" / "ecc256"
FCB_OFFSET = 0x400
FCB_SIZE = 0x200
CONTAINER_SET_OFFSET = 0x1000
SECONDARY_ALIGNMENT = 0x400
# Data stored behind the FCB in the FCB area, like the FlexSPI NOR extension of imx-mkimage
FCB_EXTENSION = bytes(range(1, 0x41))


def _write(directory: str, name: str, data: bytes) -> str:
    """Write the data to the file in directory and return its path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _create_container_set(directory: str) -> bytes:
    """Create exported AHAB container set with one unsigned container."""
    config = Config(
        {
            "family": FAMILY.name,
            "revision": "latest",
            "target_memory": "nor",
            "output": os.path.join(directory, "ahab.bin"),
            "containers": [
                {
                    "container": {
                        "srk_set": "none",
                        "images": [
                            {"system_manager": _write(directory, "sm.bin", b"\x06" * 0x100)}
                        ],
                    }
                }
            ],
        }
    )
    config.config_dir = directory
    ahab = AHABImage.load_from_config(config)
    ahab.update_fields()
    return ahab.export()


def _create_flexspi_image(directory: str, fcb_area_tail: Optional[bytes] = None) -> bytes:
    """Create FlexSPI NOR image with two container sets and data in the FCB area behind the FCB.

    :param directory: Directory used for the temporary input files.
    :param fcb_area_tail: Content of the FCB area behind the FCB, defaults to the extension
        followed by zero padding.
    :return: Binary of the FlexSPI NOR bootable image.
    """
    area_size = CONTAINER_SET_OFFSET - FCB_OFFSET - FCB_SIZE
    if fcb_area_tail is None:
        fcb_area_tail = FCB_EXTENSION + bytes(area_size - len(FCB_EXTENSION))
    assert len(fcb_area_tail) == area_size
    header = bytes(FCB_OFFSET) + FCB(FAMILY, MemoryType.FLEXSPI_NOR).export() + fcb_area_tail
    assert len(header) == CONTAINER_SET_OFFSET
    primary = _create_container_set(directory)
    # The secondary container set is placed behind the primary one on the next 1 kB boundary
    primary += b"\xff" * (-len(primary) % SECONDARY_ALIGNMENT)
    return header + primary + _create_container_set(directory)


def _sign_config() -> Config:
    """Create the AHAB signing configuration."""
    return Config(
        {
            "family": FAMILY.name,
            "revision": "latest",
            "srk_set": "oem",
            "used_srk_id": 0,
            "signer": str(KEYS_DIR / "srk0_ecc256.pem"),
            "srk_table": {
                "srk_array": [str(KEYS_DIR / f"srk{i}_ecc256.pub") for i in range(4)],
            },
        }
    )


def test_parse_keeps_data_between_segments(tmpdir: str) -> None:
    """Test the parsed bootable image keeps the FCB area and exports identical binary."""
    binary = _create_flexspi_image(tmpdir)

    bimg = BootableImage.parse(binary, family=FAMILY, mem_type=MemoryType.FLEXSPI_NOR)

    # The leading zeros in the unused key blob area and the whole FCB area tail are kept
    gaps = bimg._gaps  # pylint: disable=protected-access
    assert [offset for offset, _ in gaps] == [0, FCB_OFFSET + FCB_SIZE]
    assert bimg.export() == binary


def test_parse_does_not_store_padding_gaps(tmpdir: str) -> None:
    """Test the gaps containing only the image pattern are not stored."""
    area_size = CONTAINER_SET_OFFSET - FCB_OFFSET - FCB_SIZE
    binary = _create_flexspi_image(tmpdir, fcb_area_tail=b"\xff" * area_size)
    binary = b"\xff" * FCB_OFFSET + binary[FCB_OFFSET:]

    bimg = BootableImage.parse(binary, family=FAMILY, mem_type=MemoryType.FLEXSPI_NOR)

    assert bimg._gaps == []  # pylint: disable=protected-access
    assert bimg.export() == binary


def test_gap_overlapping_updated_segment_is_dropped(tmpdir: str, caplog: Any) -> None:
    """Test the stored gap is dropped when it collides with the segment layout."""
    caplog.set_level(logging.WARNING)
    binary = _create_flexspi_image(tmpdir)
    bimg = BootableImage.parse(binary, family=FAMILY, mem_type=MemoryType.FLEXSPI_NOR)
    # Simulate the gap that collides with the FCB segment
    bimg._gaps = [(FCB_OFFSET + 0x10, b"\x5a" * 0x10)]  # pylint: disable=protected-access

    exported = bimg.export()

    assert (
        exported[FCB_OFFSET : FCB_OFFSET + FCB_SIZE] == binary[FCB_OFFSET : FCB_OFFSET + FCB_SIZE]
    )
    assert any("overlaps an updated segment" in msg for msg in caplog.messages)


def test_parse_prefers_identified_memory_type(tmpdir: str, caplog: Any) -> None:
    """Test the memory type proven by the FCB tag is used when more memory types match."""
    caplog.set_level(logging.WARNING)
    binary = _create_flexspi_image(tmpdir)

    bimg = BootableImage.parse(binary, family=FAMILY)

    assert bimg.mem_type == MemoryType.FLEXSPI_NOR
    assert any(
        'The "Flexspi NOR" memory type will be used.' in msg
        and msg.startswith("Multiple possible memory types detected")
        for msg in caplog.messages
    )
    assert bimg.export() == binary


@pytest.mark.parametrize("mem_type", ["flexspi_nor", "auto"])
def test_ahab_sign_image_keeps_fcb_area(tmpdir: str, mem_type: str) -> None:
    """Test signing of FlexSPI NOR image keeps the whole FCB area untouched."""
    binary = _create_flexspi_image(tmpdir)
    image_path = _write(tmpdir, "flash.bin", binary)

    # Unknown label means auto-detection of the memory type
    signed, bimg = ahab_sign_image(image_path, _sign_config(), mem_type, 0)

    assert bimg.mem_type == MemoryType.FLEXSPI_NOR
    assert len(signed) == len(binary)
    assert signed[:CONTAINER_SET_OFFSET] == binary[:CONTAINER_SET_OFFSET]
    signed_ahab = AHABImage.parse(signed[CONTAINER_SET_OFFSET:], family=FAMILY)
    assert signed_ahab.ahab_containers[0].signature_block is not None
    assert signed_ahab.ahab_containers[0].signature_block.signature is not None


def test_ahab_sign_image_warns_about_dropped_data(tmpdir: str, caplog: Any) -> None:
    """Test signing warns when part of the input image is dropped by a wrong memory type."""
    caplog.set_level(logging.WARNING)
    binary = _create_flexspi_image(tmpdir)
    image_path = _write(tmpdir, "flash.bin", binary)

    # The serial downloader layout takes the primary container set for the secondary one
    signed, _ = ahab_sign_image(image_path, _sign_config(), "serial_downloader", 0)

    assert len(signed) < len(binary)
    assert any(
        f"The input data behind offset 0x{len(signed):X} is not part of the bootable image" in msg
        for msg in caplog.messages
    )


def test_ahab_sign_image_ignores_dropped_padding(tmpdir: str, caplog: Any) -> None:
    """Test signing does not warn when only the trailing padding is dropped."""
    caplog.set_level(logging.WARNING)
    binary = _create_flexspi_image(tmpdir)
    image_path = _write(tmpdir, "flash.bin", binary + b"\xff" * 0x100)

    signed, _ = ahab_sign_image(image_path, _sign_config(), "flexspi_nor", 0)

    assert len(signed) == len(binary)
    assert not any("is not part of the bootable image" in msg for msg in caplog.messages)

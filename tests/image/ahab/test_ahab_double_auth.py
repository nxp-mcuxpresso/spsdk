#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for AHAB double authentication image array entry template."""

# cspell:words LHBBHH LLQQLL

import os
from struct import pack

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_data import AhabChipContainerConfig, AHABTags, create_chip_config
from spsdk.image.ahab.ahab_iae import IaeDoubleAuthentication, ImageArrayEntry, ImageArrayEntryV2
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision


def _container(version: int, tag: int, entries: list[tuple[int, int]]) -> bytes:
    """Create minimal container header followed by image array entries (offset, size)."""
    header = pack("<BHB", version, 0x10 + 0x80 * len(entries), tag)
    header += pack("<LHBBHH", 0, 0, 0, len(entries), 0, 0)
    for offset, size in entries:
        header += pack("<LLQQLL64s32s", offset, size, 0, 0, 0, 0, bytes(64), bytes(32))
    return header


def _nxp_image(version: int, container_size: int, v2x_tag: int | None) -> bytes:
    """Create NXP firmware image with ELE container and optional V2X container."""
    ele_offset = 4 * container_size
    data = bytearray(_container(version, AHABTags.CONTAINER_HEADER.tag, [(ele_offset, 0x200)]))
    data.extend(bytes(ele_offset + 0x200 - len(data)))
    data[ele_offset : ele_offset + 0x200] = b"\xe1" * 0x200
    if v2x_tag is not None:
        v2x_offset = 4 * container_size
        v2x = _container(0, v2x_tag, [(v2x_offset, 0x200), (v2x_offset + 0x200, 0x200)])
        data[container_size : container_size + len(v2x)] = v2x
        start = container_size + v2x_offset
        data.extend(bytes(start + 0x400 - len(data)))
        data[start : start + 0x400] = b"\x2a" * 0x400
    return bytes(data)


@pytest.mark.parametrize(
    "family,revision,iae_cls,version,container_size,v2x_tag",
    [
        ("mimx943", "a0", ImageArrayEntryV2, 2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag),
        ("mimx9596", "b0", ImageArrayEntryV2, 2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag),
        ("mimx9596", "a0", ImageArrayEntry, 0, 0x400, AHABTags.CONTAINER_HEADER.tag),
    ],
)
@pytest.mark.parametrize("with_v2x", [True, False])
def test_double_authentication_ele_v2x(
    tmpdir: str,
    family: str,
    revision: str,
    iae_cls: type[ImageArrayEntry],
    version: int,
    container_size: int,
    v2x_tag: int,
    with_v2x: bool,
) -> None:
    """Test extraction of ELE and V2X firmware for V1 and V2 NXP containers."""
    nxp_image = _nxp_image(version, container_size, v2x_tag if with_v2x else None)
    file_name = os.path.join(tmpdir, "nxp_fw.img")
    with open(file_name, "wb") as f:
        f.write(nxp_image)
    chip_config = AhabChipContainerConfig(
        base=create_chip_config(family=FamilyRevision(family, revision))
    )
    entries = IaeDoubleAuthentication.create_image_array_entry(
        iae_cls, chip_config, Config({IaeDoubleAuthentication.KEY: file_name})
    )

    assert len(entries) == (2 if with_v2x else 1)
    ele = entries[0]
    assert ele.flags_image_type_name == "ele_as_image"
    assert ele.image[:container_size] == nxp_image[:container_size]
    assert ele.image[container_size : 4 * container_size] == bytes(3 * container_size)
    assert ele.image[4 * container_size :] == b"\xe1" * 0x200
    if with_v2x:
        v2x = entries[1]
        assert v2x.flags_image_type_name == "v2x_as_image"
        assert v2x.flags_core_id_name == "v2x-1"
        assert v2x.image == nxp_image[container_size : 5 * container_size + 0x400]


def test_double_authentication_v2_ignores_v1_v2x_tag(tmpdir: str) -> None:
    """Test that V2 ELE container does not pick V2X container with classic V1 offsets."""
    nxp_image = _nxp_image(2, 0x4000, None)
    nxp_image = nxp_image[:0x400] + _container(0, 0x87, [(0x200, 0x200)]) + nxp_image[0x490:]
    file_name = os.path.join(tmpdir, "nxp_fw.img")
    with open(file_name, "wb") as f:
        f.write(nxp_image)
    chip_config = AhabChipContainerConfig(base=create_chip_config(family=FamilyRevision("mimx943")))
    entries = IaeDoubleAuthentication.create_image_array_entry(
        ImageArrayEntryV2, chip_config, Config({IaeDoubleAuthentication.KEY: file_name})
    )
    assert len(entries) == 1


def test_double_authentication_version_mismatch(tmpdir: str) -> None:
    """Test that V2 NXP firmware cannot be used in V1 OEM container."""
    file_name = os.path.join(tmpdir, "nxp_fw.img")
    with open(file_name, "wb") as f:
        f.write(_nxp_image(2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag))
    chip_config = AhabChipContainerConfig(
        base=create_chip_config(family=FamilyRevision("mimx9596", "b0"))
    )
    with pytest.raises(SPSDKError, match="Invalid NXP container version"):
        IaeDoubleAuthentication.create_image_array_entry(
            ImageArrayEntry, chip_config, Config({IaeDoubleAuthentication.KEY: file_name})
        )

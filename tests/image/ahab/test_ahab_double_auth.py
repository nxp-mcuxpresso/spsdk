#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for AHAB double authentication image array entry template."""

import os
from pathlib import Path
from struct import pack

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_container import AHABContainerV2
from spsdk.image.ahab.ahab_data import (
    AhabChipContainerConfig,
    AHABTags,
    FlagsSrkSet,
    create_chip_config,
)
from spsdk.image.ahab.ahab_iae import (
    IaeDoubleAuthentication,
    ImageArrayEntry,
    ImageArrayEntryTemplates,
    ImageArrayEntryV2,
)
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.utils import _is_v2x_container, ahab_sign_image
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import SegmentAhab
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

KEYS_DIR = Path(__file__).resolve().parents[2] / "_data" / "keys" / "ecc256"


def _container(version: int, tag: int, image_entries: list[tuple[int, int]]) -> bytes:
    """Create minimal container header followed by image array entries (offset, size)."""
    header = pack("<BHB", version, 0x10 + 0x80 * len(image_entries), tag)
    header += pack("<LHBBHH", 0, 0, 0, len(image_entries), 0, 0)  # cspell:disable-line
    for offset, size in image_entries:
        # cspell:disable-next-line
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
    assert ele.load_address == ele.entry_point == 0x1FFC0000
    if with_v2x:
        v2x = entries[1]
        assert v2x.flags_image_type_name == "v2x_as_image"
        assert v2x.flags_core_id_name == "v2x-1"
        assert v2x.image == nxp_image[container_size : 5 * container_size + 0x400]
        assert v2x.load_address == v2x.entry_point == 0x8B000000


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


def _write(tmpdir: str, name: str, data: bytes) -> str:
    """Write binary file into temporary directory and return its path."""
    file_name = os.path.join(tmpdir, name)
    with open(file_name, "wb") as f:
        f.write(data)
    return file_name


def test_double_authentication_load_address_override(tmpdir: str) -> None:
    """Test that ELE and V2X container load addresses can be overridden separately."""
    file_name = _write(
        tmpdir, "nxp_fw.img", _nxp_image(2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag)
    )
    chip_config = AhabChipContainerConfig(base=create_chip_config(family=FamilyRevision("mimx943")))
    config = Config(
        {
            IaeDoubleAuthentication.KEY: file_name,
            "ele_load_address": "0x2001_0000",
            "v2x_load_address": 0x8C000000,
        }
    )
    ele, v2x = IaeDoubleAuthentication.create_image_array_entry(
        ImageArrayEntryV2, chip_config, config
    )
    assert ele.load_address == ele.entry_point == 0x20010000
    assert v2x.load_address == v2x.entry_point == 0x8C000000
    assert "load_address" not in config


@pytest.mark.parametrize(
    "extra,match",
    [
        ({"ele_load_address": 0}, "ELE container load address"),
        ({"v2x_load_address": 0}, "V2X container load address"),
        ({"load_address": 0x1FFC0000}, "'load_address' is not supported"),
        ({"entry_point": 0x1FFC0000}, "'entry_point' is not supported"),
    ],
)
def test_double_authentication_invalid_load_address(
    tmpdir: str, extra: dict[str, int], match: str
) -> None:
    """Test that missing or common load address of ELE/V2X container is rejected."""
    file_name = _write(
        tmpdir, "nxp_fw.img", _nxp_image(2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag)
    )
    chip_config = AhabChipContainerConfig(base=create_chip_config(family=FamilyRevision("mimx943")))
    with pytest.raises(SPSDKError, match=match):
        IaeDoubleAuthentication.create_image_array_entry(
            ImageArrayEntryV2,
            chip_config,
            Config({IaeDoubleAuthentication.KEY: file_name, **extra}),
        )


@pytest.mark.parametrize("family", ["mimx943", "mimx95294"])
def test_double_authentication_v2x_after_oei_ddr(tmpdir: str, family: str) -> None:
    """Test that V2X container loaded into DDR is placed after the OEI DDR image."""
    chip_config = AhabChipContainerConfig(base=create_chip_config(family=FamilyRevision(family)))
    config = [
        Config(
            {
                IaeDoubleAuthentication.KEY: _write(
                    tmpdir,
                    "nxp_fw.img",
                    _nxp_image(2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag),
                )
            }
        ),
        Config(
            {
                "oei_ddr": _write(tmpdir, "oei.bin", b"\x01" * 0x100),
                "lpddr_imem": _write(tmpdir, "imem.bin", b"\x02" * 0x100),
                "lpddr_dmem": _write(tmpdir, "dmem.bin", b"\x03" * 0x100),
                "lpddr_imem_qb": _write(tmpdir, "imem_qb.bin", b"\x04" * 0x100),
                "lpddr_dmem_qb": _write(tmpdir, "dmem_qb.bin", b"\x05" * 0x100),
            }
        ),
        Config({"system_manager": _write(tmpdir, "sm.bin", b"\x06" * 0x100)}),
    ]
    entries = ImageArrayEntryTemplates.create_image_array_entries(
        ImageArrayEntryV2, chip_config, config
    )
    assert [entry.flags_image_type_name for entry in entries] == [
        "ele_as_image",
        "oei",
        "oei_ddr",
        "v2x_as_image",
        "executable",
    ]
    # OEI DDR header positions (QB data first) are relative to the OEI DDR template start
    assert [entry.iae_header_position for entry in entries] == [None, 2, 1, None, None]


@pytest.mark.parametrize(
    "images,is_v2x",
    [
        ([("ele", "ele_as_image"), ("v2x-1", "v2x_as_image")], False),
        ([("ele", "ele_as_image"), ("v2x-1", "v2x_as_image"), ("cortex-m33", "executable")], False),
        ([("cortex-m33", "executable"), ("cortex-a55", "executable")], False),
        ([("v2x-1", "v2x_primary"), ("v2x-2", "v2x_secondary")], True),
        ([("v2x-1", "v2x_rom_patch")], True),
        ([("ele", "ele_as_image"), ("v2x-1", "v2x_as_image"), ("v2x-2", "v2x_secondary")], True),
    ],
)
def test_is_v2x_container(images: list[tuple[str, str]], is_v2x: bool) -> None:
    """Test that only the container with V2X firmware is detected as V2X container.

    The V2X image embedded as an OEM image (double authentication) must not make
    the OEM container a V2X container.
    """
    chip_config = AhabChipContainerConfig(base=create_chip_config(family=FamilyRevision("mimx943")))
    entries = [
        ImageArrayEntryTemplates._create_image_array_entry(
            ImageArrayEntryV2,
            b"\x01" * 0x10,
            chip_config,
            Config({"core_id": core_id, "image_type": image_type, "load_address": 0x1000}),
        )
        for core_id, image_type in images
    ]
    container = AHABContainerV2(chip_config=chip_config.base, image_array=entries)
    assert _is_v2x_container(container) is is_v2x


@pytest.mark.parametrize("family", ["mimx943", "mimx95294"])
def test_double_authentication_container_is_signed(tmpdir: str, family: str) -> None:
    """Test that the OEM container with embedded ELE and V2X containers is signed."""
    config = Config(
        {
            "family": family,
            "revision": "latest",
            "target_memory": "serial_downloader",
            "output": os.path.join(tmpdir, "spl.bin"),
            "containers": [
                {
                    "container": {
                        "srk_set": "none",
                        "images": [
                            {
                                "double_authentication": _write(
                                    tmpdir,
                                    "nxp_fw.img",
                                    _nxp_image(2, 0x4000, AHABTags.CONTAINER_HEADER_V1_WITH_V2.tag),
                                )
                            },
                            {"system_manager": _write(tmpdir, "sm.bin", b"\x06" * 0x100)},
                        ],
                    }
                }
            ],
        }
    )
    config.config_dir = tmpdir
    ahab = AHABImage.load_from_config(config)
    ahab.update_fields()
    image_path = _write(tmpdir, "flash.bin", ahab.export())
    assert [c.flag_srk_set for c in ahab.ahab_containers] == [FlagsSrkSet.NONE]
    assert "v2x_as_image" in [i.flags_image_type_name for i in ahab.ahab_containers[0].image_array]

    sign_config = Config(
        {
            "family": family,
            "revision": "latest",
            "srk_set": "oem",
            "used_srk_id": 0,
            "signer": str(KEYS_DIR / "srk0_ecc256.pem"),
            "srk_table": {
                "srk_array": [str(KEYS_DIR / f"srk{i}_ecc256.pub") for i in range(4)],
            },
        }
    )
    signed, _ = ahab_sign_image(image_path, sign_config, "serial_downloader", 0)

    signed_bimg = BootableImage.parse(signed, family=FamilyRevision(family))
    containers = [
        container
        for segment in signed_bimg.segments
        if isinstance(segment, SegmentAhab) and segment.ahab is not None
        for container in segment.ahab.ahab_containers
    ]
    assert len(containers) == 1
    assert containers[0].flag_srk_set == FlagsSrkSet.OEM
    assert containers[0].signature_block is not None
    assert containers[0].signature_block.signature is not None

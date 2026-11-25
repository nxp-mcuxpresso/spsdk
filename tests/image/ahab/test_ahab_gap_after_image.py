#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of preserving the data stored in the gaps between AHAB images."""

import json
import logging
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from spsdk.image.ahab.ahab_iae import ImageArrayEntry
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.utils import _keep_gaps_behind_grown_images, ahab_sign_image
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

FAMILY = "mimx95294"
KEYS_DIR = Path(__file__).resolve().parents[2] / "_data" / "keys" / "ecc256"
GAP_SIZE = 0x400
GAP_PAYLOAD = bytes(range(1, 0x41))


def _write(directory: str, name: str, data: bytes) -> str:
    """Write the data to the file in directory and return its path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _container_config(images: list[dict[str, Any]]) -> dict[str, Any]:
    """Create configuration of unsigned AHAB container with the images."""
    return {"container": {"srk_set": "none", "images": images}}


def _create_ahab(
    directory: str, containers: list[dict[str, Any]], target_memory: str = "serial_downloader"
) -> AHABImage:
    """Create updated AHAB image from the containers configuration."""
    config = Config(
        {
            "family": FAMILY,
            "revision": "latest",
            "target_memory": target_memory,
            "output": os.path.join(directory, "ahab.bin"),
            "containers": containers,
        }
    )
    config.config_dir = directory
    ahab = AHABImage.load_from_config(config)
    ahab.update_fields()
    return ahab


def _image_with_gap(directory: str) -> dict[str, Any]:
    """Create image entry with the gap prefilled from file."""
    return {
        "system_manager": _write(directory, "sm.bin", b"\x06" * 0x100),
        "gap_after_image": GAP_SIZE,
        "gap_after_image_file": _write(directory, "gap.bin", GAP_PAYLOAD),
    }


def _image_after_gap(directory: str) -> dict[str, Any]:
    """Create image entry that follows the gap."""
    return {"atf": _write(directory, "atf.bin", b"\xa7" * 0x100)}


def _ahab_with_gap(directory: str) -> AHABImage:
    """Create AHAB image with one container holding an image with the gap and an image behind it."""
    return _create_ahab(
        directory,
        [_container_config([_image_with_gap(directory), _image_after_gap(directory)])],
    )


def _images(ahab: AHABImage) -> list[ImageArrayEntry]:
    """Get the mutable image array of the first container."""
    return cast(list[ImageArrayEntry], ahab.ahab_containers[0].image_array)


def test_parse_restores_gap_after_image(tmpdir: str) -> None:
    """Test the parsed AHAB image keeps the content of the gap and exports identical binary."""
    ahab = _ahab_with_gap(tmpdir)
    exported = ahab.export()
    first, second = ahab.ahab_containers[0].image_array
    gap_start = first.image_offset + first.image_size
    assert exported[gap_start : gap_start + len(GAP_PAYLOAD)] == GAP_PAYLOAD

    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))

    parsed_first, parsed_second = parsed.ahab_containers[0].image_array
    # The whole space up to the next image is the gap, without the trailing zero padding
    assert parsed_first.gap_after_image == second.image_offset - gap_start
    assert parsed_first.gap_after_image_binary == GAP_PAYLOAD
    # The gap behind the last image is not known
    assert parsed_second.gap_after_image == 0
    assert parsed_second.gap_after_image_binary == b""
    assert parsed.export() == exported


def test_parse_restores_gap_across_containers(tmpdir: str) -> None:
    """Test the gap behind the last image of a container reaches the next container image."""
    ahab = _create_ahab(
        tmpdir,
        [
            _container_config([_image_with_gap(tmpdir)]),
            _container_config([_image_after_gap(tmpdir)]),
        ],
    )
    exported = ahab.export()

    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))

    assert len(parsed.ahab_containers) == 2
    assert parsed.ahab_containers[0].image_array[0].gap_after_image_binary == GAP_PAYLOAD
    assert parsed.export() == exported


def test_parse_without_gap_payload_keeps_no_gap_binary(tmpdir: str) -> None:
    """Test the gap containing only padding does not produce any gap payload."""
    image = _image_with_gap(tmpdir)
    image.pop("gap_after_image_file")
    ahab = _create_ahab(tmpdir, [_container_config([image, _image_after_gap(tmpdir)])])
    exported = ahab.export()

    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))

    assert parsed.ahab_containers[0].image_array[0].gap_after_image_binary == b""
    assert parsed.export() == exported


def test_parse_erased_gap_keeps_no_gap_binary(tmpdir: str) -> None:
    """Test the gap filled by the erased pattern of the target memory is taken as padding."""
    image = _image_with_gap(tmpdir)
    image.pop("gap_after_image_file")
    ahab = _create_ahab(
        tmpdir, [_container_config([image, _image_after_gap(tmpdir)])], target_memory="nor"
    )
    first, second = ahab.ahab_containers[0].image_array
    gap_start = first.image_offset + first.image_size
    data = bytearray(ahab.export())
    data[gap_start : second.image_offset] = b"\xff" * (second.image_offset - gap_start)

    parsed = AHABImage.parse(bytes(data), family=FamilyRevision(FAMILY), target_memory="nor")

    assert parsed.ahab_containers[0].image_array[0].gap_after_image == (
        second.image_offset - gap_start
    )
    assert parsed.ahab_containers[0].image_array[0].gap_after_image_binary == b""


def test_ahab_sign_image_keeps_gap_after_image(tmpdir: str) -> None:
    """Test signing of already exported image keeps the data stored in the gap."""
    ahab = _ahab_with_gap(tmpdir)
    first = ahab.ahab_containers[0].image_array[0]
    gap_start = first.image_offset + first.image_size
    image_path = _write(tmpdir, "flash.bin", ahab.export())
    sign_config = Config(
        {
            "family": FAMILY,
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

    assert signed[gap_start : gap_start + len(GAP_PAYLOAD)] == GAP_PAYLOAD
    assert signed[gap_start + len(GAP_PAYLOAD) : gap_start + GAP_SIZE] == bytes(
        GAP_SIZE - len(GAP_PAYLOAD)
    )
    signed_ahab = AHABImage.parse(signed, family=FamilyRevision(FAMILY))
    assert signed_ahab.ahab_containers[0].signature_block is not None
    assert signed_ahab.ahab_containers[0].signature_block.signature is not None


def test_parse_config_export_keeps_gap_after_image(tmpdir: str) -> None:
    """Test the configuration of the parsed image rebuilds the image including the gap data."""
    exported = _ahab_with_gap(tmpdir).export()
    data_dir = os.path.join(tmpdir, "parsed")
    os.makedirs(data_dir)
    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))

    # Load the configuration the same way as from the stored file
    config = Config(json.loads(json.dumps(parsed.get_config(data_path=data_dir))))
    config.config_dir = data_dir
    config.search_paths = [data_dir]

    images_cfg = config["containers"][0]["container"]["images"]
    assert "gap_after_image" in images_cfg[0]
    assert "gap_after_image_file" in images_cfg[0]
    assert "gap_after_image" not in images_cfg[1]
    rebuilt = AHABImage.load_from_config(config)
    rebuilt.update_fields()
    assert rebuilt.export() == exported


def test_binary_container_keeps_gap_after_image(tmpdir: str) -> None:
    """Test the AHAB image built from a binary container keeps the gap data of the container."""
    exported = _ahab_with_gap(tmpdir).export()
    config = Config(
        {
            "family": FAMILY,
            "revision": "latest",
            "target_memory": "serial_downloader",
            "output": os.path.join(tmpdir, "ahab.bin"),
            "containers": [{"binary_container": {"path": _write(tmpdir, "cnt.bin", exported)}}],
        }
    )
    config.config_dir = tmpdir

    ahab = AHABImage.load_from_config(config)
    ahab.update_fields()

    assert ahab.ahab_containers[0].image_array[0].gap_after_image_binary == GAP_PAYLOAD
    assert ahab.export() == exported


def test_grown_image_keeps_gap_data_at_original_offset(
    tmpdir: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Test the image growing into the gap shortens the gap and keeps the rest of the data."""
    exported = _ahab_with_gap(tmpdir).export()
    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))
    container = parsed.ahab_containers[0]
    original_container = deepcopy(container)
    first, second = _images(parsed)
    gap_start = first.image_offset + first.image_size
    growth = 8
    first.image = first.image + b"\xee" * growth
    container.update_fields()
    assert first.image_size == original_container.image_array[0].image_size + growth

    with caplog.at_level(logging.WARNING):
        _keep_gaps_behind_grown_images(original_container, container)

    assert "overwrites the data stored in the gap" in caplog.text
    assert first.image_offset + first.image_size + first.gap_after_image == second.image_offset
    parsed.image_info().validate()
    updated = parsed.export()
    assert updated[gap_start + growth : gap_start + len(GAP_PAYLOAD)] == GAP_PAYLOAD[growth:]
    assert updated[second.image_offset :] == exported[second.image_offset :]


def test_parse_overlapping_images_assign_gap_once(tmpdir: str) -> None:
    """Test the gap is assigned to the image reaching the furthest when images overlap."""
    exported = _ahab_with_gap(tmpdir).export()
    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))
    first, second = _images(parsed)
    gap = first.gap_after_image
    # Nested image placed in the middle of the first one must not take over the gap
    nested = deepcopy(first)
    nested.image_size = 0x10
    nested.image_offset = first.image_offset + 0x10
    _images(parsed).insert(1, nested)

    parsed._restore_gaps_after_images(  # pylint: disable=protected-access
        exported, parsed.ahab_containers
    )

    assert first.gap_after_image == gap
    assert first.gap_after_image_binary == GAP_PAYLOAD
    assert nested.gap_after_image == 0
    assert nested.gap_after_image_binary == b""

    # Image starting inside the first one and reaching behind it owns the rest of the gap
    nested.image_size = first.image_size
    parsed._restore_gaps_after_images(  # pylint: disable=protected-access
        exported, parsed.ahab_containers
    )

    nested_end = nested.image_offset + nested.image_size
    assert first.gap_after_image == 0
    assert first.gap_after_image_binary == b""
    assert nested.gap_after_image == second.image_offset - nested_end
    assert nested.gap_after_image_binary == exported[nested_end : second.image_offset].rstrip(
        b"\x00"
    )


def test_parse_ignores_empty_and_negative_images(tmpdir: str) -> None:
    """Test the empty images and images placed before the data do not own any gap."""
    exported = _ahab_with_gap(tmpdir).export()
    parsed = AHABImage.parse(exported, family=FamilyRevision(FAMILY))
    first = _images(parsed)[0]
    # Empty image placed at the container header, e.g. a dummy image entry
    empty = deepcopy(first)
    empty.image_size = 0
    empty.image_offset = 0
    # Image placed before the AHAB image data, possible with the signed image offsets
    negative = deepcopy(first)
    negative.image_offset = -0x1000
    _images(parsed).extend([empty, negative])

    parsed._restore_gaps_after_images(  # pylint: disable=protected-access
        exported, parsed.ahab_containers
    )

    assert first.gap_after_image_binary == GAP_PAYLOAD
    for image in (empty, negative):
        assert image.gap_after_image == 0
        assert image.gap_after_image_binary == b""

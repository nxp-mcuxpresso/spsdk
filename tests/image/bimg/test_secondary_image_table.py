#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""RT266x SD/eMMC secondary-image table and bootable-image integration tests."""

from pathlib import Path
from struct import pack

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import BootableImageSegment, SegmentSecondaryImageTable
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.mem_type import MemoryType
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from tests.cli_runner import CliRunner

TABLE = bytes.fromhex("00000000 00000000 33221100 00100000 00000000")
FAMILIES = ["mimxrt2660", "mimxrt2661", "mimxrt2662", "mimxrt2663"]


@pytest.fixture
def segment() -> SegmentSecondaryImageTable:
    """Create an empty secondary-image table segment."""
    return SegmentSecondaryImageTable(0x200, FamilyRevision("mimxrt2660"), MemoryType.SD)


@pytest.mark.parametrize("sector", [1, 4096, "0x1000", 0xFFFFFFFF])
def test_secondary_table_config(segment: SegmentSecondaryImageTable, sector: int | str) -> None:
    """Generate the five little-endian words and convert sectors without truncation."""
    number = int(sector, 0) if isinstance(sector, str) else sector
    segment.load_config(Config({"secondary_image_table": {"first_sector_number": sector}}))
    assert segment.size == 20
    assert segment.export() == pack("<5I", 0, 0, 0x00112233, number, 0)
    assert segment.secondary_image_offset == number * 512
    assert segment.create_config("") == {"first_sector_number": number}
    segment.verify().validate()


@pytest.mark.parametrize("value", [0, -1, 0x100000000, "0x100000000", "invalid", 1.5, True])
def test_secondary_table_bad_sector(
    segment: SegmentSecondaryImageTable, value: int | str | float | bool
) -> None:
    """Reject invalid or out-of-range sector values through the API."""
    with pytest.raises(SPSDKError):
        segment.load_config(Config({"secondary_image_table": {"first_sector_number": value}}))


@pytest.mark.parametrize("value", [{}, 0, False, [], {"wrong_field": 4096}])
def test_secondary_table_bad_config(segment: SegmentSecondaryImageTable, value: object) -> None:
    """Malformed explicit configuration must not silently omit the table."""
    with pytest.raises(SPSDKError) as exc:
        segment.load_config(Config({"secondary_image_table": value}))
    assert not isinstance(exc.value, SPSDKSegmentNotPresent)


@pytest.mark.parametrize("config", [{}, {"secondary_image_table": ""}])
def test_secondary_table_omitted(segment: SegmentSecondaryImageTable, config: dict) -> None:
    """Omitted tables leave primary-only images untouched."""
    with pytest.raises(SPSDKSegmentNotPresent):
        segment.load_config(Config(config))
    assert segment.export() == b""
    assert segment.create_config("") == ""
    with pytest.raises(SPSDKError, match="not present"):
        _ = segment.secondary_image_offset


@pytest.mark.parametrize("padding", [bytes(20), b"\xff" * 20])
def test_secondary_table_padding(segment: SegmentSecondaryImageTable, padding: bytes) -> None:
    """Both zero and erased padding in a full boot image mean no table."""
    segment.pre_parse_verify(padding).validate()
    with pytest.raises(SPSDKSegmentNotPresent):
        segment.parse_binary(padding + b"following image data")


@pytest.mark.parametrize(
    "data",
    [b"", TABLE[:19], pack("<5I", 0, 0, 0x33221100, 4096, 0), pack("<5I", 0, 0, 0x112233, 0, 0)],
)
def test_secondary_table_bad_binary(segment: SegmentSecondaryImageTable, data: bytes) -> None:
    """Reject truncation, a wrong tag/endian encoding, and a zero sector pointer."""
    assert segment.pre_parse_verify(data).has_errors
    with pytest.raises(SPSDKParsingError):
        segment.parse_binary(data)


@pytest.mark.parametrize("data", [TABLE[:19], TABLE + b"\0", bytes(20), b"\xff" * 20])
def test_secondary_table_binary_file_validation(
    segment: SegmentSecondaryImageTable, tmp_path: Path, data: bytes
) -> None:
    """An explicitly supplied binary must contain exactly one valid table."""
    path = tmp_path / "table.bin"
    path.write_bytes(data)
    with pytest.raises(SPSDKError):
        segment.load_config(Config({"secondary_image_table": str(path)}))


@pytest.mark.parametrize("reserved", [(0, 0, 0), (1, 2, 3)])
def test_secondary_table_roundtrip(
    segment: SegmentSecondaryImageTable, tmp_path: Path, reserved: tuple[int, int, int]
) -> None:
    """Preserve all five words, including reserved values in imported tables."""
    data = pack("<5I", reserved[0], reserved[1], 0x112233, 4096, reserved[2])
    segment.parse_binary(data + b"following data")
    assert segment.export() == data
    value = segment.create_config(str(tmp_path))
    if any(reserved):
        assert value == "segment_secondary_image_table.bin"
        value = str(tmp_path / value)
    config = Config({"family": "mimxrt2660", "memory_type": "sd", "secondary_image_table": value})
    config.check(BootableImage.get_validation_schemas(FamilyRevision("mimxrt2660"), MemoryType.SD))
    segment.clear()
    segment.load_config(config)
    assert segment.export() == data


@pytest.fixture
def ahab_binary(tmp_path: Path) -> bytes:
    """Build a real unsigned RT2660 AHAB image for layout/parse/CLI tests."""
    payload = tmp_path / "application.bin"
    payload.write_bytes(bytes(range(256)) * 2)
    config = Config(
        {
            "family": "mimxrt2660",
            "target_memory": "sd_emmc",
            "containers": [
                {
                    "container": {
                        "srk_set": "none",
                        "images": [
                            {
                                "image_path": str(payload),
                                "core_id": "cortex-m85",
                                "image_type": "executable",
                                "load_address": 0x22080000,
                                "entry_point": 0x22080000,
                            }
                        ],
                    }
                }
            ],
        }
    )
    ahab = AHABImage.load_from_config(config)
    ahab.update_fields()
    ahab.verify().validate()
    return ahab.export()


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("memory", [MemoryType.SD, MemoryType.EMMC])
def test_rt266x_secondary_table_layout(
    family: str, memory: MemoryType, tmp_path: Path, ahab_binary: bytes
) -> None:
    """Exercise exact offsets, primary-only compatibility, and full image round-trip."""
    path = tmp_path / "ahab.bin"
    path.write_bytes(ahab_binary)
    config = Config({"family": family, "memory_type": memory.label, "ahab_container": str(path)})
    primary = BootableImage.load_from_config(config)
    assert primary.export() == bytes(0x800) + ahab_binary
    BootableImage.parse(primary.export(), FamilyRevision(family), memory).verify().validate()
    config["secondary_image_table"] = {"first_sector_number": 4096}
    config.check(BootableImage.get_validation_schemas(FamilyRevision(family), memory))
    image = BootableImage.load_from_config(config)
    offsets = {seg.NAME.label: seg.full_image_offset for seg in image._segments}
    assert offsets == {"secondary_image_table": 0x200, "xmcd": 0x400, "ahab_container": 0x800}
    binary = image.export()
    assert binary == bytes(0x200) + TABLE + bytes(0x800 - 0x200 - len(TABLE)) + ahab_binary
    image.verify().validate()
    BootableImage.pre_parse_verify(binary, FamilyRevision(family), memory).validate()
    parsed = BootableImage.parse(binary, FamilyRevision(family), memory)
    parsed_config = parsed.get_config(str(tmp_path))
    parsed_config.search_paths = [str(tmp_path)]
    # Preserve the extracted AHAB binary; AHAB YAML hash-name casing is outside this feature.
    parsed_config["ahab_container"] = str(tmp_path / "segment_ahab_container.bin")
    parsed_config.check(parsed.get_validation_schemas(parsed.family, memory))
    assert parsed_config["secondary_image_table"] == {"first_sector_number": 4096}
    assert BootableImage.load_from_config(parsed_config).export() == binary


@pytest.mark.parametrize("initial_offset", [0x400, 0x800])
def test_secondary_table_initial_offset(
    initial_offset: int, ahab_binary: bytes, tmp_path: Path
) -> None:
    """Excluded tables must not shift remaining segments in partial images."""
    path = tmp_path / "ahab.bin"
    path.write_bytes(ahab_binary)
    config = Config(
        {
            "family": "mimxrt2660",
            "memory_type": "sd",
            "init_offset": initial_offset,
            "secondary_image_table": {"first_sector_number": 4096},
            "ahab_container": str(path),
        }
    )
    image = BootableImage.load_from_config(config)
    assert all(s.NAME != BootableImageSegment.SECONDARY_IMAGE_TABLE for s in image.segments)
    assert image.export() == bytes(0x800 - initial_offset) + ahab_binary
    assert image.get_config(str(tmp_path))["secondary_image_table"] == ""
    parsed = BootableImage(FamilyRevision("mimxrt2660"), MemoryType.SD, initial_offset)
    parsed._parse(image.export())
    parsed.verify().validate()
    assert parsed.init_offset == initial_offset
    assert parsed.export() == image.export()


def test_secondary_table_corrupt_full_image(ahab_binary: bytes) -> None:
    """A malformed table must not be silently discarded by bootable-image parsing."""
    binary = bytes(0x200) + b"\x01" * 20 + bytes(0x800 - 0x214) + ahab_binary
    assert BootableImage.pre_parse_verify(
        binary, FamilyRevision("mimxrt2660"), MemoryType.SD
    ).has_errors
    with pytest.raises(SPSDKError, match="secondary-image table"):
        BootableImage.parse(binary, FamilyRevision("mimxrt2660"), MemoryType.SD)


def test_secondary_table_raw_verification(segment: SegmentSecondaryImageTable) -> None:
    """Verify must reject malformed tables injected through the raw-block API."""
    segment.raw_block = BinaryImage("invalid table", binary=b"\x01" * 20)
    assert segment.verify().has_errors


@pytest.mark.parametrize("memory", [MemoryType.SD, MemoryType.EMMC])
def test_secondary_table_cli(
    memory: MemoryType, tmp_path: Path, cli_runner: CliRunner, ahab_binary: bytes
) -> None:
    """Expose optional templates and exercise CLI export, verification, and parsing."""
    family = FamilyRevision("mimxrt2660")
    template = yaml.safe_load(BootableImage.get_config_template(family, memory))
    assert template["secondary_image_table"] == ""
    ahab_path = tmp_path / "ahab.bin"
    ahab_path.write_bytes(ahab_binary)
    config_path = tmp_path / "config.yaml"
    output = tmp_path / "boot.bin"
    config_path.write_text(
        yaml.safe_dump(
            {
                "family": family.name,
                "memory_type": memory.label,
                "secondary_image_table": {"first_sector_number": "0x1000"},
                "ahab_container": str(ahab_path),
                "output": str(output),
            }
        )
    )
    cli_runner.invoke(nxpimage.main, ["bootable-image", "export", "-c", str(config_path)])
    assert output.read_bytes()[0x200:0x214] == TABLE
    cli_runner.invoke(
        nxpimage.main,
        ["bootable-image", "verify", "-f", family.name, "-m", memory.label, "-b", str(output)],
    )
    cli_runner.invoke(
        nxpimage.main,
        [
            "bootable-image",
            "parse",
            "-f",
            family.name,
            "-m",
            memory.label,
            "-b",
            str(output),
            "-o",
            str(tmp_path / "parsed"),
        ],
    )

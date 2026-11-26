#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Bootable image on-the-fly encryption regression tests."""

import json
from pathlib import Path
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import SegmentKeyBlob
from spsdk.image.iee.iee import Iee
from spsdk.image.iped.iped import IpedMode, IpedV1, IpedV2
from spsdk.image.otfad.otfad import Otfad
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from tests.cli_runner import CliRunner


def encryption_config(engine: str) -> dict[str, Any]:
    """Build deterministic encryption settings with a single active region.

    :param engine: Encryption engine name.
    :return: Standalone encryption configuration.
    """
    base = 0x30000000
    config: dict[str, Any] = {"family": "mimxrt1176", "output_folder": "artifacts"}
    if engine == "otfad":
        config.update(
            otfad_table_address=base,
            kek="000102030405060708090a0b0c0d0e0f",
            key_blobs=[
                {
                    "aes_key": "0x000102030405060708090a0b0c0d0e0f",
                    "aes_ctr": "0x0011223344556677",
                    "start_address": base + 0x2000,
                    "end_address": base + 0x2FFF,
                }
            ],
        )
    elif engine == "iee":
        config.update(
            keyblob_address=base,
            ibkek1="0x" + bytes(range(32)).hex(),
            ibkek2="0x" + bytes(range(32, 64)).hex(),
            key_blobs=[
                {
                    "aes_mode": "AesXTS",
                    "key_size": "CTR128XTS256",
                    "key1": "0x000102030405060708090a0b0c0d0e0f",
                    "key2": "0x202122232425262728292a2b2c2d2e2f",
                    "start_address": base + 0x2000,
                    "end_address": base + 0x3000,
                }
            ],
        )
    elif engine == "iped_v1":
        base = 0x28000000
        config.update(
            family="mimx943",
            keyblob_address=base,
            user_key="0x000102030405060708090a0b0c0d0e0f",
            regions=[
                {
                    "region_id": 4,
                    "start_address": base + 0x2000,
                    "end_address": base + 0x3000,
                    "nonce": "0x0011223344556677",
                }
            ],
        )
    else:
        config.update(
            family="mimxrt2661",
            keyblob_address=0x60000000,
            contexts=[
                {
                    "start_address": 0x60002000,
                    "end_address": 0x60003000,
                    "mode": "ctr",
                    "nonce": "0x0011223344556677",
                    "iv": "0x0001020304050607",
                    "key": "0x00000000000000000000000000000001",
                }
            ],
        )
    return config


def bootable_config(tmp_path: Path, engine_config: dict[str, Any]) -> Config:
    """Write a referenced encryption configuration in a nested directory.

    :param tmp_path: Temporary test directory.
    :param engine_config: Encryption settings.
    :return: Bootable configuration with relative paths.
    """
    nested = tmp_path / "configs"
    nested.mkdir(exist_ok=True)
    (nested / "encryption.json").write_text(json.dumps(engine_config), encoding="utf-8")
    (tmp_path / "app.bin").write_bytes(bytes(range(256)) * 33)
    app_name = {
        "mimxrt1176": "hab_container",
        "mimx943": "primary_image_container_set",
        "mimxrt2661": "ahab_container",
    }[engine_config["family"]]
    config_path = tmp_path / "bootable.json"
    config_path.write_text(
        json.dumps(
            {
                "family": engine_config["family"],
                "memory_type": (
                    "xspi_nor" if engine_config["family"] == "mimxrt2661" else "flexspi_nor"
                ),
                "keyblob": str(Path("configs") / "encryption.json"),
                app_name: "app.bin",
                "output": "bootable.bin",
            }
        ),
        encoding="utf-8",
    )
    return Config.create_from_file(str(config_path))


def application_segment(image: BootableImage) -> str:
    """Get the application segment name for a test image.

    :param image: Bootable image.
    :return: First application segment name.
    """
    return next(seg.NAME.label for seg in image._segments if not seg.BOOT_HEADER)


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
@pytest.mark.parametrize("init_offset", [0, 0x1000])
def test_bootable_encryption(tmp_path: Path, engine: str, init_offset: int) -> None:
    """Encrypt only configured regions using absolute, untrimmed image addresses."""
    config = bootable_config(tmp_path, encryption_config(engine))
    config["init_offset"] = init_offset
    image = BootableImage.load_from_config(config)
    keyblob = next(segment for segment in image._segments if isinstance(segment, SegmentKeyBlob))
    assert isinstance(keyblob, SegmentKeyBlob)
    crypto = keyblob.encryption
    assert crypto is not None
    data = bytes(range(256)) * 33
    app = image.get_segment(application_segment(image))
    app.raw_block = BinaryImage("plaintext", binary=data)
    plain = data[0x1000:0x2000]
    address = keyblob.image_base_address + 0x2000
    if isinstance(crypto, Otfad):
        encrypted = crypto.encrypt_image(plain, address, byte_swap=False)
        table = crypto.encrypt_key_blobs(
            crypto.kek,
            crypto.key_scramble_mask,
            crypto.key_scramble_align,
            crypto.keyblob_byte_swap_cnt,
        )
    elif isinstance(crypto, Iee):
        encrypted = crypto.encrypt_image(plain, address)
        table = crypto.export_key_blobs()
        assert keyblob.size == 384
    elif isinstance(crypto, IpedV1):
        encrypted = crypto.encrypt_data(plain, address)
        table = crypto.export()
    else:
        encrypted = crypto.encrypt_image(plain, address)
        table = crypto.export()
    result = image.export()
    offset = 0x1000 - init_offset
    assert result[offset:] == data[:0x1000] + encrypted + data[0x2000:]
    assert encrypted != plain
    assert image.image_info().export() == result
    assert image.export() == result
    assert app.export() == data
    if not init_offset:
        assert result[: len(table)] == table


@pytest.mark.parametrize("engine", ["otfad", "iee"])
def test_bootable_encryption_cli(cli_runner: CliRunner, tmp_path: Path, engine: str) -> None:
    """Exercise CLI loading of relative paths, binary application and encrypted output."""
    config = bootable_config(tmp_path, encryption_config(engine))
    data = bytes(range(256)) * 33
    (tmp_path / "app.bin").write_bytes(data)
    config["hab_container"] = "app.bin"
    config_path = tmp_path / "bootable.json"
    config_path.write_text(json.dumps(dict(config)), encoding="utf-8")
    expected = BootableImage.load_from_config(config).export()
    cli_runner.invoke(nxpimage.main, ["bootable-image", "export", "-c", str(config_path)])
    assert (tmp_path / "bootable.bin").read_bytes() == expected
    assert expected[0x2000:0x3000] != data[0x1000:0x2000]


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_binary_keyblob_does_not_encrypt(tmp_path: Path, engine: str) -> None:
    """Replacing the configuration with its binary table disables encryption."""
    config = bootable_config(tmp_path, encryption_config(engine))
    image = BootableImage.load_from_config(config)
    raw = image.get_segment("keyblob").export()
    (tmp_path / "keyblob.bin").write_bytes(raw)
    config["keyblob"] = "keyblob.bin"
    image = BootableImage.load_from_config(config)
    data = bytes(range(256)) * 33
    image.get_segment(application_segment(image)).raw_block = BinaryImage("app", binary=data)
    assert image.export()[0x1000:] == data
    assert not image.get_segment("keyblob").verify().has_errors


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_keyblob_clear(tmp_path: Path, engine: str) -> None:
    """Clearing a keyblob removes encryption state."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config(engine)))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    keyblob.clear()
    assert keyblob.encryption is None
    assert keyblob.encryption_ranges == []
    assert keyblob.encrypt_image(b"plain", 0) == b"plain"
    with pytest.raises(SPSDKValueError, match="No keyblob encryption"):
        _ = keyblob.image_base_address


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_keyblob_family_mismatch(tmp_path: Path, engine: str) -> None:
    """Reject encryption configurations for another family before loading keys."""
    config = bootable_config(tmp_path, encryption_config(engine))
    config["family"] = "mimxrt595s"
    config["memory_type"] = "flexspi_nor"
    with pytest.raises(SPSDKValueError, match="does not match"):
        BootableImage.load_from_config(config)


@pytest.mark.parametrize("content", ["{broken", '{"family": "mimxrt1176"}'])
def test_invalid_keyblob_config(tmp_path: Path, content: str) -> None:
    """Malformed configurations must not be treated as raw binary keyblobs."""
    config = bootable_config(tmp_path, encryption_config("otfad"))
    (tmp_path / "configs" / "encryption.json").write_text(content, encoding="utf-8")
    with pytest.raises(SPSDKError):
        BootableImage.load_from_config(config)


def test_keyblob_region_overlaps_header(tmp_path: Path) -> None:
    """Reject encryption covering the keyblob or another ROM boot header."""
    settings = encryption_config("otfad")
    settings["key_blobs"][0]["start_address"] = settings["otfad_table_address"]
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    with pytest.raises(SPSDKValueError, match="overlaps boot header keyblob"):
        image.export()


def test_keyblob_overlapping_regions(tmp_path: Path) -> None:
    """Reject ambiguous overlapping encryption contexts."""
    settings = encryption_config("iee")
    settings["key_blobs"].append(dict(settings["key_blobs"][0]))
    with pytest.raises(SPSDKValueError, match="Overlapping"):
        BootableImage.load_from_config(bootable_config(tmp_path, settings))


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_keyblob_nonzero_table_offset(tmp_path: Path, engine: str) -> None:
    """Derive the image base from the table location, not from offset zero."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config(engine)))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    base = keyblob.image_base_address
    keyblob.full_image_offset = 0x100
    assert keyblob.image_base_address == base - 0x100


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_encryption_trailing_padding(tmp_path: Path, engine: str) -> None:
    """Encryption padding is retained at the segment end without mutating plaintext."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config(engine)))
    app = image.get_segment(application_segment(image))
    app.full_image_offset = 0x2000
    data = bytes(range(31))
    app.raw_block = BinaryImage("app", binary=data)
    result = image.image_info()
    assert len(result) >= 0x2020
    assert len(image) == len(result.export())
    assert result.export()[0x2000:] != data
    assert app.export() == data


def test_iped_gcm_expansion(tmp_path: Path) -> None:
    """Keep IPED GCM tags in the output and reject relocation of trailing plaintext."""
    settings = encryption_config("iped_v2")
    settings["contexts"][0]["mode"] = "gcm"
    settings["contexts"][0]["aad"] = "0x0000000000000000"
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, IpedV2)
    app = image.get_segment(application_segment(image))
    app.full_image_offset = 0x2000
    data = bytes(range(64))
    app.raw_block = BinaryImage("app", binary=data)
    expected = keyblob.encryption.encrypt_image(data, 0x60002000)
    assert len(expected) > len(data)
    assert image.export()[0x2000:] == expected
    assert len(image) == 0x2000 + len(expected)
    app.raw_block = BinaryImage("app", binary=bytes(range(256)) * 17)
    with pytest.raises(SPSDKValueError, match="would relocate"):
        image.export()


@pytest.mark.parametrize("engine", ["otfad", "iee", "iped_v1", "iped_v2"])
def test_encrypted_config_roundtrip(tmp_path: Path, engine: str) -> None:
    """Export configuration with matching binary table and ciphertext application."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config(engine)))
    output = tmp_path / "extracted"
    config = image.get_config(str(output))
    config.search_paths = [str(output)]
    rebuilt = BootableImage.load_from_config(config)
    assert rebuilt.export() == image.export()


@pytest.mark.parametrize("output_format", ["bin", "hex", "srec", "sparse"])
def test_encryption_output_formats(
    tmp_path: Path, cli_runner: CliRunner, output_format: str
) -> None:
    """Every CLI output format carries ciphertext, not the original application."""
    config = bootable_config(tmp_path, encryption_config("iee"))
    config["output_format"] = output_format
    config["output"] = "encrypted." + output_format
    path = tmp_path / "export.json"
    path.write_text(json.dumps(dict(config)), encoding="utf-8")
    expected = BootableImage.load_from_config(config).export()
    cli_runner.invoke(nxpimage.main, ["bootable-image", "export", "-c", str(path)])
    actual = BinaryImage.load_binary_image(str(tmp_path / config["output"])).export()
    if output_format in ("hex", "srec"):
        assert actual[:384] == expected[:384]
        assert actual[0x1000:] == expected[0x1000:]
    else:
        assert actual[: len(expected)] == expected
    assert not any(actual[len(expected) :])


def test_otfad_relative_key_path(tmp_path: Path) -> None:
    """Resolve encryption keys against the nested encryption configuration."""
    settings = encryption_config("otfad")
    settings["kek"] = "kek.bin"
    config = bootable_config(tmp_path, settings)
    key = bytes(range(16))
    (tmp_path / "configs" / "kek.bin").write_bytes(key)
    image = BootableImage.load_from_config(config)
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, Otfad)
    assert keyblob.encryption.kek == key


@pytest.mark.parametrize("end_address", [0x30002FFF, 0x30003000])
def test_otfad_end_address_conventions(tmp_path: Path, end_address: int) -> None:
    """Accept both inclusive and boundary-aligned OTFAD region end conventions."""
    settings = encryption_config("otfad")
    settings["key_blobs"][0]["end_address"] = end_address
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    output = image.export()
    assert output[0x3000:] == bytes(range(256))
    assert output[0x2000:0x3000] != bytes(range(256)) * 16


@pytest.mark.parametrize("engine", ["otfad", "iee"])
def test_encryption_post_export(tmp_path: Path, engine: str) -> None:
    """Delegate auxiliary table and fuse artifact generation to the encryption engine."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config(engine)))
    output = tmp_path / "post_export"
    output.mkdir()
    files = image.post_export(str(output))
    assert files
    assert all(Path(path).is_file() for path in files)
    assert image.export()


@pytest.mark.parametrize("engine", ["otfad", "iee"])
def test_disabled_encryption_region(tmp_path: Path, engine: str) -> None:
    """Disabled OTFAD and bypass IEE contexts do not encrypt application bytes."""
    settings = encryption_config(engine)
    if engine == "otfad":
        settings["key_blobs"][0]["aes_decryption_enable"] = False
    else:
        settings["key_blobs"][0]["aes_mode"] = "Bypass"
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    assert image.export()[0x1000:] == bytes(range(256)) * 33


def test_encryption_of_generated_hab(tmp_path: Path) -> None:
    """Encrypt the HAB generated from a referenced configuration, after assembly."""
    config = bootable_config(tmp_path, encryption_config("otfad"))
    config["hab_container"] = str(
        Path(__file__).parents[2]
        / "nxpimage"
        / "data"
        / "bootable_image"
        / "mimxrt1176"
        / "flexspi_nor"
        / "as_yaml"
        / "config_hab.yaml"
    )
    image = BootableImage.load_from_config(config)
    plain = image.get_segment("hab_container").image_info().export()
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    expected = keyblob.encrypt_image(plain, 0x1000)
    assert expected != plain
    assert image.export()[0x1000:] == expected


def test_iee_unaligned_xts_application(tmp_path: Path) -> None:
    """Reject partial XTS data units rather than restarting their tweak mid-sector."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("iee")))
    app = image.get_segment("hab_container")
    app.full_image_offset = 0x2010
    with pytest.raises(SPSDKValueError, match="4 KB boundary"):
        image.export()


def test_otfad_unaligned_region_end(tmp_path: Path) -> None:
    """Reject ranges the table would round up but the encryption API would skip."""
    settings = encryption_config("otfad")
    settings["key_blobs"][0]["end_address"] = 0x30002FF8
    with pytest.raises(SPSDKValueError, match="1 KB boundaries"):
        BootableImage.load_from_config(bootable_config(tmp_path, settings))


def test_iped_gcm_overlaps_next_segment(tmp_path: Path) -> None:
    """Expanding IPED output must not overwrite another application segment."""
    settings = encryption_config("iped_v2")
    settings["contexts"][0]["mode"] = "gcm"
    settings["contexts"][0]["aad"] = "0x0000000000000000"
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    app = image.get_segment("ahab_container")
    app.full_image_offset = 0x2000
    app.raw_block = BinaryImage("app", binary=bytes(range(64)))
    next_app = type(app)(
        offset=0x2040,
        family=image.family,
        mem_type=image.mem_type,
        raw_block=BinaryImage("next", binary=bytes(range(64))),
    )
    image._segments.append(next_app)
    with pytest.raises(SPSDKError, match="overlap"):
        image.export()


def test_iped_rom_config_table_padding(tmp_path: Path) -> None:
    """Pad the IPED ROM configuration table with zeros to the database table size."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("iped_v2")))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, IpedV2)
    table = keyblob.encryption.export()
    table_size = keyblob.encryption.table_size
    assert len(keyblob.export()) == table_size
    assert image.export()[len(table) : table_size] == bytes(table_size - len(table))


def test_otfad_byte_swap(tmp_path: Path) -> None:
    """Apply the family OTFAD byte swap setting to application encryption."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("otfad")))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, Otfad)
    keyblob.encryption.byte_swap = True
    plain = (bytes(range(256)) * 33)[0x1000:0x2000]
    expected = keyblob.encryption.encrypt_image(
        plain, keyblob.image_base_address + 0x2000, byte_swap=True
    )
    assert image.export()[0x2000:0x3000] == expected


def test_iped_bypass_context_not_encrypted(tmp_path: Path) -> None:
    """IPED bypass contexts do not contribute encryption ranges, like IEE and OTFAD."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("iped_v2")))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, IpedV2)
    keyblob.encryption.contexts[0].mode = IpedMode.BYPASS
    assert keyblob.encryption_ranges == []


def test_iee_keyblob_parse_size(tmp_path: Path) -> None:
    """Keep the full IEE keyblob table when parsing an exported bootable image."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("iee")))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)
    assert isinstance(keyblob.encryption, Iee)
    table = keyblob.encryption.export_key_blobs()
    assert len(table) == Iee.IEE_KEY_BLOBS_SIZE
    parsed = SegmentKeyBlob(0, image.family, image.mem_type)
    parsed.parse_binary(image.export())
    assert len(parsed.export()) == len(table)
    assert parsed.export() == table


def test_iee_inclusive_end_address(tmp_path: Path) -> None:
    """Accept an inclusive IEE region end address, as for OTFAD."""
    reference = BootableImage.load_from_config(
        bootable_config(tmp_path, encryption_config("iee"))
    ).export()
    settings = encryption_config("iee")
    settings["key_blobs"][0]["end_address"] = 0x30002FFF
    image = BootableImage.load_from_config(bootable_config(tmp_path, settings))
    output = image.export()
    assert output[0x2000:0x3000] == reference[0x2000:0x3000]
    assert output[0x3000:] == bytes(range(256))


def test_keyblob_region_overlaps_header_init_offset(tmp_path: Path) -> None:
    """Reject encryption covering boot headers even when init_offset trims them."""
    settings = encryption_config("otfad")
    settings["key_blobs"][0]["start_address"] = settings["otfad_table_address"]
    config = bootable_config(tmp_path, settings)
    config["init_offset"] = 0x1000
    image = BootableImage.load_from_config(config)
    with pytest.raises(SPSDKValueError, match="overlaps boot header"):
        image.export()


def test_keyblob_config_not_mapping(tmp_path: Path) -> None:
    """Report a YAML scalar keyblob configuration as an invalid keyblob configuration."""
    config = bootable_config(tmp_path, encryption_config("otfad"))
    (tmp_path / "configs" / "encryption.json").write_text('"keyblob"', encoding="utf-8")
    with pytest.raises(SPSDKValueError, match="Cannot load keyblob configuration"):
        BootableImage.load_from_config(config)


def test_encrypted_image_length_does_not_encrypt(tmp_path: Path, monkeypatch: Any) -> None:
    """Calculate encrypted image length without running application encryption."""
    image = BootableImage.load_from_config(bootable_config(tmp_path, encryption_config("otfad")))
    keyblob = image.get_segment("keyblob")
    assert isinstance(keyblob, SegmentKeyBlob)

    def fail_encrypt(*_args: Any, **_kwargs: Any) -> bytes:
        pytest.fail("Image length calculation must not encrypt application data.")

    monkeypatch.setattr(keyblob, "encrypt_image", fail_encrypt)
    app = image.get_segment(application_segment(image))
    assert len(image) == image.get_segment_offset(app) + len(app)

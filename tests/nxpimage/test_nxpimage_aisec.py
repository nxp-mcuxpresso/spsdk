#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for AISEC dir-v5 container commands in nxpimage application."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.apps.nxpimage_apps.nxpimage_aisec import AISEC_MMK_SIZES, _load_key
from spsdk.image.aisec.aisec_dir import AisecDirContainer
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary
from tests.cli_runner import CliRunner

MMK = bytes(range(0x40, 0x60))
SRKH = bytes(range(0xA0, 0xC0))
BLOB = b"\xde\xad\xbe\xef" * 9


@pytest.fixture(name="workspace")
def fixture_workspace(tmp_path: Path) -> Path:
    """Create a model directory, key files and a container configuration."""
    src = tmp_path / "model"
    (src / "sub").mkdir(parents=True)
    (src / "model.onnx").write_bytes(bytes(i & 0xFF for i in range(0x10000 + 5)))
    (src / "config.json").write_bytes(b'{"layers": 3}')
    (src / "sub" / "notes.txt").write_bytes(b"notes")
    (tmp_path / "mmk.bin").write_bytes(MMK)
    (tmp_path / "srkh.txt").write_text(SRKH.hex())
    (tmp_path / "blob.bin").write_bytes(BLOB)
    _write_config(tmp_path, binding=True)
    return tmp_path


def _write_config(
    path: Path, flow: str = "discrete", family: str = "mimx9596", **crypto: Any
) -> Path:
    """Write the container configuration.

    :param path: Workspace directory.
    :param flow: Container flow.
    :param family: Target family.
    :param crypto: Additional crypto settings.
    :return: Path to the configuration.
    """
    keys: dict[str, Any] = {"mmk_id": "0x22", "mmk": "mmk.bin", "srkh": "srkh.txt"}
    if flow == "integrated":
        keys["provisioning_blob"] = "blob.bin"
    config = {
        "family": family,
        "output": "out/container.bin",
        "container": {"flow": flow, "mode": "ele_primitive_backend", "container_id": "0x1234"},
        "crypto": {"kdf": "sp800_108_cmac", **crypto},
        "keys": keys,
        "members": {
            "src_dir": "model",
            "default": {"protection": "enc_auth", "block_size": "b64k"},
            "rules": [{"match": "*.json", "protection": "auth_only"}],
        },
    }
    config_file = path / "aisec.yaml"
    config_file.write_text(yaml.safe_dump(config))
    return config_file


def _export(cli_runner: CliRunner, workspace: Path) -> Path:
    """Export the container from the workspace configuration.

    :param cli_runner: CLI runner.
    :param workspace: Workspace directory.
    :return: Path to the container binary.
    """
    result = cli_runner.invoke(
        nxpimage.main, ["aisec", "export", "-c", str(workspace / "aisec.yaml")]
    )
    assert "AISEC container" in result.output
    binary = workspace / "out" / "container.bin"
    assert binary.is_file()
    return binary


def test_nxpimage_aisec_help(cli_runner: CliRunner) -> None:
    """The aisec group is registered with all sub-commands."""
    result = cli_runner.invoke(nxpimage.main, ["--help"])
    assert "aisec" in result.output
    result = cli_runner.invoke(nxpimage.main, ["aisec", "--help"])
    for command in ("export", "get-families", "get-template", "parse", "verify"):
        assert command in result.output
    assert "get-templates" not in result.output


def test_nxpimage_aisec_get_families(cli_runner: CliRunner) -> None:
    """Supported families are listed."""
    result = cli_runner.invoke(nxpimage.main, ["aisec", "get-families", "-c", "parse"])
    assert "mimx9596" in result.output
    assert "mimx9352" in result.output
    assert "mimx9332" in result.output


@pytest.mark.parametrize("family", ["mimx9352", "mimx9332", "mimx9596"])
def test_nxpimage_aisec_get_template(cli_runner: CliRunner, tmp_path: Path, family: str) -> None:
    """The template is written exactly to the given file and documents the configuration."""
    output = tmp_path / "custom" / "aisec.yaml"
    cli_runner.invoke(nxpimage.main, ["aisec", "get-template", "-f", family, "-o", str(output)])
    assert output.is_file()
    assert list(output.parent.iterdir()) == [output]
    template = output.read_text()
    for key in ("family:", "container:", "crypto:", "keys:", "members:"):
        assert key in template
    assert yaml.safe_load(template)["family"] == family


@pytest.mark.parametrize("family", ["mimx9352", "mimx9596"])
@pytest.mark.parametrize("flow", ["discrete", "integrated"])
def test_nxpimage_aisec_export_verify(
    cli_runner: CliRunner, workspace: Path, flow: str, family: str
) -> None:
    """Exported container verifies with and without the key material."""
    _write_config(workspace, flow=flow, family=family, binding=True)
    binary = _export(cli_runner, workspace)

    result = cli_runner.invoke(nxpimage.main, ["aisec", "verify", "-b", str(binary)])
    assert "not verified (no key)" in result.output

    result = cli_runner.invoke(
        nxpimage.main,
        [
            "aisec",
            "verify",
            "-b",
            str(binary),
            "-k",
            str(workspace / "mmk.bin"),
            "--srkh",
            SRKH.hex(),
            "-p",
        ],
    )
    assert "not verified (no key)" not in result.output


def test_nxpimage_aisec_verify_fails(cli_runner: CliRunner, workspace: Path) -> None:
    """Wrong key and corrupted binaries fail the verification."""
    binary = _export(cli_runner, workspace)
    cli_runner.invoke(
        nxpimage.main,
        ["aisec", "verify", "-b", str(binary), "-k", "00" * 32, "--srkh", SRKH.hex()],
        expected_code=1,
    )
    corrupted = workspace / "corrupted.bin"
    corrupted.write_bytes(b"\x00" + load_binary(str(binary))[1:])
    cli_runner.invoke(nxpimage.main, ["aisec", "verify", "-b", str(corrupted)], expected_code=1)


@pytest.mark.parametrize(
    "mmk_source",
    [MMK.hex(), "0x" + MMK.hex(), "mmk.bin", "mmk.txt"],
)
def test_nxpimage_aisec_key_sources(
    cli_runner: CliRunner, workspace: Path, mmk_source: str
) -> None:
    """The MMK is accepted as a HEX string, a binary file or a HEX text file."""
    binary = _export(cli_runner, workspace)
    (workspace / "mmk.txt").write_text("0x" + MMK.hex() + "\n")
    if mmk_source.endswith((".bin", ".txt")):
        mmk_source = str(workspace / mmk_source)
    result = cli_runner.invoke(
        nxpimage.main,
        ["aisec", "verify", "-b", str(binary), "-k", mmk_source, "--srkh", SRKH.hex(), "-p"],
    )
    assert "not verified (no key)" not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--srkh", SRKH.hex()],
        ["-k", "0011"],
        ["-k", "zz" * 32],
        ["-k", MMK.hex(), "--srkh", "00" * 31],
        ["-k", MMK.hex() + "00"],
    ],
)
def test_nxpimage_aisec_key_options(
    cli_runner: CliRunner, workspace: Path, args: list[str]
) -> None:
    """Invalid key options are rejected."""
    binary = _export(cli_runner, workspace)
    cli_runner.invoke(nxpimage.main, ["aisec", "verify", "-b", str(binary), *args], expected_code=1)


@pytest.mark.parametrize("family", ["mimx9352", "mimx9596"])
@pytest.mark.parametrize("flow", ["discrete", "integrated"])
def test_nxpimage_aisec_parse_rebuild(
    cli_runner: CliRunner, workspace: Path, family: str, flow: str
) -> None:
    """Parsed configuration rebuilds the same container members."""
    _write_config(workspace, flow=flow, family=family, binding=True)
    binary = _export(cli_runner, workspace)
    parsed_dir = workspace / "parsed"
    result = cli_runner.invoke(
        nxpimage.main,
        [
            "aisec",
            "parse",
            "-f",
            family,
            "-b",
            str(binary),
            "-k",
            MMK.hex(),
            "--srkh",
            str(workspace / "srkh.txt"),
            "-o",
            str(parsed_dir),
        ],
    )
    assert "mmk.bin" in result.output
    assert (parsed_dir / "members" / "model.onnx").is_file()
    assert not (parsed_dir / "mmk.bin").exists()
    assert yaml.safe_load((parsed_dir / "aisec_config.yaml").read_text())["family"] == family

    (parsed_dir / "mmk.bin").write_bytes(MMK)
    cli_runner.invoke(
        nxpimage.main, ["aisec", "export", "-c", str(parsed_dir / "aisec_config.yaml")]
    )
    rebuilt = AisecDirContainer.parse(
        load_binary(str(parsed_dir / "aisec_container.bin")),
        FamilyRevision(family),
        mmk=MMK,
        srkh=SRKH,
    )
    original = AisecDirContainer.parse(
        load_binary(str(binary)), FamilyRevision(family), mmk=MMK, srkh=SRKH
    )
    assert [(m.name, m.data, m.protection) for m in rebuilt.members] == [
        (m.name, m.data, m.protection) for m in original.members
    ]


def test_nxpimage_aisec_parse_without_key(cli_runner: CliRunner, workspace: Path) -> None:
    """Without the MMK the structure is parsed and the encrypted members are reported."""
    binary = _export(cli_runner, workspace)
    parsed_dir = workspace / "parsed"
    result = cli_runner.invoke(
        nxpimage.main,
        ["aisec", "parse", "-f", "mimx9596", "-b", str(binary), "-o", str(parsed_dir)],
    )
    assert "not decrypted" in result.output
    assert "  - model.onnx" in result.output and "  - sub/notes.txt" in result.output
    assert "config.json" not in result.output
    assert (parsed_dir / "members" / "config.json").is_file()
    assert not (parsed_dir / "members" / "model.onnx").exists()
    config = yaml.safe_load((parsed_dir / "aisec_config.yaml").read_text())
    files = {f["name"]: f for f in config["members"]["files"]}
    assert "file" not in files["model.onnx"] and files["model.onnx"]["protection"] == "enc_auth"
    assert files["config.json"]["file"] == "members/config.json"


@pytest.mark.parametrize("text", [MMK[:16].hex(), "0x" + MMK[:16].hex(), MMK[:16].hex() + "\n"])
def test_load_key_hex_text_16b(tmp_path: Path, text: str) -> None:
    """A 16-byte MMK stored as HEX text (32 characters) is decoded, not taken as raw bytes."""
    key_file = tmp_path / "mmk16.txt"
    key_file.write_bytes(text.encode("ascii"))
    assert _load_key(str(key_file), "MMK", AISEC_MMK_SIZES) == MMK[:16]


def test_load_key_binary(tmp_path: Path) -> None:
    """A binary key file is loaded verbatim."""
    key_file = tmp_path / "mmk.bin"
    key_file.write_bytes(MMK[:16])
    assert _load_key(str(key_file), "MMK", AISEC_MMK_SIZES) == MMK[:16]

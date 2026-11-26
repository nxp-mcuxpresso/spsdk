#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of the AISEC dir-v5 container builder (load_from_config and export)."""

import struct
from pathlib import Path
from typing import Any

import pytest

from spsdk.crypto.cmac import cmac
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.aisec.aisec_dir import AisecDirContainer, AisecMember
from spsdk.image.aisec.aisec_dir_blocks import (
    AisecBlockHeader,
    AisecDescriptor,
    AisecMetadata,
    AisecMmkBlock,
)
from spsdk.image.aisec.aisec_dir_crypto import (
    counter_iv,
    decrypt_block,
    derive_auth_key,
    derive_enc_key,
    kdf_base_context,
    payload_size,
    sp800_108_cmac_counter,
)
from spsdk.image.aisec.aisec_dir_parser import AisecKeys, verify_container_binary
from spsdk.image.aisec.aisec_dir_types import (
    AUTH_BLOCK_SIZE,
    BLOCK_HEADER_SIZE,
    DESCRIPTOR_SIZE,
    MAC_SIZE,
    AisecBlockSize,
    AisecContainerFlag,
    AisecKdfAlg,
    AisecMemberType,
    AisecMode,
    AisecProtection,
)
from spsdk.image.cert_block.rot import Rot
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

SALT = bytes(range(1, 17))
MMK = bytes(range(0x40, 0x60))
SRKH = bytes(range(0xA0, 0xC0))
BLOB = b"\xde\xad\xbe\xef" * 9


@pytest.fixture(name="model_dir")
def fixture_model_dir(tmp_path: Path) -> Path:
    """Create a small model directory."""
    src = tmp_path / "model"
    (src / "sub").mkdir(parents=True)
    (src / "model.onnx").write_bytes(bytes(i & 0xFF for i in range(0x10000 + 5)))
    (src / "config.json").write_bytes(b'{"layers": 3}')
    (src / "sub" / "tok.txt").write_bytes(b"tokenizer")
    (src / "README").write_bytes(b"readme")
    (src / "empty.bin").write_bytes(b"")
    (tmp_path / "blob.bin").write_bytes(BLOB)
    (tmp_path / "extra.gguf").write_bytes(b"gguf-data")
    return src


def _config(model_dir: Path, **overrides: Any) -> Config:
    cfg: dict[str, Any] = {
        "family": "mimx9596",
        "output": "container.bin",
        "container": {"flow": "discrete", "mode": "ele_primitive_backend"},
        "crypto": {"kdf": "sp800_108_cmac", "container_salt": SALT.hex()},
        "keys": {"mmk_id": 5, "mmk": MMK.hex(), "srkh": SRKH.hex()},
        "members": {
            "src_dir": str(model_dir),
            "default": {"protection": "enc_auth", "block_size": "b64k"},
            "rules": [
                {"match": "*.json", "protection": "auth_only"},
                {"match": "README", "protection": "none"},
            ],
        },
    }
    for path, value in overrides.items():
        keys = path.split("__")
        cur = cfg
        for key in keys[:-1]:
            cur = cur.setdefault(key, {})
        if value is None:
            cur.pop(keys[-1], None)
        else:
            cur[keys[-1]] = value
    config = Config(cfg)
    config.search_paths = [str(model_dir.parent)]
    config.config_dir = str(model_dir.parent)
    config.check(AisecDirContainer.get_validation_schemas_from_cfg(config))
    return config


def test_load_members_order_and_rules(model_dir: Path) -> None:
    """Directory members are sorted by path components and rules are applied."""
    container = AisecDirContainer.load_from_config(_config(model_dir))
    assert [m.name for m in container.members] == [
        "README",
        "config.json",
        "empty.bin",
        "model.onnx",
        "sub/tok.txt",
    ]
    prot = {m.name: m.protection for m in container.members}
    assert prot["README"] == AisecProtection.NONE
    assert prot["config.json"] == AisecProtection.AUTH_ONLY
    assert prot["model.onnx"] == AisecProtection.ENC_AUTH
    onnx = container.members[3]
    assert onnx.member_type == AisecMemberType.ONNX
    assert onnx.block_size == AisecBlockSize.B64K
    assert onnx.block_count == 2


@pytest.mark.parametrize("flow", ["discrete", "integrated"])
@pytest.mark.parametrize(
    "family,revision,rot_type,expected_hash",
    [
        (
            "mimx9352",
            "a0",
            "srk_table_ahab",
            "cb2cc774b2dcec92c840eca0646b78f8d3661d3a43ed265a490a13aca75e190a",
        ),
        (
            "mimx9352",
            "a1",
            "srk_table_ahab",
            "cb2cc774b2dcec92c840eca0646b78f8d3661d3a43ed265a490a13aca75e190a",
        ),
        (
            "mimx9596",
            "b0",
            "srk_table_ahab_v2",
            "412600fd846385bd8263770692fba46721d30c12aede0dc19cbaf54c5c47394817"
            "9953bdaf43eb2a3cfdbfde7ae8f17bdcbb3ba79b675c2b5746c41c1f4d2d6b",
        ),
    ],
)
def test_ahab_srkh_binding(
    model_dir: Path,
    tests_root_dir: str,
    family: str,
    revision: str,
    rot_type: str,
    expected_hash: str,
    flow: str,
) -> None:
    """Bind AISEC to the family-specific AHAB hash, not a hash of individual public keys."""
    keys = [
        str(Path(tests_root_dir) / "_data" / "keys" / "ecc256" / f"srk{i}_ecc256.pub")
        for i in range(4)
    ]
    rot = Rot(FamilyRevision(family, revision), keys)
    assert rot.rot_obj.rot_type == rot_type
    srkh = rot.calculate_hash()
    assert srkh == bytes.fromhex(expected_hash)
    binding_root = srkh[:32]
    config = _config(
        model_dir,
        family=family,
        revision=revision,
        keys__srkh=binding_root.hex(),
        container__flow=flow,
        keys__provisioning_blob="blob.bin" if flow == "integrated" else None,
    )
    container = AisecDirContainer.load_from_config(config)
    assert container.srkh == binding_root
    assert kdf_base_context(container.mode.tag, binding_root) == get_hash(
        bytes([container.mode.tag]) + get_hash(binding_root, EnumHashAlgorithm.SHA256),
        EnumHashAlgorithm.SHA256,
    )
    binary = container.export()
    assert not verify_container_binary(binary, AisecKeys(MMK, binding_root)).has_errors
    parsed = AisecDirContainer.parse(
        binary, FamilyRevision(family, revision), mmk=MMK, srkh=binding_root
    )
    assert [(m.name, m.get_data()) for m in parsed.members] == [
        (m.name, m.get_data()) for m in container.members
    ]
    other_family = "mimx9596" if family == "mimx9352" else "mimx9352"
    wrong_root = Rot(FamilyRevision(other_family), keys).calculate_hash()[:32]
    assert wrong_root != binding_root
    assert verify_container_binary(binary, AisecKeys(MMK, wrong_root)).has_errors


def test_load_explicit_files(model_dir: Path) -> None:
    """Explicit members are appended after the directory members."""
    files = [
        {"name": "extra/w.gguf", "file": "extra.gguf", "protection": "auth_only"},
        {"name": "raw.dat", "file": "extra.gguf", "member_type": "other", "block_size": "b4m"},
    ]
    container = AisecDirContainer.load_from_config(_config(model_dir, members__files=files))
    extra, raw = container.members[-2:]
    assert extra.name == "extra/w.gguf"
    assert extra.member_type == AisecMemberType.GGUF
    assert extra.protection == AisecProtection.AUTH_ONLY
    assert extra.data == b"gguf-data"
    assert raw.member_type == AisecMemberType.OTHER
    assert raw.protection == AisecProtection.ENC_AUTH
    assert raw.block_size == AisecBlockSize.B4M

    only_files = AisecDirContainer.load_from_config(_config(model_dir, members={"files": files}))
    assert [m.name for m in only_files.members] == ["extra/w.gguf", "raw.dat"]


def test_explicit_file_does_not_override_src_dir(model_dir: Path) -> None:
    """An explicit member with a src_dir member name is a duplicate, not an override."""
    files = [{"name": "config.json", "file": "extra.gguf", "protection": "none"}]
    with pytest.raises(SPSDKValueError, match="Duplicate member name: 'config.json'"):
        AisecDirContainer.load_from_config(_config(model_dir, members__files=files))


def _check_container(data: bytes, container: AisecDirContainer) -> None:
    """Independently decode and verify an exported container."""
    desc = AisecDescriptor.parse(data)
    assert desc.flag == container.flag.tag
    assert desc.mode == container.mode.tag
    metadata = AisecMetadata.parse(data[desc.container_metadata_offset :])
    assert metadata.container_salt == SALT
    assert metadata.binding == container.binding
    assert metadata.kdf == container.kdf.tag
    assert desc.authentication_block_offset == DESCRIPTOR_SIZE + metadata.size
    assert desc.mmk_block_offset == desc.authentication_block_offset + AUTH_BLOCK_SIZE
    if container.flag == AisecContainerFlag.INTEGRATED:
        mmk_block = AisecMmkBlock.parse(data[desc.mmk_block_offset :])
        assert mmk_block.blob == container.provisioning_blob
        assert desc.length_header_bytes == desc.mmk_block_offset + mmk_block.size
    else:
        assert desc.length_header_bytes == desc.mmk_block_offset

    assert container.mmk is not None
    base_ctx = kdf_base_context(container.mode.tag, SRKH if container.binding else None)
    auth_key = derive_auth_key(
        container.kdf, container.mmk, base_ctx, SALT, container.auth_key_size.size
    )
    auth_off = desc.authentication_block_offset
    assert cmac(auth_key, data[: auth_off + 4]) == data[auth_off + 4 : auth_off + 20]

    offset = desc.length_header_bytes
    for entry, member in zip(metadata.entries, container.members):
        assert member.data is not None
        assert entry.name == member.name
        assert entry.member_offset == offset
        assert entry.plain_size == len(member.data)
        assert entry.member_size == payload_size(len(member.data), member.block_size.size)
        plain = b""
        pos = entry.member_offset
        for j in range(entry.block_count):
            hdr = AisecBlockHeader.parse(data[pos:])
            assert hdr.block_index == j
            block = data[pos + BLOCK_HEADER_SIZE : pos + BLOCK_HEADER_SIZE + hdr.block_len]
            if member.protection == AisecProtection.ENC_AUTH:
                enc_key = derive_enc_key(
                    container.kdf,
                    container.mmk,
                    base_ctx,
                    SALT,
                    entry.member_id,
                    container.enc_key_size.size,
                )
                assert block != member.data[: len(block)] or not block
                block = decrypt_block(enc_key, j, member.block_size.size, block)
            if member.protection == AisecProtection.NONE:
                assert hdr.block_mac == bytes(MAC_SIZE)
            plain += block
            pos += BLOCK_HEADER_SIZE + hdr.block_len
        assert plain == member.data
        if member.protection == AisecProtection.NONE:
            assert entry.member_root_mac == bytes(MAC_SIZE)
        else:
            assert entry.member_root_mac != bytes(MAC_SIZE)
        offset += entry.member_size
    assert offset == len(data)


@pytest.mark.parametrize("flow", ["discrete", "integrated"])
@pytest.mark.parametrize("kdf", ["sp800_108_cmac", "hkdf_sha256"])
@pytest.mark.parametrize("binding", [True, False])
@pytest.mark.parametrize(
    "mode", ["sw_primitive_backend", "optee_primitive_backend", "ele_primitive_backend"]
)
def test_export(model_dir: Path, flow: str, kdf: str, binding: bool, mode: str) -> None:
    """Exported containers have consistent layout, valid MACs and payloads that decrypt."""
    overrides: dict[str, Any] = {
        "container__flow": flow,
        "container__mode": mode,
        "crypto__kdf": kdf,
        "crypto__binding": binding,
        "crypto__auth_key_size": 16,
    }
    if flow == "integrated":
        overrides["keys__provisioning_blob"] = "blob.bin"
    container = AisecDirContainer.load_from_config(_config(model_dir, **overrides))
    data = container.export()
    _check_container(data, container)
    assert container.export() == data


@pytest.mark.parametrize("block_size", list(AisecBlockSize))
def test_export_block_sizes(block_size: AisecBlockSize) -> None:
    """Every block size splits the member into ceil(size / block_size) blocks."""
    data = bytes(i & 0xFF for i in range(block_size.size + 1))
    container = AisecDirContainer(
        family=FamilyRevision("mimx9596"),
        flag=AisecContainerFlag.DISCRETE,
        mode=AisecMode.SW,
        members=[AisecMember("m.bin", data, block_size=block_size)],
        binding=False,
        mmk=MMK,
        container_salt=SALT,
    )
    exported = container.export()
    _check_container(exported, container)
    entry = AisecMetadata.parse(exported[DESCRIPTOR_SIZE:]).entries[0]
    assert entry.block_count == 2


def test_export_random_salt() -> None:
    """Without a fixed salt every export uses a fresh random salt."""
    container = AisecDirContainer(
        family=FamilyRevision("mimx9596"),
        flag=AisecContainerFlag.DISCRETE,
        mode=AisecMode.ELE,
        members=[AisecMember("a.bin", b"abc")],
        binding=False,
        mmk=MMK,
    )
    salts = {AisecMetadata.parse(container.export()[DESCRIPTOR_SIZE:]).container_salt for _ in "ab"}
    assert len(salts) == 2
    assert bytes(16) not in salts


def test_counter_iv_and_kdf_vectors() -> None:
    """AES-CTR counter IV and SP 800-108 KDF construction."""
    assert counter_iv(0, 0x10000) == bytes(16)
    assert counter_iv(3, 0x10000) == (3 * 0x1000).to_bytes(16, "big")
    key = bytes(16)
    out = sp800_108_cmac_counter(key, b"\xf3", b"ctx", 40)
    blocks = [
        cmac(key, struct.pack(">I", i) + b"\xf3\x00ctx" + struct.pack(">I", 320)) for i in (1, 2, 3)
    ]
    assert out == b"".join(blocks)[:40]
    assert kdf_base_context(0) != kdf_base_context(1)
    assert kdf_base_context(0, bytes(32)) != kdf_base_context(0)
    with pytest.raises(SPSDKValueError):
        kdf_base_context(0, bytes(16))
    assert derive_auth_key(AisecKdfAlg.HKDF_SHA256, MMK, bytes(32), SALT, 24) != derive_auth_key(
        AisecKdfAlg.SP800_108_CMAC, MMK, bytes(32), SALT, 24
    )


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"keys__srkh": None}, "keys/srkh"),
        ({"container__flow": "integrated"}, "provisioning_blob"),
        ({"keys__provisioning_blob": "blob.bin"}, "only for the integrated flow"),
        ({"keys__mmk_size": 16, "keys__mmk": MMK[:16].hex()}, "must not be smaller"),
        ({"keys__mmk_size": 16}, "Invalid key input"),
        ({"keys__mmk_id": 0x40000000}, "ELE persistent key-id range"),
        ({"keys__mmk_id": 0}, "ELE persistent key-id range"),
        ({"container__mode": "sw_primitive_backend", "keys__mmk_id": 0}, "non-zero mmk_id"),
        ({"container__mode": "optee_primitive_backend", "keys__mmk_id": 0}, "non-zero mmk_id"),
        ({"crypto__container_salt": "00" * 16}, "non-zero"),
        ({"members": {"files": []}}, "has no members"),
        (
            {"members": {"files": [{"name": "../x", "file": "blob.bin"}]}},
            "'..' component",
        ),
        (
            {
                "members": {
                    "files": [
                        {"name": "a", "file": "blob.bin"},
                        {"name": "a/b", "file": "blob.bin"},
                    ]
                }
            },
            "directory prefix",
        ),
    ],
)
def test_load_invalid(model_dir: Path, overrides: dict, error: str) -> None:
    """Invalid configurations are rejected."""
    with pytest.raises(SPSDKError, match=error):
        AisecDirContainer.load_from_config(_config(model_dir, **overrides))


def test_mmk_required(model_dir: Path) -> None:
    """An explicit MMK is always required - no random MMK is generated."""
    config = _config(model_dir)
    config["keys"].pop("mmk")
    with pytest.raises(SPSDKError):
        AisecDirContainer.load_from_config(config)


def test_integrated_mmk_id_not_range_checked(model_dir: Path) -> None:
    """For the integrated flow the mmk_id is informational only."""
    container = AisecDirContainer.load_from_config(
        _config(
            model_dir,
            container__flow="integrated",
            keys__provisioning_blob="blob.bin",
            keys__mmk_id=0xFFFFFFFF,
        )
    )
    _check_container(container.export(), container)


def test_export_rejects_sealed_and_oversized_blob() -> None:
    """Sealed (on-device) flag and an oversized provisioning blob cannot be built."""

    def make(flag: AisecContainerFlag, blob: bytes | None = None) -> AisecDirContainer:
        return AisecDirContainer(
            family=FamilyRevision("mimx9596"),
            flag=flag,
            mode=AisecMode.SW,
            members=[AisecMember("a.bin", b"abc")],
            binding=False,
            mmk=MMK,
            provisioning_blob=blob,
        )

    with pytest.raises(SPSDKValueError, match="on-device"):
        make(AisecContainerFlag.SEALED).export()
    with pytest.raises(SPSDKValueError, match="maximum"):
        make(AisecContainerFlag.INTEGRATED, bytes(0x10000)).export()
    with pytest.raises(SPSDKValueError, match="must not be empty"):
        make(AisecContainerFlag.INTEGRATED, b"").check_buildable()
    AisecMmkBlock.check_blob(bytes(0xFFFB))


def test_load_members_hidden_files_warned(
    model_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Hidden files of src_dir are packed as members and a warning is printed for them."""
    (model_dir / ".DS_Store").write_bytes(b"ds")
    (model_dir / ".git").mkdir()
    (model_dir / ".git" / "HEAD").write_bytes(b"ref")
    with caplog.at_level("WARNING"):
        container = AisecDirContainer.load_from_config(_config(model_dir))
    names = [m.name for m in container.members]
    assert ".DS_Store" in names and ".git/HEAD" in names
    assert "'.DS_Store'" in caplog.text and "'.git/HEAD'" in caplog.text
    assert "'README'" not in caplog.text

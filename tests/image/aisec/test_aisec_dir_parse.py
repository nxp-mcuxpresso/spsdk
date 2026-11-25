#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of the AISEC dir-v5 container parser and verifier."""

import struct
from pathlib import Path
from typing import Callable

import pytest

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.aisec.aisec_dir import AisecDirContainer, AisecMember
from spsdk.image.aisec.aisec_dir_blocks import is_load_influencing
from spsdk.image.aisec.aisec_dir_crypto import derive_auth_key, kdf_base_context
from spsdk.image.aisec.aisec_dir_parser import (
    NOT_VERIFIED_NO_KEY,
    AisecDecodedContainer,
    AisecKeys,
    verify_container_binary,
)
from spsdk.image.aisec.aisec_dir_types import (
    DESCRIPTOR_SIZE,
    METADATA_FIXED_PREFIX_SIZE,
    AisecBlockSize,
    AisecContainerFlag,
    AisecKdfAlg,
    AisecKeySize,
    AisecMemberType,
    AisecMode,
    AisecProtection,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.verifier import Verifier, VerifierRecord, VerifierResult

SALT = bytes(range(1, 17))
MMK = bytes(range(0x40, 0x60))
SRKH = bytes(range(0xA0, 0xC0))
BLOB = b"\xde\xad\xbe\xef" * 9
FAMILY = FamilyRevision("mimx9596")

# Offsets of the fields of the first member entry
MD = DESCRIPTOR_SIZE
ENTRY0 = MD + METADATA_FIXED_PREFIX_SIZE


def _members() -> list[AisecMember]:
    return [
        AisecMember(
            "model.onnx",
            bytes(i & 0xFF for i in range(0x10000 + 7)),
            AisecProtection.ENC_AUTH,
            AisecBlockSize.B64K,
        ),
        AisecMember("config.json", b'{"a": 1}', AisecProtection.AUTH_ONLY),
        AisecMember("docs/README.txt", b"readme", AisecProtection.NONE),
        AisecMember("empty.dat", b""),
    ]


def _container(
    flag: AisecContainerFlag = AisecContainerFlag.DISCRETE,
    binding: bool = True,
    kdf: AisecKdfAlg = AisecKdfAlg.SP800_108_CMAC,
    mode: AisecMode = AisecMode.ELE,
) -> AisecDirContainer:
    return AisecDirContainer(
        family=FAMILY,
        flag=flag,
        mode=mode,
        members=_members(),
        container_id=0x1234,
        container_version=7,
        enc_key_size=AisecKeySize.AES_256,
        auth_key_size=AisecKeySize.AES_128,
        kdf=kdf,
        binding=binding,
        mmk_id=5,
        mmk=MMK,
        srkh=SRKH if binding else None,
        provisioning_blob=BLOB if flag == AisecContainerFlag.INTEGRATED else None,
        container_salt=SALT,
    )


def _resign(data: bytes, container: AisecDirContainer) -> bytes:
    """Recompute the header CMAC after a header modification."""
    decoded = AisecDecodedContainer.decode(data)
    base = kdf_base_context(container.mode.tag, SRKH if container.binding else None)
    key = derive_auth_key(
        container.kdf, MMK, base, decoded.metadata.container_salt, container.auth_key_size.size
    )
    auth_off = decoded.descriptor.authentication_block_offset
    md_end = MD + (decoded.metadata.total_len or 0)
    mac = cmac(key, data[:md_end] + data[auth_off : auth_off + 4])
    return data[: auth_off + 4] + mac + data[auth_off + 20 :]


def _patch(data: bytes, offset: int, fmt: str, value: int | bytes) -> bytes:
    size = struct.calcsize(fmt)
    return data[:offset] + struct.pack(fmt, value) + data[offset + size :]


def _errors(ver: Verifier) -> list[str]:
    """Collect names and values of all error records."""
    out: list[str] = []
    for rec in ver.records:
        if isinstance(rec, Verifier):
            out += _errors(rec)
        elif isinstance(rec, VerifierRecord) and rec.result == VerifierResult.ERROR:
            out.append(f"{rec.name}: {rec.value}")
    return out


@pytest.mark.parametrize("flag", [AisecContainerFlag.DISCRETE, AisecContainerFlag.INTEGRATED])
@pytest.mark.parametrize("binding", [True, False])
@pytest.mark.parametrize("kdf", list(AisecKdfAlg))
def test_parse_with_key(flag: AisecContainerFlag, binding: bool, kdf: AisecKdfAlg) -> None:
    """Parsing with the MMK verifies all MACs and recovers all members."""
    original = _container(flag, binding, kdf)
    data = original.export()
    parsed = AisecDirContainer.parse(data, FAMILY, mmk=MMK, srkh=SRKH)
    assert parsed.flag == flag
    assert parsed.binding == binding
    assert parsed.kdf == kdf
    assert parsed.container_id == 0x1234 and parsed.container_version == 7
    assert parsed.auth_key_size == AisecKeySize.AES_128
    assert parsed.provisioning_blob == original.provisioning_blob
    assert parsed.container_salt is None, "the salt of a parsed binary must not be reused"
    for got, exp in zip(parsed.members, original.members):
        assert (got.name, got.data, got.protection, got.block_size, got.member_type) == (
            exp.name,
            exp.data,
            exp.protection,
            exp.block_size,
            exp.member_type,
        )
    ver = parsed.verify()
    assert not ver.has_errors
    assert not ver.has_warnings or mode_is_sw(parsed)
    reexported = parsed.export()
    assert len(reexported) == len(data) and reexported != data
    assert not AisecDirContainer.parse(reexported, FAMILY, mmk=MMK, srkh=SRKH).verify().has_errors
    parsed.container_salt = SALT
    assert parsed.export() == data
    assert "Members:           4" in str(parsed)


def test_reexport_uses_fresh_salt() -> None:
    """Re-exporting a modified parsed container must not reuse the original salt/keystream."""
    data = _container().export()
    parsed = AisecDirContainer.parse(data, FAMILY, mmk=MMK, srkh=SRKH)
    parsed.members[0].data = b"\x00" * len(parsed.members[0].get_data())
    salts = {
        AisecDecodedContainer.decode(blob).metadata.container_salt
        for blob in (data, parsed.export(), parsed.export())
    }
    assert len(salts) == 3


def mode_is_sw(container: AisecDirContainer) -> bool:
    """Check whether the container uses the software (testing only) backend."""
    return container.mode == AisecMode.SW


def test_parse_without_key(tmp_path: Path) -> None:
    """Without a key the structure is verified and the MACs are reported as not verified."""
    data = _container().export()
    parsed = AisecDirContainer.parse(data, FAMILY)
    assert parsed.members[0].data is None
    assert parsed.members[0].plain_size == 0x10007
    assert parsed.members[1].data == b'{"a": 1}'
    assert parsed.locked_members == [parsed.members[0].name]
    ver = parsed.verify()
    assert not ver.has_errors
    assert ver.has_warnings
    assert NOT_VERIFIED_NO_KEY in ver.draw(colorize=False)
    config = parsed.get_config(str(tmp_path))
    files = config["members"]["files"]
    assert "file" not in files[0]
    assert files[0]["protection"] == "enc_auth"
    assert not (tmp_path / "members" / parsed.members[0].name).exists()
    assert [f.get("file") for f in files[1:]] == ["members/" + m.name for m in parsed.members[1:]]
    with pytest.raises(SPSDKValueError, match="MMK"):
        parsed.export()


def test_parse_auth_only_without_key(tmp_path: Path) -> None:
    """A container without encrypted members round-trips without a key."""
    container = _container(binding=False)
    for member in container.members:
        if member.protection == AisecProtection.ENC_AUTH:
            member.protection = AisecProtection.AUTH_ONLY
    parsed = AisecDirContainer.parse(container.export(), FAMILY)
    config = parsed.get_config(str(tmp_path))
    assert [f["name"] for f in config["members"]["files"]] == [m.name for m in container.members]


@pytest.mark.parametrize("flag", [AisecContainerFlag.DISCRETE, AisecContainerFlag.INTEGRATED])
@pytest.mark.parametrize("binding", [True, False])
def test_get_config_round_trip(tmp_path: Path, flag: AisecContainerFlag, binding: bool) -> None:
    """Parsed configuration rebuilds a byte-identical container with the same salt."""
    original = _container(flag, binding)
    data = original.export()
    parsed = AisecDirContainer.parse(data, FAMILY, mmk=MMK, srkh=SRKH)
    config = parsed.get_config(str(tmp_path))
    assert not (tmp_path / "mmk.bin").exists(), "MMK must never be written"
    assert "container_salt" not in config["crypto"]
    assert (tmp_path / "srkh.bin").exists() == binding
    assert (tmp_path / "members" / "docs" / "README.txt").read_bytes() == b"readme"
    (tmp_path / "mmk.bin").write_bytes(MMK)

    config["crypto"]["container_salt"] = SALT.hex()
    config = Config(dict(config))
    config.search_paths = [str(tmp_path)]
    config.config_dir = str(tmp_path)
    config.check(AisecDirContainer.get_validation_schemas_from_cfg(config))
    rebuilt = AisecDirContainer.load_from_config(config)
    assert rebuilt.export() == data


def test_get_config_srkh_unknown(tmp_path: Path) -> None:
    """A device-bound container parsed without the SRKH refers to a srkh.bin to provide."""
    container = _container()
    for member in container.members:
        member.protection = AisecProtection.AUTH_ONLY
    parsed = AisecDirContainer.parse(container.export(), FAMILY)
    assert parsed.srkh is None
    config = parsed.get_config(str(tmp_path))
    assert config["keys"]["srkh"] == "srkh.bin"
    assert not (tmp_path / "srkh.bin").exists()


def test_wrong_keys() -> None:
    """A wrong MMK or SRKH, or a missing SRKH fails the authentication."""
    data = _container().export()
    with pytest.raises(SPSDKParsingError, match="Header CMAC"):
        AisecDirContainer.parse(data, FAMILY, mmk=bytes(32), srkh=SRKH)
    with pytest.raises(SPSDKParsingError, match="Header CMAC"):
        AisecDirContainer.parse(data, FAMILY, mmk=MMK, srkh=bytes(32))
    with pytest.raises(SPSDKParsingError, match="SRKH binding root is required"):
        AisecDirContainer.parse(data, FAMILY, mmk=MMK)
    # 16-byte MMK is shorter than the 32-byte ENC_DKEY
    errors = _errors(verify_container_binary(data, AisecKeys(mmk=MMK[:16], srkh=SRKH)))
    assert any("MMK entropy" in e for e in errors)


def _flip(offset: int) -> Callable[[bytes], bytes]:
    return lambda d: d[:offset] + bytes([d[offset] ^ 0x01]) + d[offset + 1 :]


def _member_payload_offset(data: bytes, index: int) -> int:
    return AisecDecodedContainer.decode(data).members[index].entry.member_offset


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda d: _patch(d, 1, ">B", 4), "Version"),
        (lambda d: _patch(d, 2, ">B", 0x13), "Flag"),
        (lambda d: _patch(d, 2, ">B", 0x00), "Flag"),
        (lambda d: _patch(d, 2, ">B", 0x81), "Flag"),
        (lambda d: _patch(d, 3, ">B", 0x03), "Mode"),
        (lambda d: _patch(d, MD + 13, ">B", 0x01), "Encryption algorithm"),
        (lambda d: _patch(d, MD + 14, ">B", 0x00), "Encryption key size"),
        (lambda d: _patch(d, MD + 16, ">B", 0x11), "Authentication key size"),
        (lambda d: _patch(d, MD + 15, ">B", 0x02), "Authentication algorithm"),
        (lambda d: _patch(d, MD + 17, ">16s", bytes(16)), "Container salt"),
        (lambda d: _patch(d, MD + 37, ">B", 0x08), "MMK size"),
        (lambda d: _patch(d, MD + 38, ">B", 0x83), "KDF algorithm"),
        (lambda d: _patch(d, MD + 33, ">L", 0), "MMK ID"),
        (lambda d: _patch(d, MD + 33, ">L", 0x40000000), "MMK ID"),
        (lambda d: _patch(d, ENTRY0, ">H", 3), "Member ID"),
        (lambda d: _patch(d, ENTRY0 + 3, ">B", 0x03), "Protection"),
        (lambda d: _patch(d, ENTRY0 + 4, ">B", 0x05), "Block size"),
        (lambda d: _patch(d, ENTRY0 + 30, ">L", 3), "Block count"),
        (lambda d: _patch(d, ENTRY0 + 22, ">Q", 0x10008), "Block lengths"),
        (lambda d: _patch(d, ENTRY0 + 22, ">Q", 0x20001), "Block count"),
        (lambda d: _patch(d, ENTRY0 + 14, ">Q", 0x7FFFFFFF), "Payload structure"),
        (lambda d: _patch(d, ENTRY0 + 6, ">Q", 0), "Payload ranges"),
        (lambda d: _patch(d, ENTRY0 + 52, ">5s", b"../mo"), "Member name"),
        (lambda d: _patch(d, ENTRY0 + 52, ">5s", b"/mode"), "Member name"),
        (lambda d: _patch(d, ENTRY0 + 52, ">5s", b"mo\\de"), "Member name"),
        (lambda d: _patch(d, ENTRY0 + 52, ">5s", b"mo\x00de"), "Member name"),
        (lambda d: _patch(d, 8, ">L", 25), "metadata tag"),
        (lambda d: _patch(d, 12, ">L", 0x300), "authentication block tag"),
    ],
)
def test_must_reject_structure(mutate: Callable[[bytes], bytes], error: str) -> None:
    """Structural must-reject rules are detected without any key, even with a valid CMAC."""
    container = _container()
    data = mutate(container.export())
    try:
        data = _resign(data, container)
    except SPSDKError:
        pass
    ver = verify_container_binary(data)
    errors = _errors(ver)
    assert any(e.startswith(error) or error in e for e in errors), errors
    with pytest.raises(SPSDKParsingError):
        AisecDirContainer.parse(data, FAMILY)


def test_must_reject_duplicate_and_prefix_names() -> None:
    """Duplicate names and file-vs-directory conflicts are rejected."""
    container = AisecDirContainer(
        family=FAMILY,
        flag=AisecContainerFlag.DISCRETE,
        mode=AisecMode.OPTEE,
        members=[AisecMember("aa", b"1"), AisecMember("ab", b"2"), AisecMember("ab/x", b"3")],
        binding=False,
        mmk=MMK,
        container_salt=SALT,
    )
    with pytest.raises(SPSDKValueError, match="directory prefix"):
        container.export()
    # build a valid container, then rename members in the binary with a valid CMAC
    container.members = [
        AisecMember("aa", b"1"),
        AisecMember("ab", b"2"),
        AisecMember("cc/x", b"3"),
    ]
    data = container.export()
    name1 = data.index(b"ab")
    dup = _resign(data[:name1] + b"aa" + data[name1 + 2 :], container)
    assert any("Duplicate" in e for e in _errors(verify_container_binary(dup)))
    name2 = data.index(b"cc/x")
    prefix = _resign(data[:name2] + b"aa/x" + data[name2 + 4 :], container)
    assert any("directory prefix" in e for e in _errors(verify_container_binary(prefix)))


def test_must_reject_none_on_load_influencing() -> None:
    """protection 'none' on a load-influencing member name is rejected on build and verify."""
    container = _container()
    container.members[2].name = "docs/vocab.txt"
    with pytest.raises(SPSDKValueError, match="Load-influencing"):
        container.export()
    container.members[2].name = "docs/README.txt"
    data = container.export()
    offset = data.index(b"docs/README.txt")
    bad = _resign(data[:offset] + b"docs/model.gguf" + data[offset + 15 :], container)
    assert any("Plaintext policy" in e for e in _errors(verify_container_binary(bad)))


@pytest.mark.parametrize(
    "name,influencing",
    [
        ("model.ONNX", True),
        ("sub/tokenizer.json", True),
        ("generation_config.json", True),
        ("weights.index.json", True),
        ("a/b/sp.model", True),
        ("x.yml", True),
        ("README.md", False),
        ("LICENSE", False),
        ("sample.wav", False),
    ],
)
def test_is_load_influencing(name: str, influencing: bool) -> None:
    """Load-influencing names are detected by basename, case-insensitively."""
    assert is_load_influencing(name) == influencing


def test_must_reject_custody() -> None:
    """MMK custody rules of the integrated and discrete flags."""
    integrated = _container(AisecContainerFlag.INTEGRATED)
    data = integrated.export()
    # integrated container relabeled as discrete: a stray mmk_block / offsets mismatch
    as_discrete = _resign(_patch(data, 2, ">B", 0x12), integrated)
    assert any("MMK block absent" in e for e in _errors(verify_container_binary(as_discrete)))
    # discrete container relabeled as integrated: no tag-0x84 block
    discrete = _container()
    as_integrated = _patch(discrete.export(), 2, ">B", 0x11)
    assert _errors(verify_container_binary(as_integrated))
    # integrated: header length that does not end at the mmk_block end
    bad_len = _resign(_patch(data, 4, ">L", len(data) - 1), integrated)
    assert any("Header length" in e for e in _errors(verify_container_binary(bad_len)))
    # integrated flow: mmk_id is informational, any value is accepted
    zero_id = _resign(_patch(data, MD + 33, ">L", 0), integrated)
    assert not verify_container_binary(zero_id, AisecKeys(MMK, SRKH)).has_errors


def test_sealed_container() -> None:
    """A sealed (0x91) container can be parsed and verified but not reconfigured."""
    container = _container()
    sealed = _resign(_patch(container.export(), 2, ">B", 0x91), container)
    parsed = AisecDirContainer.parse(sealed, FAMILY, mmk=MMK, srkh=SRKH)
    assert parsed.flag == AisecContainerFlag.SEALED
    assert not parsed.verify().has_errors
    with pytest.raises(SPSDKValueError, match="on-device"):
        parsed.get_config("unused")
    # sealed: the DIE_MMK size defines the derived key length - no under-keying
    container.mmk_size = AisecKeySize.AES_128
    small = _resign(_patch(sealed, MD + 37, ">B", 0x10), container)
    assert any("MMK entropy" in e for e in _errors(verify_container_binary(small)))


def test_must_reject_mac_tampering() -> None:
    """Tampered payload and MACs are detected when the key is known."""
    container = _container()
    data = container.export()
    keys = AisecKeys(MMK, SRKH)
    off0 = _member_payload_offset(data, 0)
    # payload data of an enc_auth member
    tampered = _flip(off0 + 24 + 100)(data)
    assert not verify_container_binary(tampered).has_errors
    assert any(
        "block 0 MAC mismatch" in e for e in _errors(verify_container_binary(tampered, keys))
    )
    # block MAC of an auth_only member
    off1 = _member_payload_offset(data, 1)
    tampered = _flip(off1 + 8)(data)
    assert any("MAC mismatch" in e for e in _errors(verify_container_binary(tampered, keys)))
    # member_root_mac with a re-signed header
    tampered = _resign(_flip(ENTRY0 + 34)(data), container)
    assert any("member_root_mac" in e for e in _errors(verify_container_binary(tampered, keys)))
    # header field without re-signing
    tampered = _patch(data, MD + 5, ">L", 0x9999)
    assert any("Header CMAC" in e for e in _errors(verify_container_binary(tampered, keys)))
    # none member: non-zero MAC
    off2 = _member_payload_offset(data, 2)
    tampered = _flip(off2 + 8)(data)
    assert any("MACs must be zero" in e for e in _errors(verify_container_binary(tampered)))
    # block swap: the block index is in the block MAC
    tampered = _patch(data, off0, ">L", 1)
    assert _errors(verify_container_binary(tampered))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d[:10],
        lambda d: d[:100],
        lambda d: _patch(d, 0, ">B", 0x82),
        lambda d: _patch(d, 12, ">L", 0xFFFFFF),
        lambda d: _patch(d, MD, ">B", 0x81),
        lambda d: _patch(d, MD + 11, ">H", 9),
        lambda d: _patch(d, MD + 11, ">H", 1),
        lambda d: _patch(d, MD + 1, ">L", 0xFFFF),
    ],
)
def test_undecodable(mutate: Callable[[bytes], bytes]) -> None:
    """Binaries that cannot be decoded are reported as errors and rejected by parse."""
    data = mutate(_container().export())
    assert verify_container_binary(data).has_errors
    with pytest.raises(SPSDKError):
        AisecDirContainer.parse(data, FAMILY)


def test_verify_built_container() -> None:
    """Verify of a container created from settings checks that it can be built."""
    container = _container()
    assert not container.verify().has_errors
    container.flag = AisecContainerFlag.SEALED
    assert container.verify().has_errors


def test_member_requires_size() -> None:
    """A member without data must declare its plain size."""
    with pytest.raises(SPSDKValueError):
        AisecMember("x", None)
    member = AisecMember("x.gguf", None, plain_size=5)
    assert member.member_type == AisecMemberType.GGUF
    assert member.block_count == 1

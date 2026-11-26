#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AISEC protected-directory (dir-v5) container.

The container securely packages a whole directory (e.g. an AI/ML model directory with
weights, configuration and tokenizer files) into one binary. Each file becomes a member
protected by its own protection level (``enc_auth``, ``auth_only`` or ``none``).

Layout::

    container_descriptor (0x81) | container_metadata (0x82, incl. member entries) |
    authentication_block (0x83) | [mmk_block (0x84), flag 0x11 only] | member area
"""

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from typing_extensions import Self

from spsdk.crypto.cmac import cmac
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKParsingError, SPSDKValueError
from spsdk.image.aisec.aisec_dir_blocks import (
    AisecAuthBlock,
    AisecDescriptor,
    AisecMemberEntry,
    AisecMetadata,
    AisecMmkBlock,
    check_member_names,
    is_load_influencing,
)
from spsdk.image.aisec.aisec_dir_crypto import (
    build_member_payload,
    derive_auth_key,
    derive_enc_key,
    kdf_base_context,
)
from spsdk.image.aisec.aisec_dir_parser import (
    AisecDecodedContainer,
    AisecKeys,
    verify_container_binary,
)
from spsdk.image.aisec.aisec_dir_types import (
    AISEC_BUILDABLE_FLAGS,
    AISEC_MEMBER_TYPE_BY_EXT,
    AUTH_BLOCK_SIZE,
    CONTAINER_SALT_SIZE,
    DESCRIPTOR_SIZE,
    ELE_PERSISTENT_KEY_ID_MAX,
    ELE_PERSISTENT_KEY_ID_MIN,
    KDF_BINDING_FLAG,
    MAX_MEMBER_COUNT,
    SRKH_SIZE,
    AisecAuthAlg,
    AisecBlockSize,
    AisecContainerFlag,
    AisecEncAlg,
    AisecKdfAlg,
    AisecKeySize,
    AisecMemberType,
    AisecMode,
    AisecProtection,
)
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import find_dir, load_binary, write_file
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


@dataclass
class AisecMember:
    """One logical member (file) of the protected directory."""

    name: str
    data: bytes | None
    protection: AisecProtection = AisecProtection.ENC_AUTH
    block_size: AisecBlockSize = AisecBlockSize.B1M
    member_type: AisecMemberType | None = None
    plain_size: int = -1

    def __post_init__(self) -> None:
        """Derive the member type from the file extension and the plain size from data.

        :raises SPSDKValueError: Neither data nor plain size is known.
        """
        if self.member_type is None:
            ext = PurePosixPath(self.name).suffix.lower()
            self.member_type = AISEC_MEMBER_TYPE_BY_EXT.get(ext, AisecMemberType.RAW)
        if self.data is not None:
            self.plain_size = len(self.data)
        elif self.plain_size < 0:
            raise SPSDKValueError(f"AISEC member {self.name}: plain size must be known")

    @property
    def block_count(self) -> int:
        """Number of payload blocks of the member.

        :return: ceil(plain_size / block_size).
        """
        return -(-self.plain_size // self.block_size.size)

    def get_data(self) -> bytes:
        """Get the member plaintext.

        :raises SPSDKValueError: The plaintext is not available (enc_auth member parsed
            without the MMK).
        :return: Member plaintext.
        """
        if self.data is None:
            raise SPSDKValueError(
                f"Plaintext of the encrypted AISEC member '{self.name}' is not available, "
                "the MMK is required"
            )
        return self.data


@dataclass(repr=False)
class AisecDirContainer(FeatureBaseClass):
    """AISEC dir-v5 protected-directory container."""

    FEATURE = DatabaseManager.AISEC

    family: FamilyRevision
    flag: AisecContainerFlag
    mode: AisecMode
    members: list[AisecMember] = field(default_factory=list)
    container_id: int = 1
    container_version: int = 1
    enc_key_size: AisecKeySize = AisecKeySize.AES_256
    auth_key_size: AisecKeySize = AisecKeySize.AES_256
    kdf: AisecKdfAlg = AisecKdfAlg.HKDF_SHA256
    binding: bool = True
    mmk_id: int = 1
    mmk_size: AisecKeySize = AisecKeySize.AES_256
    mmk: bytes | None = field(default=None, repr=False)
    srkh: bytes | None = None
    provisioning_blob: bytes | None = None
    container_salt: bytes | None = None
    _binary: bytes | None = field(default=None, init=False, repr=False, compare=False)

    def __repr__(self) -> str:
        """Get short representation of the container.

        :return: Short representation.
        """
        return (
            f"AisecDirContainer(family={self.family}, flag={self.flag.label}, "
            f"mode={self.mode.label}, members={len(self.members)})"
        )

    def __str__(self) -> str:
        """Get text description of the container.

        :return: Description of the container.
        """
        ret = (
            f"AISEC dir-v5 container for {self.family}\n"
            f"  Flag:              {self.flag.label} (0x{self.flag.tag:02X})\n"
            f"  Mode:              {self.mode.label} (0x{self.mode.tag:02X})\n"
            f"  Container ID:      0x{self.container_id:08X}\n"
            f"  Container version: {self.container_version}\n"
            f"  Keys:              ENC {self.enc_key_size.size}B, AUTH "
            f"{self.auth_key_size.size}B, MMK {self.mmk_size.size}B (id 0x{self.mmk_id:08X})\n"
            f"  KDF:               {self.kdf.label}, binding: {self.binding}\n"
            f"  Members:           {len(self.members)}\n"
        )
        for member in self.members:
            assert member.member_type is not None
            ret += (
                f"    - {member.name}: {member.protection.label}, {member.block_size.label}, "
                f"{member.member_type.label}, {member.plain_size} bytes\n"
            )
        return ret

    @property
    def locked_members(self) -> list[str]:
        """Names of encrypted members whose plaintext is not known (parsed without the MMK).

        :return: List of member names.
        """
        return [member.name for member in self.members if member.data is None]

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for the AISEC dir-v5 container configuration.

        :param family: Family for which the schemas are generated.
        :return: List of validation schemas.
        """
        sch = get_schema_file(DatabaseManager.AISEC)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=sch_family["properties"], devices=cls.get_supported_families(), family=family
        )
        sch_family["main_title"] = "AISEC dir-v5 protected-directory container configuration"
        sch_family["note"] = (
            "Only the host-buildable provisioning containers (flag 0x12 discrete and "
            "flag 0x11 integrated) can be generated. No key material is stored in the container."
        )
        return [
            sch_family,
            sch["aisec_output"],
            sch["aisec_container"],
            sch["aisec_crypto"],
            sch["aisec_keys"],
            sch["aisec_members"],
        ]

    @staticmethod
    def _load_members(config: Config) -> list[AisecMember]:
        """Load the container members from the members configuration.

        :param config: Members configuration.
        :raises SPSDKValueError: No members defined.
        :return: List of members in container order.
        """
        members: list[AisecMember] = []
        if "src_dir" in config:
            src_dir = find_dir(config.get_str("src_dir"), search_paths=config.search_paths)
            default_prot = config.get_str("default/protection", "enc_auth")
            default_bs = config.get_str("default/block_size", "b1m")
            rules = config.get_list_of_configs("rules", [])
            names = [
                os.path.relpath(os.path.join(root, f), src_dir).replace(os.sep, "/")
                for root, _, files in os.walk(src_dir)
                for f in files
            ]
            for name in sorted(names, key=lambda n: n.split("/")):
                if any(part.startswith(".") for part in name.split("/")):
                    logger.warning(f"AISEC hidden file '{name}' from src_dir is packed as a member")
                prot, bs = default_prot, default_bs
                for rule in rules:
                    if fnmatch.fnmatchcase(name, rule.get_str("match")):
                        prot = rule.get_str("protection", prot)
                        bs = rule.get_str("block_size", bs)
                        break
                members.append(
                    AisecMember(
                        name=name,
                        data=load_binary(os.path.join(src_dir, *name.split("/"))),
                        protection=AisecProtection.from_label(prot),
                        block_size=AisecBlockSize.from_label(bs),
                    )
                )
        for file_cfg in config.get_list_of_configs("files", []):
            member_type = file_cfg.get("member_type")
            members.append(
                AisecMember(
                    name=file_cfg.get_str("name"),
                    data=load_binary(file_cfg.get_input_file_name("file")),
                    protection=AisecProtection.from_label(
                        file_cfg.get_str("protection", "enc_auth")
                    ),
                    block_size=AisecBlockSize.from_label(file_cfg.get_str("block_size", "b1m")),
                    member_type=AisecMemberType.from_label(member_type) if member_type else None,
                )
            )
        if not members:
            raise SPSDKValueError("AISEC container has no members: define members/src_dir or files")
        return members

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the container from configuration.

        :param config: Container configuration.
        :raises SPSDKValueError: Inconsistent configuration.
        :return: AISEC dir-v5 container.
        """
        flag = AisecContainerFlag.from_label(config.get_str("container/flow"))
        binding = config.get_bool("crypto/binding", True)
        mmk_size = AisecKeySize.from_size(config.get_int("keys/mmk_size", 32))

        srkh = None
        if binding:
            if config.get("keys/srkh") is None:
                raise SPSDKValueError("AISEC device binding is enabled, keys/srkh must be defined")
            srkh = config.load_symmetric_key("keys/srkh", SRKH_SIZE, name="SRKH")

        provisioning_blob = None
        if flag == AisecContainerFlag.INTEGRATED:
            if config.get("keys/provisioning_blob") is None:
                raise SPSDKValueError(
                    "AISEC integrated flow requires keys/provisioning_blob (ELE/EL2GO blob)"
                )
            provisioning_blob = load_binary(config.get_input_file_name("keys/provisioning_blob"))
        elif config.get("keys/provisioning_blob") is not None:
            raise SPSDKValueError(
                "keys/provisioning_blob is valid only for the integrated flow; the discrete "
                "flow resolves the POST_MMK from the keystore slot keys/mmk_id"
            )

        container_salt = None
        if config.get("crypto/container_salt") is not None:
            logger.warning("AISEC fixed container salt is used - FOR TESTING ONLY")
            container_salt = config.load_symmetric_key(
                "crypto/container_salt", CONTAINER_SALT_SIZE, name="container salt"
            )

        container = cls(
            family=config.get_family(),
            flag=flag,
            mode=AisecMode.from_label(config.get_str("container/mode")),
            members=cls._load_members(config.get_config("members")),
            container_id=config.get_int("container/container_id", 1),
            container_version=config.get_int("container/container_version", 1),
            enc_key_size=AisecKeySize.from_size(config.get_int("crypto/enc_key_size", 32)),
            auth_key_size=AisecKeySize.from_size(config.get_int("crypto/auth_key_size", 32)),
            kdf=AisecKdfAlg.from_label(config.get_str("crypto/kdf", "hkdf_sha256")),
            binding=binding,
            mmk_id=config.get_int("keys/mmk_id", 1),
            mmk_size=mmk_size,
            mmk=config.load_symmetric_key("keys/mmk", mmk_size.size, name="MMK"),
            srkh=srkh,
            provisioning_blob=provisioning_blob,
            container_salt=container_salt,
        )
        container.check_buildable()
        return container

    def check_buildable(self) -> None:
        """Check that the container can be built on the host.

        :raises SPSDKValueError: The container settings violate the dir-v5 rules.
        """
        if self.flag not in AISEC_BUILDABLE_FLAGS:
            raise SPSDKValueError(
                f"AISEC flag {self.flag.label} (0x{self.flag.tag:02X}) is an on-device state "
                "and cannot be built on the host"
            )
        self._check_key_material()
        if not 0 <= self.container_id <= 0xFFFFFFFF or not 0 <= self.mmk_id <= 0xFFFFFFFF:
            raise SPSDKValueError("AISEC container_id and mmk_id must fit into 32 bits")
        if not 0 <= self.container_version <= 0xFFFF:
            raise SPSDKValueError("AISEC container_version must fit into 16 bits")
        if not 0 < len(self.members) <= MAX_MEMBER_COUNT:
            raise SPSDKValueError(f"AISEC member count must be in range 1..{MAX_MEMBER_COUNT}")
        problems = check_member_names([m.name for m in self.members])
        problems += [
            f"Load-influencing member must not use protection 'none': {m.name!r}"
            for m in self.members
            if m.protection == AisecProtection.NONE and is_load_influencing(m.name)
        ]
        if problems:
            raise SPSDKValueError("Invalid AISEC members:\n" + "\n".join(problems))

    def _check_key_material(self) -> None:
        """Check the MMK, SRKH, provisioning blob, MMK identifier and salt.

        :raises SPSDKValueError: Invalid key material settings.
        """
        if self.mmk is None or len(self.mmk) != self.mmk_size.size:
            raise SPSDKValueError(f"AISEC MMK of {self.mmk_size.size} bytes must be provided")
        if self.mmk_size.size < max(self.enc_key_size.size, self.auth_key_size.size):
            raise SPSDKValueError(
                f"AISEC MMK size ({self.mmk_size.size} B) must not be smaller than the derived "
                f"key sizes (ENC {self.enc_key_size.size} B, AUTH {self.auth_key_size.size} B)"
            )
        if self.binding and (self.srkh is None or len(self.srkh) != SRKH_SIZE):
            raise SPSDKValueError(f"AISEC device binding requires a {SRKH_SIZE}-byte SRKH")
        if self.flag == AisecContainerFlag.INTEGRATED:
            AisecMmkBlock.check_blob(self.provisioning_blob or b"")
        elif self.provisioning_blob:
            raise SPSDKValueError("AISEC provisioning blob is valid only for the integrated flow")
        if self.flag == AisecContainerFlag.DISCRETE:
            if self.mode == AisecMode.ELE and not (
                ELE_PERSISTENT_KEY_ID_MIN <= self.mmk_id <= ELE_PERSISTENT_KEY_ID_MAX
            ):
                raise SPSDKValueError(
                    f"AISEC mmk_id 0x{self.mmk_id:08X} is outside the ELE persistent key-id "
                    f"range 0x{ELE_PERSISTENT_KEY_ID_MIN:08X}..0x{ELE_PERSISTENT_KEY_ID_MAX:08X}"
                )
            if self.mmk_id == 0:
                raise SPSDKValueError("AISEC discrete flow requires a non-zero mmk_id")
        if self.container_salt is not None and (
            len(self.container_salt) != CONTAINER_SALT_SIZE or not any(self.container_salt)
        ):
            raise SPSDKValueError(
                f"AISEC container salt must be {CONTAINER_SALT_SIZE} non-zero bytes"
            )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the container and store the member data files.

        The members are stored as an explicit file list in ``<data_path>/members``. The
        SRKH and the provisioning blob are stored into data files as well. The MMK is a
        secret and is never written: the configuration refers to ``mmk.bin`` that must be
        provided by the user. The container salt is not part of the configuration, so a
        rebuilt container uses a fresh salt.

        The plaintext of encrypted members of a container parsed without the MMK is not
        known: such members (see :attr:`locked_members`) are listed without the
        ``file`` key and no data file is stored, so the configuration describes the
        structure but cannot be rebuilt until the container is parsed with the MMK.

        :param data_path: Path to store the data files of configuration.
        :raises SPSDKValueError: Sealed container.
        :return: Configuration of the container.
        """
        if self.flag not in AISEC_BUILDABLE_FLAGS:
            raise SPSDKValueError(
                f"AISEC flag {self.flag.label} container is an on-device state, its "
                "configuration cannot be created"
            )
        files: list[dict[str, Any]] = []
        for member in self.members:
            assert member.member_type is not None
            file_cfg: dict[str, Any] = {"name": member.name}
            if member.data is None:
                logger.warning(
                    f"AISEC member '{member.name}' is encrypted and the MMK is not known, its "
                    "data file is not stored"
                )
            else:
                file_name = "members/" + member.name
                write_file(member.data, os.path.join(data_path, file_name), mode="wb")
                file_cfg["file"] = file_name
            file_cfg.update(
                {
                    "protection": member.protection.label,
                    "block_size": member.block_size.label,
                    "member_type": member.member_type.label,
                }
            )
            files.append(file_cfg)
        keys: dict[str, Any] = {
            "mmk_id": f"0x{self.mmk_id:08X}",
            "mmk_size": self.mmk_size.size,
            "mmk": "mmk.bin",
        }
        if self.binding:
            if self.srkh is None:
                logger.warning("AISEC SRKH binding root is unknown, provide srkh.bin manually")
            else:
                write_file(self.srkh, os.path.join(data_path, "srkh.bin"), mode="wb")
            keys["srkh"] = "srkh.bin"
        if self.provisioning_blob is not None:
            write_file(
                self.provisioning_blob, os.path.join(data_path, "provisioning_blob.bin"), mode="wb"
            )
            keys["provisioning_blob"] = "provisioning_blob.bin"

        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["output"] = "aisec_container.bin"
        config["container"] = {
            "flow": self.flag.label,
            "mode": self.mode.label,
            "container_id": f"0x{self.container_id:08X}",
            "container_version": self.container_version,
        }
        config["crypto"] = {
            "enc_key_size": self.enc_key_size.size,
            "auth_key_size": self.auth_key_size.size,
            "kdf": self.kdf.label,
            "binding": self.binding,
        }
        config["keys"] = keys
        config["members"] = {"files": files}
        return config

    def verify(self) -> Verifier:
        """Verify the container.

        A parsed container is verified against the dir-v5 must-reject rules; the MACs are
        verified only if the MMK (and the SRKH for a device-bound container) is known.
        A container created from configuration is checked to be buildable.

        :return: Verifier with the results.
        """
        if self._binary is not None:
            keys = AisecKeys(mmk=self.mmk, srkh=self.srkh) if self.mmk else None
            return verify_container_binary(self._binary, keys)
        ver = Verifier("AISEC dir-v5 container")
        try:
            self.check_buildable()
            ver.add_record("Container settings", True, f"{len(self.members)} members")
        except SPSDKError as exc:
            ver.add_record("Container settings", False, str(exc))
        return ver

    def export(self) -> bytes:
        """Export the container binary.

        A fresh random container salt is generated for every export unless a fixed
        (testing only) salt is set.

        :return: Container binary.
        """
        self.check_buildable()
        assert self.mmk is not None
        salt = self.container_salt or random_bytes(CONTAINER_SALT_SIZE)
        base_ctx = kdf_base_context(self.mode.tag, self.srkh if self.binding else None)
        auth_key = derive_auth_key(self.kdf, self.mmk, base_ctx, salt, self.auth_key_size.size)

        entries: list[AisecMemberEntry] = []
        payloads: list[bytes] = []
        for member_id, member in enumerate(self.members):
            assert member.member_type is not None
            enc_key = None
            if member.protection == AisecProtection.ENC_AUTH:
                enc_key = derive_enc_key(
                    self.kdf, self.mmk, base_ctx, salt, member_id, self.enc_key_size.size
                )
            payload = build_member_payload(
                plain=member.get_data(),
                member_id=member_id,
                member_type=member.member_type.tag,
                protection=member.protection,
                block_size_enum=member.block_size.tag,
                block_size=member.block_size.size,
                auth_key=auth_key,
                enc_key=enc_key,
            )
            payloads.append(payload.data)
            entries.append(
                AisecMemberEntry(
                    member_id=member_id,
                    member_type=member.member_type.tag,
                    protection=member.protection.tag,
                    block_size_enum=member.block_size.tag,
                    name=member.name,
                    member_size=len(payload.data),
                    plain_size=member.plain_size,
                    block_count=member.block_count,
                    member_root_mac=payload.root_mac,
                )
            )

        metadata = AisecMetadata(
            container_id=self.container_id,
            container_version=self.container_version,
            enc_alg=AisecEncAlg.AES_CTR.tag,
            enc_key_size=self.enc_key_size.tag,
            auth_alg=AisecAuthAlg.AES_CMAC.tag,
            auth_key_size=self.auth_key_size.tag,
            container_salt=salt,
            mmk_id=self.mmk_id,
            mmk_size=self.mmk_size.tag,
            kdf_alg=(KDF_BINDING_FLAG if self.binding else 0) | self.kdf.tag,
            entries=entries,
        )
        mmk_block = (
            AisecMmkBlock(self.provisioning_blob or b"").export()
            if self.flag == AisecContainerFlag.INTEGRATED
            else b""
        )
        auth_off = DESCRIPTOR_SIZE + metadata.size
        mmk_off = auth_off + AUTH_BLOCK_SIZE
        member_area_off = mmk_off + len(mmk_block)
        offset = member_area_off
        for entry in entries:
            entry.member_offset = offset
            offset += entry.member_size

        descriptor = AisecDescriptor(
            flag=self.flag.tag,
            mode=self.mode.tag,
            length_header_bytes=member_area_off,
            container_metadata_offset=DESCRIPTOR_SIZE,
            authentication_block_offset=auth_off,
            mmk_block_offset=mmk_off,
        ).export()
        metadata_data = metadata.export()
        auth_block = AisecAuthBlock()
        auth_block.auth_data = cmac(
            auth_key, descriptor + metadata_data + auth_block.export_header()
        )
        return descriptor + metadata_data + auth_block.export() + mmk_block + b"".join(payloads)

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: FamilyRevision = FamilyRevision("unknown"),
        mmk: bytes | None = None,
        srkh: bytes | None = None,
    ) -> Self:
        """Parse the container binary.

        The binary is verified against the dir-v5 must-reject rules first and any error
        stops the parsing. No key is needed to parse the structure. With the MMK (and the
        SRKH for a device-bound container) the MACs are verified as well and the
        plaintext of encrypted members is recovered; without it the plaintext of
        enc_auth members is not available.

        The container salt of the binary is not kept: re-exporting the parsed container
        always uses a fresh salt, so the AES-CTR keystream of the original binary is never
        reused for a modified content.

        :param data: Container binary.
        :param family: Target family.
        :param mmk: Optional MMK.
        :param srkh: Optional 32-byte SRKH binding root.
        :raises SPSDKParsingError: The container is malformed or not authentic.
        :return: Parsed container.
        """
        decoded = AisecDecodedContainer.decode(data)
        keys = AisecKeys(mmk=mmk, srkh=srkh) if mmk else None
        ver = decoded.verify(keys)
        if ver.has_errors:
            raise SPSDKParsingError(
                "Invalid AISEC dir-v5 container:\n"
                + ver.draw(results=[VerifierResult.ERROR], colorize=False)
            )
        md = decoded.metadata
        try:
            members = [
                AisecMember(
                    name=member.entry.name,
                    data=decoded.member_plaintext(index, keys),
                    protection=AisecProtection.from_tag(member.entry.protection),
                    block_size=AisecBlockSize.from_tag(member.entry.block_size_enum),
                    member_type=AisecMemberType.from_tag(member.entry.member_type),
                    plain_size=member.entry.plain_size,
                )
                for index, member in enumerate(decoded.members)
            ]
        except SPSDKKeyError as exc:
            raise SPSDKParsingError(f"Unsupported AISEC member value: {exc}") from exc
        container = cls(
            family=family,
            flag=AisecContainerFlag.from_tag(decoded.flag),
            mode=AisecMode.from_tag(decoded.descriptor.mode),
            members=members,
            container_id=md.container_id,
            container_version=md.container_version,
            enc_key_size=AisecKeySize.from_size(md.enc_key_size),
            auth_key_size=AisecKeySize.from_size(md.auth_key_size),
            kdf=AisecKdfAlg.from_tag(md.kdf),
            binding=md.binding,
            mmk_id=md.mmk_id,
            mmk_size=AisecKeySize.from_size(md.mmk_size),
            mmk=mmk,
            srkh=srkh if md.binding else None,
            provisioning_blob=decoded.mmk_block.blob if decoded.mmk_block else None,
        )
        container._binary = data
        return container

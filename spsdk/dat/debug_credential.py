#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with DebugCredential class."""

import abc
import logging
from struct import calcsize, pack, unpack, unpack_from
from typing import Any, Optional, Type

from typing_extensions import Self, TypeAlias

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key
from spsdk.dat.protocol_version import ProtocolVersion
from spsdk.dat.rot_meta import RotMeta, RotMetaDummy, RotMetaEcc, RotMetaEdgeLockEnclave, RotMetaRSA
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.image.ahab.ahab_certificate import AhabCertificate, get_ahab_certificate_class
from spsdk.image.ahab.ahab_srk import SRKRecordV2
from spsdk.image.cert_block.cert_blocks import CertBlock
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import load_binary, value_to_int

logger = logging.getLogger(__name__)


class DebugCredentialCertificate(FeatureBaseClass):
    """Base class for DebugCredentialCertificate."""

    FEATURE = DatabaseManager.DAT
    ROT_META_CLASS = RotMeta

    def __init__(
        self,
        family: FamilyRevision,
        version: ProtocolVersion,
        uuid: bytes,
        rot_meta: RotMeta,
        dck_pub: PublicKey,
        cc_socu: int,
        cc_vu: int,
        cc_beacon: int,
        rot_pub: PublicKey,
        signature: Optional[bytes] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Initialize the DebugCredential object.

        :param version: Protocol version
        :param socc: The SoC Class that this credential applies to
        :param uuid: The bytes of the unique device identifier
        :param rot_meta: Metadata for Root of Trust
        :param dck_pub: Internal binary representation of Debug Credential public key
        :param cc_socu: The Credential Constraint value that the vendor has associated with this credential.
        :param cc_vu: The Vendor Usage constraint value that the vendor has associated with this credential.
        :param cc_beacon: The non-zero Credential Beacon value, which is bound to a DC
        :param rot_pub: Internal binary representation of RoT public key
        :param signature: Debug Credential signature
        :param signature_provider: external signature provider
        """
        self.family = family
        self.version = version
        self.uuid = uuid
        self.rot_meta = rot_meta
        self.dck_pub = dck_pub
        self.cc_socu = cc_socu
        self.cc_vu = cc_vu
        if cc_beacon > 0xFFFF:
            logger.warning(
                f"Beacon value {cc_beacon} exceeds 16-bit range, it will be truncated to a 16-bit value"
            )
            cc_beacon = cc_beacon & 0xFFFF
        self.cc_beacon = cc_beacon
        self.rot_pub = rot_pub
        self.signature = signature
        self.signature_provider = signature_provider

    @property
    def socc(self) -> int:
        """The SoC Class."""
        return get_db(self.family).get_int(DatabaseManager.DAT, "socc")

    def __str__(self) -> str:
        """String representation of DebugCredential."""
        msg = f"Version : {self.version}\n"
        msg += f"SOCC    : 0x{self.socc:08X}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        msg += str(self.rot_meta)
        return msg

    def __repr__(self) -> str:
        return f"DC {self.version}, 0x{self.socc:08X}"

    @property
    def rot_hash_length(self) -> int:
        """Root of Trust debug credential hash length."""
        return 32

    @property
    def srk_count(self) -> int:
        """Get the number of Super Root Keys (SRK)."""
        return 1

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Calculate the RoT hash."""

    @abc.abstractmethod
    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        :return: binary representing the RoT key
        """

    @abc.abstractmethod
    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: binary representing the DCK key
        """

    @abc.abstractmethod
    def _get_data_to_sign(self) -> bytes:
        """Get data to be signed."""

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider."""
        if not self.signature_provider:
            raise SPSDKError("Debug Credential Signature provider is not set")
        self.signature_provider.try_to_verify_public_key(self.rot_pub)
        signature = self.signature_provider.get_signature(self._get_data_to_sign())
        if not signature:
            raise SPSDKError("Debug Credential Signature provider didn't return any signature")
        self.signature = signature

    def _vars(self) -> dict[str, Any]:
        v = vars(self).copy()
        del v["signature_provider"]
        return v

    @staticmethod
    def dat_based_on_ele(family: FamilyRevision) -> bool:
        """Get information if the DAT is based on EdgeLock Enclave hardware.

        :param family: The chip family name
        :return: True if the ELE is target HW, False otherwise
        """
        return get_db(family).get_bool(DatabaseManager.DAT, "based_on_ele", False)

    @classmethod
    def _get_class(
        cls, family: FamilyRevision, version: Optional[ProtocolVersion] = None
    ) -> Type[Self]:
        db = get_db(family)
        if db.get_bool(DatabaseManager.DAT, "based_on_ele", False):
            cnt_ver = db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1)
            if cnt_ver == 1:
                return DebugCredentialEdgeLockEnclave  # type: ignore
            if cnt_ver == 2:
                return DebugCredentialEdgeLockEnclaveV2  # type: ignore
            raise SPSDKValueError(f"Unsupported ELE container version {cnt_ver} for {family}")
        if version is None:
            raise SPSDKValueError(
                "Cannot determine the Debug Credential class "
                f"without specified protocol for {family}"
            )
        if version.is_rsa():
            return DebugCredentialCertificateRsa  # type: ignore
        if version.major == 3:
            if version.minor == 1:
                return DebugCredentialEdgeLockEnclave  # type: ignore
            return DebugCredentialEdgeLockEnclaveV2  # type: ignore
        return DebugCredentialCertificateEcc  # type: ignore

    @classmethod
    def _get_class_from_cfg(cls, config: Config) -> Type[Self]:
        family = FamilyRevision.load_from_config(config)
        db = get_db(family)

        if db.get_bool(DatabaseManager.DAT, "based_on_ele", False):
            cnt_ver = db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1)
            if cnt_ver == 1:
                version = ProtocolVersion("3.1")
            elif cnt_ver == 2:
                version = ProtocolVersion("3.2")
            else:
                raise SPSDKValueError(f"Unsupported ELE container version {cnt_ver} for {family}")
        else:
            if "rot_meta" in config:
                cfg_path = config["rot_meta"][0]
            else:
                cfg_path = config["public_key_0"]
            rot_pub = extract_public_key(file_path=cfg_path, search_paths=config.search_paths)
            version = ProtocolVersion.from_public_key(public_key=rot_pub)
        return cls._get_class(family=family, version=version)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create a debug credential object out of yaml configuration.

        :param config: Debug credential file configuration.

        :return: DebugCredential object
        """
        family = FamilyRevision.load_from_config(config)
        rot_config_file = config.get("rot_config")
        cert_block = cls.load_cert_block(rot_config_file, family) if rot_config_file else None
        rot_pub = (
            cert_block.get_root_public_key()
            if cert_block
            else extract_public_key(
                file_path=config.get_input_file_name(f"rot_meta/{config.get_int('rot_id')}")
            )
        )
        version = ProtocolVersion.from_public_key(public_key=rot_pub)
        klass = DebugCredentialCertificate._get_class(family=family, version=version)
        rot_meta_class = klass.ROT_META_CLASS
        rot_meta = (
            rot_meta_class.load_from_cert_block(cert_block)
            if cert_block
            else rot_meta_class.load_from_config(config)
        )

        try:
            pss_padding = get_db(family).get_bool(DatabaseManager.SIGNING, "pss_padding")
        except SPSDKValueError:
            pss_padding = False
        # get signer from cert block configuration if possible
        if rot_config_file:
            try:
                rot_cfg = Config.create_from_file(rot_config_file)
                config["signer"] = (
                    rot_cfg.get_str("certBlock/signer")
                    if "certBlock" in rot_cfg
                    else rot_cfg.get_str("signer")
                )
            except SPSDKError:
                # certificate block as a binary
                pass
        signature_provider = get_signature_provider(config, pss_padding=pss_padding)
        dc_obj = klass(
            family=family,
            version=version,
            uuid=bytes.fromhex(config["uuid"]),
            rot_meta=rot_meta,
            dck_pub=extract_public_key(config.get_input_file_name("dck")),
            cc_socu=config.get_int("cc_socu"),
            cc_vu=config.get_int("cc_vu"),
            cc_beacon=config.get_int("cc_beacon"),
            rot_pub=rot_pub,
            signature_provider=signature_provider,
        )
        return dc_obj  # type: ignore

    @classmethod
    def load_cert_block(cls, rot_config_file: str, family: FamilyRevision) -> CertBlock:
        """Load certificate block from a file.

        :param rot_config_file: Path to Root of Trust configuration file or binary certificate block
        :param family: Family revision for the certificate block
        :return: Loaded certificate block object
        :raises SPSDKError: When unable to create certificate block from the file
        """
        cert_block_cls = CertBlock.get_cert_block_class(family)
        try:
            config = Config.create_from_file(rot_config_file)
            logger.info("Loading configuration from cert block/MBI config file")
            if "certBlock" in config:
                return cls.load_cert_block(config.get_input_file_name("certBlock"), family)
            return cert_block_cls.load_from_config(config)
        except SPSDKError:
            logger.debug("Parsing certBlock as a binary")
            try:
                return cert_block_cls.parse(load_binary(rot_config_file))
            except (SPSDKError, TypeError) as exc:
                raise SPSDKError(
                    f"Unable to create cert block from file: {rot_config_file}"
                ) from exc

    def get_config(self, data_path: str = "./") -> Config:
        """Get configuration."""
        raise SPSDKNotImplementedError

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param family: Mandatory family name.
        :return: DebugCredential object
        """
        # The  ELE V2 is totally different to standard DC - try it first and if fail let do the standard process
        try:
            return DebugCredentialEdgeLockEnclaveV2.parse(data, family=family)  # type:ignore
        except SPSDKError:
            pass
        ver = unpack_from("<2H", data)

        klass = cls._get_class(
            family=family,
            version=ProtocolVersion.from_version(ver[0], ver[1]),
        )
        return klass.parse(data, family)  # type: ignore

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls._get_class_from_cfg(config).get_validation_schemas(family)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for what will be json schema generated.
        :return: Validation list of schemas.
        """
        schema = get_schema_file(DatabaseManager.DAT)
        sch_family: dict[str, Any] = get_schema_file("general")["family"]
        ret = []
        socc = get_db(family).get_int(DatabaseManager.DAT, "socc")
        schema["dc_content"]["properties"]["socc"]["template_value"] = hex(socc)
        update_validation_schema_family(
            sch_family["properties"], devices=cls.get_supported_families(), family=family
        )

        sch_family["main_title"] = f"Debug Credential configuration file for {family} family."
        sch_family["note"] = schema["main_note"]

        ret.append(sch_family)
        ret.append(schema["dc_content"])
        if get_db(family).get_bool(DatabaseManager.DAT, "based_on_ele", False):
            ret.append(schema["dc_srk_ca_flag"])
        return ret


class DebugCredentialCertificateRsa(DebugCredentialCertificate):
    """Class for RSA specific of DebugCredentialCertificate."""

    ROT_META_CLASS: TypeAlias = RotMetaRSA

    def __str__(self) -> str:
        msg = super().__str__()
        msg += f"RoTKH   : {self.calculate_hash().hex()}\n"
        return msg

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        return self.rot_meta.calculate_hash()

    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        :return: binary representing the RoT key
        """
        assert isinstance(self.rot_pub, PublicKeyRsa)
        return self.rot_pub.export(exp_length=4)

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: binary representing the DCK key
        """
        assert isinstance(self.dck_pub, PublicKeyRsa)
        return self.dck_pub.export(exp_length=4)

    @classmethod
    def get_data_format(cls, version: ProtocolVersion, include_signature: bool = True) -> str:
        """Get the format of exported binary data."""
        key_size = {0: 260, 1: 516}[version.minor]
        data_format = (
            "<"
            + "2H"  # Version
            + "L"  # SOCC
            + "16s"  # UUID
            + "128s"  # RoT meta
            + f"{key_size}s"  # DCK public key
            + "L"  # CC SOCU
            + "L"  # CC VU
            + "L"  # CC BEACON
            + f"{key_size}s"  # RoT public key
        )
        if include_signature:
            signature_size = {0: 256, 1: 512}[version.minor]
            data_format += f"{signature_size}s"
        return data_format

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the debug credential
        :raises SPSDKError: When Debug Credential Signature is not set, call the `sign` method first
        """
        if not self.signature:
            raise SPSDKError("Debug Credential signature is not set, call the `sign` method first")
        data = pack(
            self.get_data_format(self.version),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.rot_meta.export(),
            self.export_dck_pub(),
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.export_rot_pub(),
            self.signature,
        )
        return data

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param family: Mandatory family name.
        :return: DebugCredential object
        """
        # we need to get version first so we can calculate the data length
        version = ProtocolVersion.from_version(*unpack_from("<2H", data))
        (
            _,
            _,
            socc,
            uuid,
            rot_meta,
            dck_pub,
            cc_socu,
            cc_vu,
            cc_beacon,
            rot_pub,
            signature,
        ) = unpack_from(cls.get_data_format(version), data)
        ret = cls(
            family=family,
            version=version,
            uuid=uuid,
            rot_meta=RotMetaRSA.parse(rot_meta),
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=cc_beacon,
            rot_pub=PublicKey.parse(rot_pub),
            signature=signature,
        )
        # on top of that parse, validate also SOCC:
        if ret.socc != socc:
            raise SPSDKValueError(
                f"The SOCC form binary 0x({socc:08X}) doesn't fit family SOCC 0x({ret.socc:08X})"
            )

        return ret

    def _get_data_to_sign(self) -> bytes:
        """Collects data for signing."""
        data = pack(
            self.get_data_format(self.version, include_signature=False),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.rot_meta.export(),
            self.export_dck_pub(),
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.export_rot_pub(),
        )
        return data

    def __eq__(self, other: Any) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return isinstance(other, DebugCredentialCertificateRsa) and self._vars() == other._vars()


class DebugCredentialCertificateEcc(DebugCredentialCertificate):
    """Class for ECC specific of DebugCredential."""

    COORDINATE_SIZE = {0: 32, 1: 48, 2: 66}
    ROT_META_CLASS: TypeAlias = RotMetaEcc

    @property
    def rot_hash_length(self) -> int:
        """Root of Trust  debug credential hash length."""
        db = get_db(self.family)
        if db.get_bool(DatabaseManager.DAT, "dat_is_using_sha256_always", False):
            return 32
        assert isinstance(self.rot_pub, PublicKeyEcc)
        return self.rot_pub.key_size // 8

    def __str__(self) -> str:
        msg = super().__str__()
        msg += f"CTRK hash   : {self.calculate_hash().hex()}\n"
        return msg

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        try:
            return self.rot_meta.calculate_hash()
        except SPSDKError:
            assert isinstance(self.rot_pub, PublicKeyEcc)
            return get_hash(
                data=self.export_rot_pub(),
                algorithm=EnumHashAlgorithm.from_label(f"sha{self.rot_pub.key_size}"),
            )

    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        :return: binary representing the RoT key
        """
        assert isinstance(self.rot_pub, PublicKeyEcc)
        return self.rot_pub.export()

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: binary representing the DCK key
        """
        return self.dck_pub.export()

    def get_data_format(self, include_signature: bool = True) -> str:
        """Get the format of exported binary data."""
        assert isinstance(self.rot_pub, PublicKeyEcc)
        assert isinstance(self.dck_pub, PublicKeyEcc)
        data_format = (
            "<"
            + "2H"  # Version
            + "L"  # SOCC
            + "16s"  # UUID
            + "L"  # CC SOCU
            + "L"  # CC VU
            + "L"  # CC BEACON
            + f"{len(self.rot_meta)}s"  # RoT meta
            + f"{self.rot_pub.coordinate_size * 2}s"  # RoT public key
            + f"{self.dck_pub.coordinate_size * 2}s"  # DCK public key
        )
        if include_signature:
            if not self.signature:
                raise SPSDKError(
                    "Debug Credential signature is not set, call the `sign` method first"
                )
            data_format += f"{len(self.signature)}s"
        return data_format

    def export(self) -> bytes:
        """Export to binary form (serialization)."""
        if not self.signature:
            raise SPSDKError("Debug Credential signature is not set, call the `sign` method first")
        data = pack(
            self.get_data_format(),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta.export(),
            self.export_rot_pub(),
            self.export_dck_pub(),
            self.signature,
        )
        return data

    def _get_data_to_sign(self) -> bytes:
        """Collects data meant for signing."""
        data = pack(
            self.get_data_format(include_signature=False),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta.export(),
            self.export_rot_pub(),
            self.export_dck_pub(),
        )
        return data

    def __eq__(self, other: Any) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return isinstance(other, DebugCredentialCertificateEcc) and self._vars() == other._vars()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param family: Mandatory family name.
        :return: DebugCredential object
        """
        format_head = (
            "<"
            + "2H"  # Version
            + "L"  # SOCC
            + "16s"  # UUID
            + "L"  # CC SOCU
            + "L"  # CC VU
            + "L"  # CC BEACON
        )
        (
            version_major,
            version_minor,
            socc,
            uuid,
            cc_socu,
            cc_vu,
            beacon,
        ) = unpack_from(format_head, data)
        version = ProtocolVersion.from_version(version_major, version_minor)
        rot_meta_cls = RotMetaEcc._get_subclass(hash_size=cls.COORDINATE_SIZE[version.minor])
        rot_meta = rot_meta_cls.parse(data[calcsize(format_head) :])
        format_tail = (
            f"<{rot_meta.HASH_SIZE * 2}s{rot_meta.HASH_SIZE * 2}s{rot_meta.HASH_SIZE * 2}s"
        )
        rot_pub, dck_pub, signature = unpack_from(
            format_tail, data, calcsize(format_head) + len(rot_meta)
        )

        ret = cls(
            family=family,
            version=version,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            rot_pub=PublicKey.parse(rot_pub),
            signature=signature,
        )
        # on top of that parse, validate also SOCC:
        if ret.socc != socc:
            raise SPSDKValueError(
                f"The SOCC form binary 0x({socc:08X}) doesn't fit family SOCC 0x({ret.socc:08X})"
            )

        return ret


class DebugCredentialEdgeLockEnclave(DebugCredentialCertificateEcc):
    """EdgeLock Class."""

    ROT_META_CLASS: TypeAlias = RotMetaEdgeLockEnclave

    @property
    def rot_hash_length(self) -> int:
        """Root of Trust  debug credential hash length."""
        return 32

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        return self.rot_meta.calculate_hash()

    def get_data_format(self, include_signature: bool = True) -> str:
        """Get the format of exported binary data."""
        assert isinstance(self.rot_pub, (PublicKeyEcc, PublicKeyRsa))
        data_format = (
            "<"
            + "2H"  # Version
            + "L"  # SOCC
            + "16s"  # UUID
            + "L"  # CC SOCU
            + "L"  # CC VU
            + "L"  # CC BEACON
            + f"{len(self.rot_meta)}s"  # RoT meta
            + f"{len(self.export_dck_pub())}s"  # DCK public key
        )
        if include_signature:
            if not self.signature:
                raise SPSDKError(
                    "Debug Credential signature is not set, call the `sign` method first"
                )
            data_format += f"{len(self.signature)}s"
        return data_format

    def export(self) -> bytes:
        """Export to binary form (serialization)."""
        if not self.signature:
            raise SPSDKError("Debug Credential signature is not set, call the `sign` method first")
        data = pack(
            self.get_data_format(),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta.export(),
            self.export_dck_pub(),
            self.signature,
        )
        return data

    def _get_data_to_sign(self) -> bytes:
        """Collects data meant for signing."""
        data = pack(
            self.get_data_format(include_signature=False),
            self.version.major,
            self.version.minor,
            self.socc,
            self.uuid,
            self.cc_socu,
            self.cc_vu,
            self.cc_beacon,
            self.rot_meta.export(),
            self.export_dck_pub(),
        )
        return data

    def __eq__(self, other: Any) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return isinstance(other, DebugCredentialEdgeLockEnclave) and self._vars() == other._vars()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param family: Mandatory family name.
        :return: DebugCredential object
        """
        format_head = (
            "<"
            + "2H"  # Version
            + "L"  # SOCC
            + "16s"  # UUID
            + "L"  # CC SOCU
            + "L"  # CC VU
            + "L"  # CC BEACON
        )
        (
            version_major,
            version_minor,
            socc,
            uuid,
            cc_socu,
            cc_vu,
            beacon,
        ) = unpack_from(format_head, data)
        version = ProtocolVersion.from_version(version_major, version_minor)
        rot_meta = RotMetaEdgeLockEnclave.parse(data[calcsize(format_head) :])
        rot_pub = rot_meta.srk_table.get_source_keys()[rot_meta.flags.used_root_cert]
        format_tail = f"<{len(rot_pub.export())}s{rot_pub.signature_size}s"
        dck_pub, signature = unpack_from(format_tail, data, calcsize(format_head) + len(rot_meta))

        ret = cls(
            family=family,
            version=version,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            rot_pub=rot_pub,
            signature=signature,
        )

        # on top of that parse, validate also SOCC:
        if ret.socc != socc:
            raise SPSDKValueError(
                f"The SOCC form binary 0x({socc:08X}) doesn't fit family SOCC 0x({ret.socc:08X})"
            )

        return ret


class DebugCredentialEdgeLockEnclaveV2(DebugCredentialCertificate):
    """Debug Credential file for ELE version 2 (with PQC support)."""

    SUB_FEATURE = "ele_pqc"
    ROT_META_CLASS = RotMetaDummy

    def __init__(self, family: FamilyRevision, certificate: AhabCertificate) -> None:
        """Constructor for EdgeLock Enclave version 2 debug credential class."""
        self.certificate = certificate
        assert isinstance(certificate.public_key_0, SRKRecordV2)
        super().__init__(
            family=family,
            version=ProtocolVersion("3.2"),  # The version is NOT used in DC data
            uuid=certificate._uuid or b"",
            rot_meta=RotMetaDummy(),
            dck_pub=certificate.public_key_0.get_public_key(),
            cc_socu=self.socu,
            cc_vu=0,
            cc_beacon=self.beacon,
            # just there is a needs to put any public key it won't be used :-)
            rot_pub=certificate.public_key_0.get_public_key(),
            signature=None,
            signature_provider=None,
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DebugCredentialEdgeLockEnclaveV2):
            return False
        return self.certificate == value.certificate

    def __str__(self) -> str:
        """String representation of DebugCredential."""
        msg = "Debug Credential for ELE v2 :\n"
        msg += f" SOCC    : {hex(self.socc)}\n"
        msg += f" CC_SOCU : {hex(self.socu)}\n"
        msg += f" BEACON  : {self.beacon}\n "
        msg += str(self.certificate)
        return msg

    @property
    def srk_count(self) -> int:
        """Get the number of Super Root Keys (SRK)."""
        return 0

    def __repr__(self) -> str:
        return f"DC ELE v2, 0x{self.socc:08X}"

    @property
    def socu(self) -> int:
        """DC SOCU field."""
        _, socu, _ = unpack("<LLL", self.certificate.permission_data[:12])
        return socu

    @socu.setter
    def socu(self, value: int) -> None:
        """DC SOCU field set."""
        self.certificate.permission_data = pack("<LLL", self.socc, value, self.beacon)

    @property
    def socc(self) -> int:
        """DC SOCC field."""
        socc, _, _ = unpack("<LLL", self.certificate.permission_data[:12])
        return socc

    @socc.setter
    def socc(self, value: int) -> None:
        """DC SOCC field set."""
        self.certificate.permission_data = pack("<LLL", value, self.socu, self.beacon)

    @property
    def beacon(self) -> int:
        """DC SOCU field."""
        _, _, beacon = unpack("<LLL", self.certificate.permission_data[:12])
        return beacon

    @beacon.setter
    def beacon(self, value: int) -> None:
        """DC Beacon field set."""
        self.certificate.permission_data = pack("<LLL", self.socc, self.socu, value)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for what will be json schema generated.
        :return: Validation list of schemas.
        """
        ret = get_ahab_certificate_class(family).get_validation_schemas(family)
        schema = get_schema_file(DatabaseManager.DAT)
        db = get_db(family=family)
        update_validation_schema_family(
            sch=ret[0]["properties"], devices=cls.get_supported_families(), family=family
        )

        ret[0]["main_title"] = f"Debug Credential configuration file for {family} family."

        ret[1]["properties"].pop("permissions")
        ret[1]["required"].remove("permissions")
        ret[1]["properties"].pop("permission_data")

        use_beacon = db.get_bool(DatabaseManager.DAT, "used_beacons_on_ele", False)
        vu_instead_fuse_version = db.get_bool(DatabaseManager.DAT, "vu_instead_fuse_version", False)
        if use_beacon:
            ret.insert(2, schema["ele_dc_beacon"])
        if vu_instead_fuse_version:
            ret[1]["properties"].pop("fuse_version")
            ret.insert(3, schema["ahab_certificate_vendor_usage"])

        ret.insert(1, schema["ele_socu"])
        return ret

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create a debug credential object out of yaml configuration.

        :param config: Debug credential file configuration.

        :return: DebugCredential object
        """
        family = FamilyRevision.load_from_config(config)
        db = get_db(family=family)
        use_beacon = db.get_bool(DatabaseManager.DAT, "used_beacons_on_ele", False)
        vu_instead_fuse_version = db.get_bool(DatabaseManager.DAT, "vu_instead_fuse_version", False)
        socc = get_db(family).get_int(DatabaseManager.DAT, "socc")
        socu = value_to_int(config.pop("cc_socu", 0))
        beacon = value_to_int(config.pop("cc_beacon", 0)) if use_beacon else 0
        config["permissions"] = ["debug"]
        permission_data = pack("<LLL", socc, socu, beacon)
        config["permission_data"] = permission_data
        if vu_instead_fuse_version and "cc_vendor_usage" in config:
            config["fuse_version"] = config.get_int("cc_vendor_usage", 0)

        dc = get_ahab_certificate_class(family).load_from_config(config)
        return cls(certificate=dc, family=family)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :param family: Mandatory family name.
        :return: DebugCredential object
        """
        return cls(
            family=family, certificate=get_ahab_certificate_class(family).parse(data, family)
        )

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider."""
        self.certificate.update_fields()

    def export(self) -> bytes:
        """Export to binary form (serialization)."""
        return self.certificate.export()

    def calculate_hash(self) -> bytes:
        """Calculate the RoT hash."""
        return b""

    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        :return: binary representing the RoT key
        """
        return b""

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: binary representing the DCK key
        """
        return b""

    def _get_data_to_sign(self) -> bytes:
        """Get data to be signed."""
        return b""

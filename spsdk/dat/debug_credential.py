#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with DebugCredential class."""

import abc
import logging
import math
import os
from collections import OrderedDict
from dataclasses import dataclass
from struct import calcsize, pack, unpack, unpack_from
from typing import Any, Optional, Type, Union

from typing_extensions import Self

from spsdk import SPSDK_DATA_FOLDER
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import (
    SPSDKError,
    SPSDKKeyError,
    SPSDKNotImplementedError,
    SPSDKTypeError,
    SPSDKValueError,
)
from spsdk.image.ahab.ahab_certificate import AhabCertificate
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKRecordV2, SRKTable
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import Endianness, value_to_int
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


@dataclass
class ProtocolVersion:
    """Debug Authentication protocol version."""

    VERSIONS = [
        "1.0",
        "1.1",
        "2.0",
        "2.1",
        "2.2",
    ]

    version: str

    def __post_init__(self) -> None:
        self.validate()

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, self.__class__) and self.major == obj.major and self.minor == obj.minor
        )

    def __str__(self) -> str:
        """String representation of protocol version object."""
        return f"Version {self.major}.{self.minor}"

    def __repr__(self) -> str:
        return self.__str__()

    def is_rsa(self) -> bool:
        """Determine whether rsa or ecc is used.

        :return: True if the protocol is RSA type. False otherwise
        """
        return self.major == 1

    def validate(self) -> None:
        """Validate the protocol version value.

        :raises SPSDKValueError: In case that protocol version is using unsupported key type.
        """
        if self.version not in self.VERSIONS:
            raise SPSDKValueError(
                f"Unsupported version '{self.version}' was given. Available versions: {','.join(self.VERSIONS)}"
            )

    @property
    def major(self) -> int:
        """Get major version."""
        return int(self.version.split(".", 2)[0])

    @property
    def minor(self) -> int:
        """Get minor version."""
        return int(self.version.split(".", 2)[1])

    @classmethod
    def from_version(cls, major: int, minor: int) -> Self:
        """Load the version object from major and minor version."""
        dat_protocol = cls(f"{major}.{minor}")
        dat_protocol.validate()
        return dat_protocol

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> Self:
        """Load the version object from public key."""
        if isinstance(public_key, PublicKeyRsa):
            minor = {2048: 0, 4096: 1}[public_key.key_size]
            return cls.from_version(major=1, minor=minor)
        if isinstance(public_key, PublicKeyEcc):
            minor = {256: 0, 384: 1, 521: 2}[public_key.key_size]
            return cls.from_version(major=2, minor=minor)
        raise SPSDKTypeError(f"Unsupported public key type: {type(public_key)}")


class DebugCredentialCertificate:
    """Base class for DebugCredentialCertificate."""

    def __init__(
        self,
        version: ProtocolVersion,
        socc: int,
        uuid: bytes,
        rot_meta: "RotMeta",
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
        self.version = version
        self.socc = socc
        self.uuid = uuid
        self.rot_meta = rot_meta
        self.dck_pub = dck_pub
        self.cc_socu = cc_socu
        self.cc_vu = cc_vu
        self.cc_beacon = cc_beacon
        self.rot_pub = rot_pub
        self.signature = signature
        self.signature_provider = signature_provider

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

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Calculate the RoT hash."""

    @abc.abstractmethod
    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the debug credential certificate
        """

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

    @staticmethod
    def get_socc_list() -> dict[int, dict[str, list[str]]]:
        """Get supported SOCC list."""
        data: dict[int, dict[str, list[str]]] = {}
        # Get the SOCC information from the database
        DatabaseManager().db.devices.load_devices_from_path(
            os.path.join(SPSDK_DATA_FOLDER, "devices")
        )  # TODO This will be removed in SPSDK 2.4 when the family will be mandatory !!!!
        for dev, rev, socc in DatabaseManager().db.devices.feature_items(
            DatabaseManager.DAT, "socc"
        ):
            data.setdefault(value_to_int(socc), {}).setdefault(dev, []).append(rev)

        # Sort the all items to be nice list (also nested)
        ret: dict[int, dict[str, list[str]]] = OrderedDict()
        for socc in sorted(data):
            ret[socc] = OrderedDict()
            for dev in sorted(data[socc]):
                ret[socc][dev] = sorted(data[socc][dev])

        return ret

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
    def get_family_ambassador(socc: Union[int, str]) -> str:
        """Get family ambassador for given SOCC.

        :param socc: SOCC value
        :return: Ambassador family name
        """
        socc = value_to_int(socc)
        socc_list = DebugCredentialCertificate.get_socc_list()
        try:
            supported_families: dict[str, list[str]] = socc_list[socc]
        except KeyError as exc:
            raise SPSDKKeyError(f"Unsupported SOCC(0x{socc:08X}) by DAT tool") from exc
        return supported_families.popitem()[0]

    @staticmethod
    def dat_based_on_ele(family: str) -> bool:
        """Get information if the DAT is based on EdgeLock Enclave hardware.

        :param family: The chip family name
        :return: True if the ELE is target HW, False otherwise
        """
        return get_db(family).get_bool(DatabaseManager.DAT, "based_on_ele", False)

    @staticmethod
    def _get_class(
        family: str, version: Optional[ProtocolVersion] = None, revision: str = "latest"
    ) -> Type["DebugCredentialCertificate"]:
        db = get_db(family, revision)
        if db.get_bool(DatabaseManager.DAT, "based_on_ele", False):
            # TODO Dirty hack, remove in SPSDK 2.4 when family and revision will be mandatory
            if version and version == ProtocolVersion("2.0"):
                return DebugCredentialEdgeLockEnclave
            cnt_ver = db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1)
            if cnt_ver == 1:
                return DebugCredentialEdgeLockEnclave
            if cnt_ver == 2:
                return DebugCredentialEdgeLockEnclaveV2
            raise SPSDKValueError(f"Unsupported ELE container version {cnt_ver} for {family}")
        if version is None:
            raise SPSDKValueError(
                "Cannot determine the Debug Credential class "
                f"without specified protocol for {family}"
            )
        if version.is_rsa():
            return DebugCredentialCertificateRsa
        return DebugCredentialCertificateEcc

    @staticmethod
    def _get_class_from_cfg(
        config: dict[str, Any],
        family: str,
        search_paths: Optional[list[str]],
        revision: str = "latest",
    ) -> Type["DebugCredentialCertificate"]:
        if "rot_meta" in config:
            cfg_path = config["rot_meta"][0]
        else:
            cfg_path = config["public_key_0"]

        rot_pub = extract_public_key(file_path=cfg_path, search_paths=search_paths)
        version = ProtocolVersion.from_public_key(public_key=rot_pub)
        return DebugCredentialCertificate._get_class(
            family=family, version=version, revision=revision
        )

    @staticmethod
    def _get_rot_meta_class(
        version: ProtocolVersion, family: str, revision: str = "latest"
    ) -> Type["RotMeta"]:
        dc_class = DebugCredentialCertificate._get_class(
            family=family, version=version, revision=revision
        )
        return {
            DebugCredentialCertificateEcc: RotMetaEcc,
            DebugCredentialCertificateRsa: RotMetaRSA,
            DebugCredentialEdgeLockEnclave: RotMetaEdgeLockEnclave,
            DebugCredentialEdgeLockEnclaveV2: RotMeta,
        }[dc_class]

    @classmethod
    def create_from_yaml_config(
        cls,
        config: dict[str, Any],
        version: Optional[ProtocolVersion] = None,
        search_paths: Optional[list[str]] = None,
    ) -> "DebugCredentialCertificate":
        """Create a debug credential object out of yaml configuration.

        :param version: Debug Authentication protocol version.
        :param config: Debug credential file configuration.
        :param search_paths: List of paths where to search for the file, defaults to None

        :return: DebugCredential object
        """
        family = config.get("family")
        if family:
            revision = config.get("revision", "latest")
            socc = cls.get_socc_by_family(family=family, revision=revision)
        else:
            socc = value_to_int(config["socc"])
            family = cls.get_family_ambassador(socc)
            revision = "latest"
            logger.warning(
                "Running loading of debug credential configuration file "
                "on backward compatibility mode. Please update your configuration"
                "file to use family/revision of chip instead of using SOCC value. "
                f"Used SOCC (0x{socc:08X}) has been converted to chip ambassador "
                f" family '{family}'"
            )
        rot_pub = extract_public_key(
            file_path=config["rot_meta"][value_to_int(config["rot_id"])],
            search_paths=search_paths,
        )
        if version is None:
            version = ProtocolVersion.from_public_key(public_key=rot_pub)
            logger.info(
                f"Protocol version not defined. The version {version.version} has been determined from RoT public key"
            )
        klass = DebugCredentialCertificate._get_class(
            family=family, version=version, revision=revision
        )
        rot_meta_class = DebugCredentialCertificate._get_rot_meta_class(
            version=version, family=family, revision=revision
        )
        try:
            pss_padding = get_db(family).get_bool(DatabaseManager.SIGNING, "pss_padding")
        except SPSDKValueError:
            pss_padding = False

        signature_provider = get_signature_provider(
            sp_cfg=config.get("sign_provider"),
            local_file_key=config.get("rotk"),
            search_paths=search_paths,
            pss_padding=pss_padding,
        )
        dc_obj = klass(
            version=version,
            socc=socc,
            uuid=bytes.fromhex(config["uuid"]),
            rot_meta=rot_meta_class.load_from_config(config, search_paths),
            dck_pub=extract_public_key(config["dck"], search_paths=search_paths),
            cc_socu=value_to_int(config["cc_socu"]),
            cc_vu=value_to_int(config["cc_vu"]),
            cc_beacon=value_to_int(config["cc_beacon"]),
            rot_pub=rot_pub,
            signature_provider=signature_provider,
        )
        return dc_obj

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :return: DebugCredential object
        """
        # The  ELE V2 is totally different to standard DC - try it first and if fail let do the standard process
        try:
            return DebugCredentialEdgeLockEnclaveV2.parse(data)  # type:ignore
        except SPSDKError:
            pass
        ver = unpack_from("<2H", data)
        socc = unpack_from("<L", data, 4)

        klass = cls._get_class(
            family=cls.get_family_ambassador(socc[0]),
            version=ProtocolVersion.from_version(ver[0], ver[1]),
        )
        return klass.parse(data)  # type: ignore

    @classmethod
    def get_supported_families(cls) -> list[str]:
        """Get all supported families for DAT.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.DAT)

    @staticmethod
    def get_socc_by_family(family: str, revision: str = "latest") -> int:
        """Get corresponding SOCC by family.

        :param family: Family for what will be socc value selected.
        :param revision: For a closer specify MCU family.
        :raises SPSDKValueError: Unsupported family or revision
        :return: SOCC value.
        """
        try:
            return get_db(family, revision).get_int(DatabaseManager.DAT, "socc")
        except SPSDKError as exc:
            raise SPSDKValueError(
                f"Unsupported family {family} or revision {revision} to get SOCC. Details:\n{str(exc)}"
            ) from exc

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for what will be json schema generated.
        :param revision: For a closer specify MCU family.
        :return: Validation list of schemas.
        """
        schema = get_schema_file(DatabaseManager.DAT)
        sch_family: dict[str, Any] = get_schema_file("general")["family"]
        sch_family.pop("required")
        ret = []
        socc = DebugCredentialCertificate.get_socc_by_family(family, revision)
        schema["dc_content"]["properties"]["socc"]["template_value"] = hex(socc)
        update_validation_schema_family(
            sch_family["properties"],
            devices=DebugCredentialCertificate.get_supported_families(),
            family=family,
            revision=revision,
        )

        ret.append(sch_family)
        ret.append(schema["dc_content"])
        if get_db(family, revision).get_bool(DatabaseManager.DAT, "based_on_ele", False):
            ret.append(schema["dc_srk_ca_flag"])
        return ret

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate DC configuration template.

        :param family: Family for what will be template generated.
        :param revision: For a closer specify MCU family.
        :return: DC file template.
        """
        val_schemas = DebugCredentialCertificate.get_validation_schemas(family, revision)
        schema = get_schema_file(DatabaseManager.DAT)

        note = schema["main_note"]

        return CommentedConfig(
            main_title=f"Debug Credential file template for {family} family.",
            schemas=val_schemas,
            note=note,
        ).get_template()


class DebugCredentialCertificateRsa(DebugCredentialCertificate):
    """Class for RSA specific of DebugCredentialCertificate."""

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
    def parse(cls, data: bytes) -> Self:
        """Parse Debug credential serialized data.

        :return: Instance of this class.
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
        return cls(
            version=version,
            socc=socc,
            uuid=uuid,
            rot_meta=RotMetaRSA.parse(rot_meta),
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=cc_beacon,
            rot_pub=PublicKey.parse(rot_pub),
            signature=signature,
        )

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

    @property
    def rot_hash_length(self) -> int:
        """Root of Trust  debug credential hash length."""
        db = get_db(self.get_family_ambassador(self.socc))
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
    def parse(cls, data: bytes) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
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

        return cls(
            version=version,
            socc=socc,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            rot_pub=PublicKey.parse(rot_pub),
            signature=signature,
        )


class DebugCredentialEdgeLockEnclave(DebugCredentialCertificateEcc):
    """EdgeLock Class."""

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
    def parse(cls, data: bytes) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :return: DebugCredential object
        :raises SPSDKError: When flag is invalid
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

        return cls(
            version=version,
            socc=socc,
            uuid=uuid,
            rot_meta=rot_meta,
            dck_pub=PublicKey.parse(dck_pub),
            cc_socu=cc_socu,
            cc_vu=cc_vu,
            cc_beacon=beacon,
            rot_pub=rot_pub,
            signature=signature,
        )


class DebugCredentialEdgeLockEnclaveV2(DebugCredentialCertificate):
    """Debug Credential file for ELE version 2 (with PQC support)."""

    def __init__(self, certificate: AhabCertificate) -> None:
        """Constructor for EdgeLock Enclave version 2 debug credential class."""
        self.certificate = certificate
        assert isinstance(certificate.public_key_0, SRKRecordV2)
        super().__init__(
            version=ProtocolVersion("2.0"),  # Dummy version - is not used in DC data
            socc=0,
            uuid=certificate._uuid or b"",
            rot_meta=RotMetaDummy(),
            dck_pub=certificate.public_key_0.get_public_key(),
            cc_socu=0,
            cc_vu=0,
            cc_beacon=0,
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
        # msg += f" BEACON  : {self.cc_beacon}\n "
        msg += str(self.certificate)
        return msg

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
    def get_supported_families(cls) -> list[str]:
        """Get all supported families for DAT.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.DAT, "ele_pqc")

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for what will be json schema generated.
        :param revision: For a closer specify MCU family.
        :return: Validation list of schemas.
        """
        ret = AhabCertificate.get_validation_schemas(family, revision)
        schema = get_schema_file(DatabaseManager.DAT)
        ret[0]["properties"]["family"][
            "enum"
        ] = DebugCredentialEdgeLockEnclaveV2.get_supported_families()

        ret[1]["properties"].pop("permissions")
        ret[1]["required"].remove("permissions")
        ret[1]["properties"].pop("permission_data")
        ret.insert(1, schema["ele_socu"])
        return ret

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate DC configuration template.

        :param family: Family for what will be template generated.
        :param revision: For a closer specify MCU family.
        :return: DC file template.
        """
        val_schemas = DebugCredentialEdgeLockEnclaveV2.get_validation_schemas(family, revision)
        # schema = get_schema_file(DatabaseManager.DAT)

        # note = schema["main_note"]

        return CommentedConfig(
            main_title=f"Debug Credential file template for {family} family.",
            schemas=val_schemas,
            # note=note,
        ).get_template()

    @classmethod
    def create_from_yaml_config(
        cls,
        config: dict[str, Any],
        version: Optional[ProtocolVersion] = None,
        search_paths: Optional[list[str]] = None,
    ) -> "DebugCredentialCertificate":
        """Create a debug credential object out of yaml configuration.

        :param version: Debug Authentication protocol version.
        :param config: Debug credential file configuration.
        :param search_paths: List of paths where to search for the file, defaults to None

        :return: DebugCredential object
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        socc = cls.get_socc_by_family(family=family, revision=revision)
        socu = value_to_int(config.pop("cc_socu", 0))
        config["permissions"] = ["debug"]
        permission_data = pack("<LLL", socc, socu, 0)
        config["permission_data"] = permission_data
        dc = AhabCertificate.load_from_config(config=config, search_paths=search_paths)
        return DebugCredentialEdgeLockEnclaveV2(certificate=dc)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the debug credential.

        :param data: Raw data as bytes
        :return: DebugCredential object
        :raises SPSDKError: When flag is invalid
        """
        return cls(AhabCertificate.parse(data))

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


class RotMeta:
    """RoT meta base class."""

    @classmethod
    @abc.abstractmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMeta object
        """

    @classmethod
    @abc.abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMeta object
        """

    @abc.abstractmethod
    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """

    @abc.abstractmethod
    def __str__(self) -> str:
        """Object description in string format."""

    def __len__(self) -> int:
        """Length of exported data."""
        return len(self.export())


class RotMetaRSA(RotMeta):
    """RSA RoT meta object."""

    def __init__(self, rot_items: list[bytes]) -> None:
        """Class object initializer.

        :param rot_items: List of public key hashes
        """
        self.rot_items = rot_items

    def __str__(self) -> str:
        msg = "RSA RoT meta"
        msg += f"Number of RoT items   : {len(self.rot_items)}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return isinstance(obj, RotMetaRSA) and self.rot_items == obj.rot_items

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMetaRSA object
        """
        rot_pub_keys = config["rot_meta"]
        if len(rot_pub_keys) > 4:
            raise SPSDKValueError("The maximum number of rot public keys is 4.")
        rot_items = []
        for rot_key in rot_pub_keys:
            rot = extract_public_key(file_path=rot_key, password=None, search_paths=search_paths)
            assert isinstance(rot, PublicKeyRsa)
            data = rot.export(exp_length=3)
            rot_item = get_hash(data)
            rot_items.append(rot_item)
        return cls(rot_items)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaRSA object
        """
        if len(data) < 128:
            raise SPSDKValueError("The provided data must be 128 bytes long.")
        rot_items = []
        for index in range(0, 4):
            rot_item = data[index * 32 : (index + 1) * 32]
            if int.from_bytes(rot_item, Endianness.LITTLE.value):
                rot_items.append(rot_item)
        return cls(rot_items)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        rot_meta = bytearray(128)
        for index, rot_item in enumerate(self.rot_items):
            rot_meta[index * 32 : (index + 1) * 32] = rot_item
        return bytes(rot_meta)

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash.

        :return: RoTKH in bytes
        """
        return get_hash(data=self.export())


class RotMetaFlags:
    """Rot meta flags."""

    def __init__(self, used_root_cert: int, cnt_root_cert: int) -> None:
        """Class object initializer.

        :param used_root_cert: Index of used root certificate
        :param cnt_root_cert: Number of certificates in the RoT meta
        """
        self.used_root_cert = used_root_cert
        self.cnt_root_cert = cnt_root_cert
        self.validate()

    def validate(self) -> None:
        """Validate the flags."""
        if self.cnt_root_cert > 4:
            raise SPSDKValueError("The maximum number of certificates is 4")
        if self.used_root_cert + 1 > self.cnt_root_cert:
            raise SPSDKValueError(
                f"Used root certificate {self.used_root_cert} must be in range 0-{self.cnt_root_cert-1}."
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse flags from binary data.

        :param data: Raw data as bytes
        :returns: The RotMetaFlags object
        """
        if len(data) != 4:
            raise SPSDKValueError("Invalid data flags length to parse")
        flags = int.from_bytes(data, "little")
        if not flags & (1 << 31):
            raise SPSDKValueError("Invalid flags format to parse")
        used_root_cert = (flags >> 8) & 0x0F
        cnt_root_cert = (flags >> 4) & 0x0F
        return cls(used_root_cert, cnt_root_cert)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        flags = 0
        flags |= 1 << 31
        flags |= self.used_root_cert << 8
        flags |= self.cnt_root_cert << 4
        return pack("<L", flags)

    def __str__(self) -> str:
        msg = f"Used root cert index: {self.used_root_cert}\n"
        msg = f"Number of records in flags: {self.cnt_root_cert}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaFlags)
            and self.used_root_cert == obj.used_root_cert
            and self.cnt_root_cert == obj.cnt_root_cert
        )

    def __len__(self) -> int:
        return len(self.export())


class RotMetaEcc(RotMeta):
    """ECC RoT meta object."""

    HASH_SIZES = {32: 256, 48: 384, 66: 512}
    HASH_SIZE = 0  # to be overridden by derived class

    def __init__(self, flags: RotMetaFlags, rot_items: list[bytes]) -> None:
        """Class object initializer.

        :param flags: RotMetaFlags object
        :param rot_items: List of public key hashes
        """
        self.flags = flags
        self.rot_items = rot_items

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEcc)
            and self.flags == obj.flags
            and self.rot_items == obj.rot_items
        )

    def __str__(self) -> str:
        msg = str(self.flags)
        if self.flags.cnt_root_cert == 1:
            msg += "CRTK table not present \n"
        else:
            msg += f"CRTK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @property
    def key_size(self) -> int:
        """Key size property."""
        return self.HASH_SIZES[(len(self) - len(self.flags)) // self.flags.cnt_root_cert]

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> "RotMetaEcc":
        """Creates the RoT meta from configuration.

        :return: RotMetaEcc object
        """
        rot_pub_keys = cls._load_public_keys(config, search_paths=search_paths)
        hash_size = cls._get_hash_size(config, search_paths=search_paths)
        klass = cls._get_subclass(hash_size)
        rot_items: list[bytes] = []
        if len(rot_pub_keys) > 1:
            for pub_key in rot_pub_keys:
                data = pub_key.export()
                rot_items.append(
                    get_hash(
                        data=data,
                        algorithm=EnumHashAlgorithm.from_label(f"sha{cls.HASH_SIZES[hash_size]}"),
                    )
                )
        flags = RotMetaFlags(value_to_int(config["rot_id"]), len(rot_pub_keys))
        return klass(flags, rot_items)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        return self.flags.export() + self.export_crtk_table()

    def export_crtk_table(self) -> bytes:
        """Export CRTK table into binary form."""
        ctrk_table = b""
        if len(self.rot_items) > 1:
            for rot_item in self.rot_items:
                ctrk_table += rot_item
        return ctrk_table

    def calculate_hash(self) -> bytes:
        """Get CRKT table Hash.

        :return: CRKT table hash in bytes
        """
        crkt_table = self.export_crtk_table()
        if not crkt_table:
            raise SPSDKError("Hash cannot be calculated as crkt table is empty")
        return get_hash(
            data=crkt_table,
            algorithm=EnumHashAlgorithm.from_label(f"sha{self.key_size}"),
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaEcc object
        """
        if not cls.HASH_SIZE:
            raise SPSDKValueError("Hash size not defined.")
        flags = RotMetaFlags.parse(data[:4])
        crt_table = data[4:]
        rot_items = []
        if flags.cnt_root_cert > 1:
            for rot_item_idx in range(0, flags.cnt_root_cert):
                rot_item = crt_table[
                    rot_item_idx * cls.HASH_SIZE : (rot_item_idx + 1) * cls.HASH_SIZE
                ]
                rot_items.append(rot_item)
        return cls(flags, rot_items)

    @classmethod
    def _load_public_keys(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> list[PublicKeyEcc]:
        """Load public keys from configuration."""
        pub_key_paths = config["rot_meta"]
        if len(pub_key_paths) < 1:
            raise SPSDKValueError("At least one public key must be specified.")
        pub_keys: list[PublicKeyEcc] = []
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=search_paths
            )
            if not isinstance(pub_key, PublicKeyEcc):
                raise SPSDKTypeError("Public key must be of ECC type.")
            pub_keys.append(pub_key)
        return pub_keys

    @classmethod
    def _get_hash_size(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> int:
        hash_size = None
        pub_key_paths = config["rot_meta"]
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=search_paths
            )
            assert isinstance(pub_key, PublicKeyEcc)
            if not hash_size:
                hash_size = math.ceil(pub_key.key_size / 8)
            if hash_size != math.ceil(pub_key.key_size / 8):
                raise SPSDKValueError("All public keys must be of a same length")
        if not hash_size:
            raise SPSDKError("Hash size could not be determined.")
        return hash_size

    @classmethod
    def _get_subclass(cls, hash_size: int) -> Type["RotMetaEcc"]:
        """Get the subclass with given hash algorithm."""
        subclasses: list[Type[RotMetaEcc]] = cls._build_subclasses()
        for subclass in subclasses:
            if subclass.HASH_SIZE == hash_size:
                return subclass
        raise SPSDKValueError(f"The subclass with hash length {hash_size} does not exist.")

    @classmethod
    def _build_subclasses(cls) -> list[Type["RotMetaEcc"]]:
        """Dynamically build list of classes based on hash algorithm."""
        rot_meta_types = []
        for hash_size, hash_algo in cls.HASH_SIZES.items():
            subclass = type(f"RotMetaEcc{hash_algo}", (RotMetaEcc,), {"HASH_SIZE": hash_size})
            rot_meta_types.append(subclass)
        return rot_meta_types


class RotMetaEdgeLockEnclave(RotMeta):
    """ELE RoT meta object."""

    def __init__(self, flags: RotMetaFlags, srk_table: SRKTable) -> None:
        """Class object initializer.

        :param flags: RotMetaFlags object
        :param srk_table: SRKTable object
        """
        self.flags = flags
        self.srk_table = srk_table

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEdgeLockEnclave)
            and self.flags == obj.flags
            and self.srk_table == obj.srk_table
        )

    def __str__(self) -> str:
        msg = str(self.flags)
        if self.flags.cnt_root_cert != 4:
            msg += "Invalid count of SRK records \n"
        else:
            msg += f"SRK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Raw data as bytes
        :return: RotMetaEdgeLockEnclave object
        """
        flags = RotMetaFlags.parse(data[:4])
        srk_table = SRKTable.parse(data[4:])
        srk_table.verify().validate()
        return cls(flags, srk_table)

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Creates the RoT meta from configuration.

        :return: RotMetaEdgeLockEnclave object
        """
        rot_pub_keys = config["rot_meta"]
        flags = RotMetaFlags(value_to_int(config["rot_id"]), len(rot_pub_keys))
        if len(rot_pub_keys) != 4:
            raise SPSDKValueError("Invalid count of Super Root keys.")
        flag_ca = config.get("flag_ca", False)
        srk_flags = 0
        if flag_ca:
            srk_flags |= SRKRecord.FLAGS_CA_MASK

        srk_table = SRKTable(
            [
                SRKRecord.create_from_key(
                    extract_public_key(x, search_paths=search_paths), srk_flags=srk_flags
                )
                for x in rot_pub_keys
            ]
        )
        srk_table.update_fields()
        srk_table.verify().validate()
        return cls(flags, srk_table)

    def export(self) -> bytes:
        """Export to binary form.

        :return: binary representation of the object
        """
        return self.flags.export() + self.srk_table.export()

    def calculate_hash(self) -> bytes:
        """Get SRK table hash.

        :return: SRK table hash in bytes
        """
        self.srk_table.update_fields()
        return self.srk_table.compute_srk_hash()


class RotMetaDummy(RotMeta):
    """RoT meta dummy class."""

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Creates the RoT meta from configuration."""
        raise SPSDKNotImplementedError()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data."""
        raise SPSDKNotImplementedError()

    def export(self) -> bytes:
        """Export to binary form."""
        raise SPSDKNotImplementedError()

    def calculate_hash(self) -> bytes:
        """Get Root Of Trust Keys Hash."""
        raise SPSDKNotImplementedError()

    def __str__(self) -> str:
        """Object description in string format."""
        return "Dummy RoT Meta class"

    def __len__(self) -> int:
        """Length of exported data."""
        return 0

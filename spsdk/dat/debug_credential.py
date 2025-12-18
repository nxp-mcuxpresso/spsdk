#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Authentication Tool (DAT) debug credential management.

This module provides functionality for creating, parsing, and managing debug
credentials used in NXP's Debug Authentication Tool. It supports various
certificate types including RSA and ECC-based credentials, as well as
EdgeLock Enclave specific implementations for secure debug access control.
"""

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
    """Debug Credential Certificate for secure device authentication.

    This class manages debug credential certificates used for secure authentication
    and authorization of debug access to NXP MCU devices. It handles the creation,
    validation, and export of debug credentials including public keys, constraints,
    and digital signatures.

    :cvar FEATURE: Database manager feature identifier for DAT operations.
    :cvar ROT_META_CLASS: Root of Trust metadata class reference.
    """

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

        Creates a new DebugCredential instance with the specified parameters for secure debug access.

        :param family: Target MCU family and revision information.
        :param version: Protocol version for the debug credential.
        :param uuid: Unique device identifier bytes.
        :param rot_meta: Metadata for Root of Trust configuration.
        :param dck_pub: Debug Credential public key for authentication.
        :param cc_socu: SoC Usage credential constraint value.
        :param cc_vu: Vendor Usage credential constraint value.
        :param cc_beacon: Credential Beacon value bound to this debug credential.
        :param rot_pub: Root of Trust public key for verification.
        :param signature: Optional pre-computed debug credential signature.
        :param signature_provider: Optional external signature provider for signing.
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
        """Get the SoC Class value for the current family.

        Retrieves the SoC Class (System on Chip Class) identifier from the database
        for the configured MCU family.

        :return: SoC Class identifier as integer value.
        """
        return get_db(self.family).get_int(DatabaseManager.DAT, "socc")

    def __str__(self) -> str:
        """String representation of DebugCredential.

        Creates a formatted string containing all debug credential information including
        version, SOCC, UUID, control codes, beacon status, and root of trust metadata.

        :return: Formatted string representation of the debug credential.
        """
        msg = f"Version : {self.version}\n"
        msg += f"SOCC    : 0x{self.socc:08X}\n"
        msg += f"UUID    : {self.uuid.hex().upper()}\n"
        msg += f"CC_SOCC : {hex(self.cc_socu)}\n"
        msg += f"CC_VU   : {hex(self.cc_vu)}\n"
        msg += f"BEACON  : {self.cc_beacon}\n"
        msg += str(self.rot_meta)
        return msg

    def __repr__(self) -> str:
        """Return string representation of Debug Credential object.

        Provides a concise string representation showing the version and SOCC value
        in hexadecimal format for debugging and logging purposes.

        :return: String representation in format "DC {version}, 0x{socc:08X}".
        """
        return f"DC {self.version}, 0x{self.socc:08X}"

    @property
    def rot_hash_length(self) -> int:
        """Get Root of Trust debug credential hash length.

        :return: Hash length in bytes (always 32).
        """
        return 32

    @property
    def srk_count(self) -> int:
        """Get the number of Super Root Keys (SRK).

        :return: Number of Super Root Keys, always returns 1.
        """
        return 1

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Calculate the RoT hash.

        :return: The calculated RoT (Root of Trust) hash as bytes.
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
        """Get data to be signed.

        :return: Raw bytes data that needs to be signed for the debug credential.
        """

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider.

        This method validates that a signature provider is configured, verifies the public key
        against the root of trust, generates a signature for the debug credential data, and
        stores the resulting signature.

        :raises SPSDKError: If signature provider is not set or fails to return a signature.
        """
        if not self.signature_provider:
            raise SPSDKError("Debug Credential Signature provider is not set")
        self.signature_provider.try_to_verify_public_key(self.rot_pub)
        signature = self.signature_provider.get_signature(self._get_data_to_sign())
        if not signature:
            raise SPSDKError("Debug Credential Signature provider didn't return any signature")
        self.signature = signature

    def _vars(self) -> dict[str, Any]:
        """Get instance variables dictionary without signature provider.

        Creates a copy of the instance's __dict__ and removes the signature_provider
        attribute to avoid exposing sensitive signing functionality in variable dumps.

        :return: Dictionary of instance variables excluding signature_provider.
        """
        v = vars(self).copy()
        del v["signature_provider"]
        return v

    @staticmethod
    def dat_based_on_ele(family: FamilyRevision) -> bool:
        """Get information if the DAT is based on EdgeLock Enclave hardware.

        :param family: The chip family and revision information.
        :return: True if the ELE is target HW, False otherwise.
        """
        return get_db(family).get_bool(DatabaseManager.DAT, "based_on_ele", False)

    @classmethod
    def _get_class(
        cls, family: FamilyRevision, version: Optional[ProtocolVersion] = None
    ) -> Type[Self]:
        """Get the appropriate debug credential class for the given family and protocol version.

        This method determines which debug credential implementation to use based on the
        device family configuration and protocol version. It handles EdgeLock Enclave
        based devices as well as RSA and ECC certificate-based implementations.

        :param family: Target device family and revision.
        :param version: Protocol version to determine credential type, optional for ELE-based devices.
        :raises SPSDKValueError: When ELE container version is unsupported or protocol version
            is required but not provided.
        :return: Debug credential class type appropriate for the given parameters.
        """
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
        """Get the appropriate class type based on configuration settings.

        Determines the correct debug credential class by analyzing the family configuration
        and protocol version. For ELE-based families, uses the container version from database.
        For other families, extracts the protocol version from the public key.

        :param config: Configuration object containing family and key information.
        :raises SPSDKValueError: When unsupported ELE container version is encountered.
        :return: Class type appropriate for the specified family and protocol version.
        """
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
        """Create a debug credential object from YAML configuration.

        This method processes the configuration to extract family information, ROT metadata,
        certificates, and signing parameters to construct a complete debug credential object.

        :param config: Debug credential file configuration containing all necessary parameters.
        :raises SPSDKError: Invalid configuration or missing required files.
        :return: DebugCredential object configured according to the provided settings.
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

        The method supports loading from both Root of Trust configuration files and binary
        certificate block files. It first attempts to parse as a configuration file, and if
        that fails, tries to parse as a binary certificate block.

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
        """Get configuration for debug credential.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented yet.
        """
        raise SPSDKNotImplementedError

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential from raw binary data.

        The method first attempts to parse as EdgeLock Enclave V2 format, and if that fails,
        falls back to standard debug credential parsing based on the protocol version found
        in the data header.

        :param data: Raw binary data containing the debug credential.
        :param family: Target MCU family revision for credential validation.
        :raises SPSDKError: When data cannot be parsed as any supported debug credential format.
        :return: Parsed DebugCredential object of the appropriate subclass.
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
        """Get validation schemas based on configuration.

        Retrieves the appropriate validation schemas for the debug credential class
        by first validating the provided configuration against basic schemas, then
        determining the specific class implementation and returning its validation
        schemas for the target family.

        :param config: Configuration object containing debug credential settings
        :return: List of validation schema dictionaries for the determined class
        :raises SPSDKError: Invalid configuration or unsupported family
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls._get_class_from_cfg(config).get_validation_schemas(family)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for debug credential configuration.

        Retrieves and configures JSON validation schemas specific to the given family,
        including family-specific properties, SOCC values, and conditional schemas
        based on ELE (EdgeLock Enclave) support.

        :param family: Family revision for which the JSON schemas will be generated.
        :return: List of validation schemas including family schema, content schema,
                 and optionally SRK CA flag schema for ELE-based families.
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
    """RSA-specific implementation of Debug Credential Certificate.

    This class provides RSA cryptographic operations for debug credential certificates,
    including RSA key handling, hash calculations, and RSA-specific data export formats.

    :cvar ROT_META_CLASS: RSA-specific Root of Trust metadata class type.
    """

    ROT_META_CLASS: TypeAlias = RotMetaRSA

    def __str__(self) -> str:
        """Get string representation of the debug credential.

        The method extends the parent class string representation by adding
        the Root of Trust Key Hash (RoTKH) calculated from the credential data.

        :return: String representation including RoTKH hash in hexadecimal format.
        """
        msg = super().__str__()
        msg += f"RoTKH   : {self.calculate_hash().hex()}\n"
        return msg

    def calculate_hash(self) -> bytes:
        """Calculate Root Of Trust Keys Hash.

        This method computes the hash of the Root of Trust keys using the associated
        rotation metadata.

        :return: Root Of Trust Keys Hash (RoTKH) as bytes.
        """
        return self.rot_meta.calculate_hash()

    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        The method exports the Root of Trust (RoT) public key in binary format
        with a 4-byte exponent length.

        :raises AssertionError: If the RoT public key is not an RSA public key.
        :return: Binary representation of the RoT public key.
        """
        assert isinstance(self.rot_pub, PublicKeyRsa)
        return self.rot_pub.export(exp_length=4)

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        The method exports the Debug Credential Key (DCK) public key component
        in binary format with a 4-byte exponent length.

        :raises AssertionError: If the DCK public key is not an RSA key instance.
        :return: Binary representation of the DCK public key.
        """
        assert isinstance(self.dck_pub, PublicKeyRsa)
        return self.dck_pub.export(exp_length=4)

    @classmethod
    def get_data_format(cls, version: ProtocolVersion, include_signature: bool = True) -> str:
        """Get the format of exported binary data.

        Constructs a struct format string for packing/unpacking debug credential binary data
        based on the protocol version and signature inclusion requirements.

        :param version: Protocol version that determines key and signature sizes.
        :param include_signature: Whether to include signature field in the format.
        :return: Struct format string for binary data packing/unpacking.
        """
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
        """Export debug credential to binary form.

        Serializes the debug credential object into its binary representation that can be
        used for provisioning or storage purposes.

        :return: Binary representation of the debug credential.
        :raises SPSDKError: When debug credential signature is not set, call the `sign` method first.
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
        """Parse the debug credential from raw binary data.

        The method extracts and validates all components of a debug credential including
        version, UUID, rotation metadata, public keys, capability constraints, and signature.
        It also validates that the parsed SOCC matches the expected family SOCC.

        :param data: Raw binary data containing the debug credential
        :param family: Target MCU family revision for validation
        :raises SPSDKValueError: When parsed SOCC doesn't match expected family SOCC
        :return: Parsed DebugCredential object with all extracted components
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
        """Get data to be signed for debug credential.

        Collects and packs all the debug credential fields into a binary format
        suitable for cryptographic signing. This includes version information,
        SOCC, UUID, RoT metadata, DCK public key, challenge-response data,
        and RoT public key.

        :return: Packed binary data ready for signing.
        """
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

        Compare this DebugCredentialCertificateRsa instance with another object to determine if they
        are equal based on their internal variables.

        :param other: Object to compare with this instance.
        :return: True if other is a DebugCredentialCertificateRsa with matching internal variables,
                 False otherwise.
        """
        return isinstance(other, DebugCredentialCertificateRsa) and self._vars() == other._vars()


class DebugCredentialCertificateEcc(DebugCredentialCertificate):
    """ECC-specific Debug Credential Certificate implementation.

    This class provides ECC (Elliptic Curve Cryptography) specific functionality for debug
    credential certificates, handling ECC key operations, hash calculations, and certificate
    data formatting for NXP MCU debug authentication.

    :cvar COORDINATE_SIZE: ECC coordinate sizes mapping for different curve types.
    :cvar ROT_META_CLASS: Root of Trust metadata class for ECC operations.
    """

    COORDINATE_SIZE = {0: 32, 1: 48, 2: 66}
    ROT_META_CLASS: TypeAlias = RotMetaEcc

    @property
    def rot_hash_length(self) -> int:
        """Get Root of Trust debug credential hash length.

        The method determines the hash length based on database configuration and public key size.
        If the database specifies SHA256 usage, returns 32 bytes. Otherwise, calculates the length
        from the ECC public key size.

        :return: Hash length in bytes (32 for SHA256 or calculated from key size).
        :raises AssertionError: If rot_pub is not an instance of PublicKeyEcc.
        """
        db = get_db(self.family)
        if db.get_bool(DatabaseManager.DAT, "dat_is_using_sha256_always", False):
            return 32
        assert isinstance(self.rot_pub, PublicKeyEcc)
        return self.rot_pub.key_size // 8

    def __str__(self) -> str:
        """Get string representation of the debug credential.

        The method extends the parent class string representation by adding
        the CTRK (Credential Tool Root Key) hash information.

        :return: String representation including CTRK hash.
        """
        msg = super().__str__()
        msg += f"CTRK hash   : {self.calculate_hash().hex()}\n"
        return msg

    def calculate_hash(self) -> bytes:
        """Calculate the Root of Trust Keys Hash (RoTKH).

        The method first attempts to calculate the hash using the rot_meta object.
        If that fails, it falls back to calculating the hash directly from the
        exported public key using the appropriate SHA algorithm based on key size.

        :raises SPSDKError: When rot_meta hash calculation fails and fallback is used.
        :return: Root of Trust Keys Hash as bytes.
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

        :return: Binary data representing the RoT public key.
        """
        assert isinstance(self.rot_pub, PublicKeyEcc)
        return self.rot_pub.export()

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: Binary representing the DCK key.
        """
        return self.dck_pub.export()

    def get_data_format(self, include_signature: bool = True) -> str:
        """Get the format of exported binary data.

        Returns a struct format string that describes the binary layout of the debug
        credential data, including version, SOCC, UUID, control codes, metadata,
        public keys, and optionally the signature.

        :param include_signature: Whether to include signature in the format string.
        :raises SPSDKError: When signature is requested but not set.
        :return: Struct format string for binary data packing.
        """
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
        """Export debug credential to binary format.

        Serializes the debug credential object into its binary representation for storage
        or transmission. The credential must be signed before export.

        :raises SPSDKError: If the debug credential signature is not set.
        :return: Binary representation of the debug credential.
        """
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
        """Get data meant for signing.

        Collects and packs all debug credential data fields that need to be signed,
        excluding the signature itself. The data is packed according to the credential
        format specification.

        :return: Packed binary data ready for signing.
        """
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

        Compare this DebugCredentialCertificateEcc instance with another object to determine if they
        are equal based on their internal variables.

        :param other: Object to compare with this instance.
        :return: True if other is a DebugCredentialCertificateEcc with matching internal variables,
            False otherwise.
        """
        return isinstance(other, DebugCredentialCertificateEcc) and self._vars() == other._vars()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential from binary data.

        This method deserializes binary data into a DebugCredential object by unpacking
        the structured format and validating the SOCC (SoC Class) value
        against the family-specific SOCC.

        :param data: Raw binary data containing the debug credential structure.
        :param family: Target MCU family revision for validation purposes.
        :raises SPSDKValueError: When SOCC from binary data doesn't match family SOCC.
        :return: Parsed DebugCredential object with all fields populated.
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
    """Debug credential implementation for EdgeLock Enclave devices.

    This class provides specialized debug credential functionality for NXP EdgeLock
    Enclave secure elements, handling ECC-based authentication and credential
    management with EdgeLock-specific Root of Trust metadata.

    :cvar ROT_META_CLASS: Root of Trust metadata class for EdgeLock Enclave.
    """

    ROT_META_CLASS: TypeAlias = RotMetaEdgeLockEnclave

    @property
    def rot_hash_length(self) -> int:
        """Root of Trust debug credential hash length.

        :return: Hash length in bytes (always 32).
        """
        return 32

    def calculate_hash(self) -> bytes:
        """Calculate Root Of Trust Keys Hash.

        This method computes the hash of the Root Of Trust keys using the
        associated metadata.

        :return: Root Of Trust Keys Hash (RoTKH) as bytes.
        """
        return self.rot_meta.calculate_hash()

    def get_data_format(self, include_signature: bool = True) -> str:
        """Get the format of exported binary data.

        Constructs a struct format string for packing the debug credential data into binary format.
        The format includes version, SOCC, UUID, control codes, RoT metadata, DCK public key,
        and optionally the signature.

        :param include_signature: Whether to include signature in the format string.
        :raises SPSDKError: If signature is requested but not set.
        :return: Struct format string for binary data packing.
        """
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
        """Export debug credential to binary format for storage or transmission.

        Serializes the debug credential object into its binary representation according to
        the specified data format. The credential must be properly signed before export.

        :raises SPSDKError: Debug credential signature is not set.
        :return: Binary representation of the debug credential.
        """
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
        """Get data that needs to be signed for the debug credential.

        This method collects and packs all the necessary fields from the debug credential
        that must be included in the signature calculation, excluding the signature itself.

        :return: Packed binary data ready for signing.
        """
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

        Compare this DebugCredentialEdgeLockEnclave instance with another object to determine if they
        are equal based on their internal variables.

        :param other: Object to compare with this instance.
        :return: True if other is a DebugCredentialEdgeLockEnclave with matching internal variables,
                 False otherwise.
        """
        return isinstance(other, DebugCredentialEdgeLockEnclave) and self._vars() == other._vars()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse the debug credential from binary data.

        The method parses binary data containing a debug credential structure,
        validates the SOCC (SoC Class) value against the family,
        and constructs a DebugCredential object with all parsed components.

        :param data: Raw binary data containing the debug credential structure.
        :param family: Target MCU family revision for validation.
        :raises SPSDKValueError: When SOCC from binary data doesn't match family SOCC.
        :return: Parsed DebugCredential object with all components initialized.
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
    """Debug Credential for EdgeLock Enclave version 2 with Post-Quantum Cryptography support.

    This class represents a debug credential specifically designed for EdgeLock Enclave (ELE)
    version 2, which includes support for Post-Quantum Cryptography (PQC). It manages the
    creation and validation of debug credentials used for secure debugging operations on
    NXP MCUs with ELE v2 security subsystem.

    :cvar SUB_FEATURE: Feature identifier for ELE with PQC support.
    :cvar ROT_META_CLASS: Root of Trust metadata class used for this credential type.
    """

    SUB_FEATURE = "ele_pqc"
    ROT_META_CLASS = RotMetaDummy

    def __init__(self, family: FamilyRevision, certificate: AhabCertificate) -> None:
        """Constructor for EdgeLock Enclave version 2 debug credential class.

        Initializes a debug credential instance with the specified family revision and certificate.
        The certificate must contain a valid SRKRecordV2 public key.

        :param family: Target MCU family and revision information.
        :param certificate: AHAB certificate containing the public key and UUID for the credential.
        :raises AssertionError: If certificate.public_key_0 is not an instance of SRKRecordV2.
        """
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
        """Check equality between two DebugCredentialEdgeLockEnclaveV2 instances.

        Compares two debug credential objects by checking if their certificates are equal.
        Only returns True if the compared object is of the same type and has an identical
        certificate.

        :param value: Object to compare with this debug credential instance.
        :return: True if objects are equal, False otherwise.
        """
        if not isinstance(value, DebugCredentialEdgeLockEnclaveV2):
            return False
        return self.certificate == value.certificate

    def __str__(self) -> str:
        """Get string representation of DebugCredential.

        Returns a formatted string containing the debug credential information
        including SOCC, CC_SOCU, BEACON values and certificate details.

        :return: Formatted string representation of the debug credential.
        """
        msg = "Debug Credential for ELE v2 :\n"
        msg += f" SOCC    : {hex(self.socc)}\n"
        msg += f" CC_SOCU : {hex(self.socu)}\n"
        msg += f" BEACON  : {self.beacon}\n "
        msg += str(self.certificate)
        return msg

    @property
    def srk_count(self) -> int:
        """Get the number of Super Root Keys (SRK).

        :return: Number of Super Root Keys, currently always returns 0.
        """
        return 0

    def __repr__(self) -> str:
        """Return string representation of the Debug Credential ELE v2.

        Creates a formatted string showing the debug credential type and SOCC value
        in hexadecimal format.

        :return: String representation in format "DC ELE v2, 0x{socc:08X}".
        """
        return f"DC ELE v2, 0x{self.socc:08X}"

    @property
    def socu(self) -> int:
        """Get the SoCU (SoC Usage) field from debug credential.

        What is SoCu:
            A CC (constraint) value that is a bit mask, and whose bits are used in an SoC-specific
            manner. These bits are typically used for controlling which debug domains are
            accessed via the authentication protocol. Device-specific debug options can also be
            managed in this way.

        The SoCU field is extracted from the permission data section of the certificate
        by unpacking the first 12 bytes and returning the second 32-bit value.

        :return: SoCU field value as integer.
        """
        _, socu, _ = unpack("<LLL", self.certificate.permission_data[:12])
        return socu

    @socu.setter
    def socu(self, value: int) -> None:
        """Set the SoCU (SoC Usage) field in the debug credential.

        What is SoCu:
            A CC (constraint) value that is a bit mask, and whose bits are used in an SoC-specific
            manner. These bits are typically used for controlling which debug domains are
            accessed via the authentication protocol. Device-specific debug options can also be
            managed in this way.

        This method updates the permission data of the certificate by packing the SOCC,
        SoCU, and beacon values into a binary format.

        :param value: The SoCU value to be set in the debug credential.
        """
        self.certificate.permission_data = pack("<LLL", self.socc, value, self.beacon)

    @property
    def socc(self) -> int:
        """Get the SoCC (SoC Class) field from debug credential.

        What is SoCC:
            A unique identifier for a set of SoCs that require no SoC-specific differentiation in their
            debug authentication. The main usage is to allow a different set of debug domains
            and options to be negotiated between the device configuration and credentials. If the
            granularity of debug control warrants it, a class can contain a single revision of a single
            SoC model.

        Extracts and returns the SoCC value from the first 4 bytes of the certificate's
        permission data using little-endian byte order.

        :return: SoCC field value as integer.
        """
        socc, _, _ = unpack("<LLL", self.certificate.permission_data[:12])
        return socc

    @socc.setter
    def socc(self, value: int) -> None:
        """Set the SoCC (SoC Class) field value.

        What is SoCC:
            A unique identifier for a set of SoCs that require no SoC-specific differentiation in their
            debug authentication. The main usage is to allow a different set of debug domains
            and options to be negotiated between the device configuration and credentials. If the
            granularity of debug control warrants it, a class can contain a single revision of a single
            SoC model.

        Updates the permission data in the certificate with the new SoCC value
        while preserving the existing SOCU and beacon values.

        :param value: The SoCC field value to set.
        """
        self.certificate.permission_data = pack("<LLL", value, self.socu, self.beacon)

    @property
    def beacon(self) -> int:
        """Get the beacon value from the debug credential SOCU field.

        Extracts and returns the beacon value from the certificate's permission data
        by unpacking the third 32-bit little-endian value.

        :return: Beacon value extracted from the SOCU field.
        """
        _, _, beacon = unpack("<LLL", self.certificate.permission_data[:12])
        return beacon

    @beacon.setter
    def beacon(self, value: int) -> None:
        """Set the DC Beacon field value.

        Updates the certificate permission data with the current SOCC, SOCU, and the provided beacon value.

        :param value: The beacon value to set in the debug credential.
        """
        self.certificate.permission_data = pack("<LLL", self.socc, self.socu, value)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for Debug Credential configuration.

        The method retrieves and customizes validation schemas based on the target family,
        including AHAB certificate schemas and family-specific configurations. It handles
        special cases like beacon usage and vendor usage instead of fuse version.

        :param family: Family revision for which the JSON schema will be generated.
        :return: List of validation schemas with family-specific customizations.
        """
        ret = get_ahab_certificate_class(family).get_validation_schemas(family)
        schema = get_schema_file(DatabaseManager.DAT)
        db = get_db(family=family)
        update_validation_schema_family(
            sch=ret[0]["properties"], devices=cls.get_supported_families(), family=family
        )
        ret.pop(1)  # Remove the output container key configuration schema
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
        """Create a debug credential object from YAML configuration.

        The method processes configuration data to create a debug credential with proper
        family-specific settings, including SOCC/SOCU values, beacon configuration,
        and permission data based on the target device family capabilities.

        :param config: Debug credential file configuration containing device family,
                       SOCU value, beacon settings, and other credential parameters.
        :return: DebugCredential object configured for the specified device family.
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
        """Parse the debug credential from raw binary data.

        This method creates a DebugCredential object by parsing the provided binary data
        using the appropriate certificate class for the specified chip family.

        :param data: Raw binary data containing the debug credential.
        :param family: Chip family revision for proper parsing context.
        :return: Parsed DebugCredential object.
        """
        return cls(
            family=family, certificate=get_ahab_certificate_class(family).parse(data, family)
        )

    def sign(self) -> None:
        """Sign the DC data using SignatureProvider.

        This method updates the certificate fields and applies the digital signature
        to the Debug Credential data structure using the configured signature provider.

        :raises SPSDKError: If signature generation fails or certificate update fails.
        """
        self.certificate.update_fields()

    def export(self) -> bytes:
        """Export debug credential to binary form.

        Serializes the debug credential certificate into its binary representation
        for storage or transmission.

        :return: Binary representation of the debug credential certificate.
        """
        return self.certificate.export()

    def calculate_hash(self) -> bytes:
        """Calculate the RoT hash.

        :return: The calculated Root of Trust hash as bytes.
        """
        return b""

    def export_rot_pub(self) -> bytes:
        """Export RoT public key as bytes.

        :return: Binary representing the RoT key.
        """
        return b""

    def export_dck_pub(self) -> bytes:
        """Export Debugger public key (DCK) as bytes.

        :return: Binary representing the DCK key.
        """
        return b""

    def _get_data_to_sign(self) -> bytes:
        """Get data to be signed.

        :return: Data bytes that need to be signed for the debug credential.
        """
        return b""

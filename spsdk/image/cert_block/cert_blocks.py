#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate Block management and processing utilities.

This module provides comprehensive functionality for handling various types of
certificate blocks used in NXP secure boot and authentication processes.
It supports multiple certificate block versions and formats including V1, V2.1,
Vx, and AHAB certificate blocks with their respective headers and structures.
"""

import logging
import os
import re
from struct import calcsize, pack, unpack_from
from typing import Any, Iterable, Optional, Sequence, Type, Union

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PrivateKeyRsa, PublicKey, PublicKeyEcc
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key, extract_public_key_from_data, get_matching_key_id
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from spsdk.image.ahab.ahab_certificate import AhabCertificate, get_ahab_certificate_class
from spsdk.image.cert_block.rkht import RKHTv1, RKHTv21
from spsdk.utils.abstract import BaseClass
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, get_families, update_validation_schema_family
from spsdk.utils.misc import (
    Endianness,
    align,
    align_block,
    change_endianness,
    find_file,
    load_binary,
    load_configuration,
    split_data,
    value_to_int,
    write_file,
)

logger = logging.getLogger(__name__)


class CertBlock(FeatureBaseClass):
    """Certificate Block base class for secure boot authentication.

    This class provides a unified interface for managing different versions of
    certificate blocks used in NXP MCU secure boot processes. It handles
    certificate validation, root key management, and family-specific
    implementations across the SPSDK-supported device portfolio.

    :cvar FEATURE: Database manager feature identifier for certificate blocks.
    """

    FEATURE = DatabaseManager.CERT_BLOCK

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize certificate block with family revision.

        :param family: Family revision specification for the certificate block.
        """
        self.family = family

    @classmethod
    def get_cert_block_class(cls, family: FamilyRevision) -> Type["CertBlock"]:
        """Get certification block class by family name.

        Retrieves the appropriate certification block class that supports the specified
        chip family from all available certification block classes.

        :param family: Chip family to find certification block class for.
        :raises SPSDKError: No certification block class found for given family.
        :return: Certification block class that supports the specified family.
        """
        for cert_block_class in cls.get_cert_block_classes():
            if family in cert_block_class.get_supported_families():
                return cert_block_class
        raise SPSDKError(f"Family '{family}' is not supported in any certification block.")

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method validates the provided configuration against basic schemas, extracts
        the family information, and returns the appropriate validation schemas for the
        specific certificate block class.

        :param config: Valid configuration object containing family and other settings.
        :return: List of validation schema dictionaries for the certificate block.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls.get_cert_block_class(family).get_validation_schemas(family)

    @classmethod
    def get_all_supported_families(cls) -> list[FamilyRevision]:
        """Get supported families for all certification blocks.

        This class method aggregates and returns all supported family revisions
        from all available certification block types in the SPSDK library.

        :return: List of all supported family revisions across all cert block types.
        """
        return (
            CertBlockV1.get_supported_families()
            + CertBlockV21.get_supported_families()
            + CertBlockVx.get_supported_families()
            + CertBlockAhab.get_supported_families()
        )

    @classmethod
    def get_cert_block_classes(cls) -> list[Type["CertBlock"]]:
        """Get list of all certificate block classes.

        This method returns all subclasses of CertBlock that are currently loaded
        in the system.

        :return: List of all certificate block class types.
        """
        return CertBlock.__subclasses__()

    @property
    def rkth(self) -> bytes:
        """Get Root Key Table Hash.

        Returns a 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys.

        :return: Root Key Table Hash as bytes.
        """
        return bytes()

    @classmethod
    def find_main_cert_index(cls, config: Config) -> Optional[int]:
        """Find the index of the main certificate that matches the private key.

        Searches through all root certificates in the configuration to find the one
        whose public key corresponds to the configured signature provider's private key.

        :param config: Configuration object containing certificate and signature provider settings.
        :return: Index of the matching certificate, or None if no match is found.
        """
        try:
            signature_provider = get_signature_provider(config)
        except SPSDKError as exc:
            logger.debug(f"A signature provider could not be created: {exc}")
            return None
        root_certificates = find_root_certificates(config)
        public_keys = []
        for root_crt_file in root_certificates:
            try:
                public_key = extract_public_key(root_crt_file, search_paths=config.search_paths)
                public_keys.append(public_key)
            except SPSDKError:
                continue
        try:
            idx = get_matching_key_id(public_keys, signature_provider)
            return idx
        except (SPSDKValueError, SPSDKUnsupportedOperation) as exc:
            logger.debug(f"Main cert index could not be found: {exc}")
            return None

    @classmethod
    def get_main_cert_index(cls, config: Config) -> int:
        """Gets main certificate index from configuration.

        The method retrieves the main root certificate ID from the configuration and validates
        it against the found certificate index. If no root certificate ID is specified in
        the configuration, it attempts to find one automatically.

        :param config: Input standard configuration containing certificate settings.
        :return: Certificate index of the main certificate.
        :raises SPSDKError: If invalid configuration is provided.
        :raises SPSDKError: If correct certificate could not be identified.
        :raises SPSDKValueError: If certificate is not of correct type.
        """
        root_cert_id = config.get("mainRootCertId")
        found_cert_id = cls.find_main_cert_index(config=config)
        if root_cert_id is None:
            if found_cert_id is not None:
                return found_cert_id
            raise SPSDKError("Certificate could not be found")
        # root_cert_id may be 0 which is falsy value, therefore 'or' cannot be used
        cert_id = value_to_int(root_cert_id)
        if found_cert_id is not None and found_cert_id != cert_id:
            logger.warning("Defined certificate does not match the private key.")
        return cert_id

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse Certification block from binary file.

        :param data: Binary data of certification block
        :param family: Chip family
        :raises SPSDKNotImplementedError: The method is not implemented in sub class
        """
        raise SPSDKNotImplementedError()

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        :raises SPSDKNotImplementedError: When called on the base class (this method must be
            implemented by subclasses).
        """
        raise SPSDKNotImplementedError()


########################################################################################################################
# Certificate Block Header Class
########################################################################################################################
class CertBlockHeader(BaseClass):
    """Certificate block header for SPSDK image processing.

    This class represents the header structure of a certificate block used in secure
    boot images. It manages certificate block metadata including version information,
    flags, build numbers, and certificate table properties.

    :cvar FORMAT: Binary format string for header serialization.
    :cvar SIZE: Size of the header in bytes.
    :cvar SIGNATURE: Binary signature identifying certificate blocks.
    """

    FORMAT = "<4s2H6I"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(self, version: str = "1.0", flags: int = 0, build_number: int = 0) -> None:
        """Initialize certificate block header.

        :param version: Version of the certificate in format n.n (e.g., "1.0").
        :param flags: Flags for the Certificate Header.
        :param build_number: Build number of the certificate.
        :raises SPSDKError: When there is invalid version format.
        """
        if not re.match(r"[0-9]+\.[0-9]+", version):  # check format of the version: N.N
            raise SPSDKError("Invalid version")
        self.version = version
        self.flags = flags
        self.build_number = build_number
        self.image_length = 0
        self.cert_count = 0
        self.cert_table_length = 0

    def __repr__(self) -> str:
        """Return string representation of CertBlockHeader.

        Provides a formatted string containing the certificate block header information
        including version, flags, build number, image length, certificate count, and
        certificate table length.

        :return: Formatted string with header information.
        """
        nfo = f"CertBlockHeader: V={self.version}, F={self.flags}, BN={self.build_number}, IL={self.image_length}, "
        nfo += f"CC={self.cert_count}, CTL={self.cert_table_length}"
        return nfo

    def __str__(self) -> str:
        """Get string representation of the certificate header.

        Returns formatted text containing certificate block information including
        version, flags, build number, image length, certificate count, and
        certificate table length.

        :return: Formatted string with certificate header information.
        """
        nfo = str()
        nfo += f" CB Version:           {self.version}\n"
        nfo += f" CB Flags:             {self.flags}\n"
        nfo += f" CB Build Number:      {self.build_number}\n"
        nfo += f" CB Image Length:      {self.image_length}\n"
        nfo += f" CB Cert. Count:       {self.cert_count}\n"
        nfo += f" CB Cert. Length:      {self.cert_table_length}\n"
        return nfo

    def export(self) -> bytes:
        """Export certificate block to binary format.

        Converts the certificate block structure into its binary representation using
        the defined format with signature, version, size, flags, and certificate information.

        :return: Certificate block data in binary format.
        """
        major_version, minor_version = [int(v) for v in self.version.split(".")]
        return pack(
            self.FORMAT,
            self.SIGNATURE,
            major_version,
            minor_version,
            self.SIZE,
            self.flags,
            self.build_number,
            self.image_length,
            self.cert_count,
            self.cert_table_length,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Certificate Header object from bytes array.

        The method validates the input data size and signature, then unpacks the binary
        data to create a Certificate Header instance with proper version formatting.

        :param data: Input data as bytes containing the certificate header
        :return: Certificate Header instance
        :raises SPSDKError: Unexpected size or signature of data
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Incorrect size")
        (
            signature,
            major_version,
            minor_version,
            length,
            flags,
            build_number,
            image_length,
            cert_count,
            cert_table_length,
        ) = unpack_from(cls.FORMAT, data)
        if signature != cls.SIGNATURE:
            raise SPSDKError("Incorrect signature")
        if length != cls.SIZE:
            raise SPSDKError("Incorrect length")
        obj = cls(
            version=f"{major_version}.{minor_version}",
            flags=flags,
            build_number=build_number,
        )
        obj.image_length = image_length
        obj.cert_count = cert_count
        obj.cert_table_length = cert_table_length
        return obj


########################################################################################################################
# Certificate Block Class
########################################################################################################################
class CertBlockV1(CertBlock):
    """Certificate block version 1 implementation.

    This class represents a certificate block used in SB file 2.1 and MasterBootImage
    operations with RSA keys. It manages certificate chains, root key hashes, and
    provides functionality for signature verification and key management.

    :cvar SUB_FEATURE: Feature identifier for certificate block version 1.
    :cvar DEFAULT_ALIGNMENT: Default size alignment value in bytes.
    """

    SUB_FEATURE = "based_on_cert1"

    # default size alignment
    DEFAULT_ALIGNMENT = 16

    @property
    def header(self) -> CertBlockHeader:
        """Get the certificate block header.

        :return: Certificate block header instance.
        """
        return self._header

    @property
    def rkh(self) -> list[bytes]:
        """Get list of root keys hashes.

        Returns SHA-256 hashes of root keys from the root key hash table.

        :return: List of root key hashes, each hash as 32 bytes.
        """
        return self._rkht.rkh_list

    @property
    def rkth(self) -> bytes:
        """Get Root Key Table Hash.

        Returns a 32-byte SHA-256 hash of SHA-256 hashes of up to four root public keys
        from the Root Key Hash Table.

        :return: 32-byte hash as bytes.
        """
        return self._rkht.rkth()

    @property
    def rkth_fuses(self) -> list[int]:
        """Get list of RKHT fuses ordered from highest bit to lowest.

        The method processes the RKHT (Root Key Table Hash) data by splitting it into 4-byte chunks
        and converting each chunk to an integer using little-endian byte order. The returned values
        are formatted for use with blhost tool.

        :return: List of RKHT fuse values as integers.
        """
        result = []
        rkht = self.rkth
        while rkht:
            fuse = int.from_bytes(rkht[:4], byteorder=Endianness.LITTLE.value)
            result.append(fuse)
            rkht = rkht[4:]
        return result

    @property
    def certificates(self) -> list[Certificate]:
        """List of certificates in header.

        First certificate is root certificate and followed by optional chain certificates.

        :return: List of Certificate objects, with root certificate first followed by chain certificates.
        """
        return self._cert

    @property
    def signature_size(self) -> int:
        """Get the size of the signature in bytes.

        Returns the size of the first certificate's signature, which is used as the
        reference since the certificate is self-signed.

        :return: Size of the signature in bytes.
        """
        return len(
            self.certificates[0].signature
        )  # The certificate is self signed, return size of its signature

    @property
    def rkh_index(self) -> Optional[int]:
        """Get the index of Root Key Hash that matches the certificate.

        The method searches through the available Root Key Hashes to find a match with the
        certificate's root public key hash. Returns None if no match is found or if no
        certificate is available.

        :return: Index of matching Root Key Hash, or None if no match found.
        """
        if self._cert:
            rkh = self.get_root_public_key().key_hash()
            for index, value in enumerate(self.rkh):
                if rkh == value:
                    return index
        return None

    @property
    def alignment(self) -> int:
        """Get alignment of the binary output.

        The method returns the alignment value for binary output formatting.
        By default it uses DEFAULT_ALIGNMENT but can be customized.

        :return: Alignment value in bytes.
        """
        return self._alignment

    @alignment.setter
    def alignment(self, value: int) -> None:
        """Set the alignment value for the certificate block.

        The alignment must be a positive integer value that determines how the
        certificate block data should be aligned in memory.

        :param value: The alignment value in bytes, must be greater than 0.
        :raises SPSDKError: When the alignment value is invalid (less than or equal to 0).
        """
        if value <= 0:
            raise SPSDKError("Invalid alignment")
        self._alignment = value

    @property
    def raw_size(self) -> int:
        """Calculate the aligned size of the certificate block in bytes.

        The method computes the total size by adding the certificate block header size,
        certificate table length, and Root Key Hash Table (RKHT) size, then aligns
        the result to the specified alignment boundary.

        :return: Total aligned size of the certificate block in bytes.
        """
        size = CertBlockHeader.SIZE
        size += self._header.cert_table_length
        size += self._rkht.RKH_SIZE * self._rkht.RKHT_SIZE
        return align(size, self.alignment)

    @property
    def expected_size(self) -> int:
        """Get expected size of binary block.

        :return: Expected size of the binary block in bytes.
        """
        return self.raw_size

    @property
    def image_length(self) -> int:
        """Get image length in bytes.

        :return: Image length in bytes from the certificate block header.
        """
        return self._header.image_length

    @image_length.setter
    def image_length(self, value: int) -> None:
        """Set the image length value.

        Validates that the provided image length is positive before setting it in the header.

        :param value: New image length in bytes, must be greater than 0
        :raises SPSDKError: When the image length is invalid (zero or negative)
        """
        if value <= 0:
            raise SPSDKError("Invalid image length")
        self._header.image_length = value

    def __init__(
        self, family: FamilyRevision, version: str = "1.0", flags: int = 0, build_number: int = 0
    ) -> None:
        """Initialize certificate block with specified parameters.

        :param family: Chip family and revision information for target device.
        :param version: Certificate version string in format "major.minor" (default "1.0").
        :param flags: Configuration flags for the Certificate Block Header (default 0).
        :param build_number: Build number identifier for the certificate (default 0).
        """
        super().__init__(family)
        self._header = CertBlockHeader(version, flags, build_number)
        self._rkht: RKHTv1 = RKHTv1([])
        self._cert: list[Certificate] = []
        self._alignment = self.DEFAULT_ALIGNMENT

    def __len__(self) -> int:
        """Get the length of the certificate.

        :return: Number of bytes in the certificate.
        """
        return len(self._cert)

    def set_root_key_hash(self, index: int, key_hash: Union[bytes, bytearray, Certificate]) -> None:
        """Set root key hash into RKHT at specified index.

        Multiple root public keys are supported to allow for key revocation.

        :param index: The index of Root Key Hash in the table.
        :param key_hash: The Root Key Hash value (32 bytes, SHA-256) or Certificate where the hash
            can be created from public key.
        :raises SPSDKError: When there is invalid index of root key hash in the table.
        :raises SPSDKError: When there is invalid length of key hash.
        """
        if isinstance(key_hash, Certificate):
            key_hash = get_hash(key_hash.get_public_key().export())
        assert isinstance(key_hash, (bytes, bytearray))
        if len(key_hash) != self._rkht.RKH_SIZE:
            raise SPSDKError("Invalid length of key hash")
        self._rkht.set_rkh(index, bytes(key_hash))

    def add_certificate(self, cert: Union[bytes, Certificate]) -> None:
        """Add certificate to the certificate block.

        First call adds root certificate. Additional calls add chain certificates.
        The root certificate must be self-signed and all chain certificates must be
        verifiable using their parent certificate's public key.

        :param cert: Certificate in DER format (bytes) or Certificate object
        :raises SPSDKError: If certificate cannot be added due to invalid type,
            unsupported version, verification failure, or root certificate not self-signed
        """
        if isinstance(cert, bytes):
            cert_obj = Certificate.parse(cert)
        elif isinstance(cert, Certificate):
            cert_obj = cert
        else:
            raise SPSDKError("Invalid parameter type (cert)")
        if cert_obj.version.name != "v3":
            raise SPSDKError("Expected certificate v3 but received: " + cert_obj.version.name)
        if self._cert:  # chain certificate?
            last_cert = self._cert[-1]  # verify that it is signed by parent key
            if not cert_obj.validate(last_cert):
                raise SPSDKError("Chain certificate cannot be verified using parent public key")
        else:  # root certificate
            if not cert_obj.self_signed:
                raise SPSDKError(f"Root certificate must be self-signed.\n{str(cert_obj)}")
        self._cert.append(cert_obj)
        self._header.cert_count += 1
        self._header.cert_table_length += cert_obj.raw_size + 4

    def __repr__(self) -> str:
        """Get string representation of the certificate block.

        Returns the string representation of the certificate block header.

        :return: String representation of the header object.
        """
        return str(self._header)

    def __str__(self) -> str:
        """Get string representation of the certificate block.

        Provides detailed information about the certificate block including header details,
        public root keys hash (RKH) with indication of which key is used, RKTH hash and
        corresponding fuse values, and all certificates in the block.

        :return: Formatted string containing comprehensive certificate block information.
        """
        nfo = str(self.header)
        nfo += " Public Root Keys Hash e.g. RKH (SHA256):\n"
        rkh_index = self.rkh_index
        for index, root_key in enumerate(self._rkht.rkh_list):
            nfo += (
                f"  {index}) {root_key.hex().upper()} {'<- Used' if index == rkh_index else ''}\n"
            )
        rkth = self.rkth
        nfo += f" RKTH (SHA256): {rkth.hex().upper()}\n"
        for index, fuse in enumerate(self.rkth_fuses):
            bit_ofs = (len(rkth) - 4 * index) * 8
            nfo += f"  - RKTH fuse [{bit_ofs:03}:{bit_ofs - 31:03}]: {fuse:08X}\n"
        for index, cert in enumerate(self._cert):
            nfo += " Root Certificate:\n" if index == 0 else f" Certificate {index}:\n"
            nfo += str(cert)
        return nfo

    def verify_data(self, signature: bytes, data: bytes) -> bool:
        """Verify signature against signed data using certificate.

        The method uses the public key from the last certificate in the chain to verify
        that the provided signature matches the given data.

        :param signature: Signature bytes to be verified.
        :param data: Original data that has been signed.
        :return: True if the data signature can be confirmed using the certificate; False otherwise.
        """
        cert = self._cert[-1]
        pub_key = cert.get_public_key()
        return pub_key.verify_signature(signature=signature, data=data)

    def verify_private_key(self, private_key: PrivateKeyRsa) -> bool:
        """Verify that given private key matches the public certificate.

        The method compares the private key against the public key from the last certificate
        in the certificate chain to ensure they form a valid key pair.

        :param private_key: Private RSA key to be verified against the certificate.
        :return: True if the private key matches the public certificate; False otherwise.
        """
        cert = self.certificates[-1]  # last certificate
        pub_key = cert.get_public_key()
        return private_key.verify_public_key(pub_key)

    def export(self) -> bytes:
        """Export Certificate Block V1 object to binary format.

        Validates the certificate chain structure and exports the complete certificate block
        including header, certificates, and root key hash table (RKHT). The method ensures
        proper certificate chain validation and alignment requirements.

        :raises SPSDKError: If no certificates are present, root key hash index is missing,
            certificate chain structure is invalid, or exported data length is incorrect.
        :return: Binary representation of the Certificate Block V1.
        """
        # At least one certificate must be used
        if not self._cert:
            raise SPSDKError("At least one certificate must be used")
        # The hast of root key certificate must be in RKHT
        if self.rkh_index is None:
            raise SPSDKError("The HASH of used Root Key must be in RKHT")
        # CA: Using a single certificate is allowed. In this case, the sole certificate must be self-signed and must not
        # be a CA. If multiple certificates are used, the root must be self-signed and all but the last must be CAs.
        if self._cert[-1].ca:
            raise SPSDKError("The last chain certificate must not be CA.")
        if not all(cert.ca for cert in self._cert[:-1]):
            raise SPSDKError("All certificates except the last chain certificate must be CA")
        # Export
        data = self.header.export()
        for cert in self._cert:
            data += pack("<I", cert.raw_size)
            data += cert.export()
        data += self._rkht.export()
        data = align_block(data, self.alignment)
        if len(data) != self.raw_size:
            raise SPSDKError("Invalid length of data")
        return data

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse CertBlockV1 from binary data.

        Parses the binary data to create a CertBlockV1 instance by extracting the header,
        certificates, and root key hash table from the provided data.

        :param data: Binary data containing the certificate block
        :param family: The MCU family revision for the certificate block
        :return: Certificate Block instance
        :raises SPSDKError: Length of the data doesn't match Certificate Block length
        """
        header = CertBlockHeader.parse(data)
        offset = CertBlockHeader.SIZE
        if len(data) < (header.cert_table_length + (RKHTv1.RKHT_SIZE * RKHTv1.RKH_SIZE)):
            raise SPSDKError("Length of the data doesn't match Certificate Block length")
        obj = cls(
            family=family,
            version=header.version,
            flags=header.flags,
            build_number=header.build_number,
        )
        for _ in range(header.cert_count):
            cert_len = unpack_from("<I", data, offset)[0]
            offset += 4
            cert_obj = Certificate.parse(data[offset : offset + cert_len])
            obj.add_certificate(cert_obj)
            offset += cert_len
        obj._rkht = RKHTv1.parse(data[offset : offset + (RKHTv1.RKH_SIZE * RKHTv1.RKHT_SIZE)])
        return obj

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for certificate blocks.

        The method retrieves and configures validation schemas including family-specific
        schemas, certificate schemas, and output schemas. It updates the family schema
        with supported families and current family information.

        :param family: Target family and revision for schema validation.
        :return: List of validation schemas including family, certificate, root keys, and output schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [
            sch_family,
            sch_cfg["certificate_v1"],
            sch_cfg["certificate_root_keys"],
            sch_cfg["cert_block_output"],
        ]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of CertBlockV1 from configuration.

        The method supports loading from binary file or creating from certificate configuration.
        It processes root certificates, certificate chains, and validates the configuration
        to build a complete certificate block structure.

        :param config: Input standard configuration containing certificate paths and settings.
        :return: Instance of CertBlockV1 with loaded certificates and configuration.
        :raises SPSDKError: Invalid certificates detected, invalid configuration, or missing
            required root certificate files.
        """
        if "certBlock" in config:
            family = FamilyRevision.load_from_config(config)
            try:
                return cls.parse(
                    load_binary(config.get_input_file_name("certBlock")), family=family
                )
            except (SPSDKError, TypeError):
                cert_block_cfg = config.load_sub_config("certBlock")
                cert_block_cfg["family"] = family.name
                cert_block_cfg["revision"] = family.revision
                return cls.load_from_config(cert_block_cfg)

        image_build_number = config.get_int("imageBuildNumber", 0)
        root_certificates: list[list[str]] = [[] for _ in range(4)]
        # TODO we need to read the whole chain from the dict for a given
        # selection based on signer configuration
        root_certificates[0].append(config.get("rootCertificate0File", None))
        root_certificates[1].append(config.get("rootCertificate1File", None))
        root_certificates[2].append(config.get("rootCertificate2File", None))
        root_certificates[3].append(config.get("rootCertificate3File", None))
        main_cert_chain_id = cls.get_main_cert_index(config)
        if root_certificates[main_cert_chain_id][0] is None:
            raise SPSDKError(f"A key rootCertificate{main_cert_chain_id}File must be defined")

        # get all certificate chain related keys from config
        pattern = f"chainCertificate{main_cert_chain_id}File[0-3]"
        keys = [key for key in config.keys() if re.fullmatch(pattern, key)]
        # just in case, sort the chain certificate keys in order
        keys.sort()
        for key in keys:
            root_certificates[main_cert_chain_id].append(config[key])

        family = FamilyRevision.load_from_config(config)
        cert_block = cls(family=family, build_number=image_build_number)

        # add whole certificate chain used for image signing
        for cert_path in root_certificates[main_cert_chain_id]:
            cert_data = Certificate.load(
                find_file(str(cert_path), search_paths=config.search_paths)
            ).export(SPSDKEncoding.DER)
            cert_block.add_certificate(cert_data)
        # set root key hash of each root certificate
        empty_rec = False
        for cert_idx, cert_path_list in enumerate(root_certificates):
            if cert_path_list[0]:
                if empty_rec:
                    raise SPSDKError("There are gaps in rootCertificateXFile definition")
                cert_data = Certificate.load(
                    find_file(str(cert_path_list[0]), search_paths=config.search_paths)
                ).export(SPSDKEncoding.DER)
                cert_block.set_root_key_hash(cert_idx, Certificate.parse(cert_data))
            else:
                empty_rec = True

        return cert_block

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of Certificate V2 from object.

        Generates a configuration dictionary containing certificate file references and metadata.
        The method extracts certificate data from the current object and saves individual
        certificates to files in the specified directory.

        :param data_path: Output folder path to store certificate files.
        :raises SPSDKError: When index of used certificate is not defined.
        :return: Configuration dictionary with certificate file paths and metadata.
        """

        def create_certificate_cfg(root_id: int, chain_id: int) -> Optional[str]:
            """Create certificate configuration file and return its filename.

            Saves the certificate at the specified chain depth to a DER file in the data path
            and returns the generated filename for configuration purposes.

            :param root_id: Root certificate identifier used in filename generation.
            :param chain_id: Chain depth index of the certificate to save.
            :return: Generated filename if certificate exists at chain_id, None otherwise.
            """
            if len(self._cert) <= chain_id:
                return None

            file_name = f"certificate{root_id}_depth{chain_id}.der"
            self._cert[chain_id].save(os.path.join(data_path, file_name))
            return file_name

        cfg = Config()
        cfg["imageBuildNumber"] = self.header.build_number
        used_cert_id = self.rkh_index
        if used_cert_id is None:
            raise SPSDKError("Index of used certificate is not defined")
        cfg["mainRootCertId"] = used_cert_id

        cfg[f"rootCertificate{used_cert_id}File"] = create_certificate_cfg(used_cert_id, 0)
        for chain_ix in range(4):
            cfg[f"chainCertificate{used_cert_id}File{chain_ix}"] = create_certificate_cfg(
                used_cert_id, chain_ix + 1
            )

        return cfg

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        The method extracts the public key from the first certificate in the certificate chain,
        which represents the root certificate.

        :return: Root certificate public key object.
        """
        return self._cert[0].get_public_key()


########################################################################################################################
# Certificate Block Class for SB 3.1
########################################################################################################################


def convert_to_ecc_key(key: Union[PublicKeyEcc, bytes]) -> PublicKeyEcc:
    """Convert key into ECC key instance.

    Converts various key formats (bytes or existing ECC key) into a standardized
    PublicKeyEcc instance for consistent handling within the certificate block.

    :param key: Input key data as either existing ECC key instance or raw bytes.
    :raises SPSDKError: When the provided key is not an ECC key type.
    :return: Standardized ECC public key instance.
    """
    if isinstance(key, PublicKeyEcc):
        return key
    try:
        pub_key = extract_public_key_from_data(key)
        if not isinstance(pub_key, PublicKeyEcc):
            raise SPSDKError("Not ECC key")
        return pub_key
    except Exception:
        pass
    # Just recreate public key from the parsed data
    return PublicKeyEcc.parse(key)


class CertificateBlockHeader(BaseClass):
    """Certificate block header for SPSDK image processing.

    This class represents the header structure of certificate blocks used in secure boot
    images. It handles the binary format, version information, and size management for
    certificate block headers in NXP MCU secure provisioning.

    :cvar FORMAT: Binary format string for header structure.
    :cvar SIZE: Size of the header in bytes.
    :cvar MAGIC: Magic bytes identifier for certificate block headers.
    """

    FORMAT = "<4s2HL"
    SIZE = calcsize(FORMAT)
    MAGIC = b"chdr"

    def __init__(self, format_version: str = "2.1") -> None:
        """Initialize Certificate block header.

        Creates a new certificate block header with specified format version.
        The header manages certificate block metadata including size and version information.

        :param format_version: Certificate block format version in "major.minor" format, defaults to "2.1"
        """
        self.format_version = format_version
        self.cert_block_size = 0

    def export(self) -> bytes:
        """Export Certificate block header as bytes array.

        Converts the certificate block header into a binary format by packing
        the magic number, format version components, and block size according
        to the defined FORMAT structure.

        :return: Binary representation of the certificate block header.
        """
        major_format_version, minor_format_version = [
            int(v) for v in self.format_version.split(".")
        ]

        return pack(
            self.FORMAT,
            self.MAGIC,
            minor_format_version,
            major_format_version,
            self.cert_block_size,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Certificate block header from bytes array.

        :param data: Input data as bytes array to be parsed.
        :raises SPSDKError: Raised when SIZE is bigger than length of the data.
        :raises SPSDKError: Raised when magic number doesn't match expected MAGIC value.
        :return: CertificateBlockHeader instance with parsed data.
        """
        if cls.SIZE > len(data):
            raise SPSDKError("SIZE is bigger than length of the data without offset")
        (
            magic,
            minor_format_version,
            major_format_version,
            cert_block_size,
        ) = unpack_from(cls.FORMAT, data)

        if magic != cls.MAGIC:
            raise SPSDKError("Magic is not same!")

        obj = cls(format_version=f"{major_format_version}.{minor_format_version}")
        obj.cert_block_size = cert_block_size
        return obj

    def __len__(self) -> int:
        """Get the length of the Certificate block header.

        :return: Size of the certificate block header in bytes.
        """
        return calcsize(self.FORMAT)

    def __repr__(self) -> str:
        """Get string representation of certificate block header.

        Returns a formatted string containing the certificate block header format version
        for debugging and logging purposes.

        :return: String representation showing format version.
        """
        return f"Cert block header {self.format_version}"

    def __str__(self) -> str:
        """Get info of Certificate block header.

        Returns a formatted string containing the certificate block header information
        including format version and certificate block size.

        :return: Formatted string with certificate block header details.
        """
        info = f"Format version:              {self.format_version}\n"
        info += f"Certificate block size:      {self.cert_block_size}\n"
        return info


class CertificateBlockHeaderV2_2(CertificateBlockHeader):
    """Certificate block header implementation for format version 2.2.

    This class extends the base certificate block header to support version 2.2
    format which includes additional flags field for enhanced functionality.

    :cvar FORMAT: Binary format string for packing/unpacking header data.
    :cvar SIZE: Size of the header in bytes.
    """

    FORMAT = "<4s2H2L"
    SIZE = calcsize(FORMAT)

    def __init__(self, format_version: str = "2.2") -> None:
        """Initialize Certificate block header version 2.2.

        Creates a new certificate block header with the specified format version and
        initializes flags to zero.

        :param format_version: Format version string in "major.minor" format, defaults to "2.2".
        """
        super().__init__(format_version)
        self.flags = 0

    def export(self) -> bytes:
        """Export Certificate block header as bytes array.

        Serializes the certificate block header into a binary format using the predefined
        structure with magic number, version information, size, and flags.

        :return: Binary representation of the certificate block header.
        """
        major_format_version, minor_format_version = [
            int(v) for v in self.format_version.split(".")
        ]

        return pack(
            self.FORMAT,
            self.MAGIC,
            minor_format_version,
            major_format_version,
            self.cert_block_size,
            self.flags,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Certificate block header from bytes array.

        :param data: Input data as bytes array to parse the certificate block header from.
        :raises SPSDKError: Raised when SIZE is bigger than length of the data without offset.
        :raises SPSDKError: Raised when magic number is not equal to expected MAGIC value.
        :return: CertificateBlockHeaderV2_2 instance with parsed header data.
        """
        if cls.SIZE > len(data):
            raise SPSDKError("SIZE is bigger than length of the data without offset")
        (
            magic,
            minor_format_version,
            major_format_version,
            cert_block_size,
            flags,
        ) = unpack_from(cls.FORMAT, data)

        if magic != cls.MAGIC:
            raise SPSDKError("Magic is not same!")

        obj = cls(format_version=f"{major_format_version}.{minor_format_version}")
        obj.cert_block_size = cert_block_size
        obj.flags = flags
        return obj


class RootKeyRecord(BaseClass):
    """Root Key Record for certificate block operations.

    This class manages root key records used in SPSDK certificate blocks, handling
    root certificates, public keys, and associated metadata for secure boot operations.
    It supports ECC public keys (P-256/P-384) and manages certificate authority flags,
    root key hash tables, and certificate selection.
    """

    # P-256

    def __init__(
        self,
        ca_flag: bool,
        root_certs: Optional[Union[Sequence[PublicKeyEcc], Sequence[bytes]]] = None,
        used_root_cert: int = 0,
    ) -> None:
        """Initialize Root Key Record for certificate block.

        Creates a new Root Key Record instance with specified CA flag, root certificates,
        and the index of the root certificate to be used for ISK/image signature verification.

        :param ca_flag: Certificate Authority flag indicating if this is a CA certificate.
        :param root_certs: Sequence of root certificates as PublicKeyEcc objects or raw bytes,
            defaults to None.
        :param used_root_cert: Index of the root certificate to use (0-3), defaults to 0.
        """
        self.ca_flag = ca_flag
        self.root_certs_input = root_certs
        self.root_certs: list[PublicKeyEcc] = []
        self.used_root_cert = used_root_cert
        self.flags = 0
        self._rkht = RKHTv21([])
        self.root_public_key = b""

    @property
    def number_of_certificates(self) -> int:
        """Get number of included certificates.

        This method extracts the certificate count from the flags field by masking
        the upper 4 bits and shifting them to get the actual count value.

        :return: Number of certificates included in the certificate block.
        """
        return (self.flags & 0xF0) >> 4

    @property
    def expected_size(self) -> int:
        """Get expected binary block size.

        Calculates the total size of the certificate block including flags (4 bytes),
        root key hash table export data, and root public key data.

        :return: Expected size in bytes of the binary certificate block.
        """
        # the '4' means 4 bytes for flags
        return 4 + len(self._rkht.export()) + len(self.root_public_key)

    def __repr__(self) -> str:
        """Return string representation of the Root Key Record certificate block.

        The method extracts the certificate type from the flags field and formats
        it into a human-readable string showing the elliptic curve type used.

        :return: Formatted string containing certificate block type and curve information.
        """
        cert_type = {0x1: "secp256r1", 0x2: "secp384r1"}[self.flags & 0xF]
        return f"Cert Block: Root Key Record - ({cert_type})"

    def __str__(self) -> str:
        """Get string representation of Root key record.

        Returns formatted information about the root key record including flags,
        CA status, certificate details, root certificates, CTRK hash table,
        and root public key if available.

        :return: Formatted string with root key record information.
        """
        cert_type = {0x1: "secp256r1", 0x2: "secp384r1"}[self.flags & 0xF]
        info = ""
        info += f"Flags:           {hex(self.flags)}\n"
        info += f"  - CA:          {bool(self.ca_flag)}, ISK Certificate is {'not ' if self.ca_flag else ''}mandatory\n"
        info += f"  - Used Root c.:{self.used_root_cert}\n"
        info += f"  - Number of c.:{self.number_of_certificates}\n"
        info += f"  - Cert. type:  {cert_type}\n"
        if self.root_certs:
            info += f"Root certs:      {self.root_certs}\n"
        if self._rkht.rkh_list:
            info += f"CTRK Hash table: {self._rkht.export().hex()}\n"
        if self.root_public_key:
            info += f"Root public key: {str(convert_to_ecc_key(self.root_public_key))}\n"

        return info

    def _calculate_flags(self) -> int:
        """Calculate certificate block parameter flags.

        This method computes flags based on certificate authority status, root certificate
        usage, certificate count, and cryptographic curve types. The flags are encoded as
        a 32-bit integer with specific bit positions for different parameters.

        :return: Calculated flags as 32-bit integer with encoded certificate parameters.
        """
        flags = 0
        if self.ca_flag is True:
            flags |= 1 << 31
        if self.used_root_cert:
            flags |= self.used_root_cert << 8
        flags |= len(self.root_certs) << 4
        if self.root_certs[0].curve in ["NIST P-256", "p256", "secp256r1"]:
            flags |= 1 << 0
        if self.root_certs[0].curve in ["NIST P-384", "p384", "secp384r1"]:
            flags |= 1 << 1
        return flags

    def _create_root_public_key(self) -> bytes:
        """Create root public key data from the selected root certificate.

        Exports the public key data from the root certificate that is currently
        selected by the used_root_cert index.

        :return: Exported root public key data in bytes format.
        """
        root_key = self.root_certs[self.used_root_cert]
        root_key_data = root_key.export()
        return root_key_data

    def calculate(self) -> None:
        """Calculate all internal members of the certificate block.

        This method processes root certificates, calculates flags, creates RKHT (Root Key Hash Table),
        validates hash algorithms, and generates the root public key.

        :raises SPSDKError: The RKHT certificates inputs are missing or hash algorithm mismatch.
        """
        # pylint: disable=invalid-name
        if not self.root_certs_input:
            raise SPSDKError("Root Key Record: The root of trust certificates are not specified.")
        self.root_certs = [convert_to_ecc_key(cert) for cert in self.root_certs_input]
        self.flags = self._calculate_flags()
        self._rkht = RKHTv21.from_keys(keys=self.root_certs)
        if self._rkht.hash_algorithm != self.get_hash_algorithm(self.flags):
            raise SPSDKError("Hash algorithm does not match the key size.")
        self.root_public_key = self._create_root_public_key()

    def export(self) -> bytes:
        """Export Root key record as bytes array.

        Serializes the root key record into a binary format including flags,
        root key hash table, and root public key data.

        :raises SPSDKError: Invalid length of exported data.
        :return: Binary representation of the root key record.
        """
        data = bytes()
        data += pack("<L", self.flags)
        data += self._rkht.export()
        data += self.root_public_key
        if len(data) != self.expected_size:
            raise SPSDKError("Invalid length of data")
        return data

    @staticmethod
    def get_hash_algorithm(flags: int) -> EnumHashAlgorithm:
        """Get CTRK table hash algorithm from flags.

        Extracts the hash algorithm type from the lower 4 bits of the Root Key Record flags.

        :param flags: Root Key Record flags containing hash algorithm information.
        :raises KeyError: If the flags contain an unsupported hash algorithm value.
        :return: Hash algorithm enumeration value (SHA256 or SHA384).
        """
        return {1: EnumHashAlgorithm.SHA256, 2: EnumHashAlgorithm.SHA384}[flags & 0xF]

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Root key record from bytes array.

        :param data:  Input data as bytes array
        :return: Root key record object
        """
        (flags,) = unpack_from("<L", data)
        ca_flag = flags & 0x80000000
        used_rot_ix = (flags & 0xF00) >> 8
        number_of_hashes = (flags & 0xF0) >> 4
        rotkh_len = {0x0: 32, 0x1: 32, 0x2: 48}[flags & 0xF]
        root_key_record = cls(ca_flag=ca_flag, root_certs=[], used_root_cert=used_rot_ix)
        root_key_record.flags = flags
        offset = 4  # move offset just after FLAGS
        rkht = b""
        if number_of_hashes > 1:
            rkht_len = rotkh_len * number_of_hashes
            rkht = data[offset : offset + rkht_len]
            offset += rkht_len

        root_key_record.root_public_key = data[offset : offset + rotkh_len * 2]
        root_key_record._rkht = (
            RKHTv21.parse(rkht, cls.get_hash_algorithm(flags))
            if number_of_hashes > 1
            else RKHTv21([get_hash(root_key_record.root_public_key, cls.get_hash_algorithm(flags))])
        )
        return root_key_record


class IskCertificate(BaseClass):
    """ISK Certificate representation for secure boot operations.

    This class manages the creation, validation, and export of ISK (Image Signing Key)
    certificates used in NXP secure boot processes. It handles certificate constraints,
    signature operations, user data embedding, and ensures proper alignment and size
    validation according to device family specifications.
    """

    def __init__(
        self,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[PublicKeyEcc, bytes]] = None,
        user_data: Optional[bytes] = None,
        offset_present: bool = True,
        family: Optional[FamilyRevision] = None,
    ) -> None:
        """Initialize ISK certificate block.

        Creates a new ISK (Intermediate Signing Key) certificate block with the specified
        parameters and validates user data constraints based on the target family.

        :param constraints: Certificate constraints/version value.
        :param signature_provider: Signature provider for ISK certificate signing.
        :param isk_cert: ISK certificate as ECC public key or raw bytes.
        :param user_data: Additional user data to include in the certificate.
        :param offset_present: Whether offset field is present in the certificate.
        :param family: Target MCU family for validation of data constraints.
        :raises SPSDKError: If user data exceeds size limit or alignment requirements.
        """
        self.flags = 0
        self.offset_present = offset_present
        self.constraints = constraints
        self.signature_provider = signature_provider
        self.isk_cert = convert_to_ecc_key(isk_cert) if isk_cert else None
        self.user_data = user_data or bytes()
        if family:
            db = get_db(family=family)
            isk_data_limit = db.get_int(DatabaseManager.CERT_BLOCK, "isk_data_limit")
            if len(self.user_data) > isk_data_limit:
                raise SPSDKError(
                    f"ISK user data is too big ({len(self.user_data)} B). Max size is: {isk_data_limit} B."
                )
            isk_data_alignment = db.get_int(DatabaseManager.CERT_BLOCK, "isk_data_alignment")
            if len(self.user_data) % isk_data_alignment:
                raise SPSDKError(f"ISK user data is not aligned to {isk_data_alignment} B.")
        self.signature = bytes()
        self.coordinate_length = (
            self.signature_provider.signature_length // 2 if self.signature_provider else 0
        )
        self.isk_public_key_data = self.isk_cert.export() if self.isk_cert else bytes()

        self._calculate_flags()

    @property
    def signature_offset(self) -> int:
        """Calculate the signature offset inside the ISK Certificate.

        The method computes the offset by considering the header size (with or without
        offset field), user data length, and ISK certificate coordinate size if present.

        :return: Signature offset in bytes from the beginning of the certificate.
        """
        offset = calcsize("<3L") if self.offset_present else calcsize("<2L")
        signature_offset = offset + len(self.user_data)
        if self.isk_cert:
            signature_offset += 2 * self.isk_cert.coordinate_size

        return signature_offset

    @property
    def expected_size(self) -> int:
        """Calculate the expected binary size of the certificate block.

        The method computes the total size by summing up all components including
        signature offset (if present), constraints, flags, ISK public key data,
        user data, and ISK blob signature. The signature length is determined from
        either existing signature or signature provider.

        :return: Total expected size in bytes of the binary certificate block.
        """
        sign_len = len(self.signature) or (
            self.signature_provider.signature_length if self.signature_provider else 0
        )
        pub_key_len = (
            self.isk_cert.coordinate_size * 2 if self.isk_cert else len(self.isk_public_key_data)
        )

        offset = 4 if self.offset_present else 0
        return (
            offset  #  signature offset
            + 4  # constraints
            + 4  # flags
            + pub_key_len  # isk public key coordinates
            + len(self.user_data)  # user data
            + sign_len  # isk blob signature
        )

    def __repr__(self) -> str:
        """Return string representation of ISK Certificate.

        The method provides a human-readable representation showing the certificate type
        and the elliptic curve algorithm based on the flags field.

        :return: String representation in format "ISK Certificate, {curve_type}".
        """
        isk_type = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}[self.flags & 0xF]
        return f"ISK Certificate, {isk_type}"

    def __str__(self) -> str:
        """Get string representation of ISK certificate information.

        Provides detailed information about the ISK (Initial Secure Key) certificate including
        constraints, flags, user data, cryptographic type, and public key details.

        :return: Formatted string containing ISK certificate details.
        """
        isk_type = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}[self.flags & 0xF]
        info = ""
        info += f"Constraints:     {self.constraints}\n"
        info += f"Flags: {self.flags}\n"
        if self.user_data:
            info += f"User data:       {self.user_data.hex()}\n"
        else:
            info += "User data:       Not included\n"
        info += f"Type:            {isk_type}\n"
        info += f"Public Key:      {str(self.isk_cert)}\n"
        return info

    def _calculate_flags(self) -> None:
        """Calculate parameter flags based on certificate and user data configuration.

        This method sets the flags attribute by examining the ISK certificate curve type
        and user data presence. The flags are used to indicate the cryptographic algorithm
        and data configuration for the certificate block.

        :raises SPSDKError: ISK Certificate is required for flag calculation.
        """
        self.flags = 0
        if self.user_data:
            self.flags |= 1 << 31
        if not self.isk_cert:
            raise SPSDKError("ISK Certificate is needed when calculating flags.")
        if self.isk_cert.curve == "secp256r1":
            self.flags |= 1 << 0
        if self.isk_cert.curve == "secp384r1":
            self.flags |= 1 << 1

    def create_isk_signature(self, key_record_data: bytes, force: bool = False) -> None:
        """Create ISK signature for the certificate.

        The method generates a signature using the provided key record data combined with
        certificate metadata (offset, constraints, flags) and ISK public key data.

        :param key_record_data: Binary data of the key record to be signed.
        :param force: Force signature creation even if signature already exists.
        :raises SPSDKError: Signature provider is not specified.
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not self.signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")
        if self.offset_present:
            data = key_record_data + pack(
                "<3L", self.signature_offset, self.constraints, self.flags
            )
        else:
            data = key_record_data + pack("<2L", self.constraints, self.flags)
        data += self.isk_public_key_data + self.user_data
        self.signature = self.signature_provider.get_signature(data)

    def export(self) -> bytes:
        """Export ISK certificate as bytes array.

        Serializes the ISK (Initial Secure Key) certificate into a binary format
        by packing the certificate components including signature offset, constraints,
        flags, public key data, user data, and signature.

        :raises SPSDKError: If signature is not set or if the exported data size
            does not match the expected size.
        :return: Binary representation of the ISK certificate.
        """
        if not self.signature:
            raise SPSDKError("Signature is not set.")
        if self.offset_present:
            data = pack("<3L", self.signature_offset, self.constraints, self.flags)
        else:
            data = pack("<2L", self.constraints, self.flags)
        data += self.isk_public_key_data
        if self.user_data:
            data += self.user_data
        data += self.signature

        if len(data) != self.expected_size:
            raise SPSDKError("ISK Cert data size does not match")
        return data

    @classmethod
    def parse(cls, data: bytes, signature_size: int) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse ISK certificate from bytes array.

        Parses the ISK (Initial Secure Key) certificate data structure including signature offset,
        constraints, ISK flags, public key, optional user data, and signature components.

        :param data: Input data as bytes array containing the ISK certificate
        :param signature_size: The signature size of ISK block in bytes
        :return: Parsed ISK certificate instance
        :raises SPSDKError: Invalid certificate data format or parsing error
        """
        (signature_offset, constraints, isk_flags) = unpack_from("<3L", data)
        header_word_cnt = 3
        if signature_offset & 0xFFFF == 0x4D43:  # This means that certificate has no offset
            (constraints, isk_flags) = unpack_from("<2L", data)
            signature_offset = 72
            header_word_cnt = 2
        user_data_flag = bool(isk_flags & 0x80000000)
        isk_pub_key_length = {0x0: 32, 0x1: 32, 0x2: 48}[isk_flags & 0xF]
        offset = header_word_cnt * 4
        isk_pub_key_bytes = data[offset : offset + isk_pub_key_length * 2]
        offset += isk_pub_key_length * 2
        user_data = data[offset:signature_offset] if user_data_flag else None
        signature = data[signature_offset : signature_offset + signature_size]
        offset_present = header_word_cnt == 3
        certificate = cls(
            constraints=constraints,
            isk_cert=isk_pub_key_bytes,
            user_data=user_data,
            offset_present=offset_present,
        )
        certificate.signature = signature
        return certificate


class IskCertificateLite(BaseClass):
    """ISK Certificate Lite for secure boot operations.

    This class represents a lightweight version of an ISK (Image Signing Key) certificate
    used in NXP secure boot processes. It manages ISK public key data, constraints,
    and digital signatures for certificate validation and export operations.

    :cvar MAGIC: Certificate magic number identifier (0x4D43).
    :cvar VERSION: Certificate format version.
    :cvar ISK_PUB_KEY_LENGTH: Expected length of ISK public key data in bytes.
    :cvar ISK_SIGNATURE_SIZE: Expected size of ISK signature in bytes.
    """

    MAGIC = 0x4D43
    VERSION = 1
    HEADER_FORMAT = "<HHI"
    ISK_PUB_KEY_LENGTH = 64
    ISK_SIGNATURE_SIZE = 64
    SIGNATURE_OFFSET = 72

    def __init__(
        self,
        pub_key: Union[PublicKeyEcc, bytes],
        constraints: int = 1,
    ) -> None:
        """Constructor for ISK certificate.

        :param pub_key: ISK public key, either PublicKeyEcc object or raw bytes
        :param constraints: Certificate constraints (1 = self signed, 0 = NXP signed)
        """
        self.constraints = constraints
        self.pub_key = convert_to_ecc_key(pub_key)
        self.signature = bytes()
        self.isk_public_key_data = self.pub_key.export()

    @property
    def expected_size(self) -> int:
        """Get the expected size of the binary certificate block.

        Calculates the total size including magic number, version, constraints,
        ISK public key coordinates, and ISK blob signature.

        :return: Expected size in bytes of the binary certificate block.
        """
        return (
            +4  # magic + version
            + 4  # constraints
            + self.ISK_PUB_KEY_LENGTH  # isk public key coordinates
            + self.ISK_SIGNATURE_SIZE  # isk blob signature
        )

    def __repr__(self) -> str:
        """Return string representation of ISK Certificate lite.

        :return: String representation of the ISK Certificate lite object.
        """
        return "ISK Certificate lite"

    def __str__(self) -> str:
        """Get string representation of ISK certificate.

        Returns formatted information about the ISK certificate including constraints and public key
        details.

        :return: Formatted string containing ISK certificate information.
        """
        info = "ISK Certificate lite\n"
        info += f"Constraints:     {self.constraints}\n"
        info += f"Public Key:      {str(self.pub_key)}\n"
        return info

    def create_isk_signature(
        self, signature_provider: Optional[SignatureProvider], force: bool = False
    ) -> None:
        """Create ISK (Issuer Signing Key) signature for the certificate.

        This method generates a digital signature for the certificate using the provided
        signature provider. If a signature already exists, it will only be replaced
        when force parameter is set to True.

        :param signature_provider: Provider used to generate the digital signature
        :param force: Force regeneration of signature even if one already exists
        :raises SPSDKError: Signature provider is not specified
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")

        data = self.get_tbs_data()
        self.signature = signature_provider.get_signature(data)

    def get_tbs_data(self) -> bytes:
        """Get To-Be-Signed data for certificate block.

        Constructs the data that needs to be signed by packing the header information
        (magic, version, constraints) and appending the ISK public key data. Validates
        that the public key length and total data length match expected values.

        :raises SPSDKError: Invalid public key length or invalid TBS data length.
        :return: Packed binary data ready for signing.
        """
        data = pack(self.HEADER_FORMAT, self.MAGIC, self.VERSION, self.constraints)
        if len(self.isk_public_key_data) != self.ISK_PUB_KEY_LENGTH:
            raise SPSDKError(
                "Invalid public key length. "
                f"Expected: {self.ISK_PUB_KEY_LENGTH}, got: {len(self.isk_public_key_data)}"
            )
        data += self.isk_public_key_data
        if len(data) != self.SIGNATURE_OFFSET:
            raise SPSDKError(
                f"Invalid TBS data length. Expected: {self.SIGNATURE_OFFSET}, got: {len(data)}"
            )
        return data

    def export(self) -> bytes:
        """Export ISK certificate as bytes array.

        Serializes the ISK (Initial Secure Key) certificate into a binary format
        by combining the TBS (To Be Signed) data with the signature.

        :raises SPSDKError: Signature is not set or data size does not match expected size.
        :return: Binary representation of the ISK certificate.
        """
        if not self.signature:
            raise SPSDKError("Signature is not set.")

        data = self.get_tbs_data()
        data += self.signature

        if len(data) != self.expected_size:
            raise SPSDKError("ISK Cert data size does not match")

        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:  # pylint: disable=arguments-differ
        """Parse ISK certificate from bytes array.

        This method deserializes an ISK (Initial Secure Key) certificate from a binary data format,
        extracting the constraints, public key, and signature components.

        :param data: Input data as bytes array containing the serialized ISK certificate.
        :return: Parsed ISK certificate instance.
        """
        (_, _, constraints) = unpack_from(cls.HEADER_FORMAT, data)
        offset = calcsize(cls.HEADER_FORMAT)
        isk_pub_key_bytes = data[offset : offset + cls.ISK_PUB_KEY_LENGTH]
        offset += cls.ISK_PUB_KEY_LENGTH
        signature = data[offset : offset + cls.ISK_SIGNATURE_SIZE]
        certificate = cls(
            constraints=constraints,
            pub_key=isk_pub_key_bytes,
        )
        certificate.signature = signature
        return certificate


class CertBlockV21(CertBlock):
    """Certificate block implementation for version 2.1.

    This class manages certificate blocks used in Secure Binary 3.1 and Master Boot Image
    operations with ECC cryptographic keys. It handles root certificates, ISK certificates,
    and provides the necessary structure for secure boot chain validation.

    :cvar SUB_FEATURE: Feature identifier for certificate block v2.1.
    :cvar MAGIC: Magic bytes identifier for the certificate block header.
    :cvar FORMAT_VERSION: Version string for this certificate block format.
    """

    SUB_FEATURE = "based_on_cert21"

    MAGIC = b"chdr"
    FORMAT_VERSION = "2.1"

    def __init__(
        self,
        family: FamilyRevision,
        root_certs: Optional[Union[Sequence[PublicKeyEcc], Sequence[bytes]]] = None,
        ca_flag: bool = False,
        version: str = "2.1",
        used_root_cert: int = 0,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[PublicKeyEcc, bytes]] = None,
        user_data: Optional[bytes] = None,
    ) -> None:
        """Initialize Certificate block with specified configuration.

        Creates a certificate block with header, root key record, and optionally
        an ISK certificate based on the provided parameters and CA flag setting.

        :param family: Target MCU family and revision information.
        :param root_certs: Sequence of root certificates as PublicKeyEcc objects or raw bytes.
        :param ca_flag: Whether this is a Certificate Authority block, defaults to False.
        :param version: Certificate block version string, defaults to "2.1".
        :param used_root_cert: Index of the root certificate to use, defaults to 0.
        :param constraints: Certificate constraints value, defaults to 0.
        :param signature_provider: Provider for cryptographic signatures.
        :param isk_cert: ISK certificate as PublicKeyEcc object or raw bytes.
        :param user_data: Additional user-defined data to include in ISK certificate.
        """
        super().__init__(family)
        self.header = CertificateBlockHeader(version)
        self.root_key_record = RootKeyRecord(
            ca_flag=ca_flag, used_root_cert=used_root_cert, root_certs=root_certs
        )

        self.isk_certificate = None
        if not ca_flag and signature_provider and isk_cert:
            self.isk_certificate = IskCertificate(
                constraints=constraints,
                signature_provider=signature_provider,
                isk_cert=isk_cert,
                user_data=user_data,
                family=family,
            )

    def _set_ca_flag(self, value: bool) -> None:
        """Set the CA flag value for the root key record.

        This method updates the CA (Certificate Authority) flag in the root key record
        to indicate whether the certificate can be used as a certificate authority.

        :param value: Boolean value to set as the CA flag.
        """
        self.root_key_record.ca_flag = value

    def calculate(self) -> None:
        """Calculate all internal members.

        This method triggers the calculation of all internal components within the certificate block,
        including the root key record and any other dependent structures.
        """
        self.root_key_record.calculate()

    @property
    def signature_size(self) -> int:
        """Get the size of the signature in bytes.

        The signature size is determined by the public key data length from either
        the ISK certificate or the root key record, whichever is available.

        :return: Size of the signature in bytes.
        """
        # signature size is same as public key data
        if self.isk_certificate:
            return len(self.isk_certificate.isk_public_key_data)

        return len(self.root_key_record.root_public_key)

    @property
    def expected_size(self) -> int:
        """Calculate the expected size of the certificate block in bytes.

        The method calculates the total size by summing the header size, root key record size,
        and ISK certificate size (if present).

        :return: Expected size of the binary certificate block in bytes.
        """
        expected_size = self.header.SIZE
        expected_size += self.root_key_record.expected_size
        if self.isk_certificate:
            expected_size += self.isk_certificate.expected_size
        return expected_size

    @property
    def rkth(self) -> bytes:
        """Get Root Key Table Hash.

        Returns a 32-byte SHA-256 hash of the SHA-256 hashes of up to four root public keys
        from the root key record.

        :return: 32-byte hash as bytes.
        """
        return self.root_key_record._rkht.rkth()

    def __repr__(self) -> str:
        """Return string representation of Certificate Block 2.1.

        Provides a concise string representation showing the certificate block version
        and its expected size in bytes.

        :return: String representation in format "Cert block 2.1, Size:{size}B".
        """
        return f"Cert block 2.1, Size:{self.expected_size}B"

    def __str__(self) -> str:
        """Get string representation of Certificate block.

        Returns formatted information about the certificate block including header,
        root key record, and ISK certificate if present.

        :return: Formatted string containing certificate block information.
        """
        msg = f"HEADER:\n{str(self.header)}\n"
        msg += f"ROOT KEY RECORD:\n{str(self.root_key_record)}\n"
        if self.isk_certificate:
            msg += f"ISK Certificate:\n{str(self.isk_certificate)}\n"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array.

        This method serializes the certificate block into a binary format by combining
        the header, root key record, and optional ISK certificate data. The header's
        cert_block_size field is automatically updated to reflect the total size.

        :return: Binary representation of the certificate block.
        """
        key_record_data = self.root_key_record.export()
        self.header.cert_block_size = self.header.SIZE + len(key_record_data)
        isk_cert_data = bytes()
        if self.isk_certificate:
            self.isk_certificate.create_isk_signature(key_record_data)
            isk_cert_data = self.isk_certificate.export()
            self.header.cert_block_size += len(isk_cert_data)
        header_data = self.header.export()
        return header_data + key_record_data + isk_cert_data

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse CertBlockV21 from binary data.

        The method parses binary data to create a Certificate Block V2.1 instance,
        including certificate header, root key record, and optional ISK certificate.

        :param data: Binary data to parse
        :param family: The MCU family revision
        :return: Certificate Block V2.1 instance
        :raises SPSDKError: Length of the data doesn't match Certificate Block length
        """
        # CertificateBlockHeader
        cert_header = CertificateBlockHeader.parse(data)
        offset = len(cert_header)
        # RootKeyRecord
        root_key_record = RootKeyRecord.parse(data[offset:])
        offset += root_key_record.expected_size
        # IskCertificate
        isk_certificate = None
        if root_key_record.ca_flag == 0:
            isk_certificate = IskCertificate.parse(
                data[offset:], len(root_key_record.root_public_key)
            )
        # Certification Block V2.1
        cert_block = cls(family)
        cert_block.header = cert_header
        cert_block.root_key_record = root_key_record
        cert_block.isk_certificate = isk_certificate
        return cert_block

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for certificate blocks.

        The method retrieves and configures validation schemas including family-specific
        schemas, certificate schemas, root keys schemas, and output schemas. It updates
        the family schema with supported families for the given family revision.

        :param family: Family revision to configure validation schemas for.
        :return: List of validation schemas including family, certificate, root keys, and output schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [
            sch_family,
            sch_cfg["certificate_v21"],
            sch_cfg["certificate_root_keys"],
            sch_cfg["cert_block_output"],
        ]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of CertBlockV21 from configuration.

        The method supports loading from binary file or creating from configuration parameters.
        It handles root certificates, ISK certificates, constraints, and signature providers.

        :param config: Input standard configuration containing certificate block settings.
        :return: Instance of CertBlockV21 with calculated certificate block.
        :raises SPSDKError: If main root certificate ID doesn't exist or configuration is invalid.
        """
        if "certBlock" in config:
            family = FamilyRevision.load_from_config(config)
            try:
                return cls.parse(
                    load_binary(config.get_input_file_name("certBlock")), family=family
                )
            except (SPSDKError, TypeError):
                cert_block_cfg = config.load_sub_config("certBlock")
                cert_block_cfg["family"] = family.name
                cert_block_cfg["revision"] = family.revision
                return cls.load_from_config(cert_block_cfg)

        root_certificates = find_root_certificates(config)
        main_root_cert_id = cls.get_main_cert_index(config)

        try:
            root_certificates[main_root_cert_id]
        except IndexError as e:
            raise SPSDKError(
                f"Main root certificate with id {main_root_cert_id} does not exist"
            ) from e

        root_certs = [
            load_binary(cert_file, search_paths=config.search_paths)
            for cert_file in root_certificates
        ]

        user_data = None
        signature_provider = None
        isk_cert = None

        use_isk = config.get("useIsk", False)
        if use_isk:
            signature_provider = get_signature_provider(config)
            isk_public_key = config.get("iskPublicKey", config.get("signingCertificateFile"))
            isk_cert = load_binary(isk_public_key, search_paths=config.search_paths)

            isk_sign_data_path = config.get("iskCertData", config.get("signCertData"))
            if isk_sign_data_path:
                user_data = load_binary(isk_sign_data_path, search_paths=config.search_paths)

        isk_constraint = value_to_int(
            config.get("iskCertificateConstraint", config.get("signingCertificateConstraint", "0"))
        )
        family = FamilyRevision.load_from_config(config)
        cert_block = cls(
            family=family,
            root_certs=root_certs,
            used_root_cert=main_root_cert_id,
            user_data=user_data,
            constraints=isk_constraint,
            isk_cert=isk_cert,
            ca_flag=not use_isk,
            signature_provider=signature_provider,
        )
        cert_block.calculate()

        return cert_block

    def validate(self) -> None:
        """Validate the settings of certification block class members.

        This method performs validation checks on the certification block configuration,
        including header parsing and ISK certificate signature validation.

        :raises SPSDKError: Invalid configuration of certification block class members.
        """
        self.header.parse(self.header.export())
        if self.isk_certificate and not self.isk_certificate.signature:
            if not isinstance(self.isk_certificate.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration dictionary of the Certification block Image.

        The method generates a configuration that includes root certificates, ISK certificate
        settings, and associated data files. It saves public keys and user data to the
        specified data path and creates appropriate configuration entries.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with certificate block settings.
        """
        cfg = Config()
        cfg["signer"] = "N/A"
        cfg["signingCertificatePrivateKeyFile"] = "N/A"
        for i in range(self.root_key_record.number_of_certificates):
            key: Optional[PublicKeyEcc] = None
            if i == self.root_key_record.used_root_cert:
                key = convert_to_ecc_key(self.root_key_record.root_public_key)
            else:
                if i < len(self.root_key_record.root_certs) and self.root_key_record.root_certs[i]:
                    key = convert_to_ecc_key(self.root_key_record.root_certs[i])
            if key:
                key_file_name = os.path.join(data_path, f"rootCertificate{i}File.pub")
                key.save(key_file_name)
                cfg[f"rootCertificate{i}File"] = f"rootCertificate{i}File.pub"
            else:
                cfg[f"rootCertificate{i}File"] = (
                    "The public key is not possible reconstruct from the key hash"
                )

        cfg["mainRootCertId"] = self.root_key_record.used_root_cert
        if self.isk_certificate and self.root_key_record.ca_flag == 0:
            cfg["useIsk"] = True
            assert isinstance(self.isk_certificate.isk_cert, PublicKeyEcc)
            key = self.isk_certificate.isk_cert
            key_file_name = os.path.join(data_path, "signingCertificateFile.pub")
            key.save(key_file_name)
            cfg["signingCertificateFile"] = "signingCertificateFile.pub"
            cfg["signingCertificateConstraint"] = self.isk_certificate.constraints
            if self.isk_certificate.user_data:
                key_file_name = os.path.join(data_path, "isk_user_data.bin")
                write_file(self.isk_certificate.user_data, key_file_name, mode="wb")
                cfg["signCertData"] = "isk_user_data.bin"

        else:
            cfg["useIsk"] = False

        return cfg

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        :raises SPSDKError: If root key record is not available or parsing fails.
        :return: Root public key object parsed from the certificate block.
        """
        return PublicKey.parse(self.root_key_record.root_public_key)


########################################################################################################################
# Certificate Block Class for SB X
########################################################################################################################


########################################################################################################################
# Certificate Block Class for SB X
########################################################################################################################


class CertBlockVx(CertBlock):
    """Certificate block implementation for MC56xx family devices.

    This class provides certificate block functionality specifically designed for MC56xx
    microcontrollers, handling ISK (Intermediate Signing Key) certificate management,
    hash calculation, and binary export operations for secure boot processes.

    :cvar SUB_FEATURE: Feature identifier for certificate-based implementations.
    :cvar ISK_CERT_LENGTH: Standard length of ISK certificate in bytes.
    :cvar ISK_CERT_HASH_LENGTH: Length of ISK certificate hash in bytes.
    """

    SUB_FEATURE = "based_on_certx"

    ISK_CERT_LENGTH = 136
    ISK_CERT_HASH_LENGTH = 16  # [0:127]

    def __init__(
        self,
        family: FamilyRevision,
        isk_cert: Union[PublicKeyEcc, bytes],
        signature_provider: Optional[SignatureProvider] = None,
        self_signed: bool = True,
    ) -> None:
        """Initialize Certificate block with ISK certificate and signature provider.

        Creates a new certificate block instance with the specified family revision,
        ISK certificate, and optional signature provider for certificate operations.

        :param family: Target MCU family and revision information.
        :param isk_cert: ISK certificate as ECC public key or raw bytes.
        :param signature_provider: Optional provider for certificate signing operations.
        :param self_signed: Whether the certificate should be self-signed.
        """
        super().__init__(family)
        self.isk_cert_hash = bytes(self.ISK_CERT_HASH_LENGTH)
        self.isk_certificate = IskCertificateLite(pub_key=isk_cert, constraints=int(self_signed))
        self.signature_provider = signature_provider

    @property
    def expected_size(self) -> int:
        """Get expected size of binary block.

        :return: Expected size of the ISK certificate in bytes.
        """
        return self.isk_certificate.expected_size

    @property
    def cert_hash(self) -> bytes:
        """Calculate certificate hash from ISK certificate data.

        The method extracts the ISK certificate data and computes a hash, returning
        only the first 127 bytes of the calculated hash value.

        :return: First 127 bytes of the ISK certificate hash.
        """
        isk_cert_data = self.isk_certificate.export()
        return get_hash(isk_cert_data)[: self.ISK_CERT_HASH_LENGTH]

    def __repr__(self) -> str:
        """Return string representation of the certificate block.

        :return: String identifier for the certificate block version.
        """
        return "CertificateBlockVx"

    def __str__(self) -> str:
        """Get string representation of the Certificate block.

        Provides detailed information about the certificate block including version,
        ISK certificate details, and certificate hash.

        :return: Formatted string containing certificate block information.
        """
        msg = "Certificate block version x\n"
        msg += f"ISK Certificate:\n{str(self.isk_certificate)}\n"
        msg += f"Certificate hash: {self.cert_hash.hex()}"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array.

        Creates ISK signature using the configured signature provider and exports
        the ISK certificate data.

        :return: Certificate block data as bytes.
        """
        isk_cert_data = bytes()
        self.isk_certificate.create_isk_signature(self.signature_provider)
        isk_cert_data = self.isk_certificate.export()
        return isk_cert_data

    def get_tbs_data(self) -> bytes:
        """Get To-Be-Signed data from the ISK certificate.

        This method retrieves the To-Be-Signed (TBS) portion of the ISK (Intermediate Signing Key)
        certificate, which contains the certificate data that needs to be signed.

        :return: The TBS data as bytes from the ISK certificate.
        """
        return self.isk_certificate.get_tbs_data()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse CertBlockVx from binary file.

        The method creates a Certificate Block instance by parsing the ISK certificate from the
        provided binary data and extracting the public key and signature information.

        :param data: Binary data containing the certificate block information.
        :param family: The MCU family revision for the certificate block.
        :return: Certificate Block instance with parsed ISK certificate data.
        :raises SPSDKError: Length of the data doesn't match Certificate Block length.
        """
        # IskCertificate
        isk_certificate = IskCertificateLite.parse(data)
        cert_block = cls(
            family=family,
            isk_cert=isk_certificate.isk_public_key_data,
            self_signed=bool(isk_certificate.constraints),
        )
        cert_block.isk_certificate.signature = isk_certificate.signature
        return cert_block

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for certificate blocks.

        The method retrieves and configures validation schemas including family-specific
        schema, certificate schema, and certificate block output schema. It updates the
        family schema with supported families for the given family revision.

        :param family: Family revision to configure validation schemas for.
        :return: List of validation schemas including family, certificate, and output schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg["certificate_vx"], sch_cfg["cert_block_output"]]

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Certification block Image.

        :param data_path: Path to directory containing data files for configuration.
        :raises SPSDKNotImplementedError: Parsing of Cert Block Vx is not supported.
        """
        raise SPSDKNotImplementedError("Parsing of Cert Block Vx is not supported")

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create an instance of CertBlockVx from configuration.

        The method supports loading from binary file or creating from configuration parameters.
        It handles ISK certificates, signature providers, and family-specific settings.

        :param config: Input standard configuration containing certificate block settings.
        :return: CertBlockVx instance configured according to the provided configuration.
        :raises SPSDKError: If found gap in certificates from config file or invalid configuration.
        """
        if "certBlock" in config:
            family = FamilyRevision.load_from_config(config)
            try:
                return cls.parse(
                    load_binary(config.get_input_file_name("certBlock")), family=family
                )
            except (SPSDKError, TypeError):
                cert_block_cfg = config.load_sub_config("certBlock")
                cert_block_cfg["family"] = family.name
                cert_block_cfg["revision"] = family.revision
                return cls.load_from_config(cert_block_cfg)

        isk_certificate = config.get("iskPublicKey", config.get("signingCertificateFile"))

        signature_provider = get_signature_provider(config)
        isk_cert = load_binary(isk_certificate, search_paths=config.search_paths)
        self_signed = config.get("selfSigned", True)
        family = FamilyRevision.load_from_config(config)
        cert_block = cls(
            family,
            signature_provider=signature_provider,
            isk_cert=isk_cert,
            self_signed=self_signed,
        )

        return cert_block

    def validate(self) -> None:
        """Validate the settings of certification block class members.

        This method checks if the ISK certificate configuration is valid, specifically
        verifying that when an ISK certificate exists without a signature, a proper
        signature provider must be available.

        :raises SPSDKError: Invalid ISK certificate configuration when certificate
            exists without signature but no valid signature provider is set.
        """
        if self.isk_certificate and not self.isk_certificate.signature:
            if not isinstance(self.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    def get_otp_script(self) -> str:
        """Generate OTP programming script for writing certificate hash to fuses.

        The method creates a blhost script that programs the ISK certificate hash
        into OTP fuses starting from index 12. The hash is split into 4-byte chunks
        with proper endianness conversion for fuse programming.

        :return: Blhost script content as string for OTP fuse programming.
        """
        ret = (
            "# BLHOST Cert Block Vx fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# ISK Cert hash [0:127]: {self.cert_hash.hex()} \n\n"
        )

        fuse_value = change_endianness(self.cert_hash)
        fuse_idx = 12  # Fuse start IDX
        for fuse_data in split_data(fuse_value, 4):
            ret += f"flash-program-once {hex(fuse_idx)} 4 {fuse_data.hex()}\n"
            fuse_idx += 1

        return ret


def find_root_certificates(config: dict[str, Any]) -> list[str]:
    """Find all root certificates in configuration.

    Searches for root certificate file paths in the configuration dictionary by looking for
    keys matching the pattern 'rootCertificateXFile' where X is 0-3. Validates that there
    are no gaps in the certificate numbering sequence.

    :param config: Configuration dictionary containing certificate file paths.
    :raises SPSDKError: If there are gaps in rootCertificateXFile definition sequence.
    :return: List of root certificate file paths found in configuration.
    """
    root_certificates_loaded: list[Optional[str]] = [
        config.get(f"rootCertificate{idx}File") for idx in range(4)
    ]
    # filter out None and empty values
    root_certificates = list(filter(None, root_certificates_loaded))
    for org, filtered in zip(root_certificates_loaded, root_certificates):
        if org != filtered:
            raise SPSDKError("There are gaps in rootCertificateXFile definition")
    return root_certificates


def get_keys_or_rotkh_from_certblock_config(
    rot: Optional[str], family: Optional[FamilyRevision]
) -> tuple[Optional[Iterable[str]], Optional[bytes]]:
    """Get keys or ROTKH value from ROT config.

    ROT config might be cert block config or MBI config.
    There are four cases how cert block might be configured:
    1. MBI with certBlock property pointing to YAML file
    2. MBI with certBlock property pointing to BIN file
    3. YAML configuration of cert block
    4. Binary cert block

    :param rot: Path to ROT configuration (MBI or cert block) or path to binary cert block.
    :param family: MCU family.
    :raises SPSDKError: In case the ROTKH or keys cannot be parsed.
    :return: Tuple containing root of trust (list of paths to keys) or ROTKH in case of binary
        cert block.
    """
    root_of_trust = None
    rotkh = None
    if rot and family:
        logger.info("Loading configuration from cert block/MBI file...")
        config_dir = os.path.dirname(rot)
        try:
            config_data = load_configuration(rot, search_paths=[config_dir])
            if "certBlock" in config_data:
                try:
                    config_data = load_configuration(
                        config_data["certBlock"], search_paths=[config_dir]
                    )
                except SPSDKError:
                    cert_block = load_binary(config_data["certBlock"], search_paths=[config_dir])
                    parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                    rotkh = parsed_cert_block.rkth
            public_keys = find_root_certificates(config_data)
            root_of_trust = tuple((find_file(x, search_paths=[config_dir]) for x in public_keys))
        except SPSDKError:
            logger.debug("Parsing ROT from config did not succeed, trying it as binary")
            try:
                cert_block = load_binary(rot, search_paths=[config_dir])
                parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                rotkh = parsed_cert_block.rkth
            except SPSDKError as e:
                raise SPSDKError(f"Parsing of binary cert block failed with {e}") from e

    return root_of_trust, rotkh


class CertBlockAhab(CertBlock):
    """Certificate block implementation using AHAB Certificate format.

    This class provides certificate block functionality based on AHAB (Advanced High
    Assurance Boot) certificates, supporting SRK-based certificate blocks with AHAB v2
    48-byte format for compatible chip families.

    :cvar SUB_FEATURE: Identifier for SRK-based certificate block type.
    """

    SUB_FEATURE = "based_on_srk"

    def __init__(  # type: ignore[no-untyped-def]
        self, family: FamilyRevision, ahab_certificate: Optional[AhabCertificate] = None, **kwargs
    ) -> None:
        """Initialize AHAB-based certificate block.

        Creates a new AHAB certificate block instance either from an existing AHAB certificate
        or by creating a new one using the provided arguments.

        :param family: Chip family and revision information.
        :param ahab_certificate: Optional existing AHAB Certificate instance to use.
        :param kwargs: Additional keyword arguments for AHAB certificate creation when
            ahab_certificate is not provided.
        """
        super().__init__(family)

        if ahab_certificate:
            self._ahab_certificate = ahab_certificate
        else:
            # Create AHAB certificate with provided arguments
            ahab_cert_class = get_ahab_certificate_class(family)
            self._ahab_certificate = ahab_cert_class(family=family, **kwargs)

    @property
    def ahab_certificate(self) -> AhabCertificate:
        """Get the underlying AHAB certificate.

        :return: The AHAB certificate instance associated with this certificate block.
        """
        return self._ahab_certificate

    @property
    def expected_size(self) -> int:
        """Get expected size of binary block.

        :return: Size of the AHAB certificate in bytes.
        """
        return len(self._ahab_certificate)

    @property
    def signature_size(self) -> int:
        """Get the total size of signatures in bytes.

        Calculates the combined size of both public key signatures (key 0 and key 1)
        from the AHAB certificate. If a public key is not available or causes an error,
        its signature size is treated as 0.

        :return: Total signature size in bytes from both public keys.
        """
        sign0_size = 0
        sign1_size = 0
        try:
            if self._ahab_certificate.public_key_0:
                sign0_size = self._ahab_certificate.public_key_0.get_public_key().signature_size
        except SPSDKError:
            pass

        try:
            if self._ahab_certificate.public_key_1:
                sign1_size = self._ahab_certificate.public_key_1.get_public_key().signature_size
        except SPSDKError:
            pass

        return sign0_size + sign1_size

    def export(self) -> bytes:
        """Export certificate block as bytes.

        Updates the internal AHAB certificate fields and exports the complete
        certificate block data in binary format.

        :return: Binary representation of the certificate block.
        """
        self._ahab_certificate.update_fields()
        return self._ahab_certificate.export()

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        Extracts and returns the first public key from the AHAB certificate, which serves as the root
        public key for certificate validation.

        :raises SPSDKError: No public key available in AHAB certificate.
        :return: Public key object from the first public key in AHAB certificate.
        """
        if not self._ahab_certificate.public_key_0:
            raise SPSDKError("No public key available in AHAB certificate")
        return self._ahab_certificate.public_key_0.get_public_key()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse Certificate block from binary data.

        Creates a CertBlockAhab instance by parsing the provided binary data and extracting
        the AHAB certificate information specific to the given chip family.

        :param data: Binary data of certification block
        :param family: Chip family revision information
        :return: CertBlockAhab instance
        """
        ahab_cert_class = get_ahab_certificate_class(family)
        ahab_certificate = ahab_cert_class.parse(data, family)

        return cls(family=family, ahab_certificate=ahab_certificate)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for the specified family.

        The method retrieves the appropriate AHAB certificate class for the given family
        and delegates the schema creation to that class.

        :param family: Family revision to get validation schemas for.
        :return: List of validation schemas for the specified family.
        """
        ahab_cert_class = get_ahab_certificate_class(family)
        return ahab_cert_class.get_validation_schemas(family)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create an instance of CertBlockAhab from configuration.

        Loads family revision and AHAB certificate from the provided configuration
        and constructs a new CertBlockAhab instance.

        :param config: Input standard configuration containing family and certificate data.
        :return: Instance of CertBlockAhab with loaded family and certificate.
        """
        family = FamilyRevision.load_from_config(config)
        ahab_cert_class = get_ahab_certificate_class(family)
        ahab_certificate = ahab_cert_class.load_from_config(config)

        return cls(family=family, ahab_certificate=ahab_certificate)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of Certificate Block from object.

        :param data_path: Output folder to store possible files.
        :return: Configuration dictionary.
        """
        return self._ahab_certificate.get_config(data_path=data_path)

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for this certificate block.

        Returns families that have cert_block configuration with:
        - sub_features: [based_on_srk]
        - rot_type: "srk_table_ahab_v2_48_bytes"

        :param include_predecessors: Whether to include predecessor family revisions in the search.
        :return: List of supported family revisions that meet the configuration requirements.
        """
        supported_families = get_families(
            feature=cls.FEATURE,
            sub_feature=cls.SUB_FEATURE,
            include_predecessors=include_predecessors,
        )
        supported_families_final: list[FamilyRevision] = []
        for family_rev in supported_families:
            db = get_db(family_rev)
            cert_block_config = db.get_str(cls.FEATURE, "rot_type", "None")
            # Check for specific configuration requirements
            if cert_block_config == "srk_table_ahab_v2_48_bytes":
                supported_families_final.append(family_rev)

        return supported_families_final

    def __repr__(self) -> str:
        """Return string representation of CertBlockAhab instance.

        :return: String containing class name and target family.
        """
        return f"CertBlockAhab for {self.family}"

    def __str__(self) -> str:
        """Get string representation of AHAB Certificate Block.

        :return: Formatted string containing AHAB certificate block information.
        """
        return f"AHAB Certificate Block:\n{str(self._ahab_certificate)}"

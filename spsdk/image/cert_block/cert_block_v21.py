#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2026 NXP
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
from typing import Any, Optional, Sequence, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKey, PublicKeyEcc
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlock, convert_to_ecc_key, find_root_certificates
from spsdk.image.cert_block.rkht import RKHTv21
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import load_binary, value_to_int, write_file
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)

########################################################################################################################
# Certificate Block Class for SB 3.1
########################################################################################################################


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

    def verify(self) -> Verifier:
        """Verify the Certificate Block Header configuration.

        Validates header fields including magic, format version, and certificate block size.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="Certificate Block Header",
            description="Validates certificate block header structure and values",
        )

        # Verify magic signature
        ver.add_record(
            name="Magic signature",
            result=self.MAGIC == b"chdr",
            value=(
                f"Magic: {self.MAGIC.hex()} "
                f"({'valid' if self.MAGIC == b'chdr' else 'INVALID, expected: chdr'})"
            ),
        )

        # Verify format version format (should be N.N)
        version_valid = bool(re.match(r"[0-9]+\.[0-9]+", self.format_version))
        ver.add_record(
            name="Format version format",
            result=version_valid,
            value=(
                f"Version {self.format_version} "
                f"({'valid format' if version_valid else 'INVALID format, expected N.N'})"
            ),
        )

        # Verify certificate block size (should be non-negative and reasonable)
        ver.add_record_range(
            name="Certificate block size",
            value=self.cert_block_size,
            min_val=0,
            max_val=0xFFFFFFFF,
        )

        # Verify header size consistency
        calculated_size = calcsize(self.FORMAT)
        ver.add_record(
            name="Header size",
            result=calculated_size == self.SIZE,
            value=(
                f"Calculated: {calculated_size} bytes, Expected: {self.SIZE} bytes "
                f"({'match' if calculated_size == self.SIZE else 'MISMATCH'})"
            ),
        )

        # Verify export/parse round-trip
        try:
            exported = self.export()

            # Check exported size matches expected
            ver.add_record(
                name="Export size",
                result=len(exported) == self.SIZE,
                value=f"Exported: {len(exported)} bytes, Expected: {self.SIZE} bytes",
            )

            parsed = CertificateBlockHeader.parse(exported)

            roundtrip_valid = (
                parsed.format_version == self.format_version
                and parsed.cert_block_size == self.cert_block_size
            )

            ver.add_record(
                name="Export/Parse consistency",
                result=roundtrip_valid,
                value=(
                    "Header can be exported and parsed correctly"
                    if roundtrip_valid
                    else "Header export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

        return ver


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

    def verify(self) -> Verifier:
        """Verify the Certificate Block Header V2.2 configuration.

        Validates header fields including magic, format version, certificate block size,
        and the additional flags field specific to version 2.2.

        :return: Verifier object for validation results.
        """
        # Get parent verifier first
        ver = super().verify()

        # Update the name and description for V2.2
        ver.name = "Certificate Block Header V2.2"
        ver.description = (
            "Validates certificate block header V2.2 structure and values including flags"
        )

        # Verify flags field (32-bit range) - specific to V2.2
        ver.add_record_bit_range(
            name="Flags",
            value=self.flags,
            bit_range=32,
        )

        # Override export/parse round-trip to include flags validation
        try:
            exported = self.export()

            # Check exported size matches expected
            ver.add_record(
                name="Export size V2.2",
                result=len(exported) == self.SIZE,
                value=f"Exported: {len(exported)} bytes, Expected: {self.SIZE} bytes",
            )

            parsed = CertificateBlockHeaderV2_2.parse(exported)

            roundtrip_valid = (
                parsed.format_version == self.format_version
                and parsed.cert_block_size == self.cert_block_size
                and parsed.flags == self.flags
            )

            ver.add_record(
                name="Export/Parse consistency V2.2",
                result=roundtrip_valid,
                value=(
                    "Header V2.2 can be exported and parsed correctly with flags"
                    if roundtrip_valid
                    else "Header V2.2 export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency V2.2",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

        return ver


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
        ca_flag = bool(flags & 0x80000000)
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

    def _verify_basic_fields(self, ver: Verifier) -> None:
        """Verify basic fields of Root Key Record.

        Validates CA flag, used certificate index, and number of certificates.

        :param ver: Verifier object to add validation records to.
        """
        # Verify CA flag
        ver.add_record(
            name="CA flag",
            result=VerifierResult.SUCCEEDED,
            value=f"CA flag: {self.ca_flag} (ISK Certificate is {'not ' if self.ca_flag else ''}mandatory)",
        )

        # Verify used root certificate index (0-3)
        ver.add_record_range(
            name="Used root certificate index",
            value=self.used_root_cert,
            min_val=0,
            max_val=3,
        )

        # Verify number of certificates
        num_certs = self.number_of_certificates
        ver.add_record_range(
            name="Number of certificates",
            value=num_certs,
            min_val=0,
            max_val=4,
        )

    def _verify_certificates(self, ver: Verifier, num_certs: int) -> None:
        """Verify root certificates presence and validity.

        Validates that certificates exist, used index is valid, all are ECC keys,
        and all use the same curve.

        :param ver: Verifier object to add validation records to.
        :param num_certs: Expected number of certificates.
        """
        if num_certs == 0:
            return

        # When parsed from binary, root certificates may not be available (only RKTH)
        # So we verify that either we have the expected certificates OR we have RKTH
        has_all_certs = len(self.root_certs) == num_certs
        has_rkth = self._rkht is not None and len(self._rkht.rkh_list) > 0

        ver.add_record(
            name="Root certificates presence",
            result=has_all_certs or has_rkth,
            value=(
                f"Expected {num_certs} certificates, found {len(self.root_certs)}"
                if has_all_certs
                else f"RKTH available: {has_rkth}"
            ),
        )

        # Verify used_root_cert is within range of available certificates
        if len(self.root_certs) > 0:
            self._verify_certificate_index(ver)
            self._verify_certificate_types(ver)
            self._verify_certificate_curves(ver)

    def _verify_certificate_index(self, ver: Verifier) -> None:
        """Verify that used certificate index is within valid range.

        :param ver: Verifier object to add validation records to.
        """
        ver.add_record(
            name="Used certificate index validity",
            result=self.used_root_cert < len(self.root_certs),
            value=(
                f"Used index {self.used_root_cert} is "
                f"{'valid' if self.used_root_cert < len(self.root_certs) else 'INVALID (out of range)'}"
            ),
        )

    def _verify_certificate_types(self, ver: Verifier) -> None:
        """Verify that all root certificates are ECC keys.

        :param ver: Verifier object to add validation records to.
        """
        all_ecc = all(isinstance(cert, PublicKeyEcc) for cert in self.root_certs)
        ver.add_record(
            name="Root certificates type",
            result=all_ecc,
            value=(
                "All root certificates are ECC keys"
                if all_ecc
                else "Some certificates are NOT ECC keys"
            ),
        )

    def _verify_certificate_curves(self, ver: Verifier) -> None:
        """Verify that all certificates use the same curve.

        :param ver: Verifier object to add validation records to.
        """
        if len(self.root_certs) <= 1:
            return

        first_curve = self.root_certs[0].curve
        same_curve = all(cert.curve == first_curve for cert in self.root_certs)
        ver.add_record(
            name="Certificate curve consistency",
            result=same_curve,
            value=(
                f"All certificates use {first_curve}"
                if same_curve
                else "Certificates use DIFFERENT curves (not allowed)"
            ),
        )

    def _verify_flags_and_type(self, ver: Verifier) -> None:
        """Verify flags and certificate type.

        Validates the flags field and extracts certificate type information.

        :param ver: Verifier object to add validation records to.
        """
        # Verify flags (32-bit)
        ver.add_record_bit_range(
            name="Flags",
            value=self.flags,
            bit_range=32,
        )

        # Verify certificate type from flags
        cert_type_bits = self.flags & 0xF
        valid_cert_type = cert_type_bits in [0x1, 0x2]  # secp256r1 or secp384r1
        cert_type_name = {0x1: "secp256r1", 0x2: "secp384r1"}.get(cert_type_bits, "UNKNOWN")
        ver.add_record(
            name="Certificate type",
            result=valid_cert_type,
            value=f"Type: {cert_type_name} ({'valid' if valid_cert_type else 'INVALID'})",
        )

    def _verify_rkht(self, ver: Verifier, num_certs: int) -> None:
        """Verify RKHT (Root Key Hash Table).

        Validates RKHT entries and consistency with certificate count.

        :param ver: Verifier object to add validation records to.
        :param num_certs: Expected number of certificates.
        """
        if not (self._rkht and self._rkht.rkh_list):
            return

        rkh_count = len(self._rkht.rkh_list)
        ver.add_record(
            name="RKHT entries",
            result=rkh_count > 0,
            value=f"{rkh_count} root key hash(es) in RKHT",
        )

        # Verify RKHT count matches number of certificates
        ver.add_record(
            name="RKHT count consistency",
            result=rkh_count == num_certs or (num_certs == 1 and rkh_count == 1),
            value=f"RKHT has {rkh_count} entries, certificates: {num_certs}",
        )

    def _verify_root_public_key(self, ver: Verifier) -> None:
        """Verify root public key length.

        Validates that the root public key length matches the expected length
        for the certificate type.

        :param ver: Verifier object to add validation records to.
        """
        if not self.root_public_key:
            ver.add_record(
                name="Root public key",
                result=VerifierResult.WARNING,
                value="Root public key not set (call calculate() first)",
            )
            return

        cert_type_bits = self.flags & 0xF
        expected_key_len = {0x1: 64, 0x2: 96}.get(cert_type_bits, 0)
        cert_type_name = {0x1: "secp256r1", 0x2: "secp384r1"}.get(cert_type_bits, "UNKNOWN")

        ver.add_record(
            name="Root public key length",
            result=len(self.root_public_key) == expected_key_len,
            value=(
                f"Key length: {len(self.root_public_key)} "
                f"bytes (expected {expected_key_len} for {cert_type_name})"
            ),
        )

    def _verify_size_calculation(self, ver: Verifier) -> None:
        """Verify expected size calculation.

        Validates that the expected size can be calculated correctly.

        :param ver: Verifier object to add validation records to.
        """
        try:
            expected_size = self.expected_size
            ver.add_record(
                name="Expected size",
                result=expected_size > 0,
                value=f"Expected size: {expected_size} bytes",
            )
        except Exception as e:
            ver.add_record(
                name="Expected size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate expected size: {str(e)}",
            )

    def _verify_export_parse_roundtrip(self, ver: Verifier) -> None:
        """Verify export/parse round-trip consistency.

        Validates that the Root Key Record can be exported and parsed correctly.

        :param ver: Verifier object to add validation records to.
        """
        if not (self.root_public_key and self._rkht):
            return

        try:
            exported = self.export()

            ver.add_record(
                name="Export size consistency",
                result=len(exported) == self.expected_size,
                value=f"Exported: {len(exported)} bytes, Expected: {self.expected_size} bytes",
            )

            parsed = RootKeyRecord.parse(exported)

            roundtrip_valid = (
                parsed.ca_flag == self.ca_flag
                and parsed.used_root_cert == self.used_root_cert
                and parsed.flags == self.flags
                and len(parsed.root_public_key) == len(self.root_public_key)
            )

            ver.add_record(
                name="Export/Parse consistency",
                result=roundtrip_valid,
                value=(
                    "Root Key Record can be exported and parsed correctly"
                    if roundtrip_valid
                    else "Export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

    def verify(self) -> Verifier:
        """Verify the Root Key Record configuration.

        Validates root key record including CA flag, root certificates, used certificate index,
        flags, RKHT (Root Key Hash Table), and root public key.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="Root Key Record",
            description="Validates root key record structure and certificate configuration",
        )

        # Verify basic fields
        self._verify_basic_fields(ver)

        # Verify certificates
        num_certs = self.number_of_certificates
        self._verify_certificates(ver, num_certs)

        # Verify flags and certificate type
        self._verify_flags_and_type(ver)

        # Verify RKHT
        self._verify_rkht(ver, num_certs)

        # Verify root public key
        self._verify_root_public_key(ver)

        # Verify expected size calculation
        self._verify_size_calculation(ver)

        # Verify export/parse round-trip
        self._verify_export_parse_roundtrip(ver)

        return ver


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
        signature_offset, constraints, isk_flags = unpack_from("<3L", data)
        header_word_cnt = 3
        if signature_offset & 0xFFFF == 0x4D43:  # This means that certificate has no offset
            constraints, isk_flags = unpack_from("<2L", data)
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

    def _verify_constraints_and_flags(self, ver: Verifier) -> None:
        """Verify constraints and flags fields.

        Validates constraints and flags are within valid 32-bit range.

        :param ver: Verifier object to add validation records to.
        """
        # Verify constraints (32-bit range)
        ver.add_record_bit_range(
            name="Constraints",
            value=self.constraints,
            bit_range=32,
        )

        # Verify flags (32-bit range)
        ver.add_record_bit_range(
            name="Flags",
            value=self.flags,
            bit_range=32,
        )

    def _verify_certificate_type(self, ver: Verifier) -> int:
        """Verify certificate type from flags.

        Validates the certificate type bits and returns the type bits for further use.

        :param ver: Verifier object to add validation records to.
        :return: Certificate type bits extracted from flags.
        """
        cert_type_bits = self.flags & 0xF
        valid_cert_type = cert_type_bits in [0x0, 0x1, 0x2]  # 0=secp256r1, 1=secp256r1, 2=secp384r1
        cert_type_name = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}.get(
            cert_type_bits, "UNKNOWN"
        )
        ver.add_record(
            name="Certificate type",
            result=valid_cert_type,
            value=f"Type: {cert_type_name} ({'valid' if valid_cert_type else 'INVALID'})",
        )
        return cert_type_bits

    def _verify_user_data(self, ver: Verifier) -> None:
        """Verify user data flag consistency and length.

        Validates that user data flag matches actual user data presence.

        :param ver: Verifier object to add validation records to.
        """
        # Verify user data flag consistency
        user_data_flag = bool(self.flags & 0x80000000)
        user_data_present = len(self.user_data) > 0
        ver.add_record(
            name="User data flag consistency",
            result=user_data_flag == user_data_present,
            value=(
                f"Flag: {user_data_flag}, Data present: {user_data_present} "
                f"({'consistent' if user_data_flag == user_data_present else 'INCONSISTENT'})"
            ),
        )

        # Verify user data if present
        if self.user_data:
            ver.add_record(
                name="User data length",
                result=VerifierResult.SUCCEEDED,
                value=f"{len(self.user_data)} bytes",
                important=False,
            )

    def _verify_isk_certificate(self, ver: Verifier, cert_type_bits: int) -> None:
        """Verify ISK certificate (public key).

        Validates ISK certificate presence, public key data length, and curve consistency.

        :param ver: Verifier object to add validation records to.
        :param cert_type_bits: Certificate type bits from flags.
        """
        if self.isk_cert is None:
            ver.add_record(
                name="ISK certificate",
                result=VerifierResult.ERROR,
                value="ISK certificate is not set (required)",
            )
            return

        ver.add_record(
            name="ISK certificate",
            result=VerifierResult.SUCCEEDED,
            value=f"ISK certificate present ({self.isk_cert.curve})",
        )

        # Verify public key data length matches certificate type
        cert_type_name = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}.get(
            cert_type_bits, "UNKNOWN"
        )
        expected_key_len = {0: 64, 1: 64, 2: 96}.get(cert_type_bits, 0)
        actual_key_len = len(self.isk_public_key_data)
        ver.add_record(
            name="Public key data length",
            result=actual_key_len == expected_key_len,
            value=f"Actual: {actual_key_len} bytes, Expected: {expected_key_len} bytes for {cert_type_name}",
        )

        # Verify certificate curve matches flags
        self._verify_certificate_curve(ver, cert_type_bits, cert_type_name)

    def _verify_certificate_curve(
        self, ver: Verifier, cert_type_bits: int, cert_type_name: str
    ) -> None:
        """Verify that certificate curve matches flags.

        :param ver: Verifier object to add validation records to.
        :param cert_type_bits: Certificate type bits from flags.
        :param cert_type_name: Human-readable certificate type name.
        """
        if not self.isk_cert:
            return

        curve_matches = (cert_type_bits in [0, 1] and self.isk_cert.curve == "secp256r1") or (
            cert_type_bits == 2 and self.isk_cert.curve == "secp384r1"
        )
        ver.add_record(
            name="Certificate curve matches flags",
            result=curve_matches,
            value=(
                f"Certificate curve: {self.isk_cert.curve}, Flags indicate: "
                f"{cert_type_name} ({'match' if curve_matches else 'MISMATCH'})"
            ),
        )

    def _verify_signature_offset(self, ver: Verifier) -> None:
        """Verify signature offset if present.

        Validates that signature offset is within valid range.

        :param ver: Verifier object to add validation records to.
        """
        if not self.offset_present:
            return

        calculated_offset = self.signature_offset
        ver.add_record_range(
            name="Signature offset",
            value=calculated_offset,
            min_val=8,  # Minimum: 2 or 3 words for header
            max_val=0xFFFFFFFF,
        )

    def _verify_signature(self, ver: Verifier) -> None:
        """Verify signature presence and length.

        Validates signature is set and has correct length.

        :param ver: Verifier object to add validation records to.
        """
        if not self.signature:
            if self.signature_provider:
                ver.add_record(
                    name="Signature",
                    result=VerifierResult.WARNING,
                    value="Signature not created yet (signature provider available)",
                )
            else:
                ver.add_record(
                    name="Signature",
                    result=VerifierResult.ERROR,
                    value="Signature not set and no signature provider available",
                )
            return

        expected_sig_len = (
            self.signature_provider.signature_length
            if self.signature_provider
            else len(self.signature)
        )
        ver.add_record(
            name="Signature length",
            result=len(self.signature) == expected_sig_len,
            value=f"Actual: {len(self.signature)} bytes, Expected: {expected_sig_len} bytes",
        )

    def _verify_coordinate_length(self, ver: Verifier) -> None:
        """Verify coordinate length consistency.

        Validates coordinate length matches signature provider expectations.

        :param ver: Verifier object to add validation records to.
        """
        if not self.signature_provider:
            return

        expected_coord_len = self.signature_provider.signature_length // 2
        ver.add_record(
            name="Coordinate length",
            result=self.coordinate_length == expected_coord_len,
            value=f"Actual: {self.coordinate_length}, Expected: {expected_coord_len}",
        )

    def _verify_expected_size(self, ver: Verifier) -> None:
        """Verify expected size calculation.

        Validates that expected size can be calculated correctly.

        :param ver: Verifier object to add validation records to.
        """
        try:
            expected_size = self.expected_size
            ver.add_record(
                name="Expected size",
                result=expected_size > 0,
                value=f"Expected size: {expected_size} bytes",
            )
        except Exception as e:
            ver.add_record(
                name="Expected size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate expected size: {str(e)}",
            )

    def _verify_export_parse_roundtrip(self, ver: Verifier) -> None:
        """Verify export/parse round-trip if signature is present.

        Validates that ISK Certificate can be exported and parsed correctly.

        :param ver: Verifier object to add validation records to.
        """
        if not (self.signature and self.isk_cert):
            return

        try:
            exported = self.export()

            ver.add_record(
                name="Export size consistency",
                result=len(exported) == self.expected_size,
                value=f"Exported: {len(exported)} bytes, Expected: {self.expected_size} bytes",
            )

            parsed = IskCertificate.parse(exported, len(self.signature))

            roundtrip_valid = (
                parsed.constraints == self.constraints
                and parsed.flags == self.flags
                and len(parsed.isk_public_key_data) == len(self.isk_public_key_data)
                and len(parsed.signature) == len(self.signature)
            )

            if self.user_data:
                roundtrip_valid = roundtrip_valid and (parsed.user_data == self.user_data)

            ver.add_record(
                name="Export/Parse consistency",
                result=roundtrip_valid,
                value=(
                    "ISK Certificate can be exported and parsed correctly"
                    if roundtrip_valid
                    else "Export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

    def verify(self) -> Verifier:
        """Verify the ISK Certificate configuration.

        Validates ISK certificate including constraints, flags, signature offset,
        public key, user data, and signature.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="ISK Certificate",
            description="Validates ISK certificate structure and configuration",
        )

        # Verify constraints and flags
        self._verify_constraints_and_flags(ver)

        # Verify certificate type and get type bits for further validation
        cert_type_bits = self._verify_certificate_type(ver)

        # Verify user data
        self._verify_user_data(ver)

        # Verify ISK certificate (public key)
        self._verify_isk_certificate(ver, cert_type_bits)

        # Verify signature offset if present
        self._verify_signature_offset(ver)

        # Verify signature
        self._verify_signature(ver)

        # Verify coordinate length consistency
        self._verify_coordinate_length(ver)

        # Verify expected size calculation
        self._verify_expected_size(ver)

        # Verify export/parse round-trip
        self._verify_export_parse_roundtrip(ver)

        return ver

    def get_public_key(self) -> PublicKey:
        """Get the  public key from the ISK certificate block.

        :raises SPSDKError: If key record is not available or parsing fails.
        :return: Root public key object parsed from the certificate block.
        """
        return PublicKey.parse(self.isk_public_key_data)


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
                cls.pre_check_config(cert_block_cfg)
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

    def verify(self) -> Verifier:
        """Verify the Certificate Block V2.1 configuration.

        Validates the certificate block structure including header, root key record,
        and optional ISK certificate.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="Certificate Block V2.1",
            description="Validates certificate block V2.1 structure and configuration",
        )

        # Verify header
        ver.add_child(self.header.verify())

        # Verify root key record
        ver.add_child(self.root_key_record.verify())

        # Verify ISK certificate if present
        if self.isk_certificate:
            ver.add_child(self.isk_certificate.verify())

            # Verify that CA flag is consistent with ISK certificate presence
            ca_flag_ok = self.root_key_record.ca_flag == 0
            ca_status = (
                "consistent" if ca_flag_ok else "INCONSISTENT - ISK present but CA flag is set"
            )
            ver.add_record(
                name="CA flag consistency",
                result=ca_flag_ok,
                value=f"CA flag: {self.root_key_record.ca_flag} ({ca_status})",
            )
        else:
            # If no ISK certificate, CA flag should be set
            ca_flag_ok = self.root_key_record.ca_flag == 1
            ca_status = (
                "consistent" if ca_flag_ok else "INCONSISTENT - No ISK but CA flag is not set"
            )
            ver.add_record(
                name="CA flag consistency",
                result=ca_flag_ok,
                value=f"CA flag: {self.root_key_record.ca_flag} ({ca_status})",
            )
        # Verify expected size calculation
        try:
            expected_size = self.expected_size
            ver.add_record(
                name="Expected size",
                result=expected_size > 0,
                value=f"Expected size: {expected_size} bytes",
            )
        except Exception as e:
            ver.add_record(
                name="Expected size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate expected size: {str(e)}",
            )

        # Verify signature size
        try:
            sig_size = self.signature_size
            ver.add_record(
                name="Signature size",
                result=sig_size > 0,
                value=f"Signature size: {sig_size} bytes",
            )
        except Exception as e:
            ver.add_record(
                name="Signature size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate signature size: {str(e)}",
            )

        # Verify RKTH
        try:
            rkth = self.rkth
            ver.add_record(
                name="RKTH (Root Key Table Hash)",
                result=len(rkth) > 0,
                value=f"{rkth.hex().upper()}",
                important=False,
            )
        except Exception as e:
            ver.add_record(
                name="RKTH calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate RKTH: {str(e)}",
            )

        # Verify export/parse round-trip
        try:
            exported = self.export()

            ver.add_record(
                name="Export size consistency",
                result=len(exported) == self.expected_size,
                value=f"Exported: {len(exported)} bytes, Expected: {self.expected_size} bytes",
            )

            parsed = CertBlockV21.parse(exported, self.family)

            roundtrip_valid = (
                parsed.header.format_version == self.header.format_version
                and parsed.root_key_record.ca_flag == self.root_key_record.ca_flag
                and parsed.root_key_record.used_root_cert == self.root_key_record.used_root_cert
            )

            if self.isk_certificate and parsed.isk_certificate:
                roundtrip_valid = roundtrip_valid and (
                    parsed.isk_certificate.constraints == self.isk_certificate.constraints
                )

            ver.add_record(
                name="Export/Parse consistency",
                result=roundtrip_valid,
                value=(
                    "Certificate Block V2.1 can be exported and parsed correctly"
                    if roundtrip_valid
                    else "Export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

        return ver

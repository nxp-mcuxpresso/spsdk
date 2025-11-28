#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK AHAB container certificate management utilities.

This module provides functionality for handling AHAB (Advanced High Assurance Boot)
certificates used in NXP secure boot process. It supports both standard and
post-quantum cryptography certificates for container signature verification.
"""

import logging
import os
from struct import pack, unpack
from typing import Any, Optional, Type, cast

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import (
    RESERVED,
    UINT8,
    UINT16,
    UINT32,
    AHABSignHashAlgorithmV2,
    AHABTags,
    FlagsSrkSet,
)
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKData, SRKRecordV2, SRKTableArray
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import (
    bytes_to_print,
    extend_block,
    load_hex_string,
    value_to_bytes,
    write_file,
)
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: dict, val: Any) -> Any:
    """Get dictionary key by its value.

    Searches through the dictionary to find the key that corresponds to the given value.

    :param dictionary: Dictionary to search in.
    :param val: Value to search for.
    :raises SPSDKValueError: In case that dictionary doesn't contain the value.
    :return: Key corresponding to the given value.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class AhabCertificate(FeatureBaseClass, HeaderContainer):
    """AHAB Certificate representation for secure boot containers.

    Represents a certificate structure used within AHAB (Advanced High Assurance Boot)
    containers as part of the signature block. The certificate manages cryptographic
    validation and permission settings for secure boot operations.
    The certificate supports two variants: with and without UUID identification.
    It contains permission data, SRK (Super Root Key) records, signatures, and
    metadata required for secure boot validation.
    Certificate format::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                Permission data - 96bits                       |
        +-----+----------------------------------------------+----------------+
        |0x14 |                   Reserved                   | Fuse version   |
        +-----+----------------------------------------------+----------------+
        |0x18 |                      UUID - 128bits                           |
        +-----+---------------------------------------------------------------+
        |...  |                        SRK Record 0                           |
        +-----+---------------------------------------------------------------+
        |...  |                         SRK Data 0                            |
        +-----+---------------------------------------------------------------+
        |...  |                        SRK Record 1                           |
        +-----+---------------------------------------------------------------+
        |...  |                         SRK Data 1                            |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature 0                            |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature 1                            |
        +-----+---------------------------------------------------------------+

    :cvar PERM_NXP: NXP-specific permission flags for certificate validation.
    :cvar PERM_OEM: OEM-specific permission flags for certificate validation.
    """

    FEATURE = DatabaseManager.AHAB
    SUB_FEATURE = "certificate_supported"

    TAG = AHABTags.CERTIFICATE.tag
    VERSION = 0x02
    PERM_NXP = {
        "container": 0x01,
        "debug": 0x04,
        "secure_fuse": 0x08,
        "return_life_cycle": 0x10,
        "patch_fuses": 0x40,
    }
    PERM_OEM = {
        "container": 0x01,
        "debug": 0x04,
        "secure_fuse": 0x08,
        "return_life_cycle": 0x10,
        "patch_fuses": 0x40,
    }
    PERM_BIT_SIZE = 8
    FUSE_VERSION_BIT_SIZE = 8
    PERMISSION_DATA_SIZE = 12
    UUID_SIZE = 16

    DIFF_ATTRIBUTES_VALUES = [
        "_permissions",
        "permission_data",
        "signature_offset",
        "_uuid",
        "public_key_0",
        "signature_0",
        "public_key_1",
        "signature_1",
    ]

    def __init__(
        self,
        family: FamilyRevision,
        permissions: int = 0,
        permissions_data: bytes = b"",
        fuse_version: int = 0,
        uuid: Optional[bytes] = None,
        public_key_0: Optional[SRKRecordV2] = None,
        signature_provider_0: Optional[SignatureProvider] = None,
        public_key_1: Optional[SRKRecordV2] = None,
        signature_provider_1: Optional[SignatureProvider] = None,
    ):
        """Initialize AHAB certificate container.

        Creates a new AHAB certificate with specified family, permissions, and cryptographic
        components for secure boot authentication.

        :param family: Target chip family and revision.
        :param permissions: Certificate usage permissions flags, defaults to 0.
        :param permissions_data: Additional data for debug authentication features.
        :param fuse_version: Certificate version number, defaults to 0.
        :param uuid: 128-bit unique identifier, auto-generated if not provided.
        :param public_key_0: Primary SRK record entry describing the public key.
        :param signature_provider_0: Primary signature provider for certificate signing.
        :param public_key_1: Secondary SRK record entry describing the public key.
        :param signature_provider_1: Secondary signature provider for certificate signing.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self.family = family
        self._permissions = permissions
        self.permission_data = permissions_data
        self.fuse_version = fuse_version
        self.signature_offset = -1
        self._uuid = uuid
        self.public_key_0 = public_key_0
        self.signature_0 = ContainerSignature(
            signature_data=b"", signature_provider=signature_provider_0
        )
        self.public_key_1 = public_key_1
        self.signature_1 = (
            ContainerSignature(signature_data=b"", signature_provider=signature_provider_1)
            if signature_provider_1
            else None
        )

    def __eq__(self, other: object) -> bool:
        """Check equality of AHAB certificate objects.

        Compares all certificate attributes including permissions, permission data, signature offset,
        UUID, public keys, and signatures to determine if two certificate objects are identical.

        :param other: Object to compare with this certificate instance.
        :return: True if certificates are equal, False otherwise.
        """
        if isinstance(other, self.__class__):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._permissions == other._permissions
                and self.permission_data == other.permission_data
                and self.signature_offset == other.signature_offset
                and self._uuid == other._uuid
                and self.public_key_0 == other.public_key_0
                and self.signature_0 == other.signature_0
                and self.public_key_1 == other.public_key_1
                and self.signature_1 == other.signature_1
            ):
                return True

        return False

    def __repr__(self) -> str:
        """Return string representation of AHAB Certificate.

        :return: String representation of the certificate.
        """
        return "AHAB Certificate"

    def __str__(self) -> str:
        """Return string representation of AHAB Certificate.

        Provides a formatted string containing all certificate details including permissions,
        permission data, fuse version, UUID, public keys, and signatures.

        :return: Formatted string with certificate information.
        """
        return (
            "AHAB Certificate:\n"
            f"  Permission:         {hex(self._permissions)}\n"
            f"  Permission data:    {self.permission_data.hex()}\n"
            f"  Fuse version:       {self.fuse_version}\n"
            f"  UUID:               {self._uuid.hex() if self._uuid else 'Not Available'}\n"
            f"  Public Key 0:       {str(self.public_key_0) if self.public_key_0 else 'Not available'}\n"
            f"  Signature 0:        {str(self.signature_0) if self.signature_0 else 'Not available'}\n"
            f"  Public Key 1:       {str(self.public_key_1) if self.public_key_1 else 'Not available'}\n"
            f"  Signature 1:        {str(self.signature_1) if self.signature_1 else 'Not available'}"
        )

    @classmethod
    def format(cls) -> str:
        """Get format string for binary representation of the certificate.

        This method returns a format string that defines the structure of the binary
        representation, including endianness, header fields, signature offset,
        permissions, UUID, and other certificate-specific data fields.

        :return: Format string compatible with struct module for binary packing/unpacking.
        """
        return (
            super().format()  # endianness, header: version, length, tag
            + UINT16  # signature offset
            + UINT8  # inverted permissions
            + UINT8  # permissions
            + f"{cls.PERMISSION_DATA_SIZE}s"  # permission data
            + UINT8  # fuse_version
            + UINT8  # reserved
            + UINT16  # reserved
            + f"{cls.UUID_SIZE}s"  # UUID
        )

    def __len__(self) -> int:
        """Calculate the total length of the certificate.

        The method computes the combined length of all certificate components including
        public keys, SRK data, and signatures. For certificates with dual keys, both
        key pairs are included in the calculation.

        :raises SPSDKValueError: When certificate is not properly initialized.
        :return: Total length of the certificate in bytes.
        """
        if not (self.public_key_0 and self.public_key_0.srk_data and self.signature_0):
            raise SPSDKValueError("Certificate is not properly initialized.")
        ret = (
            super().__len__()
            + len(self.public_key_0)
            + len(self.public_key_0.srk_data)
            + len(self.signature_0)
        )
        if self.public_key_1 and self.signature_1:
            assert isinstance(self.public_key_1.srk_data, SRKData)
            ret += len(self.public_key_1) + len(self.public_key_1.srk_data) + len(self.signature_1)
        return ret

    @classmethod
    def create_permissions(cls, permissions: list[str]) -> int:
        """Create integer representation of permission field.

        The method combines NXP and OEM permission mappings to convert a list of
        permission strings into their corresponding integer bitmask representation.

        :param permissions: List of string permissions to be converted.
        :raises KeyError: Invalid permission string not found in permission mappings.
        :return: Integer representation of combined permissions as bitmask.
        """
        ret = 0
        permission_map = {}
        permission_map.update(cls.PERM_NXP)
        permission_map.update(cls.PERM_OEM)
        for permission in permissions:
            ret |= permission_map[permission]

        return ret

    @property
    def permission_to_sign_container(self) -> bool:
        """Check if certificate has permission to sign container.

        This method verifies whether the certificate contains the necessary permissions
        to sign a container by checking the container permission bit in the permissions field.

        :return: True if certificate has permission to sign container, False otherwise.
        """
        return bool(self._permissions & self.PERM_OEM["container"])

    def create_config_permissions(self, srk_set: FlagsSrkSet) -> list[str]:
        """Create list of string representation of permission field.

        The method iterates through permission bits and converts them to human-readable
        string representations using the appropriate permission mapping based on the SRK set type.

        :param srk_set: SRK set type to determine correct permission mapping (NXP or OEM).
        :return: List of string representations of active permissions.
        """
        ret = []
        perm_map = self.PERM_NXP if srk_set == FlagsSrkSet.NXP else self.PERM_OEM

        for i in range(self.PERM_BIT_SIZE):
            if self._permissions & (1 << i):
                ret.append(
                    get_key_by_val(perm_map, 1 << i)
                    if perm_map and (1 << i) in perm_map.values()
                    else f"Unknown permission {hex(1<<i)}"
                )

        return ret

    @property
    def _cert_data_to_sign(self) -> bytes:
        """Prepare certificate data for signing.

        This internal method serializes the certificate fields into a binary format
        that can be used for cryptographic signing operations.

        :return: Binary representation of certificate data ready for signing.
        """
        return pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self.signature_offset,
            ~self._permissions & 0xFF,
            self._permissions,
            extend_block(self.permission_data, self.PERMISSION_DATA_SIZE, padding=RESERVED),
            self.fuse_version,
            RESERVED,
            RESERVED,
            extend_block(self._uuid or b"", self.UUID_SIZE, padding=RESERVED),
        )

    def get_signature_data(self) -> bytes:
        """Get binary data to be signed.

        The certificate block must be properly initialized, so the data are valid for
        signing. The method returns the whole certificate block without signature part,
        including public key data and SRK data for both primary and optional secondary
        public keys.

        :raises SPSDKValueError: If Signature Block or SRK Table is missing.
        :return: Bytes representing data to be signed.
        """
        assert isinstance(self.public_key_0, SRKRecordV2)
        cert_data_to_sign = self._cert_data_to_sign
        cert_data_to_sign += self.public_key_0.export()
        assert isinstance(self.public_key_0.srk_data, SRKData)
        cert_data_to_sign += self.public_key_0.srk_data.export()
        if self.public_key_1:
            cert_data_to_sign += self.public_key_1.export()
            assert isinstance(self.public_key_1.srk_data, SRKData)
            cert_data_to_sign += self.public_key_1.srk_data.export()

        return cert_data_to_sign

    def update_fields(self) -> None:
        """Update all fields that depend on input values.

        This method recalculates the certificate length, signature offset, and updates
        all public keys and their associated data. It also generates and applies
        signatures for the certificate data.

        :raises AssertionError: If public_key_0 is not SRKRecordV2 or its srk_data is not SRKData.
        :raises AssertionError: If public_key_1 exists but its srk_data is not SRKData.
        """
        assert isinstance(self.public_key_0, SRKRecordV2)
        assert isinstance(self.public_key_0.srk_data, SRKData)
        self.public_key_0.update_fields()
        if self.public_key_1:
            self.public_key_1.update_fields()
        self.length = len(self)
        self.signature_offset = (
            self.fixed_length() + len(self.public_key_0) + len(self.public_key_0.srk_data)
        )
        if self.public_key_1:
            assert isinstance(self.public_key_1.srk_data, SRKData)
            self.signature_offset += len(self.public_key_1) + len(self.public_key_1.srk_data)
        signature_data_final = self.get_signature_data()
        self.signature_0.sign(signature_data_final)
        if self.public_key_1 and self.signature_1:
            self.signature_1.sign(signature_data_final)

    def export(self) -> bytes:
        """Export container certificate object into bytes.

        The method combines signature data with exported signatures to create
        the complete certificate binary representation. Validates that the
        computed length matches the expected certificate length.

        :raises SPSDKValueError: When certificate length doesn't match computed length.
        :return: Bytes representing container certificate content.
        """
        cert = self.get_signature_data()
        cert += self.signature_0.export()
        if self.signature_1:
            cert += self.signature_1.export()
        if self.length != len(cert):
            raise SPSDKValueError(
                f"Certificate length {self.length} doesn't match to computed length {len(cert)}"
            )
        return cert

    def verify(self, srk: Optional[SRKTableArray] = None) -> Verifier:
        """Verify container certificate data.

        Performs comprehensive verification of the certificate including header validation,
        permissions, fuse version, UUID, public keys, signature offsets, and optionally
        signature verification when SRK table is provided.

        :param srk: SRK table to allow verification of certificate signature.
        :return: Verifier object with detailed verification results.
        """
        ret = Verifier("Certificate", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_bit_range("Permissions", self._permissions, self.PERM_BIT_SIZE)
        ret.add_record_bytes(
            "Permission Data", self.permission_data, max_length=self.PERMISSION_DATA_SIZE
        )
        ret.add_record_bit_range("Fuse version", self.fuse_version, self.FUSE_VERSION_BIT_SIZE)

        if self._uuid:
            if len(self._uuid) != self.UUID_SIZE:
                ret.add_record(
                    "UUID",
                    VerifierResult.ERROR,
                    f"Invalid size. {len(self._uuid)} != {self.UUID_SIZE}",
                )
            else:
                ret.add_record("UUID", VerifierResult.SUCCEEDED, self._uuid.hex())
        else:
            ret.add_record("UUID", VerifierResult.SUCCEEDED, "Not used")

        if self.public_key_0 is None:
            ret.add_record("Public key 0", VerifierResult.ERROR, "Not exists")
        else:
            ret.add_child(self.public_key_0.verify("Public key 0"))

        if self.public_key_1 is None:
            ret.add_record("Public key 1", VerifierResult.SUCCEEDED, "Not used")
        else:
            ret.add_child(self.public_key_1.verify("Public key 1"))

        expected_signature_offset = super().__len__()

        if self.public_key_0:
            assert isinstance(self.public_key_0.srk_data, SRKData)
            expected_signature_offset += len(self.public_key_0) + len(self.public_key_0.srk_data)
        if self.public_key_1:
            assert isinstance(self.public_key_1.srk_data, SRKData)
            expected_signature_offset += len(self.public_key_1) + len(self.public_key_1.srk_data)

        if self.signature_offset != expected_signature_offset:
            ret.add_record(
                "Signature offset",
                VerifierResult.ERROR,
                f"Invalid. {self.signature_offset} != {expected_signature_offset} (expected)",
            )
        else:
            ret.add_record("Signature offset", VerifierResult.SUCCEEDED, self.signature_offset)

        if srk:
            srk_checks_ver = Verifier("SRK checks")
            ret.add_child(srk_checks_ver)
            srk_verify = srk.verify()
            if srk_verify.has_errors:
                srk_checks_ver.add_child(srk_verify, "SRK Table array")
                return ret

            srk_checks_ver.add_record("SRK table array", VerifierResult.SUCCEEDED)
            used_srk_id = srk.chip_config.used_srk_id
            revoked_keys = srk.chip_config.srk_revoke_keys

            srk_checks_ver.add_record(
                "Used SRK key id revocation",
                not bool(revoked_keys & 1 << used_srk_id),
                f"Revoked keys mask: {hex(revoked_keys)}, Used SRK key: {used_srk_id}",
            )

            srk_table_cnt = srk.srk_count

            def check_key_type(ix: int, srk_key: SRKRecordV2, key: Optional[SRKRecordV2]) -> None:
                """Validate SRK key type compatibility with certificate key.

                Compares the signing algorithm, hash algorithm, key size, and SRK flags between
                the SRK record and certificate key to ensure compatibility. Creates verification
                records for each comparison and adds them to the public key types verifier.

                :param ix: Index of the public key being validated.
                :param srk_key: SRK record containing the reference key parameters.
                :param key: Certificate SRK record to validate against reference, None if not present.
                """
                pub_key_ver = Verifier(f"Public key {ix}")
                if key is None:
                    pub_key_ver.add_record("Presence", VerifierResult.ERROR, "Is not present")
                else:
                    pub_key_ver.add_record(
                        "Signing algorithm",
                        srk_key.signing_algorithm == key.signing_algorithm,
                        f"SRK key: {srk_key.signing_algorithm}, Cert Key: {key.signing_algorithm}",
                    )
                    pub_key_ver.add_record(
                        "Hash algorithm",
                        srk_key.hash_algorithm == key.hash_algorithm,
                        f"SRK key: {srk_key.hash_algorithm}, Cert Key: {key.hash_algorithm}",
                    )
                    pub_key_ver.add_record(
                        "Key size",
                        srk_key.key_size == key.key_size,
                        f"SRK key: {srk_key.key_size}, Cert Key: {key.key_size}",
                    )
                    pub_key_ver.add_record(
                        "SRK flags",
                        srk_key.srk_flags == key.srk_flags,
                        f"SRK key: {srk_key.srk_flags}, Cert Key: {key.srk_flags}",
                    )
                public_key_types_ver.add_child(pub_key_ver)

            public_key_types_ver = Verifier("Public key checks")
            check_key_type(
                0,
                srk_key=cast(SRKRecordV2, srk._srk_tables[0].srk_records[0]),
                key=self.public_key_0,
            )
            if srk_table_cnt > 1:
                check_key_type(
                    1,
                    srk_key=cast(SRKRecordV2, srk._srk_tables[1].srk_records[0]),
                    key=self.public_key_1,
                )
            ret.add_child(public_key_types_ver)

            data_to_sign = self.get_signature_data()

            # Verify Signature
            def check_signature(ix: int, signature: Optional[ContainerSignature]) -> None:
                """Verify signature against SRK table record.

                Validates a container signature using the corresponding SRK (Super Root Key) table record
                and adds verification results to the signatures verifier.

                :param ix: Index of the signature and SRK table to use for verification.
                :param signature: Container signature to verify, None if signature is missing.
                :raises AssertionError: If srk is not an instance of SRKTableArray.
                """
                assert isinstance(srk, SRKTableArray)
                srk_public_key = srk._srk_tables[ix].srk_records[used_srk_id].get_public_key()
                srk_hash = EnumHashAlgorithm.from_label(
                    srk._srk_tables[ix].srk_records[used_srk_id].hash_algorithm.label
                )
                if signature is None:
                    signatures_ver.add_record(
                        f"Signature {ix}", VerifierResult.ERROR, "Missing Signature container"
                    )
                else:
                    sig_verify = signature.verify()
                    signatures_ver.add_child(sig_verify)
                    if not sig_verify.has_errors:
                        signatures_ver.add_record(
                            f"Signature {ix} verification",
                            srk_public_key.verify_signature(
                                signature=signature.signature_data,
                                data=data_to_sign,
                                algorithm=srk_hash,
                            ),
                            bytes_to_print(signature.signature_data),
                        )

            signatures_ver = Verifier("Signatures")
            srk_checks_ver.add_child(signatures_ver)

            check_signature(0, self.signature_0)
            if srk_table_cnt > 1:
                check_signature(1, self.signature_1)

            else:
                if self.public_key_1:
                    srk_checks_ver.add_record(
                        "Public key 1",
                        VerifierResult.WARNING,
                        "SRK is not using both signatures, The public key 1 is useless",
                    )
                if self.signature_1:
                    srk_checks_ver.add_record(
                        "Signature 1",
                        VerifierResult.WARNING,
                        "SRK is not using both signatures, The signature 1 is useless",
                    )

        else:
            ret.add_record(
                "Signature",
                VerifierResult.WARNING,
                "Cannot verified, due missing information about SRK table in verifier.",
            )

        return ret

    @classmethod
    def _parse_header(cls, data: bytes) -> tuple[int, int, int, int, bytes, int, bytes]:
        """Parse the header of the certificate from binary data.

        Extracts and returns key certificate header fields from the binary data using the
        class format specification.

        :param data: Binary data containing the certificate header.
        :return: Tuple containing (container_length, signature_offset, inverted_permissions,
            permissions, permission_data, fuse_version, uuid) where container_length is the
            total certificate container length, signature_offset is offset to signature data,
            inverted_permissions and permissions are permission bytes, permission_data contains
            permission data bytes, fuse_version is the fuse version value, and uuid contains
            UUID bytes.
        """
        (
            _,  # version
            container_length,
            _,  # tag
            signature_offset,
            inverted_permissions,
            permissions,
            permission_data,
            fuse_version,
            _,  # RESERVED,
            _,  # RESERVED,
            uuid,
        ) = unpack(cls.format(), data)
        return (
            container_length,
            signature_offset,
            inverted_permissions,
            permissions,
            permission_data,
            fuse_version,
            uuid,
        )

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse input binary chunk to the container object.

        The method parses binary data containing an AHAB certificate block and reconstructs
        the certificate object with all its components including public keys, signatures,
        and metadata.

        :param data: Binary data with Certificate block to parse.
        :param family: Family revision of the device.
        :raises SPSDKValueError: Missing family parameter or invalid certificate permissions.
        :raises SPSDKParsingError: Certificate parsing error or container length mismatch.
        :return: Object recreated from the binary data.
        """
        if family is None:
            raise SPSDKValueError("Missing family parameter")
        cls.check_container_head(data).validate()
        certificate_data_offset = cls.fixed_length()
        (
            container_length,
            signature_offset,
            inverted_permissions,
            permissions,
            permission_data,
            fuse_version,
            uuid,
        ) = cls._parse_header(data[:certificate_data_offset])

        if inverted_permissions != ~permissions & 0xFF:
            raise SPSDKValueError("Certificate parser: Invalid permissions record.")

        public_key_0 = SRKRecordV2.parse(data[certificate_data_offset:])
        certificate_data_offset += len(public_key_0)
        public_key_0.srk_data = SRKData.parse(data[certificate_data_offset:])
        certificate_data_offset += len(public_key_0.srk_data)
        # check if there is space for second key set
        public_key_1 = None
        if certificate_data_offset < signature_offset:
            public_key_1 = SRKRecordV2.parse(data[certificate_data_offset:])
            certificate_data_offset += len(public_key_1)
            public_key_1.srk_data = SRKData.parse(data[certificate_data_offset:])
            certificate_data_offset += len(public_key_1.srk_data)

        signature_0 = ContainerSignature.parse(data[signature_offset:])
        signature_1 = None
        computed_length = signature_offset
        if public_key_1:
            computed_length += len(signature_0)
            signature_1 = ContainerSignature.parse(data[computed_length:])

        if container_length != computed_length + len(signature_1) if signature_1 else 0:
            raise SPSDKParsingError(
                "The final parsing size of container doesn't fit to declared container length. "
                f"{computed_length}B != {container_length}B"
            )

        cert = cls(
            family=family,
            permissions=permissions,
            permissions_data=permission_data,
            fuse_version=fuse_version,
            uuid=uuid,
            public_key_0=public_key_0,
            public_key_1=public_key_1,
        )
        cert.signature_0 = signature_0
        cert.signature_1 = signature_1
        cert.length = container_length
        cert.signature_offset = signature_offset
        cert._parsed_header = HeaderContainerData.parse(binary=data)
        return cert

    def get_config(
        self,
        data_path: str = "./",
        index: int = 0,
        srk_set: FlagsSrkSet = FlagsSrkSet.OEM,
    ) -> Config:
        """Create configuration of the AHAB Image Certificate.

        The method generates a configuration dictionary containing all necessary parameters
        for AHAB certificate creation, including public keys, permissions, and metadata.
        Public key files are exported to the specified data path.

        :param data_path: Path to store the data files of configuration.
        :param index: Container index used for file naming.
        :param srk_set: SRK set to determine certificate permissions.
        :return: Configuration dictionary with certificate parameters.
        """
        ret_cfg = Config()
        ret_cfg["family"] = self.family.name
        ret_cfg["revision"] = self.family.revision
        assert isinstance(self.public_key_0, SRKRecordV2)
        ret_cfg["permissions"] = self.create_config_permissions(srk_set)
        if self.permission_data:
            ret_cfg["permission_data"] = self.permission_data.hex()
        if self._uuid:
            ret_cfg["uuid"] = self._uuid.hex()
        ret_cfg["fuse_version"] = self.fuse_version
        filename = (
            f"container{index}_certificate_public_key0_{self.public_key_0.get_key_name()}.pem"
        )
        public_key_0 = self.public_key_0.get_public_key()
        write_file(
            data=public_key_0.export(public_key_0.RECOMMENDED_ENCODING),
            path=os.path.join(data_path, filename),
            mode="wb",
        )
        ret_cfg["public_key_0"] = filename
        ret_cfg["signer_0"] = "N/A"
        if self.public_key_1:
            filename = (
                f"container{index}_certificate_public_key1_{self.public_key_1.get_key_name()}.pem"
            )
            public_key_1 = self.public_key_1.get_public_key()
            write_file(
                data=public_key_1.export(public_key_1.RECOMMENDED_ENCODING),
                path=os.path.join(data_path, filename),
                mode="wb",
            )
            ret_cfg["public_key_1"] = filename
            ret_cfg["signer_1"] = "N/A"

        return ret_cfg

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create AHAB certificate from configuration.

        Converts the configuration options into an AHAB image signature block certificate object
        by extracting family information, permissions, cryptographic keys, and signature providers.

        :param config: Configuration object containing AHAB certificate settings including keys,
            permissions, hash algorithms, and signature providers.
        :return: AHAB certificate object configured with the specified parameters.
        """
        family = FamilyRevision.load_from_config(config)

        cert_permissions_list = config.get_list("permissions", [])
        cert_uuid_raw = config.get("uuid")
        cert_uuid = (
            load_hex_string(
                cert_uuid_raw, expected_size=16, search_paths=config.search_paths, name="UUID"
            )
            if cert_uuid_raw
            else None
        )
        cert_permission_data_raw = config.get("permission_data")
        cert_permission_data = (
            value_to_bytes(cert_permission_data_raw) if cert_permission_data_raw else None
        )
        cert_fuse_version = config.get_int("fuse_version", 0)

        cert_hash0_str: str = config.get("hash_algorithm_0", "default")
        cert_hash0 = (
            None
            if cert_hash0_str == "default"
            else AHABSignHashAlgorithmV2.from_label(cert_hash0_str.upper())
        )
        cert_public_key0 = SRKRecordV2.create_from_key(
            extract_public_key(config.get_input_file_name("public_key_0")),
            hash_algorithm=cert_hash0,
        )
        cert_signature_provider0 = get_signature_provider(
            config, "signer_0", pss_padding=True, hash_alg=cert_public_key0.hash_algorithm
        )

        cert_public_key1 = None
        cert_signature_provider1 = None
        if "public_key_1" in config:
            cert_hash1_str: str = config.get("hash_algorithm_1", "default")
            cert_hash1 = (
                None
                if cert_hash1_str == "default"
                else AHABSignHashAlgorithmV2.from_label(cert_hash1_str.upper())
            )
            cert_public_key1_path = config.get_input_file_name("public_key_1")
            cert_public_key1 = SRKRecordV2.create_from_key(
                extract_public_key(cert_public_key1_path),
                hash_algorithm=cert_hash1,
            )
            cert_signature_provider1 = get_signature_provider(
                config, "signer_1", pss_padding=True, hash_alg=cert_public_key1.hash_algorithm
            )

        return cls(
            family=family,
            permissions=cls.create_permissions(cert_permissions_list),
            permissions_data=cert_permission_data or b"",
            fuse_version=cert_fuse_version,
            uuid=cert_uuid,
            public_key_0=cert_public_key0,
            signature_provider_0=cert_signature_provider0,
            public_key_1=cert_public_key1,
            signature_provider_1=cert_signature_provider1,
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get list of validation schemas for AHAB certificate.

        This method retrieves and configures validation schemas from the database manager,
        including AHAB, certificate block, and general family schemas. It removes required
        fields from the certificate block output schema and updates the family schema
        with supported families.

        :param family: Family revision for which the validation schema should be generated.
        :return: List of validation schemas containing family, certificate block output,
                 and AHAB certificate schemas.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)
        sch_cfg = DatabaseManager().db.get_schema_file(DatabaseManager.CERT_BLOCK)
        sch_family = DatabaseManager().db.get_schema_file("general")["family"]
        sch_cfg["cert_block_output"].pop("required")
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg["cert_block_output"], sch["ahab_certificate"]]


class AhabCertificateMcuPqc(AhabCertificate):
    """AHAB Certificate for MCU Post-Quantum Cryptography.

    This class represents a specialized AHAB certificate variant designed for MCU
    Post-Quantum Cryptography implementations. It extends the standard AHAB certificate
    with a 32-bit fuse version field instead of the standard width, providing enhanced
    security features for quantum-resistant cryptographic operations.
    The certificate contains permission data, SRK records, signatures, and UUID
    information formatted according to the AHAB container specification for MCU PQC.

    :cvar FUSE_VERSION_BIT_SIZE: Bit width for fuse version field (32-bit for MCU PQC).
    Certificate format::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                Permission data - 96bits                       |
        +-----+---------------------------------------------------------------+
        |0x14 |              Fuse Version / Vendor Usage                      |
        +-----+---------------------------------------------------------------+
        |0x18 |                      UUID - 128bits                           |
        +-----+---------------------------------------------------------------+
        |...  |                        SRK Record 0                           |
        +-----+---------------------------------------------------------------+
        |...  |                         SRK Data 0                            |
        +-----+---------------------------------------------------------------+
        |...  |                        SRK Record 1                           |
        +-----+---------------------------------------------------------------+
        |...  |                         SRK Data 1                            |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature 0                            |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature 1                            |
        +-----+---------------------------------------------------------------+

    """

    FUSE_VERSION_BIT_SIZE = 32  # 32-bit width for Fuse Version in MCU PQC variant

    def __repr__(self) -> str:
        """Return string representation of AHAB Certificate.

        :return: String describing the certificate with its fuse version type.
        """
        return "AHAB Certificate with 32-bit fuse version"

    @classmethod
    def format(cls) -> str:
        """Get the format string for binary representation of the certificate.

        The format string defines the structure used for packing/unpacking the certificate
        data including header container, signature offset, permissions, permission data,
        fuse version, and UUID fields.

        :return: Format string compatible with struct module for binary operations.
        """
        return (
            HeaderContainer.format()  # endianness, header: version, length, tag
            + UINT16  # signature offset
            + UINT8  # inverted permissions
            + UINT8  # permissions
            + f"{cls.PERMISSION_DATA_SIZE}s"  # permission data
            + UINT32  # fuse_version alias vendor usage
            + f"{cls.UUID_SIZE}s"  # UUID
        )

    @property
    def _cert_data_to_sign(self) -> bytes:
        """Prepare certificate data for signing.

        This internal method serializes the certificate fields into a binary format
        that can be used for cryptographic signing operations. The data includes
        version, length, tag, permissions, fuse version, and UUID fields.

        :return: Binary representation of certificate data ready for signing.
        """
        return pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self.signature_offset,
            ~self._permissions & 0xFF,
            self._permissions,
            extend_block(self.permission_data, self.PERMISSION_DATA_SIZE, padding=RESERVED),
            self.fuse_version,
            extend_block(self._uuid or b"", self.UUID_SIZE, padding=RESERVED),
        )

    @classmethod
    def _parse_header(cls, data: bytes) -> tuple[int, int, int, int, bytes, int, bytes]:
        """Parse the header of the certificate from binary data.

        Extracts and returns key certificate header fields from the provided binary data using
        the class format specification.

        :param data: Binary data containing the certificate header.
        :return: Tuple containing:
            - container_length: Total length of the certificate container
            - signature_offset: Offset to the signature data
            - inverted_permissions: Inverted permissions byte
            - permissions: Permissions byte
            - permission_data: Permission data bytes
            - fuse_version: Fuse version value
            - uuid: UUID bytes
        """
        (
            _,  # version
            container_length,
            _,  # tag
            signature_offset,
            inverted_permissions,
            permissions,
            permission_data,
            fuse_version,
            uuid,
        ) = unpack(cls.format(), data)
        return (
            container_length,
            signature_offset,
            inverted_permissions,
            permissions,
            permission_data,
            fuse_version,
            uuid,
        )


def get_ahab_certificate_class(family: FamilyRevision) -> Type[AhabCertificate]:
    """Get the appropriate AHAB certificate class based on the MCU family revision.

    This method retrieves the certificate type from the database for the given family
    and returns the corresponding AHAB certificate class implementation.

    :param family: MCU family revision to determine certificate type.
    :raises KeyError: If certificate type from database is not supported.
    :return: Appropriate AHAB certificate class for the specified family.
    """
    certificate_classes = {"standard": AhabCertificate, "32bit_fuse_version": AhabCertificateMcuPqc}
    certificate_type = get_db(family).get_str(DatabaseManager.AHAB, "certificate_type", "standard")
    return certificate_classes[certificate_type]

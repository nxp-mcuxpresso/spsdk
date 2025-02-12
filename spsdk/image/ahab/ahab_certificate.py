#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container Signature certificate support."""

import logging
import os
from struct import pack, unpack
from typing import Any, Optional, cast

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import RESERVED, UINT8, UINT16, AHABTags, FlagsSrkSet
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKData, SRKRecordV2, SRKTableArray
from spsdk.utils.database import DatabaseManager, get_families
from spsdk.utils.misc import (
    bytes_to_print,
    extend_block,
    find_file,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: dict, val: Any) -> Any:
    """Get Dictionary key by its value or default.

    :param dictionary: Dictionary to search in.
    :param val: Value to search
    :raises SPSDKValueError: In case that dictionary doesn't contains the value.
    :return: Key.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class AhabCertificate(HeaderContainer):
    """Class representing certificate in the AHAB container as part of the signature block.

    The Certificate comes in two forms - with and without UUID.

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

    """

    TAG = AHABTags.CERTIFICATE.tag
    VERSION = 0x02
    PERM_NXP = {
        "container": 0x01,
        "debug": 0x02,
        "secure_fuse": 0x08,
        "return_life_cycle": 0x10,
        "patch_fuses": 0x40,
    }
    PERM_OEM = {
        "container": 0x01,
        "debug": 0x02,
        "secure_fuse": 0x08,
        "return_life_cycle": 0x10,
        "patch_fuses": 0x40,
    }
    PERM_BIT_SIZE = 8
    FUSE_VERSION_BIT_SIZE = 8
    PERMISSION_DATA_SIZE = 12
    UUID_SIZE = 16

    def __init__(
        self,
        permissions: int = 0,
        permissions_data: bytes = b"",
        fuse_version: int = 0,
        uuid: Optional[bytes] = None,
        public_key_0: Optional[SRKRecordV2] = None,
        signature_provider_0: Optional[SignatureProvider] = None,
        public_key_1: Optional[SRKRecordV2] = None,
        signature_provider_1: Optional[SignatureProvider] = None,
    ):
        """Class object initializer.

        :param permissions: used to indicate what a certificate can be used for.
        :param permissions_data: Complementary information for debug auth feature.
        :param fuse_version: Version of certificate
        :param uuid: 128-bit unique identifier.
        :param public_key_0: public Key. SRK record entry describing the key. SET 1.
        :param signature_provider_0: Signature provider for certificate. Signature is calculated over
            all data from beginning of the certificate up to, but not including the signature.  SET 1.
        :param public_key_1: public Key. SRK record entry describing the key. SET 2.
        :param signature_provider_1: Signature provider for certificate. Signature is calculated over
            all data from beginning of the certificate up to, but not including the signature.  SET 2.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
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
        if isinstance(other, AhabCertificate):
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
        return "AHAB Certificate"

    def __str__(self) -> str:
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
        """Format of binary representation."""
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

    @staticmethod
    def create_permissions(permissions: list[str]) -> int:
        """Create integer representation of permission field.

        :param permissions: List of string permissions.
        :return: Integer representation of permissions.
        """
        ret = 0
        permission_map = {}
        permission_map.update(AhabCertificate.PERM_NXP)
        permission_map.update(AhabCertificate.PERM_OEM)
        for permission in permissions:
            ret |= permission_map[permission]

        return ret

    @property
    def permission_to_sign_container(self) -> bool:
        """Certificate has permission to sign container."""
        return bool(self._permissions & self.PERM_OEM["container"])

    def create_config_permissions(self, srk_set: FlagsSrkSet) -> list[str]:
        """Create list of string representation of permission field.

        :param srk_set: SRK set to get proper string values.
        :return: List of string representation of permissions.
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

    def get_signature_data(self) -> bytes:
        """Returns binary data to be signed.

        The certificate block must be properly initialized, so the data are valid for
        signing. There is signed whole certificate block without signature part.


        :raises SPSDKValueError: if Signature Block or SRK Table is missing.
        :return: bytes representing data to be signed.
        """
        assert isinstance(self.public_key_0, SRKRecordV2)
        cert_data_to_sign = pack(
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

        cert_data_to_sign += self.public_key_0.export()
        assert isinstance(self.public_key_0.srk_data, SRKData)
        cert_data_to_sign += self.public_key_0.srk_data.export()
        if self.public_key_1:
            cert_data_to_sign += self.public_key_1.export()
            assert isinstance(self.public_key_1.srk_data, SRKData)
            cert_data_to_sign += self.public_key_1.srk_data.export()

        return cert_data_to_sign

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
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

        :return: bytes representing container content.
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

        :param srk: SRK table to allow verify also signature of certificate.
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

            srk_table_cnt = len(srk._srk_tables)

            def check_key_type(ix: int, srk_key: SRKRecordV2, key: Optional[SRKRecordV2]) -> None:
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
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Certificate block to parse.
        :raises SPSDKValueError: Certificate permissions are invalid.
        :raises SPSDKParsingError: Certificate parsing error.
        :return: Object recreated from the binary data.
        """
        AhabCertificate.check_container_head(data).validate()
        certificate_data_offset = AhabCertificate.fixed_length()
        image_format = AhabCertificate.format()
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
        ) = unpack(image_format, data[:certificate_data_offset])

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

    def create_config(
        self,
        index: int,
        data_path: str,
        srk_set: FlagsSrkSet = FlagsSrkSet.OEM,
    ) -> dict[str, Any]:
        """Create configuration of the AHAB Image Certificate.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :param srk_set: SRK set to know how to create certificate permissions.
        :return: Configuration dictionary.
        """
        ret_cfg: dict[str, Any] = {}
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
        ret_cfg["signature_provider_0"] = "N/A"
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
            ret_cfg["signature_provider_1"] = "N/A"

        return ret_cfg

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Converts the configuration option into an AHAB image signature block certificate object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Certificate object.
        """
        cert_permissions_list = config.get("permissions", [])
        cert_uuid_raw = config.get("uuid")
        cert_uuid = value_to_bytes(cert_uuid_raw) if cert_uuid_raw else None
        cert_permission_data_raw = config.get("permission_data")
        cert_permission_data = (
            value_to_bytes(cert_permission_data_raw) if cert_permission_data_raw else None
        )
        cert_fuse_version = value_to_int(config.get("fuse_version", 0))
        cert_public_key0_path = config.get("public_key_0")
        assert isinstance(cert_public_key0_path, str)
        cert_public_key0_path = find_file(cert_public_key0_path, search_paths=search_paths)
        cert_public_key0 = SRKRecordV2.create_from_key(extract_public_key(cert_public_key0_path))
        cert_signature_provider0 = get_signature_provider(
            config.get("signature_provider_0"),
            config.get("signing_key_0"),
            search_paths=search_paths,
            pss_padding=True,
        )

        cert_public_key1_path = config.get("public_key_1")
        cert_public_key1 = None
        cert_signature_provider1 = None
        if cert_public_key1_path:
            cert_public_key1_path = find_file(cert_public_key1_path, search_paths=search_paths)
            cert_public_key1 = SRKRecordV2.create_from_key(
                extract_public_key(cert_public_key1_path)
            )
            cert_signature_provider1 = get_signature_provider(
                config.get("signature_provider_1"),
                config.get("signing_key_1"),
                search_paths=search_paths,
                pss_padding=True,
            )

        return cls(
            permissions=AhabCertificate.create_permissions(cert_permissions_list),
            permissions_data=cert_permission_data or b"",
            fuse_version=cert_fuse_version,
            uuid=cert_uuid,
            public_key_0=cert_public_key0,
            signature_provider_0=cert_signature_provider0,
            public_key_1=cert_public_key1,
            signature_provider_1=cert_signature_provider1,
        )

    @classmethod
    def get_validation_schemas_family(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for AHAB certificate supported families.
        """
        sch = DatabaseManager().db.get_schema_file("general")["family"]
        update_validation_schema_family(sch["properties"], cls.get_supported_families())
        return [sch]

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get all supported families for AHAB certificate.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.AHAB, sub_feature="certificate_supported")

    @staticmethod
    def get_validation_schemas(family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the validation schema should be generated.
        :param revision: Family revision of chip.
        :return: Validation list of schemas.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)
        sch_family = DatabaseManager().db.get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], AhabCertificate.get_supported_families(), family, revision
        )
        return [sch_family, sch["ahab_certificate"]]

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate AHAB configuration template.

        :param family: Family for which the validation schema should be generated.
        :param revision: Family revision of chip.
        :return: Certificate configuration templates.
        """
        yaml_data = CommentedConfig(
            "Advanced High-Assurance Boot Certificate Configuration template.",
            AhabCertificate.get_validation_schemas(family, revision),
        ).get_template()

        return yaml_data

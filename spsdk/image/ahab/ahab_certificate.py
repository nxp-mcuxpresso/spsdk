#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of AHAB container Signature certificate support."""

import logging
import os
from struct import pack, unpack
from typing import Any, Dict, List, Optional

from typing_extensions import Self

from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.utils import extract_public_key, get_matching_key_id_from_signature
from spsdk.exceptions import SPSDKValueError
from spsdk.image.ahab.ahab_abstract_interfaces import HeaderContainer, HeaderContainerData
from spsdk.image.ahab.ahab_data import UINT8, UINT16, AHABTags, FlagsSrkSet
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKTable
from spsdk.utils.database import DatabaseManager, get_families
from spsdk.utils.misc import find_file, value_to_bytes, write_file
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


def get_key_by_val(dictionary: Dict, val: Any) -> Any:
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

    Certificate format 1::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    Certificate format 2::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                            UUID                               |
        +-----+---------------------------------------------------------------+
        |...  |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    """

    TAG = [AHABTags.CERTIFICATE_UUID.tag, AHABTags.CERTIFICATE_NON_UUID.tag]
    UUID_LEN = 16
    UUID_OFFSET = 0x08
    VERSION = 0x00
    PERM_NXP = {
        "secure_enclave_debug": 0x02,
        "hdmi_debug": 0x04,
        "life_cycle": 0x10,
        "hdcp_fuses": 0x20,
    }
    PERM_OEM = {
        "container": 0x01,
        "phbc_debug": 0x02,
        "soc_debug_domain_1": 0x04,
        "soc_debug_domain_2": 0x08,
        "life_cycle": 0x10,
        "monotonic_counter": 0x20,
    }
    PERM_SIZE = 8

    def __init__(
        self,
        permissions: int = 0,
        uuid: Optional[bytes] = None,
        public_key: Optional[SRKRecord] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ):
        """Class object initializer.

        :param permissions: used to indicate what a certificate can be used for.
        :param uuid: optional 128-bit unique identifier.
        :param public_key: public Key. SRK record entry describing the key.
        :param signature_provider: Signature provider for certificate. Signature is calculated over
            all data from beginning of the certificate up to, but not including the signature.
        """
        tag = AHABTags.CERTIFICATE_UUID.tag if uuid else AHABTags.CERTIFICATE_NON_UUID.tag
        super().__init__(tag=tag, length=-1, version=self.VERSION)
        self._permissions = permissions
        self.signature_offset = -1
        self._uuid = uuid
        self.public_key = public_key
        self.signature = ContainerSignature(
            signature_data=b"", signature_provider=signature_provider
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AhabCertificate):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._permissions == other._permissions
                and self.signature_offset == other.signature_offset
                and self._uuid == other._uuid
                and self.public_key == other.public_key
                and self.signature == other.signature
            ):
                return True

        return False

    def __repr__(self) -> str:
        return "AHAB Certificate"

    def __str__(self) -> str:
        return (
            "AHAB Certificate:\n"
            f"  Permission:         {hex(self._permissions)}\n"
            f"  UUID:               {self._uuid.hex() if self._uuid else 'Not Available'}\n"
            f"  Public Key:         {str(self.public_key) if self.public_key else 'Not available'}\n"
            f"  Signature:          {str(self.signature) if self.signature else 'Not available'}"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness, header: version, length, tag
            + UINT16  # signature offset
            + UINT8  # inverted permissions
            + UINT8  # permissions
        )

    def __len__(self) -> int:
        assert self.public_key
        uuid_len = len(self._uuid) if self._uuid else 0
        return super().__len__() + uuid_len + len(self.public_key) + len(self.signature)

    @staticmethod
    def create_permissions(permissions: List[str]) -> int:
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

    def create_config_permissions(self, srk_set: FlagsSrkSet) -> List[str]:
        """Create list of string representation of permission field.

        :param srk_set: SRK set to get proper string values.
        :return: List of string representation of permissions.
        """
        ret = []
        perm_map = self.PERM_NXP if srk_set == FlagsSrkSet.NXP else self.PERM_OEM

        for i in range(self.PERM_SIZE):
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
        assert self.public_key
        cert_data_to_sign = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.signature_offset,
                ~self._permissions & 0xFF,
                self._permissions,
            )
            + self.public_key.export()
        )
        # if uuid is present, insert it into the cert data
        if self._uuid:
            cert_data_to_sign = (
                cert_data_to_sign[: self.UUID_OFFSET]
                + self._uuid
                + cert_data_to_sign[self.UUID_OFFSET :]
            )

        return cert_data_to_sign

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        assert self.public_key
        self.public_key.update_fields()
        self.tag = (
            AHABTags.CERTIFICATE_UUID.tag if self._uuid else AHABTags.CERTIFICATE_NON_UUID.tag
        )
        self.signature_offset = (
            super().__len__() + (len(self._uuid) if self._uuid else 0) + len(self.public_key)
        )
        self.length = len(self)
        self.signature.sign(self.get_signature_data())

    def export(self) -> bytes:
        """Export container certificate object into bytes.

        :return: bytes representing container content.
        """
        assert self.public_key
        cert = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.signature_offset,
                ~self._permissions & 0xFF,
                self._permissions,
            )
            + self.public_key.export()
            + self.signature.export()
        )
        # if uuid is present, insert it into the cert data
        if self._uuid:
            cert = cert[: self.UUID_OFFSET] + self._uuid + cert[self.UUID_OFFSET :]
        assert self.length == len(cert)
        return cert

    def verify(self, srk: Optional[SRKTable] = None) -> Verifier:
        """Verify container certificate data.

        :param srk: SRK table to allow verify also signature of certificate.
        """
        ret = Verifier("Certificate", description="")
        ret.add_child(self.verify_parsed_header())
        ret.add_child(self.verify_header())
        ret.add_record_bit_range("Permission", self._permissions, 8)
        if self.public_key is None:
            ret.add_record("Public key", VerifierResult.ERROR, "Not exists")
        else:
            ret.add_child(self.public_key.verify("Public key"))
        expected_signature_offset = (
            super().__len__()
            + (len(self._uuid) if self._uuid else 0)
            + (len(self.public_key) if self.public_key else 0)
        )
        if self.signature_offset != expected_signature_offset:
            ret.add_record(
                "Signature offset",
                VerifierResult.ERROR,
                f"Invalid. {self.signature_offset} != {expected_signature_offset} (expected)",
            )
        else:
            ret.add_record("Signature offset", VerifierResult.SUCCEEDED, self.signature_offset)

        if srk:
            public_keys = srk.get_source_keys()
            try:
                ix = get_matching_key_id_from_signature(
                    public_keys, self.get_signature_data(), self.signature.signature_data
                )
            except SPSDKValueError:
                ret.add_record(
                    "Signature", VerifierResult.ERROR, "The signature is invalid with all SRK keys."
                )
            else:

                ret.add_record(
                    "Signature",
                    VerifierResult.WARNING,
                    f"Signed by SRK #{ix}. Please check if works with revoked keys "
                    "and and used_srk_id in main container",
                )

        else:
            ret.add_record(
                "Signature",
                VerifierResult.WARNING,
                "Cannot verified, due missing information about SRK table in verifier.",
            )

        if self._uuid:
            if len(self._uuid) != self.UUID_LEN:
                ret.add_record(
                    "UUID",
                    VerifierResult.ERROR,
                    f"Invalid size. {len(self._uuid)} != {self.UUID_LEN}",
                )
            else:
                ret.add_record("UUID", VerifierResult.SUCCEEDED, self._uuid.hex())
        else:
            ret.add_record("UUID", VerifierResult.SUCCEEDED, "Not used")

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Certificate block to parse.
        :raises SPSDKValueError: Certificate permissions are invalid.
        :return: Object recreated from the binary data.
        """
        AhabCertificate.check_container_head(data).validate()
        certificate_data_offset = AhabCertificate.fixed_length()
        image_format = AhabCertificate.format()
        (
            _,  # version,
            container_length,
            tag,
            signature_offset,
            inverted_permissions,
            permissions,
        ) = unpack(image_format, data[:certificate_data_offset])

        if inverted_permissions != ~permissions & 0xFF:
            raise SPSDKValueError("Certificate parser: Invalid permissions record.")

        uuid = None

        if AHABTags.CERTIFICATE_UUID == tag:
            uuid = data[
                certificate_data_offset : certificate_data_offset + AhabCertificate.UUID_LEN
            ]
            certificate_data_offset += AhabCertificate.UUID_LEN

        public_key = SRKRecord.parse(data[certificate_data_offset:])

        signature = ContainerSignature.parse(data[signature_offset:container_length])

        cert = cls(
            permissions=permissions,
            uuid=uuid,
            public_key=public_key,
        )
        cert.signature = signature
        cert._parsed_header = HeaderContainerData.parse(binary=data)
        return cert

    def create_config(
        self,
        index: int,
        data_path: str,
        srk_set: FlagsSrkSet = FlagsSrkSet.OEM,
    ) -> Dict[str, Any]:
        """Create configuration of the AHAB Image Certificate.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :param srk_set: SRK set to know how to create certificate permissions.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Any] = {}
        assert self.public_key
        ret_cfg["permissions"] = self.create_config_permissions(srk_set)
        if self._uuid:
            ret_cfg["uuid"] = self._uuid.hex()
        filename = f"container{index}_certificate_public_key_{self.public_key.get_key_name()}.pem"
        public_key = self.public_key.get_public_key()
        write_file(
            data=public_key.export(public_key.RECOMMENDED_ENCODING),
            path=os.path.join(data_path, filename),
            mode="wb",
        )
        ret_cfg["public_key"] = filename
        ret_cfg["signature_provider"] = "N/A"

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "AhabCertificate":
        """Converts the configuration option into an AHAB image signature block certificate object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Certificate object.
        """
        cert_permissions_list = config.get("permissions", [])
        cert_uuid_raw = config.get("uuid")
        cert_uuid = value_to_bytes(cert_uuid_raw) if cert_uuid_raw else None
        cert_public_key_path = config.get("public_key")
        assert isinstance(cert_public_key_path, str)
        cert_public_key_path = find_file(cert_public_key_path, search_paths=search_paths)
        cert_public_key = extract_public_key(cert_public_key_path)
        cert_srk_rec = SRKRecord.create_from_key(cert_public_key)
        cert_signature_provider = get_signature_provider(
            config.get("signature_provider"),
            config.get("signing_key"),
            search_paths=search_paths,
            pss_padding=True,
        )
        return AhabCertificate(
            permissions=AhabCertificate.create_permissions(cert_permissions_list),
            uuid=cert_uuid,
            public_key=cert_srk_rec,
            signature_provider=cert_signature_provider,
        )

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)
        sch["family"]["properties"]["family"]["enum"] = get_families(DatabaseManager.AHAB)
        return [sch["family"], sch["ahab_certificate"]]

    @staticmethod
    def generate_config_template() -> str:
        """Generate AHAB configuration template.

        :return: Certificate configuration templates.
        """
        yaml_data = CommentedConfig(
            "Advanced High-Assurance Boot Certificate Configuration template.",
            AhabCertificate.get_validation_schemas(),
        ).get_template()

        return yaml_data

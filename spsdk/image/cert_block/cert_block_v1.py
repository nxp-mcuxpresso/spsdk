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
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import get_hash
from spsdk.crypto.keys import PrivateKeyRsa, PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlock
from spsdk.image.cert_block.rkht import RKHTv1
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import Endianness, align, align_block, find_file, load_binary
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


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
                cert_block_cfg["containerOutputFile"] = "cert_block.bin"
                cls.pre_check_config(cert_block_cfg)
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

    def verify(self) -> Verifier:
        """Verify the Certificate Block V1 configuration.

        Validates the certificate block structure including header, certificates,
        root key hash table, and certificate chain integrity.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="Certificate Block V1",
            description="Validates certificate block structure and certificate chain",
        )

        # Verify header
        ver.add_record(
            name="Header version",
            result=VerifierResult.SUCCEEDED,
            value=f"Version {self.header.version}",
            important=False,
        )

        ver.add_record(
            name="Build number",
            result=VerifierResult.SUCCEEDED,
            value=f"{self.header.build_number}",
            important=False,
        )

        # Verify alignment
        ver.add_record_range(
            name="Alignment",
            value=self.alignment,
            min_val=1,
            max_val=256,
        )

        # Verify image length if set
        if self.image_length > 0:
            ver.add_record(
                name="Image length",
                result=VerifierResult.SUCCEEDED,
                value=f"{self.image_length} bytes (0x{self.image_length:X})",
            )

        # Verify certificates
        if len(self._cert) == 0:
            ver.add_record(
                name="Certificates",
                result=VerifierResult.ERROR,
                value="No certificates present (at least one required)",
            )
        else:
            ver.add_record(
                name="Certificate count",
                result=VerifierResult.SUCCEEDED,
                value=f"{len(self._cert)} certificate(s)",
            )

            # Verify root certificate is self-signed
            if not self._cert[0].self_signed:
                ver.add_record(
                    name="Root certificate",
                    result=VerifierResult.ERROR,
                    value="Root certificate must be self-signed",
                )
            else:
                ver.add_record(
                    name="Root certificate",
                    result=VerifierResult.SUCCEEDED,
                    value="Root certificate is self-signed",
                )

            # Verify certificate chain structure
            if len(self._cert) > 1:
                # All certificates except last must be CA
                non_ca_certs = [i for i, cert in enumerate(self._cert[:-1]) if not cert.ca]
                if non_ca_certs:
                    ver.add_record(
                        name="Certificate chain CA structure",
                        result=VerifierResult.ERROR,
                        value=f"Certificates at indices {non_ca_certs} must be CA certificates",
                    )
                else:
                    ver.add_record(
                        name="Certificate chain CA structure",
                        result=VerifierResult.SUCCEEDED,
                        value="All intermediate certificates are CA certificates",
                    )

                # Last certificate must not be CA
                if self._cert[-1].ca:
                    ver.add_record(
                        name="Leaf certificate",
                        result=VerifierResult.ERROR,
                        value="Last certificate in chain must not be CA",
                    )
                else:
                    ver.add_record(
                        name="Leaf certificate",
                        result=VerifierResult.SUCCEEDED,
                        value="Leaf certificate is not CA",
                    )

                # Verify chain signatures
                chain_valid = True
                for i in range(1, len(self._cert)):
                    if not self._cert[i].validate(self._cert[i - 1]):
                        ver.add_record(
                            name=f"Certificate {i} signature",
                            result=VerifierResult.ERROR,
                            value=f"Certificate {i} cannot be verified with certificate {i-1}",
                        )
                        chain_valid = False

                if chain_valid:
                    ver.add_record(
                        name="Certificate chain signatures",
                        result=VerifierResult.SUCCEEDED,
                        value="All certificates in chain are properly signed",
                    )

        # Verify RKHT
        rkh_count = len([rkh for rkh in self.rkh if rkh != bytes(32)])
        ver.add_record(
            name="Root Key Hashes",
            result=VerifierResult.SUCCEEDED,
            value=f"{rkh_count} root key hash(es) configured",
        )

        # Verify RKH index
        rkh_index = self.rkh_index
        if self._cert:
            if rkh_index is None:
                ver.add_record(
                    name="RKH index match",
                    result=VerifierResult.ERROR,
                    value="Root certificate hash not found in RKHT",
                )
            else:
                ver.add_record(
                    name="RKH index match",
                    result=VerifierResult.SUCCEEDED,
                    value=f"Root certificate matches RKHT entry {rkh_index}",
                )

        # Verify RKTH
        rkth = self.rkth
        ver.add_record(
            name="RKTH (Root Key Table Hash)",
            result=VerifierResult.SUCCEEDED,
            value=f"{rkth.hex().upper()}",
            important=False,
        )

        # Verify expected size matches actual size
        try:
            exported_data = self.export()
            if len(exported_data) == self.expected_size:
                ver.add_record(
                    name="Size consistency",
                    result=VerifierResult.SUCCEEDED,
                    value=f"Expected: {self.expected_size} bytes, Actual: {len(exported_data)} bytes",
                )
            else:
                ver.add_record(
                    name="Size consistency",
                    result=VerifierResult.ERROR,
                    value=f"Expected: {self.expected_size} bytes, Actual: {len(exported_data)} bytes",
                )
        except SPSDKError as e:
            ver.add_record(
                name="Export validation",
                result=VerifierResult.ERROR,
                value=f"Cannot export certificate block: {str(e)}",
            )

        return ver

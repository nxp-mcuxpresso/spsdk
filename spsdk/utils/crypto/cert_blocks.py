#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling Certificate block."""

import logging
import re
from struct import calcsize, pack, unpack_from
from typing import Any, Dict, List, Optional, Sequence, Union

from Crypto.PublicKey import ECC

from spsdk import SPSDKError
from spsdk.crypto.loaders import load_certificate_as_bytes
from spsdk.exceptions import SPSDKValueError
from spsdk.utils import misc
from spsdk.utils.crypto import CRYPTO_SCH_FILE
from spsdk.utils.schema_validator import ValidationSchemas

from .abstract import BaseClass
from .backend_internal import internal_backend
from .certificate import Certificate
from .common import crypto_backend

logger = logging.getLogger(__name__)


class CertBlock(BaseClass):
    """Common general class for various CertBlocks."""


########################################################################################################################
# Certificate Block Header Class
########################################################################################################################
class CertBlockHeader(BaseClass):
    """Certificate block header."""

    FORMAT = "<4s2H6I"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(self, version: str = "1.0", flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: Version of the certificate in format n.n
        :param flags: Flags for the Certificate Header
        :param build_number: of the certificate
        :raises SPSDKError: When there is invalid version
        """
        if not re.match(r"[0-9]+\.[0-9]+", version):  # check format of the version: N.N
            raise SPSDKError("Invalid version")
        self.version = version
        self.flags = flags
        self.build_number = build_number
        self.image_length = 0
        self.cert_count = 0
        self.cert_table_length = 0

    def __str__(self) -> str:
        nfo = f"CertBlockHeader: V={self.version}, F={self.flags}, BN={self.build_number}, IL={self.image_length}, "
        nfo += f"CC={self.cert_count}, CTL={self.cert_table_length}"
        return nfo

    def info(self) -> str:
        """Info of the certificate header in text form."""
        nfo = str()
        nfo += f" CB Version:           {self.version}\n"
        nfo += f" CB Flags:             {self.flags}\n"
        nfo += f" CB Build Number:      {self.build_number}\n"
        nfo += f" CB Image Length:      {self.image_length}\n"
        nfo += f" CB Cert. Count:       {self.cert_count}\n"
        nfo += f" CB Cert. Length:      {self.cert_table_length}\n"
        return nfo

    def export(self) -> bytes:
        """Certificate block in binary form."""
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
    def parse(cls, data: bytes, offset: int = 0) -> "CertBlockHeader":
        """Deserialize object from bytes array.

        :param data: Input data as bytes
        :param offset: The offset of input data (default: 0)
        :return: Certificate Header instance
        :raises Exception: Unexpected size or signature of data
        """
        if cls.SIZE > len(data) - offset:
            raise Exception()
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
        ) = unpack_from(cls.FORMAT, data, offset)
        if signature != cls.SIGNATURE:
            raise Exception()
        if length != cls.SIZE:
            raise Exception()
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
class CertBlockV2(CertBlock):
    """Certificate block.

    Shared for SB file and for MasterBootImage
    """

    # size of the hash in bytes (single item in RKH table)
    RKH_SIZE = 32
    # number of hashes in RKH table (number of table entries)
    RKHT_SIZE = 4

    # default size alignment
    DEFAULT_ALIGNMENT = 16

    @property
    def header(self) -> CertBlockHeader:
        """Certificate block header."""
        return self._header

    @property
    def rkh(self) -> List[bytes]:
        """List of root keys hashes (SHA-256), each hash as 32 bytes."""
        return self._root_key_hashes

    @property
    def rkht(self) -> bytes:
        """32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        data = bytes()
        for rkh in self._root_key_hashes:
            data += rkh
        if len(data) != self.RKH_SIZE * self.RKHT_SIZE:
            raise SPSDKError("Invalid length of data")
        return internal_backend.hash(data)

    @property
    def rkht_fuses(self) -> List[int]:
        """List of RKHT fuses, ordered from highest bit to lowest.

        Note: Returned values are in format that should be passed for blhost
        """
        result = []
        rkht = self.rkht
        while rkht:
            fuse = int.from_bytes(rkht[:4], byteorder="little")
            result.append(fuse)
            rkht = rkht[4:]
        return result

    @property
    def certificates(self) -> List[Certificate]:
        """List of certificates in header.

        First certificate is root certificate and followed by optional chain certificates
        """
        return self._cert

    @property
    def signature_size(self) -> int:
        """Size of the signature in bytes."""
        return len(
            self.certificates[0].signature
        )  # The certificate is self signed, return size of its signature

    @property
    def rkh_index(self) -> Optional[int]:
        """Index of the hash that matches the certificate; None if does not match."""
        if self._cert:
            rkh = self._cert[0].public_key_hash
            for index, value in enumerate(self._root_key_hashes):
                if rkh == value:
                    return index
        return None

    @property
    def alignment(self) -> int:
        """Alignment of the binary output, by default it is DEFAULT_ALIGNMENT but can be customized."""
        return self._alignment

    @alignment.setter
    def alignment(self, value: int) -> None:
        """Setter.

        :param value: new alignment
        :raises SPSDKError: When there is invalid alignment
        """
        if value <= 0:
            raise SPSDKError("Invalid alignment")
        self._alignment = value

    @property
    def raw_size(self) -> int:
        """Aligned size of the certificate block."""
        size = CertBlockHeader.SIZE
        size += self._header.cert_table_length
        size += self.RKH_SIZE * self.RKHT_SIZE
        return misc.align(size, self.alignment)

    @property
    def image_length(self) -> int:
        """Image length in bytes."""
        return self._header.image_length

    @image_length.setter
    def image_length(self, value: int) -> None:
        """Setter.

        :param value: new image length
        :raises SPSDKError: When there is invalid image length
        """
        if value <= 0:
            raise SPSDKError("Invalid image length")
        self._header.image_length = value

    def __init__(self, version: str = "1.0", flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: of the certificate in format n.n
        :param flags: Flags for the Certificate Block Header
        :param build_number: of the certificate
        """
        self._header = CertBlockHeader(version, flags, build_number)
        self._root_key_hashes = [b"\x00" * self.RKH_SIZE for _ in range(self.RKHT_SIZE)]
        self._cert: List[Certificate] = []
        self._alignment = self.DEFAULT_ALIGNMENT

    def __str__(self) -> str:
        return str(self._header)

    def __len__(self) -> int:
        return len(self._cert)

    def set_root_key_hash(self, index: int, key_hash: Union[bytes, bytearray, Certificate]) -> None:
        """Add Root Key Hash into RKH at specified index.

        Note: Multiple root public keys are supported to allow for key revocation.

        :param index: The index of Root Key Hash in the table
        :param key_hash: The Root Key Hash value (32 bytes, SHA-256);
                        or Certificate where the hash can be created from public key
        :raises SPSDKError: When there is invalid index of root key hash in the table
        :raises SPSDKError: When there is invalid length of key hash
        """
        if isinstance(key_hash, Certificate):
            key_hash = key_hash.public_key_hash
        assert isinstance(key_hash, (bytes, bytearray))
        if index < 0 or index >= self.RKHT_SIZE:
            raise SPSDKError("Invalid index of root key hash in the table")
        if len(key_hash) != self.RKH_SIZE:
            raise SPSDKError("Invalid length of key hash")
        self._root_key_hashes[index] = bytes(key_hash)

    def add_certificate(self, cert: Union[bytes, Certificate]) -> None:
        """Add certificate.

        First call adds root certificate. Additional calls add chain certificates.

        :param cert: The certificate itself in DER format
        :raises SPSDKError: If certificate cannot be added
        """
        if isinstance(cert, bytes):
            cert_obj = Certificate(cert)
        elif isinstance(cert, Certificate):
            cert_obj = cert
        else:
            raise SPSDKError("Invalid parameter type (cert)")
        if cert_obj.version != "v3":
            raise SPSDKError("Expected certificate v3 but received: " + cert_obj.version)
        if self._cert:  # chain certificate?
            last_cert = self._cert[-1]  # verify that it is signed by parent key
            if not cert_obj.verify(last_cert.public_key_modulus, last_cert.public_key_exponent):
                raise SPSDKError("Chain certificate cannot be verified using parent public key")
        else:  # root certificate
            if cert_obj.self_signed == "no":
                raise SPSDKError(f"Root certificate must be self-signed.\n{cert_obj.info()}")
        self._cert.append(cert_obj)
        self._header.cert_count += 1
        self._header.cert_table_length += cert_obj.raw_size + 4

    def info(self) -> str:
        """Text info about certificate block."""
        nfo = self.header.info()
        nfo += " Public Root Keys Hash e.g. RKH (SHA256):\n"
        rkh_index = self.rkh_index
        for index, root_key in enumerate(self._root_key_hashes):
            nfo += (
                f"  {index}) {root_key.hex().upper()} {'<- Used' if index == rkh_index else ''}\n"
            )
        rkht = self.rkht
        nfo += f" RKHT (SHA256): {rkht.hex().upper()}\n"
        for index, fuse in enumerate(self.rkht_fuses):
            bit_ofs = (len(rkht) - 4 * index) * 8
            nfo += f"  - RKHT fuse [{bit_ofs:03}:{bit_ofs - 31:03}]: {fuse:08X}\n"
        for index, cert in enumerate(self._cert):
            nfo += " Root Certificate:\n" if index == 0 else f" Certificate {index}:\n"
            nfo += cert.info()
        return nfo

    def verify_data(self, signature: bytes, data: bytes) -> bool:
        """Signature verification.

        :param signature: to be verified
        :param data: that has been signed
        :return: True if the data signature can be confirmed using the certificate; False otherwise
        """
        cert = self._cert[-1]
        return crypto_backend().rsa_verify(
            cert.public_key_modulus, cert.public_key_exponent, signature, data
        )

    def verify_private_key(self, private_key_pem_data: bytes) -> bool:
        """Verify that given private key matches the public certificate.

        :param private_key_pem_data: to be tested; decrypted binary data in PEM format
        :return: True if yes; False otherwise
        """
        signature = crypto_backend().rsa_sign(private_key_pem_data, bytes())
        cert = self.certificates[-1]  # last certificate
        return crypto_backend().rsa_verify(
            cert.public_key_modulus, cert.public_key_exponent, signature, bytes()
        )

    def export(self) -> bytes:
        """Serialize Certificate Block V2 object."""
        # At least one certificate must be used
        if not self._cert:
            raise SPSDKError("At least one certificate must be used")
        # The hast of root key certificate must be in RKHT
        if self.rkh_index is None:
            raise SPSDKError("The HASH of used Root Key must be in RKHT")
        # CA: Using a single certificate is allowed. In this case, the sole certificate must be self-signed and must not
        # be a CA. If multiple certificates are used, the root must be self-signed and all but the last must be CAs.
        if self._cert[-1].ca:
            raise SPSDKError("The last chain certificate must not be CA")
        if not all(cert.ca for cert in self._cert[:-1]):
            raise SPSDKError("All certificates except the last chain certificate must be CA")
        # Export
        data = self.header.export()
        for cert in self._cert:
            data += pack("<I", cert.raw_size)
            data += cert.export()
        for key in self._root_key_hashes:
            data += bytes(key)
        data = misc.align_block(data, self.alignment)
        if len(data) != self.raw_size:
            raise SPSDKError("Invalid length of data")
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CertBlockV2":
        """Deserialize CertBlockV2 from binary file.

        :param data: Binary data
        :param offset: Offset within the data, where the Certificate block begins, defaults to 0
        :return: Certificate Block instance
        :raises Exception: Length of the data doesn't match Certificate Block length
        """
        header = CertBlockHeader.parse(data, offset)
        offset += CertBlockHeader.SIZE
        if (len(data) - offset) < (header.cert_table_length + (cls.RKHT_SIZE * cls.RKH_SIZE)):
            raise Exception()
        obj = cls(version=header.version, flags=header.flags, build_number=header.build_number)
        for i in range(header.cert_count):
            cert_len = unpack_from("<I", data, offset)[0]
            offset += 4
            cert_obj = Certificate(data[offset : offset + cert_len])
            obj.add_certificate(cert_obj)
            offset += cert_len
        for i in range(cls.RKHT_SIZE):
            obj.set_root_key_hash(i, data[offset : offset + cls.RKH_SIZE])
            offset += cls.RKH_SIZE
        return obj

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        sch_cfg = ValidationSchemas.get_schema_file(CRYPTO_SCH_FILE)
        return [
            sch_cfg["certificate_v2"],
            sch_cfg["certificate_v2_chain_id"],
            sch_cfg["certificate_root_keys"],
        ]

    @classmethod
    def from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "CertBlockV2":
        """Creates an instance of CertBlockV2 from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of CertBlockV2
        :raises SPSDKError: Invalid certificates detected.
        """
        image_build_number = misc.value_to_int(config.get("imageBuildNumber", 0))
        root_certificates: List[List[str]] = [[] for _ in range(4)]
        # TODO we need to read the whole chain from the dict for a given
        # selection based on mainCertPrivateKeyFile!!!
        root_certificates[0].append(config.get("rootCertificate0File", None))
        root_certificates[1].append(config.get("rootCertificate1File", None))
        root_certificates[2].append(config.get("rootCertificate2File", None))
        root_certificates[3].append(config.get("rootCertificate3File", None))
        main_cert_chain_id = get_main_cert_index(config, default=0)

        # get all certificate chain related keys from config
        pattern = f"chainCertificate{main_cert_chain_id}File[0-3]"
        keys = [key for key in config.keys() if re.fullmatch(pattern, key)]
        # just in case, sort the chain certificate keys in order
        keys.sort()
        for key in keys:
            root_certificates[main_cert_chain_id].append(config[key])

        cert_block = CertBlockV2(build_number=image_build_number)

        # add whole certificate chain used for image signing
        for cert_path in root_certificates[main_cert_chain_id]:
            cert_data = load_certificate_as_bytes(
                misc.find_file(str(cert_path), search_paths=search_paths)
            )
            cert_block.add_certificate(cert_data)
        # set root key hash of each root certificate
        empty_rec = False
        for cert_idx, cert_path_list in enumerate(root_certificates):
            if cert_path_list[0]:
                if empty_rec:
                    raise SPSDKError("There are gaps in rootCertificateXFile definition")
                cert_data = load_certificate_as_bytes(
                    misc.find_file(str(cert_path_list[0]), search_paths=search_paths)
                )
                cert_block.set_root_key_hash(cert_idx, Certificate(cert_data))
            else:
                empty_rec = True

        return cert_block


########################################################################################################################
# Certificate Block Class for SB 3.1
########################################################################################################################
def get_ecc_key_bytes(key: ECC.EccKey) -> bytes:
    """Function to get ECC Key pointQ as bytes."""
    point_x = key.pointQ.x.to_bytes(block_size=key.pointQ.size_in_bytes())  # type: ignore
    point_y = key.pointQ.y.to_bytes(block_size=key.pointQ.size_in_bytes())  # type: ignore
    return point_x + point_y


def convert_to_ecc_key(key: Union[ECC.EccKey, bytes]) -> ECC.EccKey:
    """Convert key into EccKey instance."""
    if isinstance(key, ECC.EccKey):
        return key
    return ECC.import_key(key)


class CertificateBlockHeader(BaseClass):
    """Create Certificate block header."""

    FORMAT = "<4s2HL"
    SIZE = calcsize(FORMAT)
    MAGIC = b"chdr"

    def __init__(self, format_version: str = "2.1") -> None:
        """Constructor for Certificate block header version 2.1.

        :param format_version: Major = 2, minor = 1
        """
        self.format_version = format_version
        self.cert_block_size = 0

    def info(self) -> str:
        """Get info of Certificate block header."""
        info = ""
        info += f"Format version:              {self.format_version}\n"
        info += f"Certificate block size:      {self.cert_block_size}\n"
        return info

    def export(self) -> bytes:
        """Export Certificate block header as bytes array."""
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
    def parse(cls, data: bytes, offset: int = 0) -> "CertificateBlockHeader":
        """Parse Certificate block header from bytes array.

        :param data: Input data as bytes
        :param offset: The offset of input data (default: 0)
        :raises SPSDKError: Raised when SIZE is bigger than length of the data without offset
        :raises SPSDKError: Raised when magic is not equal MAGIC
        :return: CertificateBlockHeader
        """
        if cls.SIZE > len(data) - offset:
            raise SPSDKError("SIZE is bigger than length of the data without offset")
        (
            magic,
            minor_format_version,
            major_format_version,
            cert_block_size,
        ) = unpack_from(cls.FORMAT, data, offset)

        if magic != cls.MAGIC:
            raise SPSDKError("Magic is not same!")

        obj = cls(format_version=f"{major_format_version}.{minor_format_version}")
        obj.cert_block_size = cert_block_size
        return obj


class RootKeyRecord(BaseClass):
    """Create Root key record."""

    # P-256

    def __init__(
        self,
        ca_flag: bool,
        root_certs: Union[Sequence[ECC.EccKey], Sequence[bytes]],
        used_root_cert: int = 0,
    ) -> None:
        """Constructor for Root key record.

        :param ca_flag: CA flag
        :param root_certs: Root cert used to ISK/image signature
        :param used_root_cert: Used root cert number 0-3
        """
        self.ca_flag = ca_flag
        self.root_certs = [convert_to_ecc_key(cert) for cert in root_certs]
        self.used_root_cert = used_root_cert
        self.flags = self._calculate_flags()
        self.ctrk_hash_table = self._create_ctrk_hash_table()
        self.rotkth = self._calculate_rotkth()
        self.root_public_key = self._create_root_public_key()
        # the '4' means 4 bytes for flags
        self.expected_size = 4 + len(self.ctrk_hash_table) + len(self.root_public_key)

    def info(self) -> str:
        """Get info of Root key record."""
        info = ""
        info += f"Flags:           {self.flags}\n"
        info += f"CA flag:         {self.ca_flag}\n"
        info += f"Root certs:      {self.root_certs}\n"
        info += f"Used root cert:  {self.used_root_cert}\n"
        return info

    def _calculate_flags(self) -> int:
        """Function to calculate parameter flags."""
        flags = 0
        if self.ca_flag is True:
            flags |= 1 << 31
        if self.used_root_cert:
            flags |= self.used_root_cert << 8
        flags |= len(self.root_certs) << 4
        if self.root_certs[0].curve in ["NIST P-256", "p256"]:
            flags |= 1 << 0
        if self.root_certs[0].curve in ["NIST P-384", "p384"]:
            flags |= 1 << 1
        return flags

    def _create_root_public_key(self) -> bytes:
        """Function to create root public key."""
        root_key = self.root_certs[self.used_root_cert]
        root_key_data = get_ecc_key_bytes(root_key)
        return root_key_data

    def _create_ctrk_hash_table(self) -> bytes:
        """Function to create ctrk hash table."""
        ctrk_hash_table = bytes()
        if len(self.root_certs) > 1:
            for key in self.root_certs:
                data_to_hash = get_ecc_key_bytes(key)
                ctrk_hash = internal_backend.hash(
                    data=data_to_hash, algorithm=f"sha{key.pointQ.size_in_bits()}"
                )
                ctrk_hash_table += ctrk_hash
        return ctrk_hash_table

    def _calculate_rotkth(self) -> bytes:
        return internal_backend.hash(
            self.ctrk_hash_table, f"sha{self.root_certs[0].pointQ.size_in_bits()}"
        )

    def export(self) -> bytes:
        """Export Root key record as bytes array."""
        data = bytes()
        data += pack("<L", self.flags)
        data += self.ctrk_hash_table
        data += self.root_public_key
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "BaseClass":
        """Parse Root key record from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param offset: The offset of input data
        :raises NotImplementedError: This operation is not supported
        """
        raise NotImplementedError("This operation is not supported.")


class IskCertificate(BaseClass):
    """Create ISK certificate."""

    def __init__(
        self,
        constraints: int,
        isk_private_key: Union[ECC.EccKey, bytes],
        isk_cert: Union[ECC.EccKey, bytes],
        user_data: Optional[bytes] = None,
    ) -> None:
        """Constructor for ISK certificate.

        :param constraints: Certificate version
        :param isk_private_key: P-256 or P-384 ISK private key
        :param isk_cert: ISK certificate
        :param user_data: User data
        """
        self.flags = 0
        self.constraints = constraints
        self.isk_private_key = convert_to_ecc_key(isk_private_key)
        self.isk_cert = convert_to_ecc_key(isk_cert)
        self.user_data = user_data or bytes()
        self.signature = bytes()
        self.coordinate_length = self.isk_private_key.pointQ.size_in_bytes()
        self.isk_public_key_data = get_ecc_key_bytes(self.isk_cert)

        self._calculate_flags()
        self.signature_offset = calcsize("<3L") + len(self.user_data)
        self.signature_offset += 2 * self.isk_cert.pointQ.size_in_bytes()
        self.expected_size = (
            4  #  signature offset
            + 4  # constraints
            + 4  # flags
            + 2 * self.isk_cert.pointQ.size_in_bytes()  # isk public key coordinates
            + len(self.user_data)  # user data
            + 2 * self.isk_private_key.pointQ.size_in_bytes()  # isk blob signature
        )

    def info(self) -> str:
        """Get info of ISK certificate."""
        info = ""
        info += f"Constraints:           {self.constraints}\n"
        return info

    def _calculate_flags(self) -> None:
        """Function to calculate parameter flags."""
        self.flags = 0
        if self.user_data:
            self.flags |= 1 << 31
        if self.isk_cert.curve in ["NIST P-256", "p256"]:
            self.flags |= 1 << 0
        if self.isk_cert.curve in ["NIST P-384", "p384"]:
            self.flags |= 1 << 1

    def create_isk_signature(self, key_record_data: bytes) -> None:
        """Function to create ISK signature."""
        # pylint: disable=invalid-name
        data = key_record_data + pack("<3L", self.signature_offset, self.constraints, self.flags)
        data += self.isk_public_key_data + self.user_data
        self.signature = internal_backend.ecc_sign(self.isk_private_key, data)

    def export(self) -> bytes:
        """Export ISK certificate as bytes array."""
        if not self.signature:
            raise SPSDKError("Signature is not set.")
        data = bytes()
        data += pack("<3L", self.signature_offset, self.constraints, self.flags)
        # data += pack("<2L", self.signature_offset)
        # if self.isk_public_key:
        data += self.isk_public_key_data
        if self.user_data:
            data += self.user_data
        data += self.signature
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "IskCertificate":
        """Parse ISK certificate from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param offset: The offset of input data
        :raises NotImplementedError: This operation is not supported
        """
        raise NotImplementedError("This operation is not supported.")


class CertBlockV31(CertBlock):
    """Create Certificate block version 3.1."""

    MAGIC = b"chdr"

    def __init__(
        self,
        root_certs: Union[Sequence[ECC.EccKey], Sequence[bytes]],
        ca_flag: bool,
        version: str = "2.1",
        used_root_cert: int = 0,
        constraints: int = 0,
        isk_private_key: Optional[Union[ECC.EccKey, bytes]] = None,
        isk_cert: Optional[Union[ECC.EccKey, bytes]] = None,
        user_data: Optional[bytes] = None,
    ) -> None:
        """The Constructor for Certificate block."""
        # workaround for base MasterBootImage
        self.signature_size = 0
        self.header = CertificateBlockHeader(version)
        self.root_key_record = RootKeyRecord(
            ca_flag=ca_flag, used_root_cert=used_root_cert, root_certs=root_certs
        )
        self.isk_certificate = None
        if not ca_flag:
            if not isk_private_key:
                raise SPSDKError("ISK private key is not set.")
            if not isk_cert:
                raise SPSDKError("ISK certificate is not set.")
            self.isk_certificate = IskCertificate(
                constraints=constraints,
                isk_private_key=isk_private_key,
                isk_cert=isk_cert,
                user_data=user_data,
            )
        self.expected_size = self._calculate_expected_size()

    def _set_ca_flag(self, value: bool) -> None:
        self.root_key_record.ca_flag = value

    def _calculate_expected_size(self) -> int:
        expected_size = self.header.SIZE
        expected_size += self.root_key_record.expected_size
        if self.isk_certificate:
            expected_size += self.isk_certificate.expected_size
        return expected_size

    def info(self) -> str:
        """Get info of Certificate block."""
        msg = f"HEADER:\n{self.header.info()}\n"
        msg += f"ROOT KEY RECORD:\n{self.root_key_record.info()}\n"
        if self.isk_certificate:
            msg += f"ISK\n{self.isk_certificate.info()}\n"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array."""
        logger.info(f"RoTKTH: {self.root_key_record.rotkth.hex()}")
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
    def parse(cls, data: bytes, offset: int = 0) -> "BaseClass":
        """Parse Certificate block from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param offset: The offset of input data
        :raises NotImplementedError: This operation is not supported
        """
        raise NotImplementedError("This operation is not supported.")

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        sch_cfg = ValidationSchemas.get_schema_file(CRYPTO_SCH_FILE)
        return [sch_cfg["certificate_v31"], sch_cfg["certificate_root_keys"]]

    @classmethod
    def from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "CertBlockV31":
        """Creates an instance of CertBlockV31 from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of CertBlockV3.1
        :raises SPSDKError: If found gap in certificates from config file.
        """
        root_certificates_loaded: List[Optional[str]] = [
            config.get(f"rootCertificate{idx}File") for idx in range(4)
        ]
        # filter out None and empty values
        root_certificates = list(filter(None, root_certificates_loaded))
        for org, filtered in zip(root_certificates_loaded, root_certificates):
            if org != filtered:
                raise SPSDKError("There are gaps in rootCertificateXFile definition")

        main_root_cert_id = get_main_cert_index(config, default=0)
        main_root_private_key_file = config.get("mainRootCertPrivateKeyFile")
        use_isk = config.get("useIsk", False)
        isk_certificate = config.get("signingCertificateFile")
        isk_constraint = misc.value_to_int(config.get("signingCertificateConstraint", "0"))
        isk_sign_data_path = config.get("signCertData")

        root_certs = [
            misc.load_binary(cert_file, search_paths=search_paths)
            for cert_file in root_certificates
        ]
        user_data = None
        isk_private_key = None
        isk_cert = None

        if use_isk:
            assert isk_certificate and main_root_private_key_file
            if isk_sign_data_path:
                user_data = misc.load_binary(isk_sign_data_path, search_paths=search_paths)
            isk_private_key = misc.load_binary(
                main_root_private_key_file, search_paths=search_paths
            )
            isk_cert = misc.load_binary(isk_certificate, search_paths=search_paths)

        cert_block = CertBlockV31(
            root_certs=root_certs,
            used_root_cert=main_root_cert_id,
            user_data=user_data,
            constraints=isk_constraint,
            isk_cert=isk_cert,
            ca_flag=not use_isk,
            isk_private_key=isk_private_key,
        )

        return cert_block

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of certification block class members.
        """
        self.header.parse(self.header.export())
        if self.isk_certificate:
            if not isinstance(self.isk_certificate.isk_private_key, ECC.EccKey):
                raise SPSDKError("Invalid ISK certificate.")


def get_main_cert_index(config: Dict[str, Any], default: Optional[int] = None) -> int:
    """Gets main certificate index from configuration.

    :param config: Input standard configuration.
    :param default: List of paths where to search for the file, defaults to None
    :return: Instance of CertBlockV2
    :raises SPSDKError: If invalid configuration is provided.
    :raises SPSDKValueError: If certificate is not of correct type.
    """
    root_cert_id = config.get("mainRootCertId")
    cert_chain_id = config.get("mainCertChainId")
    if root_cert_id is not None and cert_chain_id is not None and root_cert_id != cert_chain_id:
        raise SPSDKError(
            "The mainRootCertId and mainRootCertId are specified and have different values."
        )
    if root_cert_id is None and cert_chain_id is None:
        if default is None:
            raise SPSDKError("Main cert ID is not specified. Use a property mainRootCertId.")
        return default
    # root_cert_id may be 0 which is falsy value, therefore 'or' cannot be used
    cert_index = root_cert_id if root_cert_id != None else cert_chain_id
    try:
        cert_index = int(cert_index)  # type: ignore[arg-type]
    except ValueError:
        raise SPSDKValueError(f"A certificate index is not a number: {cert_index}")
    return cert_index

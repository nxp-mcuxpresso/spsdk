#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling Certificate block."""

import datetime
import logging
import os
import re
from struct import calcsize, pack, unpack_from
from typing import Any, Dict, List, Optional, Sequence, Union

from Crypto.PublicKey import ECC

from spsdk import SPSDKError
from spsdk.crypto import loaders
from spsdk.crypto.loaders import load_certificate_as_bytes
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKValueError
from spsdk.utils import misc
from spsdk.utils.crypto import CRYPTO_SCH_FILE
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas

from .abstract import BaseClass
from .backend_internal import internal_backend
from .certificate import Certificate
from .common import crypto_backend, get_matching_key_id

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
        :raises SPSDKError: Unexpected size or signature of data
        """
        if cls.SIZE > len(data) - offset:
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
        ) = unpack_from(cls.FORMAT, data, offset)
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
    def expected_size(self) -> int:
        """Expected size of binary block."""
        return self.raw_size

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
            raise SPSDKError("The last chain certificate must not be CA.")
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
        :raises SPSDKError: Length of the data doesn't match Certificate Block length
        """
        header = CertBlockHeader.parse(data, offset)
        offset += CertBlockHeader.SIZE
        if (len(data) - offset) < (header.cert_table_length + (cls.RKHT_SIZE * cls.RKH_SIZE)):
            raise SPSDKError("Length of the data doesn't match Certificate Block length")
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
        main_cert_chain_id = get_main_cert_index(config, search_paths=search_paths)
        if root_certificates[main_cert_chain_id][0] is None:
            raise SPSDKError(f"A key rootCertificate{main_cert_chain_id}File must be defined")

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

    def get_config(self, output_folder: str) -> Dict[str, Any]:
        """Create configuration of Certificate V2 from object.

        :param output_folder: Output folder to store possible files.
        :return: Configuration dictionary.
        """

        def create_certificate_cfg(root_id: int, chain_id: int) -> Optional[str]:
            if len(self._cert) <= chain_id:
                return None

            file_name = f"certificate{root_id}_depth{chain_id}.der"
            misc.write_file(
                self._cert[chain_id].dump(), os.path.join(output_folder, file_name), mode="wb"
            )
            return file_name

        cfg: Dict[str, Optional[Union[str, int]]] = {}
        cfg["imageBuildNumber"] = self.header.build_number
        used_cert_id = self.rkh_index
        assert used_cert_id is not None
        cfg["mainRootCertId"] = used_cert_id

        cfg[f"rootCertificate{used_cert_id}File"] = create_certificate_cfg(used_cert_id, 0)
        for chain_ix in range(4):
            cfg[f"chainCertificate{used_cert_id}File{chain_ix}"] = create_certificate_cfg(
                used_cert_id, chain_ix + 1
            )

        return cfg


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
    try:
        return ECC.import_key(key)
    except Exception:
        pass
    # Just recreate public key from the parsed data
    coordinate_length = len(key) // 2
    coor_x = int.from_bytes(key[:coordinate_length], byteorder="big")
    coor_y = int.from_bytes(key[coordinate_length:], byteorder="big")
    curve = "secp256r1" if coordinate_length == 32 else "secp384r1"
    ecc_point = ECC.EccPoint(coor_x, coor_y, curve)
    return ECC.EccKey(curve=curve, point=ecc_point)


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
        info = f"Format version:              {self.format_version}\n"
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

    def __len__(self) -> int:
        """Length of the Certificate block header."""
        return calcsize(self.FORMAT)


class RootKeyRecord(BaseClass):
    """Create Root key record."""

    # P-256

    def __init__(
        self,
        ca_flag: bool,
        root_certs: Optional[Union[Sequence[ECC.EccKey], Sequence[bytes]]] = None,
        used_root_cert: int = 0,
    ) -> None:
        """Constructor for Root key record.

        :param ca_flag: CA flag
        :param root_certs: Root cert used to ISK/image signature
        :param used_root_cert: Used root cert number 0-3
        """
        self.ca_flag = ca_flag
        self.root_certs_input = root_certs
        self.root_certs: List[ECC.EccKey] = []
        self.used_root_cert = used_root_cert
        self.flags = 0
        self.ctrk_hash_table = b""
        self.rotkth = b""
        self.root_public_key = b""

    @property
    def number_of_certificates(self) -> int:
        """Get number of included certificates."""
        return (self.flags & 0xF0) >> 4

    @property
    def expected_size(self) -> int:
        """Get expected binary block size."""
        # the '4' means 4 bytes for flags
        return 4 + len(self.ctrk_hash_table) + len(self.root_public_key)

    def info(self) -> str:
        """Get info of Root key record."""
        cert_type = {0x1: "NIST P-256", 0x2: "NIST P-384"}[self.flags & 0xF]
        info = ""
        info += f"Flags:           {hex(self.flags)}\n"
        info += f"  - CA:          {bool(self.ca_flag)}, ISK Certificate is {'not ' if self.ca_flag else ''}mandatory\n"
        info += f"  - Used Root c.:{self.used_root_cert}\n"
        info += f"  - Number of c.:{self.number_of_certificates}\n"
        info += f"  - Cert. type:  {cert_type}\n"
        if self.root_certs:
            info += f"Root certs:      {self.root_certs}\n"
        if self.ctrk_hash_table:
            info += f"CTRK Hash table: {self.ctrk_hash_table.hex()}\n"
        if self.root_public_key:
            info += f"Root public key: {str(convert_to_ecc_key(self.root_public_key))}\n"

        return info

    def _calculate_flags(self) -> int:
        """Function to calculate parameter flags."""
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
                    data=data_to_hash, algorithm=self.get_hash_algorithm(self.flags)
                )
                ctrk_hash_table += ctrk_hash
        return ctrk_hash_table

    def _calculate_rotkth(self) -> bytes:
        return internal_backend.hash(
            data=self.ctrk_hash_table, algorithm=self.get_hash_algorithm(self.flags)
        )

    def calculate(self) -> None:
        """Calculate all internal members.

        :raises SPSDKError: The RoT certificates inputs are missing.
        """
        # pylint: disable=invalid-name
        if not self.root_certs_input:
            raise SPSDKError("Root Key Record: The root of trust certificates are not specified.")
        self.root_certs = [convert_to_ecc_key(cert) for cert in self.root_certs_input]
        self.flags = self._calculate_flags()
        self.ctrk_hash_table = self._create_ctrk_hash_table()
        self.rotkth = self._calculate_rotkth()
        self.root_public_key = self._create_root_public_key()

    def export(self) -> bytes:
        """Export Root key record as bytes array."""
        data = bytes()
        data += pack("<L", self.flags)
        data += self.ctrk_hash_table
        data += self.root_public_key
        assert len(data) == self.expected_size
        return data

    @staticmethod
    def get_hash_algorithm(flags: int) -> str:
        """Get CTRK table hash algorithm.

        :param flags: Root Key Record flags
        :return: Name of hash algorithm
        """
        return {1: "sha256", 2: "sha384"}[flags & 0xF]

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "RootKeyRecord":
        """Parse Root key record from bytes array.

        :param data:  Input data as bytes array
        :param offset: The offset of input data
        :return: Root key record object
        """
        (flags,) = unpack_from("<L", data, offset=offset)
        ca_flag = flags & 0x80000000
        used_rot_ix = (flags & 0xF00) >> 8
        number_of_hashes = (flags & 0xF0) >> 4
        rotkh_len = {0x1: 32, 0x2: 48}[flags & 0xF]
        root_key_record = RootKeyRecord(ca_flag=ca_flag, root_certs=[], used_root_cert=used_rot_ix)
        root_key_record.flags = flags
        offset += 4  # move offset just after FLAGS
        if number_of_hashes > 1:
            root_key_record.ctrk_hash_table = data[offset : offset + rotkh_len * number_of_hashes]
            offset += rotkh_len * number_of_hashes
        root_key_record._calculate_rotkth()
        root_key_record.root_public_key = data[offset : offset + rotkh_len * 2]

        return root_key_record


class IskCertificate(BaseClass):
    """Create ISK certificate."""

    def __init__(
        self,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[ECC.EccKey, bytes]] = None,
        user_data: Optional[bytes] = None,
    ) -> None:
        """Constructor for ISK certificate.

        :param constraints: Certificate version
        :param signature_provider: ISK Signature Provider
        :param isk_cert: ISK certificate
        :param user_data: User data
        """
        self.flags = 0
        self.constraints = constraints
        self.signature_provider = signature_provider
        self.isk_cert = convert_to_ecc_key(isk_cert) if isk_cert else None
        self.user_data = user_data or bytes()
        self.signature = bytes()
        self.coordinate_length = (
            self.signature_provider.signature_length // 2 if self.signature_provider else 0
        )
        self.isk_public_key_data = get_ecc_key_bytes(self.isk_cert) if self.isk_cert else bytes()

        self._calculate_flags()

    @property
    def signature_offset(self) -> int:
        """Signature offset inside the ISK Certificate."""
        signature_offset = calcsize("<3L") + len(self.user_data)
        if self.isk_cert:
            signature_offset += 2 * self.isk_cert.pointQ.size_in_bytes()

        return signature_offset

    @property
    def expected_size(self) -> int:
        """Binary block expected size."""
        sign_len = len(self.signature) or (
            self.signature_provider.signature_length if self.signature_provider else 0
        )
        pub_key_len = (
            self.isk_cert.pointQ.size_in_bytes() * 2
            if self.isk_cert
            else len(self.isk_public_key_data)
        )

        return (
            4  #  signature offset
            + 4  # constraints
            + 4  # flags
            + pub_key_len  # isk public key coordinates
            + len(self.user_data)  # user data
            + sign_len  # isk blob signature
        )

    def info(self) -> str:
        """Get info of ISK certificate."""
        isk_type = {0x1: "NIST P-256", 0x2: "NIST P-384"}[self.flags & 0xF]
        info = ""
        info += f"Constraints:     {self.constraints}\n"
        if self.user_data:
            info += f"User data:       {self.user_data.hex()}\n"
        else:
            info += "User data:       Not included\n"
        info += f"Type:            {isk_type}\n"
        info += f"Public Key:      {str(self.isk_cert)}\n"
        return info

    def _calculate_flags(self) -> None:
        """Function to calculate parameter flags."""
        self.flags = 0
        if self.user_data:
            self.flags |= 1 << 31
        assert self.isk_cert
        if self.isk_cert.curve in ["NIST P-256", "p256", "secp256r1"]:
            self.flags |= 1 << 0
        if self.isk_cert.curve in ["NIST P-384", "p384", "secp384r1"]:
            self.flags |= 1 << 1

    def create_isk_signature(self, key_record_data: bytes, force: bool = False) -> None:
        """Function to create ISK signature.

        :raises SPSDKError: Signature provider is not specified.
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not self.signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")
        data = key_record_data + pack("<3L", self.signature_offset, self.constraints, self.flags)
        data += self.isk_public_key_data + self.user_data
        self.signature = self.signature_provider.sign(data)

    def export(self) -> bytes:
        """Export ISK certificate as bytes array."""
        if not self.signature:
            raise SPSDKError("Signature is not set.")
        data = pack("<3L", self.signature_offset, self.constraints, self.flags)
        data += self.isk_public_key_data
        if self.user_data:
            data += self.user_data
        data += self.signature

        assert len(data) == self.expected_size
        return data

    @classmethod
    def parse(  # type: ignore
        cls, data: bytes, signature_size: int, offset: int = 0
    ) -> "IskCertificate":
        """Parse ISK certificate from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param signature_size: The signature size of ISK block
        :param offset: The offset of input data
        :raises NotImplementedError: This operation is not supported
        """
        (signature_offset, constraints, isk_flags) = unpack_from("<3L", data, offset)
        signature_offset += offset
        user_data_flag = bool(isk_flags & 0x80000000)
        isk_pub_key_length = {0x1: 32, 0x2: 48}[isk_flags & 0xF]
        offset += 3 * 4
        isk_pub_key_bytes = data[offset : offset + isk_pub_key_length * 2]
        offset += isk_pub_key_length * 2
        user_data = data[offset:signature_offset] if user_data_flag else None
        signature = data[signature_offset : signature_offset + signature_size]

        certificate = IskCertificate(
            constraints=constraints, isk_cert=isk_pub_key_bytes, user_data=user_data
        )
        certificate.signature = signature
        return certificate


class CertBlockV31(CertBlock):
    """Create Certificate block version 3.1."""

    MAGIC = b"chdr"
    FORMAT_VERSION = "2.1"

    def __init__(
        self,
        root_certs: Optional[Union[Sequence[ECC.EccKey], Sequence[bytes]]] = None,
        ca_flag: bool = False,
        version: str = "2.1",
        used_root_cert: int = 0,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[ECC.EccKey, bytes]] = None,
        user_data: Optional[bytes] = None,
    ) -> None:
        """The Constructor for Certificate block."""
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
            )

    def _set_ca_flag(self, value: bool) -> None:
        self.root_key_record.ca_flag = value

    def calculate(self) -> None:
        """Calculate all internal members."""
        self.root_key_record.calculate()

    @property
    def signature_size(self) -> int:
        """Size of the signature in bytes."""
        # signature size is same as public key data
        if self.isk_certificate:
            return len(self.isk_certificate.isk_public_key_data)

        return len(self.root_key_record.root_public_key)

    @property
    def expected_size(self) -> int:
        """Expected size of binary block."""
        expected_size = self.header.SIZE
        expected_size += self.root_key_record.expected_size
        if self.isk_certificate:
            expected_size += self.isk_certificate.expected_size
        return expected_size

    @property
    def rkht(self) -> bytes:
        """32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return self.root_key_record.rotkth

    def info(self) -> str:
        """Get info of Certificate block."""
        msg = f"HEADER:\n{self.header.info()}\n"
        msg += f"ROOT KEY RECORD:\n{self.root_key_record.info()}\n"
        if self.isk_certificate:
            msg += f"ISK Certificate:\n{self.isk_certificate.info()}\n"
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
    def parse(cls, data: bytes, offset: int = 0) -> "CertBlockV31":
        """Parse Certificate block from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param offset: The offset of input data
        :raises SPSDKError: Magic do not match
        """
        # CertificateBlockHeader
        cert_header = CertificateBlockHeader.parse(data, offset)
        offset += len(cert_header)
        # RootKeyRecord
        root_key_record = RootKeyRecord.parse(data, offset)
        offset += root_key_record.expected_size
        # IskCertificate
        isk_certificate = None
        if root_key_record.ca_flag == 0:
            isk_certificate = IskCertificate.parse(
                data, len(root_key_record.root_public_key), offset
            )
        # Certification Block V3.1
        cert_block = CertBlockV31()
        cert_block.header = cert_header
        cert_block.root_key_record = root_key_record
        cert_block.isk_certificate = isk_certificate
        return cert_block

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
        binary_block = config.get("binaryCertificateBlock")
        if binary_block:
            return CertBlockV31.parse(misc.load_binary(binary_block, search_paths))

        root_certificates = find_root_certificates(config)
        main_root_cert_id = get_main_cert_index(config, search_paths=search_paths)

        try:
            root_certificates[main_root_cert_id]
        except IndexError as e:
            raise SPSDKError(
                f"Main root certificate with id {main_root_cert_id} does not exist"
            ) from e

        main_root_private_key_file = config.get("mainRootCertPrivateKeyFile")
        signature_provider = config.get("iskSignProvider")
        use_isk = config.get("useIsk", False)
        isk_certificate = config.get("signingCertificateFile")
        isk_constraint = misc.value_to_int(config.get("signingCertificateConstraint", "0"))
        isk_sign_data_path = config.get("signCertData")

        root_certs = [
            misc.load_binary(cert_file, search_paths=search_paths)
            for cert_file in root_certificates
        ]
        user_data = None
        signature_provider = None
        isk_cert = None

        if use_isk:
            assert isk_certificate and (main_root_private_key_file or signature_provider)
            if isk_sign_data_path:
                user_data = misc.load_binary(isk_sign_data_path, search_paths=search_paths)
            signature_provider = get_signature_provider(
                signature_provider,
                main_root_private_key_file,
                search_paths=search_paths,
                mode="deterministic-rfc6979",
            )
            isk_cert = misc.load_binary(isk_certificate, search_paths=search_paths)

        cert_block = CertBlockV31(
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
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of certification block class members.
        """
        self.header.parse(self.header.export())
        if self.isk_certificate:
            if not isinstance(self.isk_certificate.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    @staticmethod
    def generate_config_template() -> str:
        """Generate configuration for certification block v31."""
        val_schemas = CertBlockV31.get_validation_schemas()
        val_schemas.append(ValidationSchemas.get_schema_file(CRYPTO_SCH_FILE)["cert_block_output"])
        yaml_data = CommentedConfig(
            "Certification Block V31 template",
            val_schemas,
        ).export_to_yaml()
        return yaml_data

    def get_config(self, output_folder: str) -> Dict[str, Any]:
        """Create configuration dictionary of the Certification block Image.

        :param output_folder: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg: Dict[str, Optional[Union[str, int]]] = {}
        cfg["mainRootCertPrivateKeyFile"] = "N/A"
        cfg["signingCertificatePrivateKeyFile"] = "N/A"
        for i in range(self.root_key_record.number_of_certificates):
            key: Optional[ECC.EccKey] = None
            if i == self.root_key_record.used_root_cert:
                key = convert_to_ecc_key(self.root_key_record.root_public_key)
            else:
                if i < len(self.root_key_record.root_certs) and self.root_key_record.root_certs[i]:
                    key = convert_to_ecc_key(self.root_key_record.root_certs[i])
            if key:
                key_file_name = os.path.join(output_folder, f"rootCertificate{i}File.pub")
                misc.write_file(key.export_key(format="PEM"), key_file_name)
                cfg[f"rootCertificate{i}File"] = f"rootCertificate{i}File.pub"
            else:
                cfg[
                    f"rootCertificate{i}File"
                ] = "The public key is not possible reconstruct from the key hash"

        cfg["mainRootCertId"] = self.root_key_record.used_root_cert
        if self.isk_certificate and self.root_key_record.ca_flag == 0:
            cfg["useIsk"] = True
            assert self.isk_certificate.isk_cert
            key = self.isk_certificate.isk_cert
            key_file_name = os.path.join(output_folder, "signingCertificateFile.pub")
            misc.write_file(key.export_key(format="PEM"), key_file_name)
            cfg["signingCertificateFile"] = "signingCertificateFile.pub"
            cfg["signingCertificateConstraint"] = self.isk_certificate.constraints
            if self.isk_certificate.user_data:
                key_file_name = os.path.join(output_folder, "isk_user_data.bin")
                misc.write_file(self.isk_certificate.user_data, key_file_name, mode="wb")
                cfg["signCertData"] = "isk_user_data.bin"

        else:
            cfg["useIsk"] = False

        return cfg

    def create_config(self, data_path: str) -> str:
        """Create configuration of the Certification block Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration in string.
        """
        cfg = self.get_config(data_path)
        val_schemas = CertBlockV31.get_validation_schemas()

        yaml_data = CommentedConfig(
            main_title=(
                "Certification block v3.1 recreated configuration from :"
                f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
            ),
            schemas=val_schemas,
            values=cfg,
        ).export_to_yaml()
        return yaml_data


def get_main_cert_index(config: Dict[str, Any], search_paths: Optional[List[str]] = None) -> int:
    """Gets main certificate index from configuration.

    :param config: Input standard configuration.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: Instance of CertBlockV2
    :raises SPSDKError: If invalid configuration is provided.
    :raises SPSDKError: If correct certificate could not be identified.
    :raises SPSDKValueError: If certificate is not of correct type.
    """
    root_cert_id = config.get("mainRootCertId")
    cert_chain_id = config.get("mainCertChainId")
    if root_cert_id is not None and cert_chain_id is not None and root_cert_id != cert_chain_id:
        raise SPSDKError(
            "The mainRootCertId and mainRootCertId are specified and have different values."
        )
    found_cert_id = find_main_cert_index(config=config, search_paths=search_paths)
    if root_cert_id is None and cert_chain_id is None:
        if found_cert_id is not None:
            return found_cert_id
        else:
            raise SPSDKError("Certificate could not be found")
    # root_cert_id may be 0 which is falsy value, therefore 'or' cannot be used
    cert_id = root_cert_id if root_cert_id is not None else cert_chain_id
    try:
        cert_id = int(cert_id)  # type: ignore[arg-type]
    except ValueError as exc:
        raise SPSDKValueError(f"A certificate index is not a number: {cert_id}") from exc
    if found_cert_id is not None and found_cert_id != cert_id:
        logger.warning("Defined certificate does not match the private key.")
    return cert_id


def find_main_cert_index(
    config: Dict[str, Any], search_paths: Optional[List[str]] = None
) -> Optional[int]:
    """Go through all certificates and find the index matching to private key.

    :param config: Configuration to be searched.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: List of root certificates.
    """
    try:
        signature_provider = get_signature_provider(
            sp_cfg=config.get("signProvider"),
            local_file_key=config.get("mainCertPrivateKeyFile"),
            search_paths=search_paths,
        )
    except SPSDKError as exc:
        logger.debug(f"A signature provider could not be created: {exc}")
        return None

    root_certificates = find_root_certificates(config)
    public_keys = []
    for root_crt_file in root_certificates:
        try:
            public_key = loaders.extract_public_key(root_crt_file, search_paths=search_paths)
            public_keys.append(public_key)
        except SPSDKError:
            continue
    try:
        idx = get_matching_key_id(public_keys, signature_provider)
        return idx
    except ValueError:
        return None


def find_root_certificates(config: Dict[str, Any]) -> List[str]:
    """Find all root certificates in configuration.

    :param config: Configuration to be searched.
    :raises SPSDKError: If invalid configuration is provided.
    :return: List of root certificates.
    """
    root_certificates_loaded: List[Optional[str]] = [
        config.get(f"rootCertificate{idx}File") for idx in range(4)
    ]
    # filter out None and empty values
    root_certificates = list(filter(None, root_certificates_loaded))
    for org, filtered in zip(root_certificates_loaded, root_certificates):
        if org != filtered:
            raise SPSDKError("There are gaps in rootCertificateXFile definition")
    return root_certificates

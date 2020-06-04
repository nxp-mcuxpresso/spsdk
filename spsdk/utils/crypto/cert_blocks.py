#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling Certificate block."""

import re
from struct import pack, unpack_from, calcsize
from typing import List, Optional, Union

from spsdk.utils import misc
from .abstract import BaseClass
from .backend_internal import internal_backend
from .certificate import Certificate
from .common import crypto_backend


########################################################################################################################
# Certificate Block Header Class
########################################################################################################################
class CertBlockHeader(BaseClass):
    """Certificate block header."""

    FORMAT = '<4s2H6I'
    SIZE = calcsize(FORMAT)
    SIGNATURE = b'cert'

    def __init__(self, version: str = '1.0', flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: Version of the certificate in format n.n
        :param flags: Flags for the Certificate Header
        :param build_number: of the certificate
        """
        assert re.match(r'[0-9]+\.[0-9]+', version)  # check format of the version: N.N
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
        major_version, minor_version = [int(v) for v in self.version.split('.')]
        return pack(self.FORMAT,
                    self.SIGNATURE,
                    major_version,
                    minor_version,
                    self.SIZE,
                    self.flags,
                    self.build_number,
                    self.image_length,
                    self.cert_count,
                    self.cert_table_length)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CertBlockHeader':
        """Deserialize object from bytes array.

        :param data: Input data as bytes
        :param offset: The offset of input data (default: 0)
        :return: Certificate Header instance
        :raises Exception: Unexpected size or signature of data
        """
        if cls.SIZE > len(data) - offset:
            raise Exception()
        (signature, major_version, minor_version, length, flags, build_number, image_length, cert_count,
         cert_table_length) = unpack_from(cls.FORMAT, data, offset)
        if signature != cls.SIGNATURE:
            raise Exception()
        if length != cls.SIZE:
            raise Exception()
        obj = cls(version=f'{major_version}.{minor_version}', flags=flags, build_number=build_number)
        obj.image_length = image_length
        obj.cert_count = cert_count
        obj.cert_table_length = cert_table_length
        return obj


########################################################################################################################
# Certificate Block Class
########################################################################################################################
class CertBlockV2(BaseClass):
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
        assert len(data) == self.RKH_SIZE * self.RKHT_SIZE
        return internal_backend.hash(data)

    @property
    def rkht_fuses(self) -> List[int]:
        """List of RKHT fuses, ordered from highest bit to lowest.

        Note: Returned values are in format that should be passed for blhost
        """
        result = list()
        rkht = self.rkht
        while rkht:
            fuse = int.from_bytes(rkht[:4], byteorder='little')
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
        return len(self.certificates[0].signature)  # The certificate is self signed, return size of its signature

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
        """
        assert value > 0
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
        """
        assert value > 0
        self._header.image_length = value

    def __init__(self, version: str = '1.0', flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: of the certificate in format n.n
        :param flags: Flags for the Certificate Block Header
        :param build_number: of the certificate
        """
        self._header = CertBlockHeader(version, flags, build_number)
        self._root_key_hashes = [b'\x00' * self.RKH_SIZE for _ in range(self.RKHT_SIZE)]
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
        """
        if isinstance(key_hash, Certificate):
            key_hash = key_hash.public_key_hash
        assert isinstance(key_hash, (bytes, bytearray))
        assert 0 <= index < self.RKHT_SIZE
        assert len(key_hash) == self.RKH_SIZE
        self._root_key_hashes[index] = bytes(key_hash)

    def add_certificate(self, cert: Union[bytes, Certificate]) -> None:
        """Add certificate.

        First call adds root certificate. Additional calls add chain certificates.

        :param cert: The certificate itself in DER format
        :raise ValueError: if certificate cannot be added
        """
        if isinstance(cert, bytes):
            cert_obj = Certificate(cert)
        elif isinstance(cert, Certificate):
            cert_obj = cert
        else:
            raise ValueError('Invalid parameter type (cert)')
        if cert_obj.version != 'v3':
            raise ValueError('Expected certificate v3 but received: ' + cert_obj.version)
        if self._cert:  # chain certificate?
            last_cert = self._cert[-1]  # verify that it is signed by parent key
            if not cert_obj.verify(last_cert.public_key_modulus, last_cert.public_key_exponent):
                raise ValueError('Chain certificate cannot be verified using parent public key')
        else:  # root certificate
            if cert_obj.self_signed == "no":
                raise ValueError("Root certificate must be self-signed")
        self._cert.append(cert_obj)
        self._header.cert_count += 1
        self._header.cert_table_length += cert_obj.raw_size + 4

    def info(self) -> str:
        """Text info about certificate block."""
        nfo = self.header.info()
        nfo += " Public Root Keys Hash e.g. RKH (SHA256):\n"
        rkh_index = self.rkh_index
        for index, root_key in enumerate(self._root_key_hashes):
            nfo += f"  {index}) {root_key.hex().upper()} {'<- Used' if index == rkh_index else ''}\n"
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
        return crypto_backend().rsa_verify(cert.public_key_modulus, cert.public_key_exponent, signature, data)

    def verify_private_key(self, private_key_pem_data: bytes) -> bool:
        """Verify that given private key matches the public certificate.

        :param private_key_pem_data: to be tested; decrypted binary data in PEM format
        :return: True if yes; False otherwise
        """
        signature = crypto_backend().rsa_sign(private_key_pem_data, bytes())
        cert = self.certificates[-1]  # last certificate
        return crypto_backend().rsa_verify(cert.public_key_modulus, cert.public_key_exponent, signature, bytes())

    def export(self) -> bytes:
        """Serialize Certificate Block V2 object."""
        # At least one certificate must be used
        if not self._cert:
            raise ValueError("At least one certificate must be used")
        # The hast of root key certificate must be in RKHT
        if self.rkh_index is None:
            raise ValueError("The HASH of used Root Key must be in RKHT")
        # CA: Using a single certificate is allowed. In this case, the sole certificate must be self-signed and must not
        # be a CA. If multiple certificates are used, the root must be self-signed and all but the last must be CAs.
        if self._cert[-1].ca:
            raise ValueError("The last chain certificate must not be CA")
        if not all(cert.ca for cert in self._cert[:-1]):
            raise ValueError("All certificates except the last chain certificate must be CA")
        # Export
        data = self.header.export()
        for cert in self._cert:
            data += pack('<I', cert.raw_size)
            data += cert.export()
        for key in self._root_key_hashes:
            data += bytes(key)
        data = misc.align_block(data, self.alignment)
        assert len(data) == self.raw_size
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CertBlockV2':
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
            cert_len = unpack_from('<I', data, offset)[0]
            offset += 4
            cert_obj = Certificate(data[offset: offset + cert_len])
            obj.add_certificate(cert_obj)
            offset += cert_len
        for i in range(cls.RKHT_SIZE):
            obj.set_root_key_hash(i, data[offset: offset + cls.RKH_SIZE])
            offset += cls.RKH_SIZE
        return obj

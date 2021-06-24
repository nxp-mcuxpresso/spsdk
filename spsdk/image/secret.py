#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands and responses used by SDP module."""
import math
from hashlib import sha256
from struct import pack, unpack_from, unpack
from typing import List, Optional, Union, Any, Iterator

from cryptography.x509 import Certificate, KeyUsage, ExtensionNotFound
from cryptography.hazmat.primitives.asymmetric import rsa

from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import DebugInfo
from .header import SegTag, Header
from .misc import modulus_fmt, hexdump_fmt
from .. import SPSDKError


class EnumAlgorithm(Enum):
    """Algorithm types."""

    ANY = (0x00, "Algorithm type ANY")
    HASH = (0x01, "Hash algorithm type")
    SIG = (0x02, "Signature algorithm type")
    F = (0x03, "Finite field arithmetic")
    EC = (0x04, "Elliptic curve arithmetic")
    CIPHER = (0x05, "Cipher algorithm type")
    MODE = (0x06, "Cipher/hash modes")
    WRAP = (0x07, "Key wrap algorithm type")
    # Hash algorithms
    SHA1 = (0x11, "SHA-1 algorithm ID")
    SHA256 = (0x17, "SHA-256 algorithm ID")
    SHA512 = (0x1B, "SHA-512 algorithm ID")
    # Signature algorithms
    PKCS1 = (0x21, "PKCS#1 RSA signature algorithm")
    # Cipher algorithms
    AES = (0x55, "AES algorithm ID")
    # Cipher or hash modes
    CCM = (0x66, "Counter with CBC-MAC")
    # Key wrap algorithms
    BLOB = (0x71, "SHW-specific key wrap")


class EnumSRK(Enum):
    """Entry type in the System Root Key Table."""

    KEY_PUBLIC = (0xE1, "Public key type: data present")
    KEY_HASH = (0xEE, "Any key: hash only")


class BaseClass:
    """Base SPSDK class."""

    def __init__(self, tag: SegTag, version: int = 0x40):
        """Constructor.

        :param tag: section TAG
        :param version: format version
        """
        self._header = Header(tag=tag, param=version)

    @property
    def version(self) -> int:
        """Format version."""
        return self._header.param

    @property
    def version_major(self) -> int:
        """Major format version."""
        return self.version >> 4

    @property
    def version_minor(self) -> int:
        """Minor format version."""
        return self.version & 0xF

    @property
    def size(self) -> int:
        """Size of the exported binary data."""
        raise NotImplementedError()

    def info(self) -> str:
        """Description about the instance."""
        raise NotImplementedError()

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Serialization to binary form.

        :param dbg_info: optional instance allowing to debug exported data; provides commented export
        :return: binary representation of the instance
        """
        raise NotImplementedError()


class SecretKeyBlob:
    """Secret Key Blob."""

    @property
    def blob(self) -> bytes:
        """Data of Secret Key Blob."""
        return self._data

    @blob.setter
    def blob(self, value: Union[bytes, bytearray]) -> None:
        assert isinstance(value, (bytes, bytearray))
        self._data = value

    @property
    def size(self) -> int:
        """Size of Secret Key Blob."""
        return len(self._data) + 4

    def __init__(self, mode: int, algorithm: int, flag: int) -> None:
        """Initialize Secret Key Blob."""
        self.mode = mode
        self.algorithm = algorithm
        self.flag = flag
        self._data = bytearray()

    def __repr__(self) -> str:
        return "SecKeyBlob <Mode: {}, Algo: {}, Flag: 0x{:02X}, Size: {}>".format(
            self.mode, self.algorithm, self.flag, len(self._data)
        )

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, SecretKeyBlob) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def info(self) -> str:
        """String representation of the Secret Key Blob."""
        msg = "-" * 60 + "\n"
        msg += "SecKeyBlob\n"
        msg += "-" * 60 + "\n"
        msg += "Mode:      {}\n".format(self.mode)
        msg += "Algorithm: {}\n".format(self.algorithm)
        msg += "Flag:      0x{:02X}\n".format(self.flag)
        msg += "Size:      {} Bytes\n".format(len(self._data))
        return msg

    def export(self) -> bytes:
        """Export of Secret Key Blob."""
        raw_data = pack("4B", self.mode, self.algorithm, self.size, self.flag)
        raw_data += bytes(self._data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecretKeyBlob":
        """Parse of Secret Key Blob."""
        (mode, alg, size, flg) = unpack_from("4B", data, offset)
        offset += 4
        obj = cls(mode, alg, flg)
        obj.blob = data[offset : offset + size]
        return obj


class CertificateImg(BaseClass):
    """Certificate structure for bootable image."""

    @property
    def size(self) -> int:
        """Size of Certificate structure for bootable image."""
        return Header.SIZE + len(self._data)

    def __init__(self, version: int = 0x40, data: bytes = None) -> None:
        """Initialize the certificate structure for bootable image."""
        super().__init__(SegTag.CRT, version)
        self._data = bytearray() if data is None else bytearray(data)

    def __repr__(self) -> str:
        return (
            f"Certificate <Ver: {self.version_major}.{self.version_minor}, Size: {len(self._data)}>"
        )

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, CertificateImg) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        return self._data.__iter__()

    def info(self) -> str:
        """String representation of the CertificateImg."""
        msg = "-" * 60 + "\n"
        msg += "Certificate (Ver: {:X}.{:X}, Size: {})\n".format(
            self.version >> 4, self.version & 0xF, len(self._data)
        )
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export."""
        self._header.length = self.size
        raw_data = self._header.export()
        dbg_info.append_binary_section("header", raw_data)
        raw_data += self._data
        dbg_info.append_binary_section("data", self._data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CertificateImg":
        """Parse."""
        header = Header.parse(data, offset, SegTag.CRT)
        offset += Header.SIZE
        return cls(header.param, data[offset : offset + header.length - Header.SIZE])


class Signature(BaseClass):
    """Class representing a signature."""

    @property
    def size(self) -> int:
        """Size of a signature."""
        return Header.SIZE + len(self._data)

    def __init__(self, version: int = 0x40, data: bytes = None) -> None:
        """Initialize the signature."""
        super().__init__(tag=SegTag.SIG, version=version)
        self._data = bytearray() if data is None else bytearray(data)

    def __repr__(self) -> str:
        return f"Signature <Ver: {self.version >> 4}.{self.version & 0xF}, Size: {len(self._data)}>"

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, Signature) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        return self._data.__iter__()

    def info(self) -> str:
        """String representation of the signature."""
        msg = "-" * 60 + "\n"
        msg += "Signature (Ver: {:X}.{:X}, Size: {})\n".format(
            self.version >> 4, self.version & 0xF, len(self._data)
        )
        msg += "-" * 60 + "\n"
        return msg

    @property
    def data(self) -> bytes:
        """Signature data."""
        return bytes(self._data)

    @data.setter
    def data(self, value: Union[bytes, bytearray]) -> None:
        """Signature data."""
        self._data = bytearray(value)

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export."""
        self._header.length = self.size
        raw_data = self._header.export()
        dbg_info.append_binary_section("header", raw_data)
        raw_data += self.data
        dbg_info.append_binary_section("data", self.data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "Signature":
        """Parse."""
        header = Header.parse(data, offset, SegTag.SIG)
        offset += Header.SIZE
        return cls(header.param, data[offset : offset + header.length - Header.SIZE])


class MAC(BaseClass):
    """Structure that holds initial parameter for AES encryption/description.

    - nonce - initialization vector for AEAD AES128 decryption
    - mac - message authentication code to verify the decryption was successful
    """

    # AES block size in bytes; This also match size of the MAC and
    AES128_BLK_LEN = 16

    def __init__(
        self,
        version: int = 0x40,
        nonce_len: int = 0,
        mac_len: int = AES128_BLK_LEN,
        data: Optional[bytes] = None,
    ):
        """Constructor.

        :param version: format version, should be 0x4x
        :param nonce_len: number of NONCE bytes
        :param mac_len: number of MAC bytes
        :param data: nonce and mac bytes joined together
        """
        super().__init__(tag=SegTag.MAC, version=version)
        self.nonce_len = nonce_len
        self.mac_len = mac_len
        self._data: bytes = bytes() if data is None else bytes(data)
        if data:
            self._validate_data()

    @property
    def size(self) -> int:
        """Size of binary representation in bytes."""
        return Header.SIZE + 4 + self.nonce_len + self.mac_len

    def _validate_data(self) -> None:
        """Validates the data.

        :raise ValueError: if data length does not match with parameters
        """
        if len(self.data) != self.nonce_len + self.mac_len:
            raise ValueError(
                f"length of data ({len(self.data)}) does not match with "
                f"nonce_bytes({self.nonce_len})+mac_bytes({self.mac_len})"
            )

    @property
    def data(self) -> bytes:
        """NONCE and MAC bytes joined together."""
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Setter.

        :param value: NONCE and MAC bytes joined together
        """
        self._data = value
        self._validate_data()

    @property
    def nonce(self) -> bytes:
        """NONCE bytes for the encryption/decryption."""
        self._validate_data()
        return self._data[0 : self.nonce_len]

    @property
    def mac(self) -> bytes:
        """MAC bytes for the encryption/decryption."""
        self._validate_data()
        return self._data[self.nonce_len : self.nonce_len + self.mac_len]

    def update_aead_encryption_params(self, nonce: bytes, mac: bytes) -> None:
        """Update AEAD encryption parameters for encrypted image.

        :param nonce: initialization vector, length depends on image size,
        :param mac: message authentication code used to authenticate uncrypted data, 16 bytes
        """
        assert len(mac) == MAC.AES128_BLK_LEN
        assert 11 <= len(nonce) <= 13
        self.nonce_len = len(nonce)
        assert self.mac_len == MAC.AES128_BLK_LEN
        self.data = nonce + mac

    def __repr__(self) -> str:
        return "MAC <Ver: {:X}.{:X}, Nonce: {}, MAC: {}>".format(
            self.version_major, self.version_minor, self.nonce_len, self.mac_len
        )

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, MAC) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def __len__(self) -> int:
        return len(self._data)

    def info(self) -> str:
        """Text info about the instance."""
        msg = "-" * 60 + "\n"
        msg += "MAC (Version: {:X}.{:X})\n".format(self.version >> 4, self.version & 0xF)
        msg += "-" * 60 + "\n"
        msg += "Nonce Len: {} Bytes\n".format(self.nonce_len)
        msg += "MAC Len:   {} Bytes\n".format(self.mac_len)
        msg += f"[{self._data.hex()}]\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export instance into binary form (serialization).

        :param dbg_info: optional instance providing debug info about exported content
        :return: binary form
        """
        self._validate_data()
        self._header.length = self.size
        raw_data = self._header.export()
        dbg_info.append_binary_data("header", raw_data)
        raw_data += pack(">4B", 0, self.nonce_len, 0, self.mac_len)
        dbg_info.append("nonce=" + self.nonce.hex())
        dbg_info.append("mac=" + self.mac.hex())
        raw_data += self.data
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "MAC":
        """Parse binary data and creates the instance (deserialization).

        :param data: being parsed
        :param offset: to start parse the data
        :return: the instance
        """
        header = Header.parse(data, offset, SegTag.MAC)
        offset += Header.SIZE
        (_, nonce_bytes, _, mac_bytes) = unpack_from(">4B", data, offset)
        offset += 4
        return cls(
            header.param,
            nonce_bytes,
            mac_bytes,
            data[offset : offset + header.length - (Header.SIZE + 4)],
        )


class SRKException(SPSDKError):
    """SRK table processing exceptions."""


class NotImplementedSRKPublicKeyType(SRKException):
    """This SRK public key algorithm is not yet implemented."""


class NotImplementedSRKCertificate(SRKException):
    """This SRK public key algorithm is not yet implemented."""


class NotImplementedSRKItem(SRKException):
    """This type of SRK table item is not implemented."""


class SrkItem:
    """Base class for items in the SRK Table, see `SrkTable` class.

    We do not inherit from BaseClass because our header parameter
    is an algorithm identifier, not a version number.
    """

    @property
    def size(self) -> int:
        """Size of the exported binary data."""
        raise NotImplementedError()

    def info(self) -> str:
        """Description about the instance."""
        raise NotImplementedError()

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data."""
        raise NotImplementedError()

    def hashed_entry(self) -> "SrkItem":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        raise NotImplementedError()

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Serialization to binary form.

        :param dbg_info: optional instance allowing to debug exported data; provides commented export
        :return: binary representation of the instance
        """
        raise NotImplementedError()

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SrkItem":
        """Pick up the right implementation of an SRK item.

        :param data: The bytes array of SRK segment
        :param offset: The offset of input data
        :return: SrkItem: One of the SrkItem subclasses
        :raises NotImplementedSRKPublicKeyType: Unsupported key algorithm
        :raises NotImplementedSRKItem: Unsupported tag
        """
        header = Header.parse(data, offset)
        if header.tag == EnumSRK.KEY_PUBLIC:
            if header.param == EnumAlgorithm.PKCS1:
                return SrkItemRSA.parse(data, offset)
            raise NotImplementedSRKPublicKeyType(f"{header.param}")
        if header.tag == EnumSRK.KEY_HASH:
            return SrkItemHash.parse(data, offset)
        raise NotImplementedSRKItem(f"TAG = {header.tag}, PARAM = {header.param}")

    @classmethod
    def from_certificate(cls, cert: Certificate) -> "SrkItem":
        """Pick up the right implementation of an SRK item."""
        assert isinstance(cert, Certificate)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return SrkItemRSA.from_certificate(cert)
        raise NotImplementedSRKCertificate()


class SrkItemHash(SrkItem):
    """Hashed stub of some public key.

    This is a valid entry of the SRK table, it represents
    some public key of unknown algorithm.
    Can only provide its hashed value of itself.
    """

    @property
    def algorithm(self) -> int:
        """Hashing algorithm used."""
        return self._header.param

    @property
    def size(self) -> int:
        """Size of an SRK item."""
        return self._header.length

    def __init__(self, algorithm: int, digest: bytes) -> None:
        """Build the stub entry with public key hash only.

        :param algorithm: int: Hash algorithm, only SHA256 now
        :param digest: bytes: Hash digest value
        """
        assert algorithm == EnumAlgorithm.SHA256
        self._header = Header(tag=EnumSRK.KEY_HASH, param=algorithm)
        self.digest = digest
        self._header.length += len(digest)

    def __repr__(self) -> str:
        return "SRK Hash <Algorithm: {}>".format(EnumAlgorithm[self._header.param])  # type: ignore

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, SrkItemHash) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def info(self) -> str:
        """String representation of SrkItemHash."""
        msg = str()
        msg += "Hash algorithm: {}\n".format(EnumAlgorithm[self._header.param])  # type: ignore
        msg += "Hash value:\n"
        msg += hexdump_fmt(self.digest)
        return msg

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data."""
        return self.digest

    def hashed_entry(self) -> "SrkItemHash":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        return self

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export."""
        data = self._header.export()
        data += self.digest
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SrkItemHash":
        """Parse SRK table item data.

        :param data: The bytes array of SRK segment
        :param offset: The offset of input data
        :return: SrkItemHash: SrkItemHash object
        :raises NotImplementedSRKItem: Unknown tag
        """
        header = Header.parse(data, offset, EnumSRK.KEY_HASH)
        rest = data[offset + header.SIZE :]
        if header.param == EnumAlgorithm.SHA256:
            digest = rest[: sha256().digest_size]
            return cls(EnumAlgorithm.SHA256, digest)
        raise NotImplementedSRKItem(f"TAG = {header.tag}, PARAM = {header.param}")


class SrkItemRSA(SrkItem):
    """RSA public key in SRK Table, see `SrkTable` class."""

    @property
    def algorithm(self) -> int:
        """Algorithm."""
        return self._header.param

    @property
    def size(self) -> int:
        """Size of an SRK item."""
        return self._header.length

    @property
    def flag(self) -> int:
        """Flag."""
        return self._flag

    @flag.setter
    def flag(self, value: int) -> None:
        assert value in (0, 0x80)
        self._flag = value

    @property
    def key_length(self) -> int:
        """Key length of Item in SRK Table."""
        return len(self.modulus) * 8

    def __init__(self, modulus: bytes, exponent: bytes, flag: int = 0) -> None:
        """Initialize the srk table item."""
        assert isinstance(modulus, bytes)
        assert isinstance(exponent, bytes)
        self._header = Header(tag=EnumSRK.KEY_PUBLIC, param=EnumAlgorithm.PKCS1)
        self.flag = flag
        self.modulus = modulus
        self.exponent = exponent
        self._header.length += 8 + len(self.modulus) + len(self.exponent)

    def __repr__(self) -> str:
        return "SRK <Algorithm: {}, CA: {}>".format(
            EnumAlgorithm[self.algorithm],  # type: ignore
            "YES" if self.flag == 0x80 else "NO",
        )  # type: ignore

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, SrkItemRSA) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def info(self) -> str:
        """String representation of SrkItemRSA."""
        msg = str()
        msg += "Algorithm: {}\n".format(EnumAlgorithm[self.algorithm])  # type: ignore
        msg += "Flag:      0x{:02X} {}\n".format(self.flag, "(CA)" if self.flag == 0x80 else "")
        msg += "Length:    {} bit\n".format(self.key_length)
        msg += "Modulus:\n"
        msg += modulus_fmt(self.modulus)
        msg += "\n"
        msg += "Exponent: {0} (0x{0:X})\n".format(int.from_bytes(self.exponent, "big"))
        return msg

    def sha256(self) -> bytes:
        """Export SHA256 hash of the data."""
        srk_data = self.export()
        return sha256(srk_data).digest()

    def hashed_entry(self) -> "SrkItemHash":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        return SrkItemHash(EnumAlgorithm.SHA256, self.sha256())

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export."""
        data = self._header.export()
        data += pack(">4B2H", 0, 0, 0, self.flag, len(self.modulus), len(self.exponent))
        data += bytes(self.modulus)
        data += bytes(self.exponent)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SrkItemRSA":
        """Parse SRK table item data.

        :param data: The bytes array of SRK segment
        :param offset: The offset of input data
        :return: SrkItemRSA: SrkItemRSA object
        """
        Header.parse(data, offset, EnumSRK.KEY_PUBLIC)
        offset += Header.SIZE + 3
        (flag, modulus_len, exponent_len) = unpack_from(">B2H", data, offset)
        offset += 5
        modulus = data[offset : offset + modulus_len]
        offset += modulus_len
        exponent = data[offset : offset + exponent_len]
        return cls(modulus, exponent, flag)

    @classmethod
    def from_certificate(cls, cert: Certificate) -> "SrkItemRSA":
        """Create SRKItemRSA from certificate."""
        assert isinstance(cert, Certificate)

        flag = 0
        try:
            key_usage = cert.extensions.get_extension_for_class(KeyUsage)
            assert isinstance(key_usage.value, KeyUsage)
            if key_usage.value.key_cert_sign:
                flag = 0x80
        except ExtensionNotFound:
            pass

        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            public_key = cert.public_key()
            assert isinstance(public_key, rsa.RSAPublicKey)
            pub_key_numbers = public_key.public_numbers()
            assert isinstance(pub_key_numbers, rsa.RSAPublicNumbers)
            # get modulus and exponent of public key since we are RSA
            modulus_len = math.ceil(pub_key_numbers.n.bit_length() / 8)
            exponent_len = math.ceil(pub_key_numbers.e.bit_length() / 8)
            modulus = pub_key_numbers.n.to_bytes(modulus_len, "big")
            exponent = pub_key_numbers.e.to_bytes(exponent_len, "big")

            return cls(modulus, exponent, flag)
        raise NotImplementedSRKCertificate()


class SrkTable(BaseClass):
    """SRK table."""

    @property
    def size(self) -> int:
        """Size of SRK table."""
        size = Header.SIZE
        for key in self._keys:
            size += key.size
        return size

    def __init__(self, version: int = 0x40) -> None:
        """Initialize SRT Table.

        :param version: format version
        """
        super().__init__(tag=SegTag.CRT, version=version)
        self._keys: List[SrkItem] = []

    def __repr__(self) -> str:
        return "SRK_Table <Version: {:X}.{:X}, Keys: {}>".format(
            self.version_major, self.version_minor, len(self._keys)
        )

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, SrkTable) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def __len__(self) -> int:
        return len(self._keys)

    def __getitem__(self, key: int) -> SrkItem:
        return self._keys[key]

    def __setitem__(self, key: int, value: SrkItem) -> None:
        assert isinstance(value, SrkItem)
        self._keys[key] = value

    def __iter__(self) -> Iterator[SrkItem]:
        return self._keys.__iter__()

    def info(self) -> str:
        """Text info about the instance."""
        msg = "-" * 60 + "\n"
        msg += "SRK Table (Version: {:X}.{:X}, #Keys: {})\n".format(
            self.version_major, self.version_minor, len(self._keys)
        )
        msg += "-" * 60 + "\n"
        for i, srk in enumerate(self._keys):
            msg += f"SRK Key Index: {i} \n"
            msg += srk.info()
            msg += "\n"
        return msg

    def append(self, srk: SrkItem) -> None:
        """Add SRK item.

        :param srk: item to be added
        """
        self._keys.append(srk)

    def get_fuse(self, index: int) -> int:
        """Retrieve fuse value for the given index.

        :param index: of the fuse, 0-7
        :return: value of the specified fuse; the value is in format, that cane be used as parameter for SDP
                `efuse_read_once` or `efuse_write_once`
        """
        assert 0 <= index < 8
        int_data = self.export_fuses()[index * 4 : (1 + index) * 4]
        assert len(int_data) == 4
        return unpack("<I", int_data)[0]

    def export_fuses(self) -> bytes:
        """SRK items in binary form, see `SRK_fuses.bin` file."""
        data = b""
        for srk in self._keys:
            data += srk.sha256()
        return sha256(data).digest()

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export into binary form (serialization).

        :param dbg_info: optional instance allowing to debug exported content
        :return: binary representation of the instance
        """
        self._header.length = self.size
        raw_data = self._header.export()
        dbg_info.append_binary_section("header", raw_data)
        for srk in self._keys:
            item_data = srk.export()
            raw_data += item_data
            dbg_info.append_binary_section("srk_item", item_data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SrkTable":
        """Parse of SRK table."""
        header = Header.parse(data, offset, SegTag.CRT)
        offset += Header.SIZE
        obj = cls(header.param)
        obj._header.length = header.length  # pylint: disable=protected-access
        length = header.length - Header.SIZE
        while length > 0:
            srk = SrkItem.parse(data, offset)
            offset += srk.size
            length -= srk.size
            obj.append(srk)
        return obj

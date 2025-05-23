#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of HAB image SRK (Super Root Keys) support."""

import math
from hashlib import sha256
from struct import pack, unpack, unpack_from
from typing import Any, Iterator

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate, ExtensionNotFound
from spsdk.crypto.crypto_types import SPSDKKeyUsage
from spsdk.crypto.keys import EccCurve, PublicKeyEcc, PublicKeyRsa, get_ecc_curve
from spsdk.exceptions import SPSDKError
from spsdk.image.hab.constants import EnumAlgorithm
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.image.misc import hexdump_fmt, modulus_fmt
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class SRKException(SPSDKError):
    """SRK table processing exceptions."""


class NotImplementedSRKPublicKeyType(SRKException):
    """This SRK public key algorithm is not yet implemented."""


class NotImplementedSRKCertificate(SRKException):
    """This SRK public key algorithm is not yet implemented."""


class NotImplementedSRKItem(SRKException):
    """This type of SRK table item is not implemented."""


class EnumSRK(SpsdkEnum):
    """Entry type in the System Root Key Table."""

    KEY_PUBLIC = (0xE1, "KEY_PUBLIC", "Public key type: data present")
    KEY_HASH = (0xEE, "KEY_HASH", "Any key: hash only")


class SrkItem:
    """Base class for items in the SRK Table, see `SrkTable` class.

    We do not inherit from BaseClass because our header parameter
    is an algorithm identifier, not a version number.
    """

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @property
    def size(self) -> int:
        """Size of the exported binary data.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def __str__(self) -> str:
        """Description about the instance.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def hashed_entry(self) -> "SrkItem":
        """This SRK item should be replaced with an incomplete entry with its digest.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def export(self) -> bytes:
        """Serialization to binary form.

        :return: binary representation of the instance
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Pick up the right implementation of an SRK item.

        :param data: The bytes array of SRK segment
        :return: SrkItem: One of the SrkItem subclasses
        :raises NotImplementedSRKPublicKeyType: Unsupported key algorithm
        :raises NotImplementedSRKItem: Unsupported tag
        """
        header = Header.parse(data)
        if header.tag == EnumSRK.KEY_PUBLIC:
            if header.param == EnumAlgorithm.PKCS1:
                return SrkItemRSA.parse(data)  # type: ignore
            if header.param == EnumAlgorithm.ECDSA:
                return SrkItemEcc.parse(data)  # type: ignore
            raise NotImplementedSRKPublicKeyType(f"{header.param}")
        if header.tag == EnumSRK.KEY_HASH:
            return SrkItemHash.parse(data)  # type: ignore
        raise NotImplementedSRKItem(f"TAG = {header.tag}, PARAM = {header.param}")

    @classmethod
    def from_certificate(cls, cert: Certificate) -> "SrkItem":
        """Pick up the right implementation of an SRK item."""
        assert isinstance(cert, Certificate)
        try:
            return SrkItemRSA.from_certificate(cert)
        except SPSDKError:
            pass
        try:
            return SrkItemEcc.from_certificate(cert)
        except SPSDKError:
            pass
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
        :raises SPSDKError: If incorrect algorithm
        """
        if algorithm != EnumAlgorithm.SHA256:
            raise SPSDKError("Incorrect algorithm")
        self._header = Header(tag=EnumSRK.KEY_HASH.tag, param=algorithm)
        self.digest = digest
        self._header.length += len(digest)

    def __repr__(self) -> str:
        return f"SRK Hash <Algorithm: {EnumAlgorithm.from_tag(self._header.param)}>"

    def __str__(self) -> str:
        """String representation of SrkItemHash."""
        msg = str()
        msg += f"Hash algorithm: {EnumAlgorithm.from_tag(self._header.param)}\n"
        msg += "Hash value:\n"
        msg += hexdump_fmt(self.digest)
        return msg

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data."""
        return self.digest

    def hashed_entry(self) -> "SrkItemHash":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        return self

    def export(self) -> bytes:
        """Export."""
        data = self._header.export()
        data += self.digest
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table item data.

        :param data: The bytes array of SRK segment
        :return: SrkItemHash: SrkItemHash object
        :raises NotImplementedSRKItem: Unknown tag
        """
        header = Header.parse(data, EnumSRK.KEY_HASH.tag)
        rest = data[header.SIZE :]
        if header.param == EnumAlgorithm.SHA256:
            digest = rest[: sha256().digest_size]
            return cls(EnumAlgorithm.SHA256.tag, digest)
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
        if value not in (0, 0x80):
            raise SPSDKError("Incorrect flag")
        self._flag = value

    @property
    def key_length(self) -> int:
        """Key length of Item in SRK Table."""
        return len(self.modulus) * 8

    def __init__(self, modulus: bytes, exponent: bytes, flag: int = 0) -> None:
        """Initialize the srk table item."""
        assert isinstance(modulus, bytes)
        assert isinstance(exponent, bytes)
        self._header = Header(tag=EnumSRK.KEY_PUBLIC.tag, param=EnumAlgorithm.PKCS1.tag)
        self.flag = flag
        self.modulus = modulus
        self.exponent = exponent
        self._header.length += 8 + len(self.modulus) + len(self.exponent)

    def __repr__(self) -> str:
        return (
            f"SRK <Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}, "
            f"CA: {'YES' if self.flag == 0x80 else 'NO'}>"
        )

    def __str__(self) -> str:
        """String representation of SrkItemRSA."""
        exp = int.from_bytes(self.exponent, Endianness.BIG.value)
        return (
            f"Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}\n"
            f"Flag:      0x{self.flag:02X} {'(CA)' if self.flag == 0x80 else ''}\n"
            f"Length:    {self.key_length} bit\n"
            "Modulus:\n"
            f"{modulus_fmt(self.modulus)}\n"
            f"Exponent: {exp} (0x{exp:X})\n"
        )

    def sha256(self) -> bytes:
        """Export SHA256 hash of the data."""
        srk_data = self.export()
        return sha256(srk_data).digest()

    def hashed_entry(self) -> "SrkItemHash":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        return SrkItemHash(EnumAlgorithm.SHA256.tag, self.sha256())

    def export(self) -> bytes:
        """Export."""
        data = self._header.export()
        data += pack(">4B2H", 0, 0, 0, self.flag, len(self.modulus), len(self.exponent))
        data += bytes(self.modulus)
        data += bytes(self.exponent)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table item data.

        :param data: The bytes array of SRK segment
        :return: SrkItemRSA: SrkItemRSA object
        """
        Header.parse(data, EnumSRK.KEY_PUBLIC.tag)
        (flag, modulus_len, exponent_len) = unpack_from(">B2H", data, Header.SIZE + 3)
        offset = 5 + Header.SIZE + 3
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
            key_usage = cert.extensions.get_extension_for_class(SPSDKKeyUsage)
            assert isinstance(key_usage.value, SPSDKKeyUsage)
            if key_usage.value.key_cert_sign:
                flag = 0x80
        except ExtensionNotFound:
            pass
        try:
            public_key = cert.get_public_key()
            if not isinstance(public_key, PublicKeyRsa):
                raise SPSDKError("Not an RSA key")
            # get modulus and exponent of public key since we are RSA
            modulus_len = math.ceil(public_key.n.bit_length() / 8)
            exponent_len = math.ceil(public_key.e.bit_length() / 8)
            modulus = public_key.n.to_bytes(modulus_len, Endianness.BIG.value)
            exponent = public_key.e.to_bytes(exponent_len, Endianness.BIG.value)

            return cls(modulus, exponent, flag)
        except SPSDKError as exc:
            raise NotImplementedSRKCertificate() from exc


class SrkItemEcc(SrkItem):
    """ECC public key in SRK Table, see `SrkTable` class."""

    ECC_KEY_TYPE = {
        EccCurve.SECP256R1: 0x4B,
        EccCurve.SECP384R1: 0x4D,
        EccCurve.SECP521R1: 0x4E,
    }

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
        # Check
        if value not in (0, 0x80):
            raise SPSDKError("Incorrect flag")
        self._flag = value

    def __init__(self, key_size: int, x_coordinate: int, y_coordinate: int, flag: int = 0) -> None:
        """Initialize the srk table item."""
        self._header = Header(tag=EnumSRK.KEY_PUBLIC.tag, param=EnumAlgorithm.ECDSA.tag)
        self.x_coordinate = x_coordinate
        self.y_coordinate = y_coordinate
        self.key_size = key_size
        self.coordinate_size = math.ceil(key_size / 8)
        self.flag = flag
        self._header.length += (
            8
            + len(self.x_coordinate.to_bytes(self.coordinate_size, byteorder=Endianness.BIG.value))
            + len(self.y_coordinate.to_bytes(self.coordinate_size, byteorder=Endianness.BIG.value))
        )

    def __repr__(self) -> str:
        return (
            f"SRK <Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}, "
            f"CA: {'YES' if self.flag == 0x80 else 'NO'}>"
        )

    def __str__(self) -> str:
        """String representation of SrkItemEcc."""
        return (
            f"Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}\n"
            f"Flag:      0x{self.flag:02X} {'(CA)' if self.flag == 0x80 else ''}\n"
            f"Key size:    {self.key_size} bit\n"
            f"X coordinate:    {self.x_coordinate}\n"
            f"Y coordinate:    {self.y_coordinate}\n"
        )

    def sha256(self) -> bytes:
        """Export SHA256 hash of the data."""
        srk_data = self.export()
        return sha256(srk_data).digest()

    def hashed_entry(self) -> "SrkItemHash":
        """This SRK item should be replaced with an incomplete entry with its digest."""
        return SrkItemHash(EnumAlgorithm.SHA256.tag, self.sha256())

    def export(self) -> bytes:
        """Export."""
        data = self._header.export()
        curve_id = self.ECC_KEY_TYPE[get_ecc_curve(self.key_size // 8)]
        data += pack(
            ">8B", 0, 0, 0, self.flag, curve_id, 0, self.key_size >> 8 & 0xFF, self.key_size & 0xFF
        )
        data += self.x_coordinate.to_bytes(self.coordinate_size, byteorder=Endianness.BIG.value)
        data += self.y_coordinate.to_bytes(self.coordinate_size, byteorder=Endianness.BIG.value)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table item data.

        :param data: The bytes array of SRK segment
        :return: SrkItemEcc: SrkItemEcc object
        """
        Header.parse(data, EnumSRK.KEY_PUBLIC.tag)
        (flag, curve_id, _, key_size) = unpack_from(">3BH", data, Header.SIZE + 3)
        if curve_id not in list(cls.ECC_KEY_TYPE.values()):
            raise SPSDKError(f"Unknown curve with id {curve_id}")
        offset = 5 + Header.SIZE + 3
        coordinate_size = math.ceil(key_size / 8)
        x_coordinate = data[offset : offset + coordinate_size]
        offset += coordinate_size
        y_coordinate = data[offset : offset + coordinate_size]
        return cls(
            key_size,
            int.from_bytes(x_coordinate, Endianness.BIG.value),
            int.from_bytes(y_coordinate, Endianness.BIG.value),
            flag,
        )

    @classmethod
    def from_certificate(cls, cert: Certificate) -> "SrkItemEcc":
        """Create SrkItemEcc from certificate."""
        flag = 0
        try:
            key_usage = cert.extensions.get_extension_for_class(SPSDKKeyUsage)
            assert isinstance(key_usage.value, SPSDKKeyUsage)
            if key_usage.value.key_cert_sign:
                flag = 0x80
        except ExtensionNotFound:
            pass

        try:
            public_key = cert.get_public_key()
            if not isinstance(public_key, PublicKeyEcc):
                raise SPSDKError("Not an ECC key")
            return cls(public_key.key_size, public_key.x, public_key.y, flag)
        except SPSDKError as exc:
            raise NotImplementedSRKCertificate() from exc


class SrkTable(BaseClass):
    """SRK table."""

    def __init__(self, version: int = 0x40) -> None:
        """Initialize SRT Table.

        :param version: format version
        """
        self._header = Header(tag=SegmentTag.CRT.tag, param=version)
        self._keys: list[SrkItem] = []

    @property
    def size(self) -> int:
        """Size of SRK table."""
        size = Header.SIZE
        for key in self._keys:
            size += key.size
        return size

    def __len__(self) -> int:
        return len(self._keys)

    def __getitem__(self, key: int) -> SrkItem:
        return self._keys[key]

    def __setitem__(self, key: int, value: SrkItem) -> None:
        assert isinstance(value, SrkItem)
        self._keys[key] = value

    def __iter__(self) -> Iterator[SrkItem]:
        return self._keys.__iter__()

    def __repr__(self) -> str:
        return (
            f"SRK_Table <Version: {self._header.version_major:X}.{self._header.version_minor:X},"
            f" Keys: {len(self._keys)}>"
        )

    def __str__(self) -> str:
        """Text info about the instance."""
        msg = "-" * 60 + "\n"
        msg += (
            f"SRK Table (Version: {self._header.version_major:X}.{self._header.version_minor:X}, "
            f"#Keys: {len(self._keys)})\n"
        )
        msg += "-" * 60 + "\n"
        for i, srk in enumerate(self._keys):
            msg += f"SRK Key Index: {i} \n"
            msg += str(srk)
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
        :raises SPSDKError: If incorrect index of the fuse
        :raises SPSDKError: If incorrect length of SRK items
        """
        if index < 0 or index >= 8:
            raise SPSDKError("Incorrect index of the fuse")
        int_data = self.export_fuses()[index * 4 : (1 + index) * 4]
        if len(int_data) != 4:
            raise SPSDKError("Incorrect length of SRK items")
        return unpack("<I", int_data)[0]

    def export_fuses(self) -> bytes:
        """SRK items in binary form, see `SRK_fuses.bin` file."""
        data = b""
        for srk in self._keys:
            data += srk.sha256()
        return sha256(data).digest()

    def export(self) -> bytes:
        """Export into binary form (serialization).

        :return: binary representation of the instance
        """
        self._header.length = self.size
        raw_data = self._header.export()
        for srk in self._keys:
            raw_data += srk.export()
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse of SRK table."""
        header = Header.parse(data, SegmentTag.CRT.tag)
        offset = Header.SIZE
        obj = cls(header.param)
        obj._header.length = header.length  # pylint: disable=protected-access
        length = header.length - Header.SIZE
        while length > 0:
            srk = SrkItem.parse(data[offset:])
            offset += srk.size
            length -= srk.size
            obj.append(srk)
        return obj

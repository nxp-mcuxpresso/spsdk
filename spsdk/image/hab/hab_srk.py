#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Super Root Keys (SRK) implementation.

This module provides comprehensive support for handling Super Root Keys in HAB
(High Assurance Boot) context, including SRK table management, key item handling
for RSA and ECC algorithms, and hash-based key representations.
"""

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
    """Exception class for SRK table processing operations.

    This exception is raised when errors occur during SRK (Super Root Key) table
    creation, validation, or manipulation within the HAB (High Assurance Boot)
    security framework.
    """


class NotImplementedSRKPublicKeyType(SRKException):
    """Exception raised when an unsupported SRK public key algorithm is encountered.

    This exception is thrown when attempting to use a public key algorithm
    that is not yet implemented in the SPSDK SRK handling functionality.
    """


class NotImplementedSRKCertificate(SRKException):
    """Exception raised when an unsupported SRK public key algorithm is encountered.

    This exception is thrown when attempting to process or validate an SRK certificate
    that uses a cryptographic algorithm not yet implemented in the SPSDK library.
    """


class NotImplementedSRKItem(SRKException):
    """Exception raised when an unsupported SRK table item type is encountered.

    This exception is thrown when attempting to process or create an SRK (Super Root Key)
    table item that is not yet implemented in the current SPSDK version.
    """


class EnumSRK(SpsdkEnum):
    """Entry type enumeration for the System Root Key Table.

    This enumeration defines the supported entry types that can be used in HAB
    (High Assurance Boot) System Root Key Tables, specifying whether the entry
    contains a full public key or just a hash reference.

    :cvar KEY_PUBLIC: Public key type with full key data present.
    :cvar KEY_HASH: Hash-only key type for any key format.
    """

    KEY_PUBLIC = (0xE1, "KEY_PUBLIC", "Public key type: data present")
    KEY_HASH = (0xEE, "KEY_HASH", "Any key: hash only")


class SrkItem:
    """Base class for Super Root Key (SRK) table items in HAB authentication.

    This class defines the interface for SRK table entries used in High Assurance Boot (HAB)
    authentication. SRK items represent cryptographic keys or certificates that form the root
    of trust for secure boot operations. The class provides abstract methods for key operations
    like hashing, serialization, and digest generation.
    """

    def __eq__(self, other: Any) -> bool:
        """Check equality of two HAB SRK objects.

        Compares two HAB SRK (Super Root Key) objects by checking if they are of the same
        class type and have identical instance variables.

        :param other: Object to compare with this HAB SRK instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        """Check if two objects are not equal.

        This method implements the inequality comparison operator by negating the equality
        comparison result.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    @property
    def size(self) -> int:
        """Size of the exported binary data.

        :raises NotImplementedError: Derived class has to implement this method.
        :return: Size in bytes of the exported binary data.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def __str__(self) -> str:
        """Get string representation of the instance.

        This method provides a human-readable description of the HAB SRK instance
        and must be implemented by derived classes.

        :raises NotImplementedError: Derived class has to implement this method
        :return: String representation of the instance
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data.

        :raises NotImplementedError: Derived class has to implement this method.
        :return: SHA256 hash of the original data.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def hashed_entry(self) -> "SrkItem":
        """Get hashed entry representation of this SRK item.

        This SRK item should be replaced with an incomplete entry with its digest.

        :raises NotImplementedError: Derived class has to implement this method.
        :return: SRK item with hashed representation.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def export(self) -> bytes:
        """Export the instance to its binary representation.

        This method serializes the current instance into a binary format that can be
        used for storage or transmission. Must be implemented by derived classes.

        :raises NotImplementedError: Derived class has to implement this method.
        :return: Binary representation of the instance.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK item data and return appropriate implementation.

        The method analyzes the header of SRK segment data to determine the correct
        SRK item type and returns the corresponding parsed object instance.

        :param data: The bytes array of SRK segment data to parse.
        :return: Parsed SRK item instance (RSA, ECC, or Hash type).
        :raises NotImplementedSRKPublicKeyType: Unsupported key algorithm.
        :raises NotImplementedSRKItem: Unsupported SRK tag type.
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
        """Create SRK item from certificate by detecting the appropriate type.

        This factory method automatically determines whether the certificate contains
        an RSA or ECC key and returns the corresponding SrkItem implementation.

        :param cert: X.509 certificate to create SRK item from
        :return: SRK item instance (either SrkItemRSA or SrkItemEcc)
        :raises NotImplementedSRKCertificate: When certificate type is not supported
        """
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
    """SRK table hash entry for public key digest.

    This class represents a hashed stub entry in the Super Root Key (SRK) table
    that contains only the digest of a public key without the full key data.
    Used when the complete public key information is not available or needed,
    providing a lightweight reference through its hash value.
    """

    @property
    def algorithm(self) -> int:
        """Get the hashing algorithm identifier.

        Returns the algorithm parameter from the header that specifies which
        hashing algorithm is used for this SRK (Super Root Key).

        :return: Integer identifier of the hashing algorithm.
        """
        return self._header.param

    @property
    def size(self) -> int:
        """Get the size of an SRK item in bytes.

        :return: Size of the SRK item as specified in the header length field.
        """
        return self._header.length

    def __init__(self, algorithm: int, digest: bytes) -> None:
        """Initialize SRK table entry with public key hash.

        Creates a stub entry containing only the hash digest of a public key,
        used in HAB (High Assurance Boot) SRK (Super Root Key) tables.

        :param algorithm: Hash algorithm identifier, currently only SHA256 is supported
        :param digest: Hash digest value of the public key
        :raises SPSDKError: If unsupported algorithm is provided
        """
        if algorithm != EnumAlgorithm.SHA256:
            raise SPSDKError("Incorrect algorithm")
        self._header = Header(tag=EnumSRK.KEY_HASH.tag, param=algorithm)
        self.digest = digest
        self._header.length += len(digest)

    def __repr__(self) -> str:
        """Return string representation of SRK Hash object.

        Provides a human-readable string representation showing the algorithm type
        used for the SRK hash.

        :return: String representation containing the algorithm name.
        """
        return f"SRK Hash <Algorithm: {EnumAlgorithm.from_tag(self._header.param)}>"

    def __str__(self) -> str:
        """String representation of SrkItemHash.

        Creates a formatted string containing the hash algorithm type and the hash value
        in hexadecimal format for debugging and display purposes.

        :return: Formatted string with hash algorithm and digest value.
        """
        msg = str()
        msg += f"Hash algorithm: {EnumAlgorithm.from_tag(self._header.param)}\n"
        msg += "Hash value:\n"
        msg += hexdump_fmt(self.digest)
        return msg

    def sha256(self) -> bytes:
        """Export SHA256 hash of the original data.

        :return: SHA256 hash digest as bytes.
        """
        return self.digest

    def hashed_entry(self) -> "SrkItemHash":
        """Get hashed entry representation of this SRK item.

        This method returns a representation of the SRK item that should be replaced
        with an incomplete entry containing its digest for hash-based operations.

        :return: The same SRK item instance configured for hash-based usage.
        """
        return self

    def export(self) -> bytes:
        """Export the SRK (Super Root Key) data as bytes.

        Serializes the SRK header and digest into a binary format suitable for
        storage or transmission.

        :return: Binary representation of the SRK data containing header and digest.
        """
        data = self._header.export()
        data += self.digest
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table item data from bytes array.

        The method parses the header and extracts the digest based on the algorithm
        specified in the header parameter. Currently only SHA256 algorithm is supported.

        :param data: The bytes array of SRK segment to parse.
        :raises NotImplementedSRKItem: Unknown tag or unsupported algorithm.
        :return: SrkItemHash object with parsed data.
        """
        header = Header.parse(data, EnumSRK.KEY_HASH.tag)
        rest = data[header.SIZE :]
        if header.param == EnumAlgorithm.SHA256:
            digest = rest[: sha256().digest_size]
            return cls(EnumAlgorithm.SHA256.tag, digest)
        raise NotImplementedSRKItem(f"TAG = {header.tag}, PARAM = {header.param}")


class SrkItemRSA(SrkItem):
    """RSA public key item for SRK (Super Root Key) Table.

    This class represents an RSA public key entry within the SRK Table used in HAB
    (High Assurance Boot) authentication. It manages RSA key data including modulus,
    exponent, and certificate authority flags for secure boot verification.
    """

    @property
    def algorithm(self) -> int:
        """Get the algorithm identifier from the header.

        :return: Algorithm identifier value from the header parameter.
        """
        return self._header.param

    @property
    def size(self) -> int:
        """Get the size of an SRK item.

        :return: Size of the SRK item in bytes.
        """
        return self._header.length

    @property
    def flag(self) -> int:
        """Get the flag value.

        :return: The flag value as an integer.
        """
        return self._flag

    @flag.setter
    def flag(self, value: int) -> None:
        """Set the flag value for the SRK entry.

        The flag indicates the status or properties of the Super Root Key entry.
        Only values 0 and 0x80 are valid for this field.

        :param value: Flag value to set (must be 0 or 0x80).
        :raises SPSDKError: If the provided flag value is not 0 or 0x80.
        """
        if value not in (0, 0x80):
            raise SPSDKError("Incorrect flag")
        self._flag = value

    @property
    def key_length(self) -> int:
        """Get the key length of the SRK table item in bits.

        The key length is calculated by multiplying the modulus length in bytes by 8
        to convert to bits.

        :return: Key length in bits.
        """
        return len(self.modulus) * 8

    def __init__(self, modulus: bytes, exponent: bytes, flag: int = 0) -> None:
        """Initialize the SRK table item.

        Creates a new SRK (Super Root Key) table item with the provided RSA key components
        and initializes the header with appropriate tags and calculated length.

        :param modulus: RSA key modulus as bytes.
        :param exponent: RSA key exponent as bytes.
        :param flag: Optional flag value for the SRK item, defaults to 0.
        """
        assert isinstance(modulus, bytes)
        assert isinstance(exponent, bytes)
        self._header = Header(tag=EnumSRK.KEY_PUBLIC.tag, param=EnumAlgorithm.PKCS1.tag)
        self.flag = flag
        self.modulus = modulus
        self.exponent = exponent
        self._header.length += 8 + len(self.modulus) + len(self.exponent)

    def __repr__(self) -> str:
        """Return string representation of SRK object.

        Provides a human-readable string containing the algorithm type and CA flag status
        for debugging and logging purposes.

        :return: Formatted string with algorithm and CA flag information.
        """
        return (
            f"SRK <Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}, "
            f"CA: {'YES' if self.flag == 0x80 else 'NO'}>"
        )

    def __str__(self) -> str:
        """String representation of SrkItemRSA.

        Returns a formatted string containing the RSA key details including algorithm,
        flag status, key length, modulus, and exponent values.

        :return: Formatted string representation of the RSA SRK item.
        """
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
        """Export SHA256 hash of the SRK data.

        This method computes the SHA256 hash digest of the exported SRK (Super Root Key) data.

        :return: SHA256 hash digest of the SRK data as bytes.
        """
        srk_data = self.export()
        return sha256(srk_data).digest()

    def hashed_entry(self) -> "SrkItemHash":
        """Create a hashed entry representation of this SRK item.

        This method generates an incomplete SRK entry containing only the SHA256 digest
        of the current SRK item, which can be used for verification purposes.

        :return: SRK item hash containing SHA256 algorithm tag and digest.
        """
        return SrkItemHash(EnumAlgorithm.SHA256.tag, self.sha256())

    def export(self) -> bytes:
        """Export the SRK (Super Root Key) data to binary format.

        Serializes the SRK header, flag, modulus and exponent lengths, and the actual
        modulus and exponent values into a binary representation suitable for HAB
        (High Assurance Boot) processing.

        :return: Binary representation of the SRK data.
        """
        data = self._header.export()
        data += pack(">4B2H", 0, 0, 0, self.flag, len(self.modulus), len(self.exponent))
        data += bytes(self.modulus)
        data += bytes(self.exponent)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table item data from bytes array.

        The method parses the binary data of an SRK (Super Root Key) segment and extracts
        the RSA key components including modulus, exponent, and flags.

        :param data: The bytes array containing SRK segment data to parse.
        :return: SrkItemRSA object with parsed RSA key components.
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
        """Create SRKItemRSA from X.509 certificate.

        Extracts RSA public key parameters (modulus and exponent) from the provided certificate
        and creates an SRKItemRSA instance. Also processes key usage extension to set appropriate
        flags for certificate signing capability.

        :param cert: X.509 certificate containing RSA public key.
        :raises SPSDKError: If the certificate does not contain an RSA public key.
        :raises NotImplementedSRKCertificate: If certificate processing fails.
        :return: SRKItemRSA instance created from certificate's RSA public key.
        """
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
    """ECC public key item for SRK (Super Root Key) Table.

    This class represents an ECC public key entry within the SRK Table used in HAB
    (High Assurance Boot) authentication. It manages ECC key coordinates, algorithm
    parameters, and certificate authority flags for secure boot operations.

    :cvar ECC_KEY_TYPE: Mapping of ECC curves to their corresponding key type identifiers.
    """

    ECC_KEY_TYPE = {
        EccCurve.SECP256R1: 0x4B,
        EccCurve.SECP384R1: 0x4D,
        EccCurve.SECP521R1: 0x4E,
    }

    @property
    def algorithm(self) -> int:
        """Get the algorithm identifier from the header.

        :return: Algorithm identifier value from the header parameter.
        """
        return self._header.param

    @property
    def size(self) -> int:
        """Get the size of an SRK item in bytes.

        :return: Size of the SRK item as specified in the header length field.
        """
        return self._header.length

    @property
    def flag(self) -> int:
        """Get flag value.

        :return: Flag value as integer.
        """
        return self._flag

    @flag.setter
    def flag(self, value: int) -> None:
        """Set the flag value for HAB SRK.

        The flag indicates specific properties or states of the Super Root Key.
        Only values 0 and 0x80 are valid flag settings.

        :param value: Flag value to set, must be either 0 or 0x80
        :raises SPSDKError: If the provided flag value is not 0 or 0x80
        """
        # Check
        if value not in (0, 0x80):
            raise SPSDKError("Incorrect flag")
        self._flag = value

    def __init__(self, key_size: int, x_coordinate: int, y_coordinate: int, flag: int = 0) -> None:
        """Initialize the SRK table item for ECDSA public key.

        Creates a new SRK (Super Root Key) table item with ECDSA public key coordinates
        and initializes the header with appropriate tag and length calculations.

        :param key_size: Size of the key in bits (e.g., 256, 384, 521).
        :param x_coordinate: X coordinate of the ECDSA public key as integer.
        :param y_coordinate: Y coordinate of the ECDSA public key as integer.
        :param flag: Optional flags for the SRK item, defaults to 0.
        """
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
        """Return string representation of SRK object.

        Provides a human-readable string containing the algorithm type and CA flag status.

        :return: Formatted string with algorithm and CA flag information.
        """
        return (
            f"SRK <Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}, "
            f"CA: {'YES' if self.flag == 0x80 else 'NO'}>"
        )

    def __str__(self) -> str:
        """String representation of SrkItemEcc.

        Provides a formatted string containing the ECC SRK item details including algorithm,
        flag status, key size, and coordinate values.

        :return: Formatted string with ECC SRK item information.
        """
        return (
            f"Algorithm: {EnumAlgorithm.from_tag(self.algorithm)}\n"
            f"Flag:      0x{self.flag:02X} {'(CA)' if self.flag == 0x80 else ''}\n"
            f"Key size:    {self.key_size} bit\n"
            f"X coordinate:    {self.x_coordinate}\n"
            f"Y coordinate:    {self.y_coordinate}\n"
        )

    def sha256(self) -> bytes:
        """Export SHA256 hash of the SRK data.

        Computes and returns the SHA256 hash digest of the exported SRK (Super Root Key) data.

        :return: SHA256 hash digest of the SRK data.
        """
        srk_data = self.export()
        return sha256(srk_data).digest()

    def hashed_entry(self) -> "SrkItemHash":
        """Create a hashed entry representation of this SRK item.

        This method generates an incomplete SRK entry containing only the SHA256 digest
        of the current SRK item, which can be used for verification purposes.

        :return: SRK item hash containing the SHA256 algorithm tag and digest.
        """
        return SrkItemHash(EnumAlgorithm.SHA256.tag, self.sha256())

    def export(self) -> bytes:
        """Export ECC key data in binary format.

        Exports the ECC key including header, curve information, flags, key size,
        and coordinate data in the proper binary format for HAB processing.

        :return: Binary representation of the ECC key data.
        """
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
        """Parse SRK table item data from bytes array.

        The method parses binary data containing ECC key information including curve ID,
        key size, and coordinate data to create an SrkItemEcc object.

        :param data: The bytes array of SRK segment containing ECC key data.
        :raises SPSDKError: Unknown curve with unsupported curve ID.
        :return: SrkItemEcc object with parsed ECC key parameters.
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
        """Create SrkItemEcc from certificate.

        Extracts ECC public key information from a certificate and creates an SrkItemEcc instance.
        The method also checks for key usage extensions to determine if the certificate can be
        used for certificate signing.

        :param cert: X.509 certificate containing ECC public key.
        :raises NotImplementedSRKCertificate: When certificate doesn't contain valid ECC key or
            other processing errors occur.
        :return: SrkItemEcc instance created from certificate's public key data.
        """
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
    """HAB Super Root Key (SRK) table container.

    This class manages a collection of SRK items used in HAB (High Assurance Boot)
    authentication. The SRK table contains cryptographic keys that form the root
    of trust for secure boot operations in NXP MCUs.
    """

    def __init__(self, version: int = 0x40) -> None:
        """Initialize SRK Table.

        :param version: Format version of the SRK table, defaults to 0x40.
        """
        self._header = Header(tag=SegmentTag.CRT.tag, param=version)
        self._keys: list[SrkItem] = []

    @property
    def size(self) -> int:
        """Calculate the total size of the SRK table in bytes.

        The size includes the header size plus the cumulative size of all keys
        contained in the SRK table.

        :return: Total size of the SRK table in bytes.
        """
        size = Header.SIZE
        for key in self._keys:
            size += key.size
        return size

    def __len__(self) -> int:
        """Get the number of keys in the SRK table.

        :return: Number of keys stored in the SRK table.
        """
        return len(self._keys)

    def __getitem__(self, key: int) -> SrkItem:
        """Get SRK item by index.

        Retrieves a specific SRK (Super Root Key) item from the internal keys collection
        using zero-based indexing.

        :param key: Index of the SRK item to retrieve.
        :raises IndexError: If the key index is out of range.
        :raises KeyError: If the key is not found in the collection.
        :return: SRK item at the specified index.
        """
        return self._keys[key]

    def __setitem__(self, key: int, value: SrkItem) -> None:
        """Set SRK item at specified index.

        Assigns an SRK (Super Root Key) item to the specified index position in the
        SRK table.

        :param key: Index position where to store the SRK item.
        :param value: SRK item to be stored at the specified index.
        :raises AssertionError: If value is not an instance of SrkItem.
        """
        assert isinstance(value, SrkItem)
        self._keys[key] = value

    def __iter__(self) -> Iterator[SrkItem]:
        """Iterate over SRK items in the collection.

        Provides an iterator interface to access all SrkItem objects stored in this SRK table.

        :return: Iterator yielding SrkItem objects from the internal keys collection.
        """
        return self._keys.__iter__()

    def __repr__(self) -> str:
        """Return string representation of SRK Table.

        Provides a formatted string showing the version and number of keys in the SRK table.

        :return: String representation with version and key count information.
        """
        return (
            f"SRK_Table <Version: {self._header.version_major:X}.{self._header.version_minor:X},"
            f" Keys: {len(self._keys)}>"
        )

    def __str__(self) -> str:
        """Get string representation of the SRK table.

        Provides a formatted text representation containing the SRK table header information
        (version and key count) and detailed information about each SRK key in the table.

        :return: Formatted string with SRK table details including version, key count, and
            individual key information.
        """
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
        """Add SRK item to the collection.

        :param srk: SRK item to be added to the internal keys list.
        """
        self._keys.append(srk)

    def get_fuse(self, index: int) -> int:
        """Retrieve fuse value for the given index.

        The method extracts a 4-byte fuse value from the SRK data at the specified index position.
        The returned value is formatted for use with SDP efuse operations.

        :param index: Index of the fuse (0-7).
        :return: Value of the specified fuse formatted for SDP efuse_read_once or efuse_write_once.
        :raises SPSDKError: If incorrect index of the fuse.
        :raises SPSDKError: If incorrect length of SRK items.
        """
        if index < 0 or index >= 8:
            raise SPSDKError("Incorrect index of the fuse")
        int_data = self.export_fuses()[index * 4 : (1 + index) * 4]
        if len(int_data) != 4:
            raise SPSDKError("Incorrect length of SRK items")
        return unpack("<I", int_data)[0]

    def export_fuses(self) -> bytes:
        """Export SRK fuses in binary format.

        Generates binary representation of Super Root Key (SRK) fuses by computing
        SHA256 hash of all individual SRK key hashes concatenated together.
        The result corresponds to the content of `SRK_fuses.bin` file.

        :return: SHA256 digest of concatenated SRK key hashes as binary data.
        """
        data = b""
        for srk in self._keys:
            data += srk.sha256()
        return sha256(data).digest()

    def export(self) -> bytes:
        """Export SRK table into binary form.

        Serializes the SRK (Super Root Key) table by updating the header length
        and concatenating the header with all individual SRK entries.

        :return: Binary representation of the complete SRK table.
        """
        self._header.length = self.size
        raw_data = self._header.export()
        for srk in self._keys:
            raw_data += srk.export()
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SRK table from binary data.

        This method parses a binary representation of an SRK (Super Root Key) table,
        extracting the header and individual SRK items to reconstruct the complete table.

        :param data: Binary data containing the SRK table to parse.
        :return: Parsed SRK table instance.
        """
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

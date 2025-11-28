#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Root Key Hash Table (RKHT) implementation.

This module provides functionality for creating, parsing, and managing Root Key Hash
Tables used in secure boot processes. It supports multiple RKHT versions including
RKHTv1 and RKHTv21 with their specific formats and validation requirements.
"""

import logging
import math
from abc import abstractmethod
from typing import Optional, Sequence, Type, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_length
from spsdk.crypto.keys import PrivateKey, PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.utils import extract_public_key, extract_public_key_from_data
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


class RKHT:
    """Root Key Hash Table for secure boot certificate blocks.

    This class manages a collection of root key hashes used in secure boot operations.
    It provides functionality to create hash tables from various key formats including
    public keys, private keys, and certificates, and calculates the root key table hash
    for certificate block validation.
    """

    def __init__(self, rkh_list: list[bytes]) -> None:
        """Initialize Root Key Hash Table.

        Creates a new Root Key Hash Table instance with the provided list of root key hashes.
        The table supports a maximum of 4 root key hashes.

        :param rkh_list: List of root key hashes as bytes objects
        :raises SPSDKError: When more than 4 root key hashes are provided
        """
        if len(rkh_list) > 4:
            raise SPSDKError("Number of Root Key Hashes can not be larger than 4.")
        self.rkh_list = rkh_list

    @classmethod
    def from_keys(
        cls,
        keys: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Create RKHT from list of keys.

        The method converts various key formats to public keys, validates that all keys are of the same
        type and use the same hash algorithm, then creates RKHT from their hashes.

        :param keys: List of public keys/certificates/private keys/bytes to process
        :param password: Optional password to open secured private keys, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: If keys are not of same type or don't use same hash algorithm
        :return: New RKHT instance created from the provided keys
        """
        public_keys = (
            [cls.convert_key(x, password, search_paths=search_paths) for x in keys] if keys else []
        )
        if not all(isinstance(x, type(public_keys[0])) for x in public_keys):
            raise SPSDKError("RKHT must contains all keys of a same instances.")
        if not all(
            cls._get_hash_algorithm(x) == cls._get_hash_algorithm(public_keys[0])
            for x in public_keys
        ):
            raise SPSDKError("RKHT must have same hash algorithm for all keys.")

        rotk_hashes = [cls._calc_key_hash(key) for key in public_keys]
        return cls(rotk_hashes)

    @abstractmethod
    def rkth(self) -> bytes:
        """Root Key Table Hash.

        Computes and returns the hash of all public key hashes in the root key table.

        :return: Hash of hashes of public keys as bytes.
        """

    @staticmethod
    def _get_hash_algorithm(key: PublicKey) -> EnumHashAlgorithm:
        """Get hash algorithm for the given public key.

        The method determines the appropriate hash algorithm based on the key type.
        For ECC keys, it uses SHA with the same bit size as the key. For RSA keys,
        it always uses SHA-256 regardless of the key length.

        :param key: Public key to determine hash algorithm for.
        :raises SPSDKError: Unsupported key type.
        :return: Hash algorithm enum value.
        """
        if isinstance(key, PublicKeyEcc):
            return EnumHashAlgorithm.from_label(f"sha{key.key_size}")

        if isinstance(key, PublicKeyRsa):
            # In case of RSA keys, hash is always SHA-256, regardless of the key length
            return EnumHashAlgorithm.SHA256

        raise SPSDKError("Unsupported key type to load.")

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Get the hash algorithm used for root key hashes.

        Determines the hash algorithm based on the size of the root key hashes
        in the RKH list.

        :raises SPSDKError: When no root key hashes are available to determine algorithm.
        :return: Hash algorithm enumeration value.
        """
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorithm name. No root key hashes.")
        return EnumHashAlgorithm.from_label(f"sha{self.hash_algorithm_size}")

    @property
    def hash_algorithm_size(self) -> int:
        """Get the hash algorithm size in bits.

        The method determines the hash algorithm size based on the length of the first
        Root Key Hash (RKH) in the list. The size is calculated by multiplying the
        byte length by 8 to get the bit size.

        :raises SPSDKError: When no public keys are provided in the RKH list.
        :return: Hash algorithm size in bits.
        """
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorithm size. No public keys provided.")
        return len(self.rkh_list[0]) * 8

    @staticmethod
    def _calc_key_hash(
        public_key: PublicKey,
        algorithm: Optional[EnumHashAlgorithm] = None,
    ) -> bytes:
        """Calculate a hash out of public key's exponent and modulus in RSA case, X/Y in EC.

        The method extracts key components (exponent/modulus for RSA, x/y coordinates for ECC)
        and computes their hash using the specified or default algorithm.

        :param public_key: Public key to compute hash from.
        :param algorithm: Hash algorithm to use, defaults to key-specific algorithm if None.
        :raises SPSDKError: Unsupported public key type.
        :return: Computed hash as bytes.
        """
        n_1 = 0
        n_2 = 0
        if isinstance(public_key, PublicKeyRsa):
            n_1 = public_key.e
            n1_len = math.ceil(n_1.bit_length() / 8)
            n_2 = public_key.n
            n2_len = math.ceil(n_2.bit_length() / 8)
        elif isinstance(public_key, PublicKeyEcc):
            n_1 = public_key.y
            n_2 = public_key.x
            n1_len = n2_len = public_key.coordinate_size
        else:
            raise SPSDKError(f"Unsupported key type: {type(public_key)}")

        n1_bytes = n_1.to_bytes(n1_len, Endianness.BIG.value)
        n2_bytes = n_2.to_bytes(n2_len, Endianness.BIG.value)

        algorithm = algorithm or RKHT._get_hash_algorithm(public_key)
        return get_hash(n2_bytes + n1_bytes, algorithm=algorithm)

    @staticmethod
    def get_class(family: FamilyRevision) -> Type["RKHT"]:
        """Get RKHT class for given family.

        Retrieves the appropriate RKHT (Root Key Hash Table) class implementation
        based on the specified family revision by looking up the certificate block
        type in the database.

        :param family: The family revision to get RKHT class for.
        :return: RKHT class corresponding to the given family.
        :raises SPSDKError: When the family doesn't support RKHT or has invalid
            certificate block configuration.
        """
        cert_blocks = {
            "cert_block_1": RKHTv1,
            "cert_block_21": RKHTv21,
        }
        val = get_db(family).get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        if val is None or val not in cert_blocks:
            raise SPSDKError("The family doesn't support RKHT")

        return cert_blocks[val]

    @staticmethod
    def convert_key(
        key: Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> PublicKey:
        """Convert various key formats into a PublicKey object.

        Accepts multiple input formats including Certificate, PrivateKey, PublicKey objects,
        file paths as strings, or raw key data as bytes/bytearray and converts them to
        a standardized PublicKey object.

        :param key: Public key in Certificate/Private key, Public key as a path to file,
            loaded bytes or supported class.
        :param password: Optional password to open secured private keys, defaults to None.
        :param search_paths: List of paths where to search for the file, defaults to None.
        :raises SPSDKError: Invalid key type.
        :return: Public Key object.
        """
        if isinstance(key, PublicKey):
            return key

        if isinstance(key, PrivateKey):
            return key.get_public_key()

        if isinstance(key, Certificate):
            if key.ca:
                setattr(key, "ca", True)
            return key.get_public_key()

        if isinstance(key, str):
            return extract_public_key(key, password, search_paths=search_paths)

        if isinstance(key, (bytes, bytearray)):
            return extract_public_key_from_data(key, password)

        raise SPSDKError("RKHT: Unsupported key to load.")

    def __str__(self) -> str:
        """String representation of the Root Key Hash Table.

        Creates a formatted string containing hash algorithm information,
        hash size, number of root key hashes, and hexadecimal representation
        of each root key hash in the table.

        :return: Formatted string with complete RKHT information.
        """
        result = f"Hash Algorithm: {self.hash_algorithm.name}\n"
        result += f"Hash Algorithm Size: {self.hash_algorithm_size} bits\n"
        result += f"Number of Root Key Hashes: {len(self.rkh_list)}\n"
        for i, rkh in enumerate(self.rkh_list, 1):
            result += f"RKH {i}: {rkh.hex()}\n"
        return result


class RKHTv1(RKHT):
    """Root Key Hash Table implementation for certificate block version 1.

    This class manages a table of root key hashes used in certificate block v1 format,
    providing functionality to store, validate, and export SHA256 hashes of root keys
    for secure boot verification.

    :cvar RKHT_SIZE: Number of root key hash entries in the table (4).
    :cvar RKH_SIZE: Size of each root key hash in bytes (32).
    """

    RKHT_SIZE = 4
    RKH_SIZE = 32

    def __init__(
        self,
        rkh_list: list[bytes],
    ) -> None:
        """Initialize Root Key Hash Table with provided key hashes.

        Validates that all provided root key hashes have the correct size before
        creating the table.

        :param rkh_list: List of root key hash bytes, each must be RKH_SIZE length
        :raises SPSDKError: Invalid key hash size detected
        """
        for key_hash in rkh_list:
            if len(key_hash) != self.RKH_SIZE:
                raise SPSDKError(f"Invalid key hash size: {len(key_hash)}")
        super().__init__(rkh_list)

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Get the hash algorithm used for certificate block validation.

        :return: The SHA256 hash algorithm enumeration value.
        """
        return EnumHashAlgorithm.SHA256

    def export(self) -> bytes:
        """Export RKHT as bytes.

        Converts the Root Key Hash Table (RKHT) to its binary representation by concatenating
        all root key hashes. Missing entries are filled with zero bytes to maintain the
        expected table size.

        :raises SPSDKError: Invalid length of exported data.
        :return: Binary representation of the RKHT table.
        """
        rotk_table = b""
        for i in range(self.RKHT_SIZE):
            if i < len(self.rkh_list) and self.rkh_list[i]:
                rotk_table += self.rkh_list[i]
            else:
                rotk_table += bytes(self.RKH_SIZE)
        if len(rotk_table) != self.RKH_SIZE * self.RKHT_SIZE:
            raise SPSDKError("Invalid length of data.")
        return rotk_table

    @classmethod
    def parse(cls, rkht: bytes) -> Self:
        """Parse Root Key Hash Table into RKHTv1 object.

        :param rkht: Valid RKHT table as bytes.
        :return: RKHTv1 object with parsed key hashes.
        """
        rotkh_len = len(rkht) // cls.RKHT_SIZE
        offset = 0
        key_hashes = []
        for _ in range(cls.RKHT_SIZE):
            key_hashes.append(rkht[offset : offset + rotkh_len])
            offset += rotkh_len
        return cls(key_hashes)

    def rkth(self) -> bytes:
        """Root Key Table Hash.

        Computes the hash of the exported root key table using the configured hash algorithm.

        :return: Hash of the exported root key table data.
        """
        rotkh = get_hash(self.export(), self.hash_algorithm)
        return rotkh

    def set_rkh(self, index: int, rkh: bytes) -> None:
        """Set Root Key Hash at specified index in the hash table.

        The method fills gaps with zero-filled hashes if keys are not set consecutively.
        Validates index bounds and hash size consistency.

        :param index: Index in the hash table (0-3).
        :param rkh: Root Key Hash bytes to be set.
        :raises SPSDKError: If index is greater than 3, hash size doesn't match existing
            hashes, or total number of hashes exceeds 4.
        """
        if index > 3:
            raise SPSDKError("Key hash can not be larger than 3.")
        if self.rkh_list and len(rkh) != len(self.rkh_list[0]):
            raise SPSDKError("Root Key Hash must be the same size as other hashes.")
        # fill the gap with zeros if the keys are not consecutive
        for idx in range(index + 1):
            if len(self.rkh_list) < idx + 1:
                self.rkh_list.append(bytes(self.RKH_SIZE))
        if len(self.rkh_list) > 4:
            raise SPSDKError("Number of Root Key Hashes can not be larger than 4.")
        self.rkh_list[index] = rkh

    def __str__(self) -> str:
        """String representation of the Root Key Hash Table.

        :return: Formatted string containing RKHT information and inherited data.
        """
        result = "Root Key Hash Table (RKHTv1):\n"
        result += super().__str__()
        return result


class RKHTv21(RKHT):
    """Root Key Hash Table implementation for certificate block version 2.1.

    This class provides specialized handling of root key hash tables used in
    certificate block v2.1, including parsing, exporting, and hash computation
    functionality for cryptographic key validation.
    """

    def export(self) -> bytes:
        """Export RKHT (Root Key Hash Table) as bytes.

        Concatenates all root key hashes from the RKH list into a single byte array
        for serialization purposes.

        :return: Concatenated root key hashes as bytes, empty if RKH list has one or fewer items.
        """
        hash_table = bytes()
        if len(self.rkh_list) > 1:
            hash_table = bytearray().join(self.rkh_list)
        return bytes(hash_table)

    @classmethod
    def parse(cls, rkht: bytes, hash_algorithm: EnumHashAlgorithm) -> Self:
        """Parse Root Key Hash Table into RKHTv21 object.

        The method validates the RKHT table length against the specified hash algorithm
        and creates a list of root key hashes by splitting the input data.

        :param rkht: Valid RKHT table as bytes.
        :param hash_algorithm: Hash algorithm to be used for validation.
        :raises SPSDKError: If RKHT table length doesn't match the hash algorithm.
        :return: RKHTv21 object containing parsed root key hashes.
        """
        rkh_len = get_hash_length(hash_algorithm)
        if len(rkht) % rkh_len != 0:
            raise SPSDKError(
                f"The length of Root Key Hash Table does not match the hash algorithm {hash_algorithm}"
            )
        offset = 0
        rkh_list = []
        rkht_size = len(rkht) // rkh_len
        for _ in range(rkht_size):
            rkh_list.append(rkht[offset : offset + rkh_len])
            offset += rkh_len
        return cls(rkh_list)

    def rkth(self) -> bytes:
        """Get Root Key Table Hash.

        Computes the hash of the root key table. If only one root key hash exists,
        returns that hash directly. For multiple root key hashes, computes and returns
        the hash of the entire exported root key table.

        :return: Root Key Table Hash as bytes, or empty bytes if no records exist.
        """
        if not self.rkh_list:
            logger.debug("RKHT has no records.")
            return bytes()
        if len(self.rkh_list) == 1:
            rotkh = self.rkh_list[0]
        else:
            rotkh = get_hash(self.export(), self.hash_algorithm)
        return rotkh

    def __str__(self) -> str:
        """String representation of the Root Key Hash Table.

        Provides a formatted string containing the RKHT version information
        and inherited table data for debugging and display purposes.

        :return: Formatted string representation of the RKHT object.
        """
        result = "Root Key Hash Table (RKHTv21):\n"
        result += super().__str__()
        return result

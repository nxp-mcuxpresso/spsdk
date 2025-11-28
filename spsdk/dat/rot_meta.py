#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Root of Trust (RoT) metadata management utilities.

This module provides classes and functionality for handling Root of Trust
metadata in various formats including RSA, ECC, EdgeLock Enclave, and dummy
implementations for secure provisioning operations.
"""

import abc
import logging
import math
from struct import pack
from typing import Type

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.utils import extract_public_key
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKTypeError, SPSDKValueError
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKTable
from spsdk.image.cert_block.cert_blocks import CertBlock, CertBlockV1, CertBlockV21
from spsdk.utils.config import Config
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


class RotMeta:
    """Root of Trust metadata base class.

    This abstract base class defines the interface for managing Root of Trust (RoT)
    metadata in SPSDK. It provides methods for loading, parsing, exporting, and
    calculating hashes of RoT data across different NXP MCU implementations.
    """

    @classmethod
    @abc.abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create the RoT meta from configuration.

        :param config: Configuration object containing RoT metadata settings.
        :return: RotMeta object created from the provided configuration.
        """

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Load RoT meta from certificate block.

        This method is not supported for this RoT meta type and will always raise an exception.

        :param cert_block: Certificate block to load from.
        :raises SPSDKError: Always raised as this operation is not supported.
        """
        raise SPSDKError(f"The {cls.__name__} does not support loading from certificate block.")

    @classmethod
    @abc.abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the RotMeta object from binary data.

        :param data: Raw binary data to parse into RotMeta object.
        :return: Parsed RotMeta object instance.
        """

    @abc.abstractmethod
    def export(self) -> bytes:
        """Export to binary form.

        :return: Binary representation of the object.
        """

    @abc.abstractmethod
    def calculate_hash(self) -> bytes:
        """Calculate the hash of Root Of Trust keys.

        This method computes the cryptographic hash of the Root Of Trust keys
        that are used for secure boot verification.

        :return: Root Of Trust Keys Hash (RoTKH) as bytes.
        """

    @abc.abstractmethod
    def __str__(self) -> str:
        """Get object description in string format.

        :return: String representation of the object.
        """

    def __len__(self) -> int:
        """Get the length of exported data.

        :return: Number of bytes in the exported data.
        """
        return len(self.export())


class RotMetaRSA(RotMeta):
    """RSA Root of Trust metadata container.

    This class manages RSA-based Root of Trust metadata including public key
    hashes and provides functionality for configuration loading, parsing, and
    validation of RSA RoT structures used in secure provisioning operations.
    """

    def __init__(self, rot_items: list[bytes]) -> None:
        """Initialize Root of Trust metadata object.

        :param rot_items: List of public key hashes as bytes objects.
        """
        self.rot_items = rot_items

    def __str__(self) -> str:
        """Return string representation of RSA RoT metadata.

        Provides a formatted string containing information about the RSA Root of Trust
        metadata, including the number of RoT items.

        :return: Formatted string with RSA RoT metadata information.
        """
        msg = "RSA RoT meta"
        msg += f"Number of RoT items   : {len(self.rot_items)}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        Compare this RotMetaRSA instance with another object to determine if they are equal.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(obj, RotMetaRSA) and self.rot_items == obj.rot_items

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        Loads Root of Trust metadata by extracting RSA public keys from the provided
        configuration and computing their hashes.

        :param config: Configuration object containing rot_meta list with key file paths.
        :raises SPSDKValueError: If more than 4 RoT public keys are provided.
        :return: RotMetaRSA object with loaded RoT metadata.
        """
        rot_pub_keys = config.get_list("rot_meta")
        if len(rot_pub_keys) > 4:
            raise SPSDKValueError("The maximum number of rot public keys is 4.")
        rot_items = []
        for rot_key in rot_pub_keys:
            rot = extract_public_key(
                file_path=rot_key, password=None, search_paths=config.search_paths
            )
            assert isinstance(rot, PublicKeyRsa)
            data = rot.export(exp_length=3)
            rot_item = get_hash(data)
            rot_items.append(rot_item)
        return cls(rot_items)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the RotMetaRSA object from binary data.

        The method extracts up to 4 ROT (Root of Trust) items from the provided 128-byte data buffer.
        Each ROT item is 32 bytes long and only non-zero items are included in the result.

        :param data: Raw binary data containing ROT metadata, must be exactly 128 bytes
        :raises SPSDKValueError: If the provided data is less than 128 bytes long
        :return: RotMetaRSA object containing parsed ROT items
        """
        if len(data) < 128:
            raise SPSDKValueError("The provided data must be 128 bytes long.")
        rot_items = []
        for index in range(0, 4):
            rot_item = data[index * 32 : (index + 1) * 32]
            if int.from_bytes(rot_item, Endianness.LITTLE.value):
                rot_items.append(rot_item)
        return cls(rot_items)

    def export(self) -> bytes:
        """Export RoT metadata to binary representation.

        Converts the Root of Trust metadata items into a 128-byte binary format where each
        RoT item occupies 32 bytes in sequential order.

        :return: 128-byte binary representation of the RoT metadata.
        """
        rot_meta = bytearray(128)
        for index, rot_item in enumerate(self.rot_items):
            rot_meta[index * 32 : (index + 1) * 32] = rot_item
        return bytes(rot_meta)

    def calculate_hash(self) -> bytes:
        """Calculate the hash of the Root of Trust keys.

        This method computes the hash value for all Root of Trust keys by first
        exporting the current RoT configuration and then calculating its hash using
        the configured hash algorithm.

        :return: Root of Trust Keys Hash (RoTKH) as bytes.
        """
        return get_hash(data=self.export())

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Creates the RoT meta from certificate block.

        The method extracts Root of Trust metadata from a certificate block and creates
        a new RotMetaRSA object with the root key hashes.

        :param cert_block: Certificate block to extract Root of Trust metadata from
        :raises SPSDKTypeError: Invalid certificate block type, only CertBlockV1 is supported
        :raises SPSDKValueError: Certificate block has no root key hashes
        :return: RotMetaRSA object
        """
        if not isinstance(cert_block, CertBlockV1):
            raise SPSDKTypeError(
                f"Invalid certificate block type. Only {CertBlockV1.__name__} is supported."
            )

        rot_items = [bytes(rkh) for rkh in cert_block.rkh]
        if not rot_items:
            raise SPSDKValueError("Certificate block has no root key hashes")

        return cls(rot_items)


class RotMetaFlags:
    """Root of Trust metadata flags container.

    This class manages flags that specify which root certificate is used
    and the total count of certificates in the Root of Trust metadata.
    It provides functionality for validation, binary parsing, and export
    operations for DAT (Debug Authentication Tool) operations.
    """

    def __init__(self, used_root_cert: int, cnt_root_cert: int) -> None:
        """Initialize RoT metadata object.

        :param used_root_cert: Index of used root certificate
        :param cnt_root_cert: Number of certificates in the RoT meta
        """
        self.used_root_cert = used_root_cert
        self.cnt_root_cert = cnt_root_cert
        self.validate()

    def validate(self) -> None:
        """Validate the root certificate flags.

        Validates that the certificate count and used certificate index are within
        valid ranges. The maximum number of certificates is 4, and the used root
        certificate index must be within the available certificate range.

        :raises SPSDKValueError: If certificate count exceeds 4 or used certificate
            index is out of range.
        """
        if self.cnt_root_cert > 4:
            raise SPSDKValueError("The maximum number of certificates is 4")
        if self.used_root_cert + 1 > self.cnt_root_cert:
            raise SPSDKValueError(
                f"Used root certificate {self.used_root_cert} must be in range 0-{self.cnt_root_cert-1}."
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse flags from binary data.

        The method extracts used root certificate count and total root certificate count
        from 4-byte binary data with specific format validation.

        :param data: Raw binary data containing flags (must be exactly 4 bytes).
        :raises SPSDKValueError: Invalid data length or invalid flags format.
        :return: The RotMetaFlags object with parsed certificate counts.
        """
        if len(data) != 4:
            raise SPSDKValueError("Invalid data flags length to parse")
        flags = int.from_bytes(data, "little")
        if not flags & (1 << 31):
            raise SPSDKValueError("Invalid flags format to parse")
        used_root_cert = (flags >> 8) & 0x0F
        cnt_root_cert = (flags >> 4) & 0x0F
        return cls(used_root_cert, cnt_root_cert)

    def export(self) -> bytes:
        """Export to binary form.

        Converts the object to its binary representation by packing the flags field
        which contains the used root certificate index, root certificate count,
        and control bits into a 4-byte little-endian format.

        :return: Binary representation of the object as bytes.
        """
        flags = 0
        flags |= 1 << 31
        flags |= self.used_root_cert << 8
        flags |= self.cnt_root_cert << 4
        return pack("<L", flags)

    def __str__(self) -> str:
        """Get string representation of the root certificate metadata.

        Provides a formatted string containing information about the used root certificate
        index and the total number of records in flags.

        :return: Formatted string with root certificate metadata information.
        """
        msg = f"Used root cert index: {self.used_root_cert}\n"
        msg = f"Number of records in flags: {self.cnt_root_cert}\n"
        return msg

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        Compare this RotMetaFlags instance with another object to determine if they are equal.

        :param obj: Object to compare with.
        :return: True if objects are equal, False otherwise.
        """
        return (
            isinstance(obj, RotMetaFlags)
            and self.used_root_cert == obj.used_root_cert
            and self.cnt_root_cert == obj.cnt_root_cert
        )

    def __len__(self) -> int:
        """Get the length of the exported data.

        Returns the number of bytes in the exported representation of this object.

        :return: Length of the exported data in bytes.
        """
        return len(self.export())


class RotMetaEcc(RotMeta):
    """ECC Root of Trust metadata manager.

    This class manages ECC-based Root of Trust metadata including public key hashes,
    flags, and CRTK (Certificate Root Table Key) operations for secure provisioning.

    :cvar HASH_SIZES: Mapping of hash lengths to corresponding bit sizes.
    :cvar HASH_SIZE: Hash size in bytes, overridden by derived classes.
    """

    HASH_SIZES = {32: 256, 48: 384, 66: 512}
    HASH_SIZE = 0  # to be overridden by derived class

    def __init__(self, flags: RotMetaFlags, rot_items: list[bytes]) -> None:
        """Initialize RotMeta object with flags and rotation items.

        :param flags: RotMetaFlags object containing metadata flags
        :param rot_items: List of public key hashes as bytes
        """
        self.flags = flags
        self.rot_items = rot_items

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        Compares this RotMetaEcc instance with another object to determine if they are equal.
        Objects are considered equal if they are both RotMetaEcc instances with matching
        flags and rot_items attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEcc)
            and self.flags == obj.flags
            and self.rot_items == obj.rot_items
        )

    def __str__(self) -> str:
        """Get string representation of RoT metadata.

        Provides information about the flags and CRTK table status, including the number
        of root certificate entries.

        :return: Formatted string describing the RoT metadata flags and CRTK table status.
        """
        msg = str(self.flags)
        if self.flags.cnt_root_cert == 1:
            msg += "CRTK table not present \n"
        else:
            msg += f"CRTK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @property
    def key_size(self) -> int:
        """Get the key size in bytes for the root certificate.

        The key size is calculated based on the total length of the metadata,
        excluding flags, divided by the number of root certificates.

        :return: Key size in bytes as determined from HASH_SIZES mapping.
        """
        return self.HASH_SIZES[(len(self) - len(self.flags)) // self.flags.cnt_root_cert]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        Loads public keys from configuration, determines hash size, and creates appropriate
        RoT metadata with flags and hashed key items for multi-key scenarios.

        :param config: Configuration object containing RoT settings and public keys.
        :return: RotMetaEcc object instance with configured flags and key items.
        """
        rot_pub_keys = cls._load_public_keys(config)
        hash_size = cls._get_hash_size(config)
        klass = cls._get_subclass(hash_size)
        rot_items: list[bytes] = []
        if len(rot_pub_keys) > 1:
            for pub_key in rot_pub_keys:
                data = pub_key.export()
                rot_items.append(
                    get_hash(
                        data=data,
                        algorithm=EnumHashAlgorithm.from_label(f"sha{cls.HASH_SIZES[hash_size]}"),
                    )
                )
        flags = RotMetaFlags(config.get_int("rot_id"), len(rot_pub_keys))
        return klass(flags, rot_items)  # type: ignore

    def export(self) -> bytes:
        """Export the RoT metadata to binary format.

        This method serializes the Root of Trust metadata by combining the exported
        flags with the CRTK (Certificate Root Trust Key) table data.

        :return: Binary representation of the RoT metadata object.
        """
        return self.flags.export() + self.export_crtk_table()

    def export_crtk_table(self) -> bytes:
        """Export CRTK table into binary form.

        Concatenates all ROT items into a single binary table if there are multiple items.

        :return: Binary representation of the CRTK table, empty bytes if single or no ROT items.
        """
        ctrk_table = b""
        if len(self.rot_items) > 1:
            for rot_item in self.rot_items:
                ctrk_table += rot_item
        return ctrk_table

    def calculate_hash(self) -> bytes:
        """Calculate hash of the CRKT table.

        The method exports the CRKT table and calculates its hash using SHA algorithm
        with key size matching the configured key size.

        :raises SPSDKError: When CRKT table is empty and hash cannot be calculated.
        :return: CRKT table hash in bytes.
        """
        crkt_table = self.export_crtk_table()
        if not crkt_table:
            raise SPSDKError("Hash cannot be calculated as crkt table is empty")
        return get_hash(
            data=crkt_table,
            algorithm=EnumHashAlgorithm.from_label(f"sha{self.key_size}"),
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        Parses binary data to create a RotMetaEcc object by extracting flags and root certificate
        table information.

        :param data: Raw binary data containing flags and certificate table
        :raises SPSDKValueError: Hash size not defined
        :return: Parsed RotMetaEcc object
        """
        if not cls.HASH_SIZE:
            raise SPSDKValueError("Hash size not defined.")
        flags = RotMetaFlags.parse(data[:4])
        crt_table = data[4:]
        rot_items = []
        if flags.cnt_root_cert > 1:
            for rot_item_idx in range(0, flags.cnt_root_cert):
                rot_item = crt_table[
                    rot_item_idx * cls.HASH_SIZE : (rot_item_idx + 1) * cls.HASH_SIZE
                ]
                rot_items.append(rot_item)
        return cls(flags, rot_items)

    @classmethod
    def _load_public_keys(cls, config: Config) -> list[PublicKeyEcc]:
        """Load public keys from configuration.

        Extracts and validates ECC public keys from the specified configuration paths.
        All keys must be of ECC type for successful loading.

        :param config: Configuration object containing public key paths and search paths.
        :raises SPSDKValueError: At least one public key must be specified.
        :raises SPSDKTypeError: Public key must be of ECC type.
        :return: List of loaded ECC public keys.
        """
        pub_key_paths = config.get_list("rot_meta")
        if len(pub_key_paths) < 1:
            raise SPSDKValueError("At least one public key must be specified.")
        pub_keys: list[PublicKeyEcc] = []
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=config.search_paths
            )
            if not isinstance(pub_key, PublicKeyEcc):
                raise SPSDKTypeError("Public key must be of ECC type.")
            pub_keys.append(pub_key)
        return pub_keys

    @classmethod
    def _get_hash_size(cls, config: Config) -> int:
        """Get hash size from ROT metadata configuration.

        Extracts public keys from the provided configuration and determines the hash size
        based on the key size. All public keys must have the same length.

        :param config: Configuration object containing ROT metadata with public key paths.
        :raises SPSDKValueError: When public keys have different lengths.
        :raises SPSDKError: When hash size cannot be determined.
        :return: Hash size in bytes calculated from public key size.
        """
        hash_size = None
        pub_key_paths = config.get_list("rot_meta")
        for pub_key_path in pub_key_paths:
            pub_key = extract_public_key(
                file_path=pub_key_path, password=None, search_paths=config.search_paths
            )
            assert isinstance(pub_key, PublicKeyEcc)
            if not hash_size:
                hash_size = math.ceil(pub_key.key_size / 8)
            if hash_size != math.ceil(pub_key.key_size / 8):
                raise SPSDKValueError("All public keys must be of a same length")
        if not hash_size:
            raise SPSDKError("Hash size could not be determined.")
        return hash_size

    @classmethod
    def _get_subclass(cls, hash_size: int) -> Type["RotMetaEcc"]:
        """Get the subclass with given hash algorithm.

        Searches through available RotMetaEcc subclasses to find one that matches
        the specified hash size.

        :param hash_size: Size of the hash algorithm in bytes.
        :raises SPSDKValueError: When no subclass with the specified hash size exists.
        :return: The RotMetaEcc subclass that supports the given hash size.
        """
        subclasses: list[Type[RotMetaEcc]] = cls._build_subclasses()
        for subclass in subclasses:
            if subclass.HASH_SIZE == hash_size:
                return subclass
        raise SPSDKValueError(f"The subclass with hash length {hash_size} does not exist.")

    @classmethod
    def _build_subclasses(cls) -> list[Type["RotMetaEcc"]]:
        """Dynamically build list of classes based on hash algorithm.

        Creates subclasses of RotMetaEcc for each hash algorithm defined in HASH_SIZES,
        with each subclass having its own HASH_SIZE attribute.

        :return: List of dynamically created RotMetaEcc subclasses.
        """
        rot_meta_types = []
        for hash_size, hash_algo in cls.HASH_SIZES.items():
            subclass = type(f"RotMetaEcc{hash_algo}", (RotMetaEcc,), {"HASH_SIZE": hash_size})
            rot_meta_types.append(subclass)
        return rot_meta_types

    @classmethod
    def load_from_cert_block(cls, cert_block: CertBlock) -> Self:
        """Creates the RoT meta from certificate block.

        The method extracts Root of Trust metadata from a certificate block and creates
        the appropriate subclass instance based on the hash size found in the certificate
        block's root key hash table.

        :param cert_block: Certificate block to extract Root of Trust metadata from
        :raises SPSDKTypeError: When an unsupported certificate block type is provided
        :return: RotMetaEdgeLockEnclave object
        """
        if not isinstance(cert_block, CertBlockV21):
            raise SPSDKTypeError(
                f"Invalid certificate block type. Only {CertBlockV21.__name__} is supported."
            )
        # Get the right subclass based on hash size
        subclass = cls._get_subclass(len(cert_block.root_key_record._rkht.rkh_list[0]))
        flags = RotMetaFlags(
            cert_block.root_key_record.used_root_cert,
            cert_block.root_key_record.number_of_certificates,
        )

        return subclass(flags, cert_block.root_key_record._rkht.rkh_list)  # type: ignore


class RotMetaEdgeLockEnclave(RotMeta):
    """EdgeLock Enclave Root of Trust metadata container.

    This class manages RoT (Root of Trust) metadata specifically for EdgeLock Enclave
    devices, including flags configuration and SRK (Super Root Key) table management.
    It provides functionality for parsing binary data, loading from configuration,
    and validating the integrity of the RoT metadata structure.
    """

    def __init__(self, flags: RotMetaFlags, srk_table: SRKTable) -> None:
        """Initialize RotMeta object with flags and SRK table.

        :param flags: RotMetaFlags object containing rotation metadata flags
        :param srk_table: SRKTable object containing Super Root Key table data
        """
        self.flags = flags
        self.srk_table = srk_table

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        Compare this RotMetaEdgeLockEnclave instance with another object to determine if they are equal.
        Objects are considered equal if they are both RotMetaEdgeLockEnclave instances with matching
        flags and srk_table attributes.

        :param obj: Object to compare with this instance.
        :return: True if objects are equal, False otherwise.
        """
        return (
            isinstance(obj, RotMetaEdgeLockEnclave)
            and self.flags == obj.flags
            and self.srk_table == obj.srk_table
        )

    def __str__(self) -> str:
        """Return string representation of the RoT metadata.

        Provides a formatted string containing the flags information and validation
        of the SRK (Super Root Key) table entries count.

        :return: Formatted string with flags and SRK table validation status.
        """
        msg = str(self.flags)
        if self.flags.cnt_root_cert != 4:
            msg += "Invalid count of SRK records \n"
        else:
            msg += f"SRK table has {self.flags.cnt_root_cert} entries\n"
        return msg

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        Creates a RotMetaEdgeLockEnclave instance by parsing the provided binary data,
        extracting flags and SRK table information.

        :param data: Raw binary data containing flags and SRK table information
        :raises SPSDKError: Invalid data format or SRK table verification failure
        :return: RotMetaEdgeLockEnclave object
        """
        flags = RotMetaFlags.parse(data[:4])
        srk_table = SRKTable.parse(data[4:])
        srk_table.verify().validate()
        return cls(flags, srk_table)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        The method parses configuration data to create a RotMetaEdgeLockEnclave object with
        proper flags and SRK table containing exactly 4 Super Root keys.

        :param config: Configuration object containing rot_meta, rot_id, and optional flag_ca.
        :raises SPSDKValueError: Invalid count of Super Root keys (must be exactly 4).
        :return: RotMetaEdgeLockEnclave object with configured flags and SRK table.
        """
        rot_pub_keys = config.get_list("rot_meta")
        flags = RotMetaFlags(config.get_int("rot_id"), len(rot_pub_keys))
        if len(rot_pub_keys) != 4:
            raise SPSDKValueError("Invalid count of Super Root keys.")
        flag_ca = config.get("flag_ca", False)
        srk_flags = 0
        if flag_ca:
            srk_flags |= SRKRecord.FLAGS_CA_MASK

        srk_table = SRKTable(
            [
                SRKRecord.create_from_key(
                    extract_public_key(x, search_paths=config.search_paths), srk_flags=srk_flags
                )
                for x in rot_pub_keys
            ]
        )
        srk_table.update_fields()
        srk_table.verify().validate()
        return cls(flags, srk_table)

    def export(self) -> bytes:
        """Export the RoT metadata to binary representation.

        Combines the flags and SRK table data into a single binary format suitable
        for device provisioning or storage.

        :return: Binary representation containing exported flags and SRK table data.
        """
        return self.flags.export() + self.srk_table.export()

    def calculate_hash(self) -> bytes:
        """Calculate SRK table hash.

        This method updates the SRK table fields and computes the cryptographic hash
        of the SRK (Super Root Key) table used for secure boot verification.

        :return: SRK table hash in bytes.
        """
        self.srk_table.update_fields()
        return self.srk_table.compute_srk_hash()


class RotMetaDummy(RotMeta):
    """SPSDK Root of Trust metadata dummy implementation.

    This class provides a placeholder implementation of the RotMeta interface
    that raises SPSDKNotImplementedError for all operations. It serves as a
    stub for testing or as a base for future implementations where RoT
    metadata functionality is not yet required.
    """

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates the RoT meta from configuration.

        :param config: Configuration object containing RoT metadata settings.
        :raises SPSDKNotImplementedError: Method is not yet implemented.
        """
        raise SPSDKNotImplementedError()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the object from binary data.

        :param data: Binary data to parse the object from.
        :raises SPSDKNotImplementedError: Method not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    def export(self) -> bytes:
        """Export to binary form.

        :raises SPSDKNotImplementedError: Method not implemented.
        """
        raise SPSDKNotImplementedError()

    def calculate_hash(self) -> bytes:
        """Calculate Root Of Trust Keys Hash.

        This method computes the hash value for the Root Of Trust keys used in
        secure provisioning operations.

        :raises SPSDKNotImplementedError: Method is not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    def __str__(self) -> str:
        """Get string representation of the RoT Meta object.

        :return: String description of the object.
        """
        return "Dummy RoT Meta class"

    def __len__(self) -> int:
        """Get the length of exported data.

        :return: Length of the exported data in bytes.
        """
        return 0

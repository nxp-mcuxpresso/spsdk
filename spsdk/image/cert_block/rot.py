#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Root of Trust (RoT) hash calculation and certificate block management.

This module provides functionality for calculating RoT hashes and managing
certificate blocks across different NXP MCU families. It supports various
RoT implementations including HAB and AHAB certificate blocks with different
versions and SRK table formats.
"""


from abc import abstractmethod
from typing import Optional, Sequence, Type, Union

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.keys import PrivateKey, PublicKey
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.image.ahab.ahab_srk import SRKRecord, SRKRecordV2
from spsdk.image.ahab.ahab_srk import SRKTable as AhabSrkTable
from spsdk.image.ahab.ahab_srk import SRKTableV2 as AhabSrkTableV2
from spsdk.image.cert_block.rkht import RKHT, RKHTv1, RKHTv21
from spsdk.image.hab.hab_srk import SrkItem as HabSrkItem
from spsdk.image.hab.hab_srk import SrkTable as HabSrkTable
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import load_binary


class Rot:
    """Root of Trust abstraction for certificate block operations.

    This class provides a unified interface for Root of Trust hash calculation and export
    operations across multiple NXP device families. It automatically selects the appropriate
    RoT implementation based on the target device family and manages the underlying RoT
    object lifecycle.
    """

    def __init__(
        self,
        family: FamilyRevision,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize Root of Trust object.

        Creates a Root of Trust instance using the appropriate class based on the specified
        family revision and provided cryptographic materials.

        :param family: Target MCU family and revision specification.
        :param keys_or_certs: Sequence of cryptographic materials (file paths, raw data,
            or cryptographic objects) to be used for Root of Trust.
        :param password: Optional password for encrypted private keys.
        :param search_paths: Optional list of directories to search for key/certificate files.
        """
        self.rot_obj = self.get_rot_class(family)(
            keys_or_certs=keys_or_certs, password=password, search_paths=search_paths
        )

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash.

        :return: Hash of the Root of Trust object as bytes.
        """
        return self.rot_obj.calculate_hash()

    def export(self) -> bytes:
        """Export RoT (Root of Trust) data.

        :return: Exported RoT data as bytes.
        """
        return self.rot_obj.export()

    def __str__(self) -> str:
        """Return string representation of the RoT object.

        :return: String representation of the underlying RoT object.
        """
        return str(self.rot_obj)

    @classmethod
    def parse(cls, family: FamilyRevision, data: bytes) -> "Rot":
        """Parse RoT from binary data."""
        rot_class = cls.get_rot_class(family)
        rot_obj = rot_class.parse(data)
        instance = cls.__new__(cls)
        instance.rot_obj = rot_obj
        return instance

    @classmethod
    def get_supported_families(cls) -> list[FamilyRevision]:
        """Get all supported families for certificate block.

        :return: List of supported family revisions for certificate block operations.
        """
        return get_families(DatabaseManager.CERT_BLOCK)

    @classmethod
    def get_rot_class(cls, family: FamilyRevision) -> Type["RotBase"]:
        """Get RoT class for the specified family.

        Retrieves the appropriate Root of Trust (RoT) class based on the family revision
        by querying the database for the RoT type configuration.

        :param family: Family revision to get RoT class for.
        :return: RoT class type for the specified family.
        """
        db = get_db(family)
        rot_type = db.get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        return RotBase.get_rot_class(rot_type)


class RotBase:
    """Root of Trust base class for certificate block operations.

    This abstract base class provides a foundation for implementing different types of Root of Trust
    (RoT) mechanisms used in secure boot and certificate validation. It manages cryptographic keys
    and certificates, and provides a registry system for different RoT implementations.

    :cvar rot_type: Identifier for the specific RoT implementation type.
    :cvar _registry: Registry mapping RoT type strings to their implementation classes.
    """

    rot_type: Optional[str] = None
    _registry: dict[str, Type["RotBase"]] = {}

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize Root of Trust (RoT) with cryptographic keys or certificates.

        The RoT manages a collection of cryptographic materials that can be provided
        as file paths, raw data, or cryptographic objects for certificate block creation.

        :param keys_or_certs: Collection of keys or certificates as file paths, raw data,
            or cryptographic objects (PublicKey, PrivateKey, Certificate).
        :param password: Optional password for encrypted key files.
        :param search_paths: Optional list of directories to search for key/certificate files.
        """
        self.keys_or_certs = keys_or_certs
        self.password = password
        self.search_paths = search_paths

    @classmethod
    def register(cls, rot_class: Type["RotBase"]) -> Type["RotBase"]:
        """Register a RoT implementation class.

        Registers a Root of Trust (RoT) implementation class in the internal registry
        for later retrieval and instantiation based on RoT type.

        :param rot_class: The RoT implementation class to register.
        :return: The same RoT class that was registered.
        """
        if rot_class.rot_type:
            cls._registry[rot_class.rot_type] = rot_class
        return rot_class

    @classmethod
    def get_rot_class(cls, rot_type: str) -> Type["RotBase"]:
        """Get RoT implementation by type.

        Retrieves the RoT (Root of Trust) class implementation based on the specified type
        from the internal registry.

        :param rot_type: The type identifier of the RoT implementation to retrieve.
        :raises SPSDKError: When the specified RoT type does not exist in the registry.
        :return: The RoT class implementation corresponding to the specified type.
        """
        if rot_type not in cls._registry:
            raise SPSDKError(f"A RoT type {rot_type} does not exist.")
        return cls._registry[rot_type]

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> "RotBase":
        """Parse RoT from binary data."""

    @abstractmethod
    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate RoT hash.

        Computes the hash value for the Root of Trust (RoT) data structure
        using the configured hash algorithm.

        :return: Hash bytes of the RoT data.
        """

    @abstractmethod
    def export(self) -> bytes:
        """Export the RoT table as binary data.

        Serializes the Root of Trust (RoT) table into its binary representation
        for use in secure boot processes.

        :return: Binary representation of the RoT table.
        """

    @abstractmethod
    def __str__(self) -> str:
        """Return string representation of the RoT object.

        :return: String representation containing RoT configuration details.
        """


@RotBase.register
class RotCertBlockv1(RotBase):
    """Root of Trust implementation for certificate block version 1.

    This class provides Root of Trust functionality specifically for certificate block
    version 1 format, managing cryptographic keys and certificates used in secure boot
    operations. It handles RKHT (Root Key Hash Table) generation and RoT hash calculation
    for NXP MCU secure provisioning.

    :cvar rot_type: Identifier for certificate block v1 RoT type.
    """

    rot_type = "cert_block_1"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize RoT certificate block version 1.

        Creates a new RoT (Root of Trust) certificate block v1 instance with the provided
        keys or certificates and generates the corresponding RKHT (Root Key Hash Table) v1.

        :param keys_or_certs: Sequence of keys or certificates as file paths, raw data, or objects.
        :param password: Optional password for encrypted private keys.
        :param search_paths: Optional list of directories to search for key/certificate files.
        :raises SPSDKError: If RKHT creation fails or invalid keys/certificates provided.
        """
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv1.from_keys(self.keys_or_certs, self.password, self.search_paths)

    @classmethod
    def parse(cls, data: bytes) -> "RotCertBlockv1":
        """Parse RoT from binary data."""
        raise SPSDKNotImplementedError("Parsing for RotCertBlockv1 is not implemented.")

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate RoT hash.

        Computes the hash value for the Root of Trust using the internal RKHT (Root Key Hash Table).

        :return: Hash bytes of the Root of Trust.
        """
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export the Root of Trust (RoT) data as bytes.

        :return: Binary representation of the RoT hash table data.
        """
        return self.rkht.export()

    def __str__(self) -> str:
        """Return string representation of the RoT (Root of Trust).

        :return: String representation of the RKHT (Root Key Hash Table).
        """
        return str(self.rkht)


@RotBase.register
class RotCertBlockv21(RotBase):
    """Root of Trust implementation for certificate block version 2.1.

    This class provides Root of Trust functionality specifically designed for certificate
    block version 2.1, managing cryptographic keys and certificates used in secure boot
    processes. It handles RKHT (Root Key Hash Table) generation and RoT hash calculations
    for NXP MCU secure provisioning.

    :cvar rot_type: Identifier for certificate block v21 RoT type.
    """

    rot_type = "cert_block_21"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize RoT certificate block v21.

        Creates a new instance of the RoT (Root of Trust) certificate block version 21
        with the provided keys or certificates and generates the corresponding RKHT.

        :param keys_or_certs: Sequence of keys or certificates as file paths, raw data,
            or cryptographic objects (PublicKey, PrivateKey, Certificate).
        :param password: Optional password for encrypted private keys.
        :param search_paths: Optional list of additional paths to search for key/cert files.
        :raises SPSDKError: If RKHT creation fails or invalid keys/certificates provided.
        """
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv21.from_keys(self.keys_or_certs, self.password, self.search_paths)

    @classmethod
    def parse(cls, data: bytes) -> "RotCertBlockv21":
        """Parse RoT from binary data."""
        raise SPSDKNotImplementedError("Parsing for RotCertBlockv21 is not implemented.")

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate RoT hash."""
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export Root of Trust (RoT) data to binary format.

        :return: Binary representation of the RoT data structure.
        """
        return self.rkht.export()

    def __str__(self) -> str:
        """Return string representation of the RoT (Root of Trust).

        :return: String representation of the RKHT (Root Key Hash Table).
        """
        return str(self.rkht)


@RotBase.register
class RotSrkTableAhab(RotBase):
    """Root of Trust implementation for AHAB SRK Table operations.

    This class manages the creation and validation of Super Root Key (SRK) tables
    specifically for AHAB (Advanced High Assurance Boot) secure boot operations.
    It handles key conversion, SRK record creation, and provides hash calculation
    and export functionality for the root of trust.

    :cvar rot_type: Identifier for AHAB SRK table root of trust type.
    """

    rot_type = "srk_table_ahab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize AHAB SRK table with provided keys or certificates.

        Creates an AHAB SRK (Super Root Key) table from the provided sequence of keys
        or certificates. The keys are converted to the appropriate format and used to
        create SRK records. The table is then validated for errors.

        :param keys_or_certs: Sequence of keys or certificates in various formats
            (file paths, raw data, or cryptographic objects).
        :param password: Optional password for encrypted keys.
        :param search_paths: Optional list of paths to search for key files.
        :raises SPSDKError: If the SRK table validation fails.
        """
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = AhabSrkTable(
            [
                SRKRecord.create_from_key(RKHT.convert_key(key, password, search_paths))
                for key in keys_or_certs
            ]
        )
        self.srk.update_fields()
        verifier = self.srk.verify()
        if verifier.has_errors:  # Check for errors
            raise SPSDKError(verifier.draw())

    @classmethod
    def parse(cls, data: bytes) -> "RotSrkTableAhab":
        """Parse RoT from binary data."""
        instance = cls.__new__(cls)
        instance.password = None
        instance.search_paths = None
        instance.srk = AhabSrkTable.parse(data)
        # Extract public keys from parsed SRK records
        instance.keys_or_certs = [
            record.get_public_key()
            for record in instance.srk.srk_records
            if hasattr(record, "get_public_key")
        ]
        return instance

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash.

        Computes the hash of the Root of Trust (RoT) by delegating to the SRK
        (Super Root Key) hash calculation method.

        :return: The computed RoT hash as bytes.
        """
        return self.srk.compute_srk_hash()

    def export(self) -> bytes:
        """Export Root of Trust (RoT) data.

        :return: Exported RoT data as bytes.
        """
        return self.srk.export()

    def __str__(self) -> str:
        return str(self.srk)


@RotBase.register
class RotSrkTableAhabV2(RotBase):
    """SPSDK Root of Trust implementation for AHAB SRK Table version 2.

    This class manages the creation and validation of Root of Trust structures
    specifically for AHAB (Advanced High Assurance Boot) SRK (Super Root Key)
    Table version 2. It handles key processing, hash calculation, and export
    functionality for secure boot operations.

    :cvar rot_type: Identifier for this Root of Trust type.
    """

    rot_type = "srk_table_ahab_v2"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize AHAB SRK table with provided keys or certificates.

        Creates an AHAB SRK (Super Root Key) table from a sequence of keys or certificates,
        processes them into SRK records, and validates the resulting table structure.

        :param keys_or_certs: Sequence of keys or certificates in various formats (file paths,
            raw data, or key/certificate objects) to be included in the SRK table.
        :param password: Optional password for encrypted key files.
        :param search_paths: Optional list of directory paths to search for key/certificate files.
        :raises SPSDKError: If the created SRK table fails validation.
        """
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = AhabSrkTableV2(
            [
                SRKRecordV2.create_from_key(
                    RKHT.convert_key(key, password, search_paths), srk_id=key_id
                )
                for key_id, key in enumerate(keys_or_certs)
            ]
        )
        self.srk.update_fields()
        verifier = self.srk.verify()
        if verifier.has_errors:  # Check for errors
            raise SPSDKError(verifier.draw())

    @classmethod
    def parse(cls, data: bytes) -> "RotSrkTableAhabV2":
        """Parse RoT from binary data for AHAB SRK Table version 2."""
        raise SPSDKNotImplementedError("Parsing for AHAB v2 SRK Table is not implemented.")

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash.

        Computes the hash of the Root of Trust (RoT) by delegating to the SRK
        (Super Root Key) hash calculation method.

        :return: The computed RoT hash as bytes.
        """
        return self.srk.compute_srk_hash()

    def export(self) -> bytes:
        """Export Root of Trust (RoT) data.

        :return: Exported RoT data as bytes.
        """
        return self.srk.export()

    def __str__(self) -> str:
        """Get string representation of the RoT object.

        :return: String representation of the SRK (Super Root Key).
        """
        return str(self.srk)


@RotBase.register
class RotSrkTableAhabV2_48Bytes(RotSrkTableAhabV2):
    """AHAB Root of Trust SRK Table with 48-byte hash truncation.

    This class extends the standard AHAB v2 SRK table implementation to provide
    a variant that truncates the calculated hash to 48 bytes instead of the
    full hash length, meeting specific hardware or protocol requirements.

    :cvar rot_type: Identifier for this RoT variant type.
    """

    rot_type = "srk_table_ahab_v2_48_bytes"

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash.

        Computes the hash value for the Root of Trust (RoT) by calling the parent
        class hash calculation method and truncating the result to 48 bytes.

        :return: First 48 bytes of the calculated hash.
        """
        return super().calculate_hash()[:48]


@RotBase.register
class RotSrkTableHab(RotBase):
    """Root of Trust implementation for HAB (High Assurance Boot) SRK Table.

    This class manages the creation and processing of SRK (Super Root Key) tables
    used in HAB-based secure boot implementations. It handles certificate loading,
    SRK item creation, and hash calculation for root of trust establishment.

    :cvar rot_type: Identifier for HAB SRK table root of trust type.
    """

    rot_type = "srk_table_hab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
    ) -> None:
        """Initialize HAB SRK table with certificates or keys.

        Creates a HAB (High Assurance Boot) SRK (Super Root Key) table from the provided
        certificates or keys. All inputs must be valid certificates for HAB RoT calculation.

        :param keys_or_certs: Sequence of certificates or keys as file paths, raw data, or
            cryptographic objects
        :param password: Optional password for encrypted certificate files
        :param search_paths: Optional list of directories to search for certificate files
        :raises SPSDKError: When unable to load certificate or when non-certificate object
            is provided
        """
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = HabSrkTable()
        for certificate in keys_or_certs:
            if isinstance(certificate, (str, bytes, bytearray)):
                try:
                    certificate = self._load_certificate(certificate, search_paths)
                except SPSDKError as exc:
                    raise SPSDKError(
                        "Unable to load certificate. Certificate must be provided for HAB RoT calculation."
                    ) from exc
            if not isinstance(certificate, Certificate):
                raise SPSDKError("Certificate must be provided for HAB RoT calculation.")
            item = HabSrkItem.from_certificate(certificate)
            self.srk.append(item)

    @classmethod
    def parse(cls, data: bytes) -> "RotSrkTableHab":
        """Parse RoT from binary data."""
        raise SPSDKNotImplementedError("Parsing for HAB table is not implemented.")

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash.

        The method calculates the Root of Trust hash by exporting the SRK fuses data.

        :return: RoT hash as bytes data from SRK fuses export.
        """
        return self.srk.export_fuses()

    def export(self) -> bytes:
        """Export RoT (Root of Trust) data.

        :return: Exported RoT data as bytes.
        """
        return self.srk.export()

    @classmethod
    def _load_certificate(
        cls,
        certificate: Union[str, bytes, bytearray],
        search_paths: Optional[list[str]] = None,
    ) -> Certificate:
        """Load certificate from various input formats.

        The method accepts certificate data as a file path, bytes, or bytearray and attempts
        to parse it into a Certificate object. If a file path is provided, it will be loaded
        using the specified search paths.

        :param certificate: Certificate data as file path, bytes, or bytearray.
        :param search_paths: Optional list of paths to search for certificate file.
        :raises SPSDKError: Unable to load or parse the certificate.
        :return: Parsed certificate object.
        """
        if isinstance(certificate, str):
            certificate = load_binary(certificate, search_paths)
        try:
            return Certificate.parse(certificate)
        except SPSDKError as exc:
            raise SPSDKError("Unable to load certificate.") from exc

    def __str__(self) -> str:
        """Get string representation of the RoT object.

        :return: String representation of the SRK (Super Root Key) data.
        """
        return str(self.srk)

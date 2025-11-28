#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK TP Data Container implementation for secure provisioning.

This module provides functionality for creating, parsing, and managing TP (Trust Provisioning)
Data Containers used in NXP MCU secure provisioning workflows. It includes support for various
payload types, authentication methods, and data entry management.
"""

import struct
from typing import Mapping, Type, Union

import hexdump
from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import (
    PrivateKey,
    PublicKey,
    PublicKeyDilithium,
    PublicKeyEcc,
    PublicKeyMLDSA,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import align, align_block, load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum

# ALIGNMENT = 8
ALIGNMENT = 4


class PayloadType(SpsdkEnum):
    """DICE payload type enumeration for data container operations.

    This enumeration defines all supported payload types used in DICE (Device Identifier
    Composition Engine) data containers, including challenge data, platform configuration,
    cryptographic keys, certificates, and signature payloads.
    """

    # fmt: off
    CHALLENGE       = (0x2000, "CHALLENGE", "Initial challenge data")
    PLATFORM_DATA   = (0x2001, "PLATFORM_DATA", "Platform specific configuration data")
    ROM_PATCH_HASH  = (0x20A4, "ROM_PATCH_HASH", "Hash of IFR1 ROM patch")
    DICE_ALIAS_KEY  = (0x20C0, "DICE_ALIAS_KEY", "DICE Alias Key")
    NXP_DIE_ID_AUTH_CERT        = (0xF0F0, "NXP_DIE_ID_AUTH_CERT", "NXP_DIE_ID_AUTH_CERT")
    NXP_DIE_ECID_ID_UID         = (0x0F0F, "NXP_DIE_ECID_ID_UID", "NXP_DIE_ECID_ID_UID")
    NXP_DIE_RFC4122v4_ID_UUID   = (0x9696, "NXP_DIE_RFC4122v4_ID_UUID", "NXP_DIE_RFC4122v4_ID_UUID")
    NXP_DIE_ID_AUTH_PUK         = (0x9966, "NXP_DIE_ID_AUTH_PUK", "NXP_DIE_ID_AUTH_PUK")

    ECDSA_SIGNATURE  = (0x20, "ECDSA_SIGNATURE", "ECDSA Signature Payload")
    MLDSA_SIGNATURE  = (0x30, "MLDSA_SIGNATURE", "MLDSA Signature Payload")

    DICE_FCM_ECDSA_CERT_TEMPLATE = (0x67F7, "DICE_FCM_ECDSA_CERT_TEMPLATE", "Template for DICEv2 FMC ECDSA certificate")
    DICE_FCM_MLDSA_CERT_TEMPLATE = (0x59F9, "DICE_FCM_MLDSA_CERT_TEMPLATE", "Template for DICEv2 FMC MLDSA certificate")
    DICE_FCM_CERT_DESCRIPTOR = (0x4898, "DICE_FCM_CERT_DESCRIPTOR", "Offset descriptor for DICEv2 FMC certificate")


class AuthenticationType(SpsdkEnum):
    """Enumeration of authentication types for DICE identification.

    This enumeration defines the supported authentication methods used in DICE
    (Device Identifier Composition Engine) operations for secure device identification
    and attestation.
    """

    # fmt: off
    NONE      = (0x00, "NONE", "No authentication")
    ECDSA     = (0x20, "ECDSA", "ECDSA")
    MLDSA     = (0x30, "MLDSA", "MLDSA")


class EntryType(SpsdkEnum):
    """DICE Entry type enumeration.

    This enumeration defines the supported entry types used in DICE (Device Identifier
    Composition Engine) data containers for secure provisioning operations.
    """

    # fmt: off
    STANDARD        = (0xA0, "standard", "Standard Entry")
    DESTINATION     = (0xB0, "destination", "Destination Entry")
    AUTHENTICATION  = (0xC0, "authentication", "Authentication Entry")


class DestinationType(SpsdkEnum):
    """Destination type enumeration for DICE data container entries.

    Defines the available destination types where data can be stored or written
    during DICE provisioning operations, including memory addresses and OTP indices.
    """

    # fmt: off
    MEMORY  = (0, "memory", "Address in memory")
    OTP     = (2, "otp", "Index in OTP")


class BaseElement(BaseClass):
    """Base class for DICE data container elements.

    This class provides a foundation for all elements that can be used within
    DICE data containers, offering common functionality and standardized
    representation methods for derived classes.
    """

    def __repr__(self) -> str:
        """Return string representation of the object.

        This method provides a developer-friendly string representation that includes
        the class name and all instance variables.

        :return: String representation containing class name and instance variables.
        """
        return f"<{self.__class__.__name__} {vars(self)}>"


class EntryHeader(BaseElement):
    """DICE entry header representation for data container structures.

    This class manages the common header structure used by all DICE entry types,
    providing serialization and parsing capabilities for entry metadata including
    type identification, payload information, and size calculations.

    :cvar FORMAT: Binary format string for struct packing and unpacking operations.
    :cvar SIZE: Total byte size of the serialized entry header structure.
    """

    #: Binary format for entry header (used by the struct module)
    FORMAT = "<H2B2H"
    #: Total size of the entry header
    SIZE = struct.calcsize(FORMAT)

    def __init__(
        self,
        tag: int,
        payload_size: int,
        payload_type: int,
        entry_extra: int = 0,
    ) -> None:
        """Initialize Entry header.

        :param tag: Tag indicating entry type, see `EntryType`
        :param payload_size: Size of entry payload, excluding header and padding
        :param payload_type: Type of entry payload
        :param entry_extra: Extra type specific data
        """
        self.tag = tag
        self.payload_size = payload_size
        self.payload_type = payload_type
        self.entry_extra = entry_extra

    def stringify_payload_type(self) -> str:
        """Return a stringified payload type.

        The method formats the payload type as a hexadecimal value with its corresponding
        description from either AuthenticationType or PayloadType enum based on the entry tag.

        :return: Formatted string containing hex value and description of payload type.
        """
        enum = AuthenticationType if self.tag == EntryType.AUTHENTICATION else PayloadType
        return f"{self.payload_type:#06x} - {enum.from_tag(self.payload_type).description}"

    def __str__(self) -> str:
        """Get string representation of the data container entry.

        Provides formatted information about the entry including its type, payload size,
        and extra data with both hexadecimal and decimal representations.

        :return: Formatted string containing entry type, size, and extra data information.
        """
        info = (
            f"Entry type:   {self.tag:#x} - {EntryType.get_description(self.tag)}\n"
            f"Entry size:   {self.payload_size:#06x} - {self.payload_size}\n"
            f"Entry extra:  {self.entry_extra:#06x} - {self.entry_extra}\n"
        )
        return info

    def export(self) -> bytes:
        """Export the entry header as serialized bytes.

        Serializes the entry header structure using the predefined format, packing
        payload size, tag, entry extra data, and payload type into binary data.

        :return: Serialized entry header as bytes.
        """
        data = struct.pack(
            self.FORMAT,
            self.payload_size,
            0,
            self.tag,
            self.entry_extra,
            self.payload_type,
        )
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the entry header from binary data.

        Parse binary data using the class FORMAT string to extract header components
        and create a new instance with the parsed values.

        :param data: Binary data containing the entry header information.
        :return: New instance of the class with parsed header data.
        """
        size, _, tag, extra, p_type = struct.unpack_from(cls.FORMAT, data)
        return cls(tag=tag, payload_size=size, payload_type=p_type, entry_extra=extra)


class DestinationHeader(BaseElement):
    """DICE destination header for data container operations.

    This class represents a destination header that stores destination address
    and type information for DICE (Device Identifier Composition Engine) data
    containers. It provides serialization and parsing capabilities for binary
    data exchange.

    :cvar FORMAT: Binary format string for struct packing/unpacking operations.
    :cvar SIZE: Total size in bytes of the serialized destination header.
    """

    #: Binary format for destination record (used by the struct module)
    FORMAT = "<4BL"
    #: Total size of the destination record
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, destination: int, destination_type: DestinationType) -> None:
        """Initialize the destination record.

        :param destination: Destination address
        :param destination_type: Destination type, see: `DestinationType`
        """
        self.destination = destination
        self.destination_type = destination_type

    def __str__(self) -> str:
        """Get string representation of the data container.

        Provides formatted information about the destination type and destination address
        in a human-readable format.

        :return: Formatted string containing destination type description and address.
        """
        info = (
            f"Dest. type:   {self.destination_type.description}\n"
            f"Destination:  {self.destination:#010x}\n"
        )
        return info

    def export(self) -> bytes:
        """Export destination record to binary format.

        Converts the destination record into a binary format using the predefined
        FORMAT structure with destination type tag and destination value.

        :return: Serialized destination record as bytes.
        """
        data = struct.pack(self.FORMAT, self.destination_type.tag, 0, 0, 0, self.destination)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the destination record from binary data.

        Parse binary data using the class FORMAT string to extract destination type
        and destination value, then create a new instance with the parsed values.

        :param data: Binary data containing the destination record information.
        :raises SPSDKError: Invalid data format or parsing error.
        :return: New instance of the destination record class.
        """
        dest_type, _, _, _, dest = struct.unpack_from(cls.FORMAT, data)
        return cls(destination=dest, destination_type=DestinationType.from_tag(dest_type))


class DataEntry(BaseElement):
    """DICE standard data entry container.

    This class represents a standard data entry in DICE (Device Identifier Composition Engine)
    data containers, managing payload data with associated metadata including type information
    and serialization capabilities.

    :cvar TAG: Entry type tag identifier for standard data entries.
    """

    TAG = EntryType.STANDARD.tag

    def __init__(self, payload: bytes, payload_type: int, extra: int = 0) -> None:
        """Initialize Standard Data Entry.

        :param payload: Data entry payload bytes.
        :param payload_type: Data entry type identifier.
        :param extra: Extra information for the entry, defaults to 0.
        """
        self.payload = payload
        self.header = EntryHeader(
            tag=self.TAG, payload_size=len(payload), payload_type=payload_type, entry_extra=extra
        )

    def _stringify_payload_type(self) -> str:
        """Get string representation of payload type.

        This method delegates to the header's stringify_payload_type method to convert
        the payload type into its string representation.

        :return: String representation of the payload type.
        """
        return self.header.stringify_payload_type()

    def _stringify_payload(self) -> str:
        """Convert payload data to a human-readable string representation.

        This method formats the payload information including its type and data content.
        For small payloads (4 bytes or less), the data is displayed as a hex string.
        For larger payloads, a formatted hexdump is provided.

        :return: Formatted string containing payload type and data representation.
        """
        info = f"Payload type: {self._stringify_payload_type()}\n"
        info += "Payload data: "
        if len(self.payload) <= 4:
            info += f"{self.payload.hex()}\n"
        else:
            info += f"\n{hexdump.hexdump(self.payload, result='return')}\n"
        return info

    def __str__(self) -> str:
        """Get string representation of the data container.

        Combines the header string representation with the payload string representation
        to provide a complete view of the data container contents.

        :return: String representation containing header and payload information.
        """
        info = str(self.header)
        info += self._stringify_payload()
        return info

    @property
    def total_size(self) -> int:
        """Calculate total size of the entry including header and padding.

        The method calculates the complete size by adding the header size and the aligned payload size
        according to the specified alignment.

        :return: Total size in bytes including header and padding.
        """
        size = struct.calcsize(self.header.FORMAT)
        size += align(len(self.payload), alignment=ALIGNMENT)
        return size

    def export(self) -> bytes:
        """Serialize the data container entry to bytes.

        The method exports the header and payload data, then aligns the resulting
        block according to the specified alignment requirements.

        :return: Serialized entry data as aligned byte sequence.
        """
        data = self.header.export()
        data += self.payload
        return align_block(data, alignment=ALIGNMENT)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse entry from binary data.

        Reconstructs an entry object from its binary representation by parsing the header
        and extracting the payload data.

        :param data: Binary data containing the entry header and payload.
        :return: Reconstructed entry object with parsed payload and metadata.
        """
        header = EntryHeader.parse(data)
        payload_offset = header.SIZE
        payload_length = header.payload_size
        payload = data[payload_offset : payload_offset + payload_length]
        return cls(payload=payload, payload_type=header.payload_type, extra=header.entry_extra)


class DataDestinationEntry(DataEntry):
    """Data entry with destination information for DICE operations.

    This class extends DataEntry to include destination metadata, specifying
    where the data should be written (memory address or OTP index) and the
    destination type. Used in DICE data containers for entries that require
    specific placement during provisioning.

    :cvar TAG: Entry type tag identifier for destination entries.
    """

    TAG = EntryType.DESTINATION.tag

    def __init__(
        self,
        payload: bytes,
        payload_type: int,
        destination: int,
        destination_type: DestinationType,
        extra: int = 0,
    ) -> None:
        """Initialize data entry with destination record.

        Creates a new data entry instance that includes destination information
        for specifying where the payload should be written (memory address or OTP index).

        :param payload: Data entry payload bytes.
        :param payload_type: Data entry type identifier.
        :param destination: Destination memory address or OTP index.
        :param destination_type: Destination type specifying memory or OTP.
        :param extra: Extra data field, defaults to 0.
        """
        super().__init__(payload, payload_type, extra)
        self.destination_header = DestinationHeader(
            destination=destination, destination_type=destination_type
        )

    def __str__(self) -> str:
        """Get string representation of the data container.

        The method creates a formatted string containing the header information,
        destination header details, and payload data for display purposes.

        :return: Formatted string representation of the data container.
        """
        info = str(self.header)
        info += str(self.destination_header)
        info += self._stringify_payload()
        return info

    @property
    def total_size(self) -> int:
        """Calculate total size of the data container entry.

        The method computes the complete size including the base entry size,
        destination header, and any required padding.

        :return: Total size in bytes of the entry including all components.
        """
        size = super().total_size
        size += struct.calcsize(self.destination_header.FORMAT)
        return size

    def export(self) -> bytes:
        """Serialize the data container entry to bytes.

        Exports the complete entry by concatenating the header, destination header,
        and payload data, then aligning the result to the required boundary.

        :return: Serialized entry data aligned to the specified alignment boundary.
        """
        data = self.header.export()
        data += self.destination_header.export()
        data += self.payload
        return align_block(data, alignment=ALIGNMENT)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data to reconstruct the data container entry.

        Parses the binary data to extract entry header, destination header, and payload
        information to create a complete data container entry object.

        :param data: Binary data containing the serialized entry information.
        :return: Reconstructed data container entry instance.
        """
        header = EntryHeader.parse(data)
        dest_header = DestinationHeader.parse(data[header.SIZE :])
        payload_start = header.SIZE + dest_header.SIZE
        payload_size = header.payload_size
        payload = data[payload_start : payload_start + payload_size]
        return cls(
            payload=payload,
            payload_type=header.payload_type,
            extra=header.entry_extra,
            destination=dest_header.destination,
            destination_type=dest_header.destination_type,
        )


class DataAuthenticationEntry(DataEntry):
    """Data authentication entry for DICE integrity verification.

    This class represents the final data entry in a DICE data container that is used
    for authentication and integrity checking of the container contents.

    :cvar TAG: Entry type tag identifier for authentication entries.
    """

    TAG = EntryType.AUTHENTICATION.tag

    def get_auth_type(self) -> AuthenticationType:
        """Get appropriate Authentication type.

        The method retrieves the authentication type by converting the header's payload type
        using the AuthenticationType enumeration.

        :return: Authentication type based on the header payload type.
        """
        return AuthenticationType.from_tag(self.header.payload_type)


class DataAuthenticationEntryV2(DataAuthenticationEntry):
    """Data Authentication Entry Version 2 for DICE integrity verification.

    This class represents the second version of data authentication entries used
    in DICE (Device Identifier Composition Engine) operations. It extends the base
    DataAuthenticationEntry with enhanced authentication type handling and improved
    payload type identification for integrity checking processes.
    """

    def get_auth_type(self) -> AuthenticationType:
        """Get appropriate Authentication type.

        Retrieves the authentication type from the header's entry_extra field by converting
        the tag value to the corresponding AuthenticationType enum.

        :return: Authentication type derived from header entry extra data.
        """
        return AuthenticationType.from_tag(self.header.entry_extra)

    def _stringify_payload_type(self) -> str:
        """Convert payload type to human-readable string representation.

        Extracts the authentication type from the header's entry_extra field and returns
        its description or label as a string for display purposes.

        :return: Human-readable description or label of the payload authentication type.
        """
        auth_type = AuthenticationType.from_tag(self.header.entry_extra)
        return auth_type.description or auth_type.label


class ContainerHeader(BaseElement):
    """DICE container header for binary data serialization.

    This class represents the header structure of DICE containers, managing version
    information and container metadata. It provides functionality for serializing
    headers to binary format and reconstructing them from binary data streams.

    :cvar FORMAT: Binary format string for struct packing/unpacking operations.
    :cvar SIZE: Total size of the container header in bytes.
    :cvar TAG: Magic number identifying the start of a container in binary data.
    """

    #: Binary format for entry header (used by the struct module)
    FORMAT = "<4B2H"
    #: Total size of the container header
    SIZE = struct.calcsize(FORMAT)
    #: Tag (magic) indicating start of the container in binary stream
    TAG = 0x33

    def __init__(self, major: int = 1, minor: int = 0, patch: int = 0) -> None:
        """Initialize Container Header with version information.

        :param major: Major version number, defaults to 1
        :param minor: Minor version number, defaults to 0
        :param patch: Patch revision number, defaults to 0
        """
        self.size = 0
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self) -> str:
        """Get string representation of the data container.

        Provides version information and size details in a formatted string.

        :return: Formatted string containing version and size information.
        """
        info = f"Version: {self.major}.{self.minor}.{self.patch}\n"
        info += f"Size:    {self.size:#x} - {self.size}\n"
        return info

    def export(self) -> bytes:
        """Export container header to binary format.

        Serializes the container header data including patch, minor, major version numbers,
        TAG identifier, and size information into a binary format using struct packing.

        :return: Binary representation of the container header.
        """
        data = struct.pack(self.FORMAT, self.patch, self.minor, self.major, self.TAG, self.size, 0)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse container header from binary data.

        Reconstructs a container header instance by unpacking binary data according to the
        defined format and validates the TAG field.

        :param data: Binary data containing the container header information.
        :raises SPSDKError: Invalid TAG found in the binary data.
        :return: New container header instance with parsed values.
        """
        patch, minor, major, tag, size, _ = struct.unpack_from(cls.FORMAT, data)
        if tag != cls.TAG:
            raise SPSDKError(f"Invalid TAG found: {hex(tag)}, expected {hex(cls.TAG)}")
        header = cls(major=major, minor=minor, patch=patch)
        header.size = size
        return header


class TPDataContainer(BaseElement):
    """TrustProvisioning Data Container for DICE operations.

    This class manages a collection of data entries used in Trust Provisioning
    operations, providing functionality to add, retrieve, and serialize entries
    with automatic header management and size tracking.
    """

    def __init__(self, major: int = 1, minor: int = 0, patch: int = 0) -> None:
        """Initialize the data container with version information.

        Creates a new data container with the specified version numbers and initializes
        an empty list of data entries.

        :param major: Major version number of the container.
        :param minor: Minor version number of the container.
        :param patch: Patch version number of the container.
        """
        self.header = ContainerHeader(major=major, minor=minor, patch=patch)
        #: list containing individual entries (shall not be modified directly)
        self._entries: list[DataEntry] = []

    def __str__(self) -> str:
        """Return string representation of TrustProvisioning Data Container.

        Provides a formatted string containing the container header information,
        entry count, and detailed information for each entry. For NXP_DIE_ID_AUTH_CERT
        payload types, the payload is parsed and displayed with proper indentation.

        :return: Formatted string representation of the data container.
        """
        info = (
            f"TrustProvisioning Data Container\n"
            f"{self.header}"
            f"Entries: (count: {len(self._entries)})\n"
        )
        for entry in self._entries:
            info += "-" * 76 + "\n"
            if entry.header.payload_type == PayloadType.NXP_DIE_ID_AUTH_CERT:
                info += "\n    ".join(str(TPDataContainer.parse(entry.payload)).splitlines()) + "\n"
            else:
                info += str(entry)
        return info

    def __len__(self) -> int:
        """Get the number of entries in the data container.

        :return: Number of entries stored in the container.
        """
        return len(self._entries)

    def add_entry(self, entry: DataEntry) -> None:
        """Add an entry to the container.

        The method appends a new data entry to the internal entries list and updates
        the container header to reflect the changes.

        :param entry: Data entry to be added to the container.
        """
        self._entries.append(entry)
        self._update_header()

    def _update_header(self) -> None:
        """Update size information in container header.

        The method calculates the total size by summing up the total_size of all entries
        in the container and updates the header's size field accordingly.
        """
        size = sum(entry.total_size for entry in self._entries)
        self.header.size = size

    def export(self) -> bytes:
        """Serialize the data container to bytes.

        Exports the container by serializing the header followed by all entries
        in their current order.

        :return: Serialized container data as bytes.
        """
        data = self.header.export()
        for entry in self._entries:
            data += entry.export()
        return data

    def get_entry(self, payload_type: PayloadType) -> DataEntry:
        """Get the first entry for the given type.

        :param payload_type: Type of an entry to look for.
        :raises SPSDKError: Container doesn't have an entry of required type.
        :return: Entry with given type.
        """
        for entry in self._entries:
            if entry.header.payload_type == payload_type:
                return entry
        raise SPSDKError(f"Container doesn't have an entry with type {payload_type.label}")

    def get_entries(self, payload_type: PayloadType) -> list[DataEntry]:
        """Get all entries for given payload type.

        :param payload_type: Type of payload to filter entries by.
        :return: List of data entries matching the specified payload type.
        """
        return [entry for entry in self._entries if entry.header.payload_type == payload_type]

    def get_data_entries(self) -> list[DataEntry]:
        """Get all data entries excluding authentication entries.

        Filters the internal entries list to return only data entries, excluding
        any authentication-related entries from the container.

        :return: List of data entries without authentication entries.
        """
        return [
            entry
            for entry in self._entries
            if not isinstance(entry, (DataAuthenticationEntry, DataAuthenticationEntryV2))
        ]

    def get_auth_entries(self) -> list[DataAuthenticationEntry]:
        """Get all authentication entries from the data container.

        Retrieves a filtered list containing only authentication entries (both DataAuthenticationEntry
        and DataAuthenticationEntryV2 types) from the internal entries collection.

        :return: List of authentication entries found in the container.
        """
        return [
            entry
            for entry in self._entries
            if isinstance(entry, (DataAuthenticationEntry, DataAuthenticationEntryV2))
        ]

    def get_tbs_data(self) -> bytes:
        """Prepare data to be signed/verified.

        Exports the header and all data entries, then concatenates them to create
        the To-Be-Signed (TBS) data structure used for cryptographic operations.

        :return: Concatenated bytes of header and data entries ready for signing/verification.
        """
        data_entries = self.get_data_entries()
        data_to_sign = self.header.export()
        data_to_sign += b"".join(entry.export() for entry in data_entries)
        return data_to_sign

    def add_auth_entry(self, auth_type: AuthenticationType, key: Union[bytes, PrivateKey]) -> None:
        """Add the final data authentication entry.

        This method creates and adds an authentication entry by signing the to-be-signed data
        with the provided key. If no data entries exist, the method returns early without
        adding any authentication entry.

        :param auth_type: Authentication type specifying the signature algorithm to use.
        :param key: Private key for signing, either as raw bytes or PrivateKey object.
        :raises SPSDKError: Unknown or not-implemented Authentication type.
        """
        data_entries = self.get_data_entries()
        if not data_entries:
            return

        data_to_sign = self.get_tbs_data()
        sign_key = PrivateKey.parse(key) if isinstance(key, bytes) else key
        signature = sign_key.sign(data_to_sign)

        self.add_entry(
            DataAuthenticationEntry(payload=signature, payload_type=auth_type.tag, extra=0x0)
        )

    @staticmethod
    def _validate_mldsa(
        auth_entry: DataAuthenticationEntry,
        keys: list[PublicKey],
        data_to_validate: bytes,
    ) -> bool:
        """Validate MLDSA signature for a single authentication entry.

        This method validates an MLDSA-87 signature by checking the payload size requirements
        and verifying the signature against the provided public keys.

        :param auth_entry: Authentication entry containing the MLDSA signature to validate.
        :param keys: List of public keys to validate the signature against.
        :param data_to_validate: Raw data bytes that were signed.
        :raises SPSDKError: If signature payload size is invalid or no MLDSA public key found.
        :return: True if signature is valid, False otherwise.
        """
        # actual MLDSA-87 signature is 0x1213 bytes long
        # in the container, the auth_entry contains some padding
        if auth_entry.header.payload_size < 0x1213:
            raise SPSDKError(
                "Invalid MLDSA signature payload size. "
                f"Expected >= 0x1213, got {auth_entry.header.payload_size:x}"
            )

        for public_key in keys:
            # MLDSA keys might get recognized as Dilithium key, as they have the same length
            if isinstance(public_key, (PublicKeyMLDSA, PublicKeyDilithium)):
                break
        else:
            raise SPSDKError("Supplied keys don't contain MLDSA public key")

        return public_key.verify_signature(
            auth_entry.payload[:0x1213],
            data_to_validate,
            algorithm=EnumHashAlgorithm.SHA512,
        )

    @staticmethod
    def _validate_ecdsa(
        auth_entry: DataAuthenticationEntry,
        keys: list[PublicKey],
        data_to_validate: bytes,
    ) -> bool:
        """Validate ECDSA signature against provided data.

        This method verifies an ECDSA signature stored in the authentication entry
        against the given data using the first available EC public key from the
        provided key list.

        :param auth_entry: Authentication entry containing the ECDSA signature to validate.
        :param keys: List of public keys to search for an EC key.
        :param data_to_validate: Raw data bytes that should match the signature.
        :raises SPSDKError: If no EC public key is found in the supplied keys list.
        :return: True if signature is valid, False otherwise.
        """
        for public_key in keys:
            if isinstance(public_key, PublicKeyEcc):
                break
        else:
            raise SPSDKError("Supplied keys doesn't contain EC public key")
        # ECDSA signature doesn't contain any padding, can be used as is
        return public_key.verify_signature(auth_entry.payload, data_to_validate)

    def validate(self, keys: list[Union[bytes, PublicKey]]) -> bool:
        """Validate signature/authentication code.

        The method validates all authentication entries in the data container using the provided keys.
        It supports ECDSA and MLDSA authentication types and ensures that the number of keys matches
        the number of authentication entries.

        :param keys: List of keys (bytes or PublicKey objects) for validating signatures.
        :raises SPSDKError: No data/authentication entries, key count mismatch, validation failure,
                           or unknown authentication type.
        :return: True if all signatures/authentication codes are valid.
        """
        data_entries = self.get_data_entries()
        if not data_entries:
            raise SPSDKError("No data entries to validate")

        auth_entries = self.get_auth_entries()
        if not auth_entries:
            raise SPSDKError("No authentication entries to validate")

        data_to_validate = self.get_tbs_data()

        if len(keys) != len(auth_entries):
            raise SPSDKError("Number of keys does not match number of authentication entries")

        key_candidates: list[PublicKey] = [
            PublicKey.parse(key) if isinstance(key, bytes) else key for key in keys
        ]

        for i, auth_entry in enumerate(auth_entries):

            if auth_entry.get_auth_type() == AuthenticationType.MLDSA:
                if not self._validate_ecdsa(auth_entry, key_candidates, data_to_validate):
                    raise SPSDKError(f"Authentication failed for MLDSA (entry #{i})")
                break

            if auth_entry.get_auth_type() == AuthenticationType.ECDSA:
                if not self._validate_ecdsa(auth_entry, key_candidates, data_to_validate):
                    raise SPSDKError(f"Authentication failed for ECDSA (entry #{i})")
                break

            raise SPSDKError(f"Invalid/unknown authentication type {auth_entry} for entry #{i}")

        return True

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct container from binary data.

        Parses the binary data to extract container header and all contained entries,
        reconstructing the complete container structure.

        :param data: Binary data containing the serialized container.
        :return: Reconstructed container instance with all parsed entries.
        """
        header = ContainerHeader.parse(data=data)
        offset = ContainerHeader.SIZE
        container = cls()
        while offset < len(data) and offset < header.size:
            entry = parse_entry(data=data[offset:])
            offset += entry.total_size
            container.add_entry(entry=entry)
        return container

    @classmethod
    def load(cls, path: str) -> Self:
        """Load container from a file.

        :param path: Path to the file containing container data.
        :return: Reconstructed container instance.
        :raises SPSDKError: If file cannot be read or parsed.
        """
        data = load_binary(path)
        try:
            return cls.parse(data)
        except Exception as e:
            raise SPSDKError(f"Error loading container from {path}: {str(e)}") from e


#: Mapping between entry type and its corresponding DataEntry class
_ENTRY_CLASSES: Mapping[EntryType, Type[DataEntry]] = {
    EntryType.STANDARD: DataEntry,
    EntryType.DESTINATION: DataDestinationEntry,
    EntryType.AUTHENTICATION: DataAuthenticationEntry,
}


def parse_entry(data: bytes) -> "DataEntry":
    """Parse data entry from raw bytes data.

    Common parser for all known DataEntry classes that automatically detects
    the entry type from the tag byte and delegates parsing to the appropriate
    class.

    :param data: Raw bytes data containing the data entry to parse.
    :raises KeyError: Unknown entry type tag found in data.
    :raises IndexError: Data too short to contain valid entry tag.
    :return: Parsed DataEntry instance of the appropriate subclass.
    """
    tag = data[3]
    return _ENTRY_CLASSES[EntryType.from_tag(tag)].parse(data=data)

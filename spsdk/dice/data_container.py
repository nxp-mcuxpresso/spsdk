#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module implementing the TP Data Container."""

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
    """Enumeration of all supported Payload types."""

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
    """Enumeration of authentication types for DIE identification."""

    # fmt: off
    NONE      = (0x00, "NONE", "No authentication")
    ECDSA     = (0x20, "ECDSA", "ECDSA")
    MLDSA     = (0x30, "MLDSA", "MLDSA")


class EntryType(SpsdkEnum):
    """Enumeration of all supported Entry types."""

    # fmt: off
    STANDARD        = (0xA0, "standard", "Standard Entry")
    DESTINATION     = (0xB0, "destination", "Destination Entry")
    AUTHENTICATION  = (0xC0, "authentication", "Authentication Entry")


class DestinationType(SpsdkEnum):
    """Destination type setting for DataDestinationEntry."""

    # fmt: off
    MEMORY  = (0, "memory", "Address in memory")
    OTP     = (2, "otp", "Index in OTP")


class BaseElement(BaseClass):
    """Base class for items used in data_container."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {vars(self)}>"


class EntryHeader(BaseElement):
    """Common Entry header for all entry types."""

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
        """Return a stringified payload type."""
        enum = AuthenticationType if self.tag == EntryType.AUTHENTICATION else PayloadType
        return f"{self.payload_type:#06x} - {enum.from_tag(self.payload_type).description}"

    def __str__(self) -> str:
        info = (
            f"Entry type:   {self.tag:#x} - {EntryType.get_description(self.tag)}\n"
            f"Entry size:   {self.payload_size:#06x} - {self.payload_size}\n"
            f"Entry extra:  {self.entry_extra:#06x} - {self.entry_extra}\n"
        )
        return info

    def export(self) -> bytes:
        """Serialize the entry header."""
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
        """Reconstruct the entry header from binary data."""
        size, _, tag, extra, p_type = struct.unpack_from(cls.FORMAT, data)
        return cls(tag=tag, payload_size=size, payload_type=p_type, entry_extra=extra)


class DestinationHeader(BaseElement):
    """Header used to store destination information."""

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
        info = (
            f"Dest. type:   {self.destination_type.description}\n"
            f"Destination:  {self.destination:#010x}\n"
        )
        return info

    def export(self) -> bytes:
        """Serialize the destination record."""
        data = struct.pack(self.FORMAT, self.destination_type.tag, 0, 0, 0, self.destination)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the destination record from binary data."""
        dest_type, _, _, _, dest = struct.unpack_from(cls.FORMAT, data)
        return cls(destination=dest, destination_type=DestinationType.from_tag(dest_type))


class DataEntry(BaseElement):
    """Standard data entry."""

    TAG = EntryType.STANDARD.tag

    def __init__(self, payload: bytes, payload_type: int, extra: int = 0) -> None:
        """Initialize Standard Data Entry.

        :param payload: Data entry payload
        :param payload_type: Data entry type
        :param extra: Extra information for the entry
        """
        self.payload = payload
        self.header = EntryHeader(
            tag=self.TAG, payload_size=len(payload), payload_type=payload_type, entry_extra=extra
        )

    def _stringify_payload_type(self) -> str:
        return self.header.stringify_payload_type()

    def _stringify_payload(self) -> str:
        info = f"Payload type: {self._stringify_payload_type()}\n"
        info += "Payload data: "
        if len(self.payload) <= 4:
            info += f"{self.payload.hex()}\n"
        else:
            info += f"\n{hexdump.hexdump(self.payload, result='return')}\n"
        return info

    def __str__(self) -> str:
        info = str(self.header)
        info += self._stringify_payload()
        return info

    @property
    def total_size(self) -> int:
        """Returns total size of the entry (including header and padding)."""
        size = struct.calcsize(self.header.FORMAT)
        size += align(len(self.payload), alignment=ALIGNMENT)
        return size

    def export(self) -> bytes:
        """Serialize the entry."""
        data = self.header.export()
        data += self.payload
        return align_block(data, alignment=ALIGNMENT)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the entry from binary data."""
        header = EntryHeader.parse(data)
        payload_offset = header.SIZE
        payload_length = header.payload_size
        payload = data[payload_offset : payload_offset + payload_length]
        return cls(payload=payload, payload_type=header.payload_type, extra=header.entry_extra)


class DataDestinationEntry(DataEntry):
    """Data entry including destination information."""

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

        :param payload: Data entry payload
        :param payload_type: Data entry type
        :param destination: Destination memory address/OTP index
        :param destination_type: Destination type memory/OTP
        """
        super().__init__(payload, payload_type, extra)
        self.destination_header = DestinationHeader(
            destination=destination, destination_type=destination_type
        )

    def __str__(self) -> str:
        info = str(self.header)
        info += str(self.destination_header)
        info += self._stringify_payload()
        return info

    @property
    def total_size(self) -> int:
        """Returns total size of the entry (including header and padding)."""
        size = super().total_size
        size += struct.calcsize(self.destination_header.FORMAT)
        return size

    def export(self) -> bytes:
        """Serialize the entry."""
        data = self.header.export()
        data += self.destination_header.export()
        data += self.payload
        return align_block(data, alignment=ALIGNMENT)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the entry header from binary data."""
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
    """Final Data entry used for integrity check."""

    TAG = EntryType.AUTHENTICATION.tag

    def get_auth_type(self) -> AuthenticationType:
        """Get appropriate Authentication type."""
        return AuthenticationType.from_tag(self.header.payload_type)


class DataAuthenticationEntryV2(DataAuthenticationEntry):
    """Final Data entry V2 used for integrity check."""

    def get_auth_type(self) -> AuthenticationType:
        """Get appropriate Authentication type."""
        return AuthenticationType.from_tag(self.header.entry_extra)

    def _stringify_payload_type(self) -> str:
        auth_type = AuthenticationType.from_tag(self.header.entry_extra)
        return auth_type.description or auth_type.label


class ContainerHeader(BaseElement):
    """Main container header."""

    #: Binary format for entry header (used by the struct module)
    FORMAT = "<4B2H"
    #: Total size of the container header
    SIZE = struct.calcsize(FORMAT)
    #: Tag (magic) indicating start of the container in binary stream
    TAG = 0x33

    def __init__(self, major: int = 1, minor: int = 0, patch: int = 0) -> None:
        """Initialize Container Header with version information.

        :param major: major version, defaults to 1
        :param minor: minor version, defaults to 0
        :param patch: patch re-vision, defaults to 0
        """
        self.size = 0
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self) -> str:
        info = f"Version: {self.major}.{self.minor}.{self.patch}\n"
        info += f"Size:    {self.size:#x} - {self.size}\n"
        return info

    def export(self) -> bytes:
        """Serialize the container header."""
        data = struct.pack(self.FORMAT, self.patch, self.minor, self.major, self.TAG, self.size, 0)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct the container header from binary data."""
        patch, minor, major, tag, size, _ = struct.unpack_from(cls.FORMAT, data)
        if tag != cls.TAG:
            raise SPSDKError(f"Invalid TAG found: {hex(tag)}, expected {hex(cls.TAG)}")
        header = cls(major=major, minor=minor, patch=patch)
        header.size = size
        return header


class TPDataContainer(BaseElement):
    """TrustProvisioning Data Container."""

    def __init__(self, major: int = 1, minor: int = 0, patch: int = 0) -> None:
        """Initialize the container."""
        self.header = ContainerHeader(major=major, minor=minor, patch=patch)
        #: list containing individual entries (shall not be modified directly)
        self._entries: list[DataEntry] = []

    def __str__(self) -> str:
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
        return len(self._entries)

    def add_entry(self, entry: DataEntry) -> None:
        """Add an entry to the container."""
        self._entries.append(entry)
        self._update_header()

    def _update_header(self) -> None:
        """Update size information in container header."""
        size = sum(entry.total_size for entry in self._entries)
        self.header.size = size

    def export(self) -> bytes:
        """Serialize the container."""
        data = self.header.export()
        for entry in self._entries:
            data += entry.export()
        return data

    def get_entry(self, payload_type: PayloadType) -> DataEntry:
        """Get the first entry for the given type.

        :param payload_type: Type of an entry to look for
        :raises SPSDKError: Container doesn't have an entry of required type
        :return: Entry with given type
        """
        for entry in self._entries:
            if entry.header.payload_type == payload_type:
                return entry
        raise SPSDKError(f"Container doesn't have an entry with type {payload_type.label}")

    def get_entries(self, payload_type: PayloadType) -> list[DataEntry]:
        """Get all entries for given payload type."""
        return [entry for entry in self._entries if entry.header.payload_type == payload_type]

    def get_data_entries(self) -> list[DataEntry]:
        """Get all data entries excluding authentication entries."""
        return [
            entry
            for entry in self._entries
            if not isinstance(entry, (DataAuthenticationEntry, DataAuthenticationEntryV2))
        ]

    def get_auth_entries(self) -> list[DataAuthenticationEntry]:
        """Get all authentication entries."""
        return [
            entry
            for entry in self._entries
            if isinstance(entry, (DataAuthenticationEntry, DataAuthenticationEntryV2))
        ]

    def get_tbs_data(self) -> bytes:
        """Prepare data to be signed/verified."""
        data_entries = self.get_data_entries()
        data_to_sign = self.header.export()
        data_to_sign += b"".join(entry.export() for entry in data_entries)
        return data_to_sign

    def add_auth_entry(self, auth_type: AuthenticationType, key: Union[bytes, PrivateKey]) -> None:
        """Add the final data authentication entry.

        :param auth_type: Authentication Type
        :param key: Key for authentication
        :raises SPSDKError: Unknown or not-implemented Authentication type
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

        :param auth_entry: Authentication entry to validate
        :param keys: List of keys to validate against
        :return: True if signature is valid
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
        for public_key in keys:
            if isinstance(public_key, PublicKeyEcc):
                break
        else:
            raise SPSDKError("Supplied keys doesn't contain EC public key")
        # ECDSA signature doesn't contain any padding, can be used as is
        return public_key.verify_signature(auth_entry.payload, data_to_validate)

    def validate(self, keys: list[Union[bytes, PublicKey]]) -> bool:
        """Validate signature/authentication code.

        :param keys: Keys for validating signature
        :raises SPSDKError: Unknown or non-implemented Authentication type
        :return: True if signature/authentication code is valid
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
        """Reconstruct container from binary data."""
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

        :param path: Path to the file containing container data
        :return: Reconstructed container instance
        :raises SPSDKError: If file cannot be read or parsed
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
    """Common parser for all known DataEntry classes."""
    tag = data[3]
    return _ENTRY_CLASSES[EntryType.from_tag(tag)].parse(data=data)

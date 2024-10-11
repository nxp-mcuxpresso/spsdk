#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module implementing the TrustProvisioning Data Container."""

import struct
from abc import abstractmethod
from typing import Any, Mapping, Type

import hexdump
from typing_extensions import Self

from spsdk.tp.data_container.data_container_auth import (
    AuthenticationType,
    get_auth_data_len,
    sign,
    validate,
)
from spsdk.tp.data_container.payload_types import PayloadType
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.utils.misc import align, align_block
from spsdk.utils.spsdk_enum import SpsdkEnum

ALIGNMENT = 8


class EntryType(SpsdkEnum):
    """Enumeration of all supported Entry types."""

    STANDARD = (0xA0, "standard", "Standard Entry")
    DESTINATION = (0xB0, "destination", "Destination Entry")
    AUTHENTICATION = (0xC0, "authentication", "Authentication Entry")


class DestinationType(SpsdkEnum):
    """Destination type setting for DataDestinationEntry."""

    MEMORY = (0, "memory", "Address in memory")
    OTP = (2, "otp", "Index in OTP")


class BaseElement:
    """Base class for items used in data_container."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {vars(self)}>"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and vars(self) == vars(other)

    @abstractmethod
    def export(self) -> bytes:
        """Serialize object data."""

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Reconstruct object from serialized data."""


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
            raise SPSDKTpError(f"Invalid TAG found: {hex(tag)}, expected {hex(cls.TAG)}")
        header = cls(major=major, minor=minor, patch=patch)
        header.size = size
        return header


class Container(BaseElement):
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
        :raises SPSDKTpError: Container doesn't have an entry of required type
        :return: Entry with given type
        """
        for entry in self._entries:
            if entry.header.payload_type == payload_type:
                return entry
        raise SPSDKTpError(f"Container doesn't have an entry with type {payload_type.label}")

    def get_entries(self, payload_type: PayloadType) -> list[DataEntry]:
        """Get all entries for given payload type."""
        return [entry for entry in self._entries if entry.header.payload_type == payload_type]

    def add_auth_entry(self, auth_type: AuthenticationType, key: bytes) -> None:
        """Add the final data authentication entry.

        :param auth_type: Authentication Type
        :param key: Key for authentication
        :raises SPSDKTpError: Unknown or not-implemented Authentication type
        """
        if any(isinstance(entry, DataAuthenticationEntry) for entry in self._entries):
            raise SPSDKTpError("Can't add additional AuthEntry")
        # to add DataAuth entry we need all data so far + header of a not-yet-existing entry :/
        # on top of that we need to add "pro-forma" entry to update container header
        auth_data_len = get_auth_data_len(auth_type=auth_type)
        if self.header.major == 2:
            self.add_entry(
                DataAuthenticationEntryV2(
                    payload=bytes(auth_data_len), payload_type=0x0, extra=auth_type.tag
                )
            )
        else:
            self.add_entry(
                DataAuthenticationEntry(
                    payload=bytes(auth_data_len), payload_type=auth_type.tag, extra=0x0
                )
            )
        data = self.export()

        # find actual data to sign (skip the pro-forma signature)
        auth_entry = self._entries[-1]
        raw_data_end = auth_entry.total_size
        raw_data_end -= EntryHeader.SIZE
        data_to_sign = data[:-raw_data_end]

        signature = sign(data=data_to_sign, auth_type=auth_type, key=key)
        # update payload for last entry (signature)
        self._entries[-1].payload = signature

    def validate(self, key: bytes) -> bool:
        """Validate signature/authentication code.

        :param key: Key for validating signature
        :raises SPSDKTpError: Unknown or non-implemented Authentication type
        :return: True if signature/authentication code is valid
        """
        if not isinstance(self._entries[-1], DataAuthenticationEntry):
            raise SPSDKTpError("DataAuth Entry is not at the end of container")
        data = self.export()
        # to perform validation we need to split serialized:
        # - 'raw_data', signature, and padding
        # raw_data starts at the begging and ends with header of last entry (including the header)
        auth_entry = self._entries[-1]
        raw_data_end = auth_entry.total_size
        raw_data_end -= EntryHeader.SIZE
        data_to_validate = data[:-raw_data_end]

        return validate(
            data=data_to_validate,
            signature=auth_entry.payload,
            auth_type=auth_entry.get_auth_type(),
            key=key,
        )

    def get_auth_type(self) -> AuthenticationType:
        """Get the authentication type of the container."""
        if not isinstance(self._entries[-1], DataAuthenticationEntry):
            return AuthenticationType.NONE
        return self._entries[-1].get_auth_type()

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

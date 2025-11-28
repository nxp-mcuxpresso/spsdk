#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO Secure Objects management utilities.

This module provides functionality for handling secure objects used in EL2GO
provisioning, including TLV element processing, secure object validation,
and secure objects container management.
"""

from enum import Enum
from typing import Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db


class ElementTag(int, Enum):
    """TLV (Type-Length-Value) element tag enumeration for EL2GO secure objects.

    This enumeration defines the standardized tag values used to identify different
    types of elements within TLV-encoded secure object structures in the EL2GO
    provisioning system.
    """

    MAGIC = 0x40
    KEY_ID = 0x41
    KEY_ALGO = 0x42
    KEY_USAGE = 0x43
    KEY_TYPE = 0x44
    KEY_BITS = 0x45
    KEY_LIFETIME = 0x46
    DEVICE_LIFETIME = 0x47
    WRAP_KEY_ID = 0x50
    WRAP_ALGO = 0x51
    IV = 0x52
    SIGN_KEY_ID = 0x53
    SIGN_ALGO = 0x54
    KEY_BLOB = 0x55
    PROV_ID = 0x56
    SIGNATURE = 0x5E


class ValidationMethod(str, Enum):
    """Validation method enumeration for EL2GO Secure Objects.

    This enumeration defines the available validation methods that can be applied
    to secure objects during processing and verification operations.

    :cvar NONE: No validation applied to secure objects.
    :cvar MAX_COUNT: Validation based on maximum count of secure objects.
    :cvar MAX_SO_SIZE: Validation based on maximum size of individual secure objects.
    :cvar MAX_TOTAL_SIZE: Validation based on maximum total size of all secure objects.
    """

    NONE = "none"
    MAX_COUNT = "max_count"
    MAX_SO_SIZE = "max_so_size"
    MAX_TOTAL_SIZE = "max_total_size"


INTERNAL_SECURE_OBJECTS_IDS = [0x7FFF817A, 0x7FFF817B]


class TLVElement:
    """TLV (Tag-Length-Value) element representation for secure object encoding.

    This class provides functionality for creating, parsing, and manipulating TLV-encoded
    data structures commonly used in secure provisioning operations. It handles the
    encoding and decoding of binary data according to TLV format specifications.
    """

    def __init__(self, tag: Union[ElementTag, int], data: bytes):
        """Create TLV element.

        Initialize a Tag-Length-Value element with the specified tag and data.
        The constructor automatically calculates the length and builds the raw
        byte representation of the TLV element.

        :param tag: Element tag identifier, either as ElementTag enum or integer.
        :param data: Raw data bytes to be stored in the TLV value field.
        """
        self.tag = ElementTag(tag) if isinstance(tag, int) else tag
        self.value = data
        self.length = len(data)
        self.raw = bytes([self.tag]) + self.encode_length(self.length) + self.value

    def __repr__(self) -> str:
        """Return string representation of the secure object.

        The representation includes the tag name and the size of the value in bytes.

        :return: String in format "TagName(sizeB)" where TagName is the object's tag
            name and size is the value length in bytes.
        """
        return f"{self.tag.name}({len(self.value)}B)"

    def __str__(self) -> str:
        """Return string representation of the secure object.

        Provides a human-readable string that includes both the object's representation
        and its value for debugging and logging purposes.

        :return: Formatted string containing object representation and value.
        """
        return f"{repr(self)}: {self.value!r}"

    def export(self) -> bytes:
        """Export TLV element to binary data.

        :return: Raw binary representation of the TLV element.
        """
        return self.raw

    @property
    def size(self) -> int:
        """Get total size of TLV element in bytes.

        :return: Size of the TLV element in bytes.
        """
        return len(self.raw)

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, int]:
        """Parse TLV element from binary data and return element with offset to next TLV.

        The method parses Type-Length-Value structure from binary data starting at the beginning
        of the data buffer and calculates the offset to the next TLV element.

        :param data: Binary data containing TLV element to parse.
        :raises IndexError: When data buffer is too short for TLV parsing.
        :return: Tuple containing parsed TLV element and offset to next TLV element.
        """
        tag = ElementTag(data[0])
        length, offset = TLVElement.parse_length(data)
        value = data[offset : offset + length]
        return cls(tag, value), offset + length

    @classmethod
    def parse_length(cls, data: bytes) -> tuple[int, int]:
        """Parse length of TLV (Type-Length-Value) element.

        This method parses the length field of a TLV element according to ASN.1 DER encoding rules.
        It supports short form (length < 128) and long form (length >= 128) encodings.

        :param data: Raw bytes containing the TLV element starting with tag byte.
        :return: Tuple containing the parsed length value and offset to the value field.
        :raises ValueError: Invalid length encoding format.
        """
        if data[1] < 0x80:
            return data[1], 2
        if data[1] == 0x81:
            return data[2], 3
        if data[1] == 0x82:
            return int.from_bytes(data[2:4], "big"), 4
        if data[1] == 0x83:
            return int.from_bytes(data[2:5], "big"), 5
        raise ValueError("Invalid length encoding")

    @classmethod
    def encode_length(cls, length: int) -> bytes:
        """Encode length of TLV element.

        Encodes the length value according to DER (Distinguished Encoding Rules) format
        for TLV (Type-Length-Value) structures. Supports lengths up to 24-bit values.

        :param length: Length value to encode (0 to 16777215).
        :raises ValueError: If length is negative or exceeds maximum supported value.
        :return: Encoded length as bytes according to DER rules.
        """
        if length < 0x80:
            return bytes([length])
        if length < 0x100:
            return bytes([0x81, length])
        if length < 0x10000:
            return bytes([0x82, length >> 8, length & 0xFF])
        if length < 0x1000000:
            return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError("Invalid length")


class SecureObject(list[TLVElement]):
    """EdgeLock 2GO Secure Object representation.

    This class represents a secure object used in EdgeLock 2GO provisioning,
    containing a collection of TLV (Tag-Length-Value) elements that define
    the object's properties and data. Secure objects can be either internal
    (predefined) or external (user-defined) and are identified by unique IDs.
    """

    def get_object_id(self) -> int:
        """Get the object ID from secure object elements.

        Iterates through all elements in the secure object to find the element
        with KEY_ID tag and extracts the object ID value from it.

        :return: Object ID as integer value.
        :raises ValueError: Object ID element not found in the secure object.
        """
        for element in self:
            if element.tag == ElementTag.KEY_ID:
                return int.from_bytes(element.value, "big")
        raise ValueError("Object ID not found")

    def __repr__(self) -> str:
        """Return string representation of the Secure Object.

        Provides a concise string representation showing the object ID in hexadecimal format,
        current length, and total size for debugging and logging purposes.

        :return: String representation in format "<SO(0xID) len=X, size=Y>".
        """
        return f"<SO({self.get_object_id():0x}) len={len(self)}, size={self.size}>"

    def __str__(self) -> str:
        """Return string representation of the object with indented elements.

        Creates a multi-line string representation where the first line contains
        the object's repr() and subsequent lines show each element indented by
        two spaces.

        :return: Multi-line string representation with indented elements.
        """
        lines = [repr(self)]
        for element in self:
            lines.append("  " + str(element))
        return "\n".join(lines)

    @property
    def size(self) -> int:
        """Get total size of Secure Object.

        Calculates the sum of sizes of all elements contained within this Secure Object.

        :return: Total size in bytes of all elements in the Secure Object.
        """
        return sum(element.size for element in self)

    @property
    def length(self) -> int:
        """Get the number of elements in the Secure Object.

        :return: Number of elements in the Secure Object.
        """
        return len(self)

    @property
    def is_internal(self) -> bool:
        """Check if Secure Object is internal.

        Internal secure objects are predefined objects with specific IDs that are
        managed internally by the system.

        :return: True if the secure object is internal, False otherwise.
        """
        return self.get_object_id() in INTERNAL_SECURE_OBJECTS_IDS

    def export(self) -> bytes:
        """Export Secure Object to binary data.

        Concatenates all elements in the secure object and exports them as a single
        binary representation.

        :return: Binary data containing the exported secure object.
        """
        return b"".join(element.export() for element in self)

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, int]:
        """Parse Secure Object from binary data and return offset to next Secure Object.

        The method parses TLV elements from binary data to construct a Secure Object. It validates
        that the first element is a MAGIC tag with value 'edgelock2go' and stops parsing when
        it encounters the next Secure Object's MAGIC tag.

        :param data: Binary data containing the Secure Object to parse.
        :raises ValueError: Invalid Secure Object TAG or MAGIC value.
        :return: Tuple containing the parsed Secure Object instance and offset to next object.
        """
        elements: list[TLVElement] = []
        base_offset = 0
        while data:
            element, offset = TLVElement.parse(data)

            if len(elements) == 0:
                # check if first element is MAGIC
                if element.tag != ElementTag.MAGIC:
                    raise ValueError(
                        f"Invalid Secure Object TAG. Expected {ElementTag.MAGIC}, got {element.tag}"
                    )
                if element.value != b"edgelock2go":
                    raise ValueError(
                        f"Invalid Secure Object MAGIC value. Expected 'edgelock2go' got {element.value.hex()}"
                    )
            # we are too far in the next Secure Object
            if len(elements) > 1 and element.tag == ElementTag.MAGIC:
                break

            elements.append(element)
            data = data[offset:]
            base_offset += offset

        return cls(elements), base_offset


class SecureObjects(list[SecureObject]):
    """Collection of Secure Objects for EL2GO provisioning.

    This class extends the standard list to provide specialized functionality for
    managing secure objects including binary serialization, parsing, validation,
    and separation of internal/external objects for secure provisioning workflows.
    """

    def export(self) -> bytes:
        """Export Secure Objects to binary data.

        Concatenates all secure objects in the collection into a single binary representation
        by calling the export method on each object and joining the results.

        :return: Binary data containing all exported secure objects concatenated together.
        """
        return b"".join(obj.export() for obj in self)

    def __str__(self) -> str:
        """Get string representation of all secure objects.

        Converts all secure objects in the collection to their string representations
        and joins them with newline characters.

        :return: Multi-line string containing all secure objects, each on a separate line.
        """
        return "\n".join(str(obj) for obj in self)

    @property
    def size(self) -> int:
        """Get the size of all Secure Objects in bytes.

        :return: Total size of all secure objects in the collection in bytes.
        """
        return sum(obj.size for obj in self)

    @property
    def length(self) -> int:
        """Get the number of Secure Objects.

        :return: Number of Secure Objects in the collection.
        """
        return len(self)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Secure Objects from binary data.

        This method parses a sequence of secure objects from the provided binary data
        by iteratively parsing individual SecureObject instances until all data is consumed.

        :param data: Binary data containing one or more secure objects to parse.
        :return: New instance containing all parsed secure objects.
        """
        objects = []
        while data:
            obj, offset = SecureObject.parse(data)
            objects.append(obj)
            data = data[offset:]
        return cls(objects)

    def split_int_ext(self) -> tuple[bytes, bytes]:
        """Split Secure Objects into internal and external.

        Iterates through all secure objects in the collection and separates them
        based on their internal/external classification. Internal objects are
        concatenated into one byte sequence, external objects into another.

        :return: Tuple containing internal objects data and external objects data.
        """
        internal = b""
        external = b""
        for obj in self:
            if obj.is_internal:
                internal += obj.export()
            else:
                external += obj.export()
        return internal, external

    def validate(self, family: FamilyRevision) -> bool:
        """Validate Secure Objects against family-specific validation rules.

        The method retrieves validation configuration from the database for the specified
        family and executes the configured validators to ensure secure objects meet
        the required criteria.

        :param family: Target MCU family and revision for validation rules.
        :raises SPSDKError: If validation fails.
        :return: True if all validations pass successfully.
        """
        db = get_db(family=family)
        validator_string = db.get_str(DatabaseManager.EL2GO_TP, "validation_method", "none")
        # format of the validator_string: "method1=value1[,value2];method2=value3;..."
        validators = self._make_validator(validator_string)
        return self._run_validators(validators)

    def _run_validators(self, validators: dict[ValidationMethod, list[int]]) -> bool:
        """Run validation methods on the secure objects collection.

        Validates the secure objects collection against specified validation methods
        including count limits, individual object size limits, and total size limits.

        :param validators: Dictionary mapping validation methods to their limit values
        :raises SPSDKError: When any validation method fails its criteria
        :return: True if all validations pass
        """
        if ValidationMethod.NONE in validators:
            return True
        for method, values in validators.items():
            if method == ValidationMethod.MAX_COUNT:
                if self.length > int(values[0]):
                    raise SPSDKError(f"Too many Secure Objects. Max {values[0]}, got {len(self)}")
            if method == ValidationMethod.MAX_SO_SIZE:
                if any(obj.size > int(values[0]) for obj in self):
                    raise SPSDKError(f"Secure Object too big. Max {values[0]}")
            if method == ValidationMethod.MAX_TOTAL_SIZE:
                if sum(obj.size for obj in self) > int(values[0]):
                    raise SPSDKError(f"Total size of Secure Objects too big. Max {values[0]}")
        return True

    @classmethod
    def _make_validator(cls, validator_string: str) -> dict[ValidationMethod, list[int]]:
        """Parse validator configuration from string format.

        Converts a semicolon-separated string of validation methods into a dictionary
        mapping validation methods to their associated parameter values.

        :param validator_string: String containing validation methods separated by semicolons,
            with optional parameters in format "method=value1,value2".
        :return: Dictionary mapping ValidationMethod enum values to lists of integer
            parameters.
        """
        validators = {}
        for validator in validator_string.split(";"):
            if validator == ValidationMethod.NONE:
                continue
            if "=" in validator:
                m, values = validator.split("=")
                method = ValidationMethod(m)
            else:
                method = ValidationMethod(validator)
                values = ""
            validators[method] = [int(v) for v in values.split(",")]
        return validators

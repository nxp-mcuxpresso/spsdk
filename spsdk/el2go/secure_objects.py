#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module provides the Secure Objects helpers for the EL2GO."""

from enum import Enum
from typing import Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db


class ElementTag(int, Enum):
    """Type of TLV element."""

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
    SIGNATURE = 0x5E


class ValidationMethod(str, Enum):
    """Validation method for Secure Objects."""

    NONE = "none"
    MAX_COUNT = "max_count"
    MAX_SO_SIZE = "max_so_size"
    MAX_TOTAL_SIZE = "max_total_size"


INTERNAL_SECURE_OBJECTS_IDS = [0x7FFF817A, 0x7FFF817B]


class TLVElement:
    """TLV element class."""

    def __init__(self, tag: Union[ElementTag, int], data: bytes):
        """Create TLV element."""
        self.tag = ElementTag(tag) if isinstance(tag, int) else tag
        self.value = data
        self.length = len(data)
        self.raw = bytes([self.tag]) + self.encode_length(self.length) + self.value

    def __repr__(self) -> str:
        """Return string representation."""
        return f"{self.tag.name}({len(self.value)}B)"

    def __len__(self) -> int:
        """Return length of TLV element."""
        return len(self.raw)

    def export(self) -> bytes:
        """Export TLV element to binary data."""
        return self.raw

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, int]:
        """Parse TLV element from binary data and offset to next TLV element."""
        tag = ElementTag(data[0])
        length, offset = TLVElement.parse_length(data)
        value = data[offset : offset + length]
        return cls(tag, value), offset + length

    @classmethod
    def parse_length(cls, data: bytes) -> tuple[int, int]:
        """Parse length of TLV element. Return tuple of (length, offset to value)."""
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
        """Encode length of TLV element."""
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
    """Secure Object class."""

    def __len__(self) -> int:
        return sum(len(element) for element in self)

    def get_object_id(self) -> int:
        """Get the object ID."""
        for element in self:
            if element.tag == ElementTag.KEY_ID:
                return int.from_bytes(element.value, "big")
        raise ValueError("Object ID not found")

    @property
    def is_internal(self) -> bool:
        """Check if Secure Object is internal."""
        return self.get_object_id() in INTERNAL_SECURE_OBJECTS_IDS

    def export(self) -> bytes:
        """Export Secure Object to binary data."""
        return b"".join(element.export() for element in self)

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, int]:
        """Parse Secure Object from binary data and offset to next Secure Object."""
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
    """List of Secure Objects."""

    def export(self) -> bytes:
        """Export Secure Objects to binary data."""
        return b"".join(obj.export() for obj in self)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Secure Objects from binary data."""
        objects = []
        while data:
            obj, offset = SecureObject.parse(data)
            objects.append(obj)
            data = data[offset:]
        return cls(objects)

    def split_int_ext(self) -> tuple[bytes, bytes]:
        """Split Secure Objects into internal and external."""
        internal = b""
        external = b""
        for obj in self:
            if obj.is_internal:
                internal += obj.export()
            else:
                external += obj.export()
        return internal, external

    def validate(self, family: str) -> bool:
        """Validate Secure Objects.

        :raises SPSDKError: If validation fails.
        """
        db = get_db(device=family)
        validator_string = db.get_str(DatabaseManager.EL2GO_TP, "validation_method", "none")
        # format of the validator_string: "method1=value1[,value2];method2=value3;..."
        validators = self._make_validator(validator_string)
        return self._run_validators(validators)

    def _run_validators(self, validators: dict[ValidationMethod, list[int]]) -> bool:
        """Run validators."""
        if ValidationMethod.NONE in validators:
            return True
        for method, values in validators.items():
            if method == ValidationMethod.MAX_COUNT:
                if len(self) > int(values[0]):
                    raise SPSDKError(f"Too many Secure Objects. Max {values[0]}, got {len(self)}")
            if method == ValidationMethod.MAX_SO_SIZE:
                if any(len(obj) > int(values[0]) for obj in self):
                    raise SPSDKError(f"Secure Object too big. Max {values[0]}")
            if method == ValidationMethod.MAX_TOTAL_SIZE:
                if sum(len(obj) for obj in self) > int(values[0]):
                    raise SPSDKError(f"Total size of Secure Objects too big. Max {values[0]}")
        return True

    @classmethod
    def _make_validator(cls, validator_string: str) -> dict[ValidationMethod, list[int]]:
        """Make validator from string."""
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

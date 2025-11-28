#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Authentication protocol version management.

This module provides the ProtocolVersion class for handling version information
in the Debug Authentication Tool (DAT) protocol, including version comparison
and validation functionality.
"""


from dataclasses import dataclass

from typing_extensions import Self

from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKTypeError, SPSDKValueError


@dataclass
class ProtocolVersion:
    """Debug Authentication protocol version manager.

    This class represents and manages protocol versions used in Debug Authentication
    operations, providing version validation, comparison, and type determination
    functionality across different SPSDK authentication protocols.

    :cvar VERSIONS: List of supported protocol version strings.
    """

    VERSIONS = [
        "1.0",
        "1.1",
        "2.0",
        "2.1",
        "2.2",
        "3.0",  # 3.0 is the same as 3.2 AHAB v2
        "3.1",  # AHAB
        "3.2",  # AHAB v2
    ]

    version: str

    def __post_init__(self) -> None:
        """Post-initialization validation method.

        Validates the protocol version instance after all fields have been initialized
        by the dataclass constructor.

        :raises SPSDKValueError: If validation fails for any protocol version field.
        """
        self.validate()

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        Compare this protocol version instance with another object to determine if they are equal.
        Two protocol versions are considered equal if they have the same major and minor version numbers.

        :param obj: Object to compare with this protocol version instance.
        :return: True if objects are equal protocol versions with matching major and minor numbers,
            False otherwise.
        """
        return (
            isinstance(obj, self.__class__) and self.major == obj.major and self.minor == obj.minor
        )

    def __str__(self) -> str:
        """Get string representation of protocol version object.

        :return: String in format "Version {major}.{minor}".
        """
        return f"Version {self.major}.{self.minor}"

    def __repr__(self) -> str:
        """Return string representation of the object.

        This method delegates to __str__() to provide a string representation
        suitable for debugging and development purposes.

        :return: String representation of the object.
        """
        return self.__str__()

    def is_rsa(self) -> bool:
        """Determine whether RSA or ECC cryptographic algorithm is used.

        This method checks the major version number to identify the cryptographic
        algorithm type used in the protocol.

        :return: True if the protocol uses RSA cryptographic algorithm, False otherwise.
        """
        return self.major == 1

    def validate(self) -> None:
        """Validate the protocol version value.

        :raises SPSDKValueError: In case that protocol version is using unsupported version.
        """
        if self.version not in self.VERSIONS:
            raise SPSDKValueError(
                f"Unsupported version '{self.version}' was given. Available versions: {','.join(self.VERSIONS)}"
            )

    @property
    def major(self) -> int:
        """Get major version from version string.

        :raises IndexError: When version string format is invalid.
        :return: Major version number as integer.
        """
        return int(self.version.split(".", 2)[0])

    @property
    def minor(self) -> int:
        """Get minor version from version string.

        Extracts and returns the minor version number from the version string
        by splitting on dots and taking the second element.

        :raises IndexError: If version string doesn't contain at least two dot-separated parts.
        :raises ValueError: If the minor version part cannot be converted to integer.
        :return: Minor version number as integer.
        """
        return int(self.version.split(".", 2)[1])

    @classmethod
    def from_version(cls, major: int, minor: int) -> Self:
        """Load the version object from major and minor version.

        :param major: Major version number.
        :param minor: Minor version number.
        :raises SPSDKValueError: Invalid version format or unsupported version.
        :return: Protocol version object with validated version.
        """
        dat_protocol = cls(f"{major}.{minor}")
        dat_protocol.validate()
        return dat_protocol

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> Self:
        """Load the version object from public key.

        Creates a protocol version instance based on the type and key size of the provided
        public key. RSA keys map to major version 1, ECC keys to major version 2, with
        minor versions determined by key size.

        :param public_key: Public key object (RSA or ECC) to determine version from.
        :raises SPSDKTypeError: Unsupported public key type provided.
        :return: Protocol version instance corresponding to the public key.
        """
        if isinstance(public_key, PublicKeyRsa):
            minor = {2048: 0, 4096: 1}[public_key.key_size]
            return cls.from_version(major=1, minor=minor)
        if isinstance(public_key, PublicKeyEcc):
            minor = {256: 0, 384: 1, 521: 2}[public_key.key_size]
            return cls.from_version(major=2, minor=minor)
        raise SPSDKTypeError(f"Unsupported public key type: {type(public_key)}")

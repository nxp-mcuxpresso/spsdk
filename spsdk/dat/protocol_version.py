#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication protocol version class."""


from dataclasses import dataclass

from typing_extensions import Self

from spsdk.crypto.keys import PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.exceptions import SPSDKTypeError, SPSDKValueError


@dataclass
class ProtocolVersion:
    """Debug Authentication protocol version."""

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
        self.validate()

    def __eq__(self, obj: object) -> bool:
        """Check object equality.

        :param other: object to compare with.
        :return: True if matches, False otherwise.
        """
        return (
            isinstance(obj, self.__class__) and self.major == obj.major and self.minor == obj.minor
        )

    def __str__(self) -> str:
        """String representation of protocol version object."""
        return f"Version {self.major}.{self.minor}"

    def __repr__(self) -> str:
        return self.__str__()

    def is_rsa(self) -> bool:
        """Determine whether rsa or ecc is used.

        :return: True if the protocol is RSA type. False otherwise
        """
        return self.major == 1

    def validate(self) -> None:
        """Validate the protocol version value.

        :raises SPSDKValueError: In case that protocol version is using unsupported key type.
        """
        if self.version not in self.VERSIONS:
            raise SPSDKValueError(
                f"Unsupported version '{self.version}' was given. Available versions: {','.join(self.VERSIONS)}"
            )

    @property
    def major(self) -> int:
        """Get major version."""
        return int(self.version.split(".", 2)[0])

    @property
    def minor(self) -> int:
        """Get minor version."""
        return int(self.version.split(".", 2)[1])

    @classmethod
    def from_version(cls, major: int, minor: int) -> Self:
        """Load the version object from major and minor version."""
        dat_protocol = cls(f"{major}.{minor}")
        dat_protocol.validate()
        return dat_protocol

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> Self:
        """Load the version object from public key."""
        if isinstance(public_key, PublicKeyRsa):
            minor = {2048: 0, 4096: 1}[public_key.key_size]
            return cls.from_version(major=1, minor=minor)
        if isinstance(public_key, PublicKeyEcc):
            minor = {256: 0, 384: 1, 521: 2}[public_key.key_size]
            return cls.from_version(major=2, minor=minor)
        raise SPSDKTypeError(f"Unsupported public key type: {type(public_key)}")

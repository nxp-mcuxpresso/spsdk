#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Data structures used throughout the DICE module."""

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Union

from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.dice.exceptions import SPSDKDICEError


@dataclass
class APIResponse:
    """Response from the verification service."""

    api: str
    status: str
    message: str
    expected_had: Optional[str] = None
    actual_had: Optional[str] = None

    @property
    def success(self) -> bool:
        """Flag indicating whether the response is successful."""
        return self.status in ["OK", "HAD_DIFF"]

    def __repr__(self) -> str:
        return f"APIResponse(api={self.api}, status={self.status}, message={self.message})"


class DICEVerificationService(ABC):
    """Abstract class defining DICE Verification Service interface."""

    @abstractmethod
    def register_dice_ca_puk(self, key_data: bytes) -> APIResponse:
        """Register DICE CA PUK in the service."""

    @abstractmethod
    def register_version(self, data: bytes) -> APIResponse:
        """Register new version or update existing one."""

    @abstractmethod
    def get_challenge(self, pre_set: Optional[str] = None) -> bytes:
        """Get challenge vector from the service."""

    @abstractmethod
    def verify(self, data: bytes, reset_challenge: bool = False) -> APIResponse:
        """Submit DICE response for verification."""


class DICETarget(ABC):
    """Abstract class defining DICE Target (MCU) interface."""

    @abstractmethod
    def get_ca_puk(self, rkth: bytes) -> bytes:
        """Generate and return DICE CA PUK from the target."""

    @abstractmethod
    def get_dice_response(self, challenge: bytes) -> bytes:
        """Generate and return DICE response to challenge on the target."""


class DICEResponse:
    """Representation of the DICE Response (Target's response to challenge)."""

    # RTF, HAD, DIE_PUK, CA_SIGN, UUID, Version, Challenge, DIE_SIGN
    DATA_TO_SIGN = ">32s48s64s64s16s4s32s"
    FORMAT = DATA_TO_SIGN + "64s"

    def __init__(
        self,
        die_puk: Union[str, bytes, PublicKeyEcc],
        rtf: Union[str, bytes],
        had: Union[str, bytes],
        uuid: Union[str, bytes],
        version: Union[int, bytes],
        challenge: Union[str, bytes],
        ca_signature: Optional[Union[str, bytes]] = None,
        die_signature: Optional[Union[str, bytes]] = None,
    ) -> None:
        """Initialize the DICE Response object.

        :param uuid: UUID of the chip
        :param challenge: Challenge vector from verification service
        :param rtf: Runtime fingerprint
        :param had: Hardware Attestation Data
        :param signature: Response signature (available when parsing), defaults to None
        """
        if isinstance(die_puk, PublicKeyEcc):
            self.die_puk = die_puk.export()
        else:
            self.die_puk = bytes.fromhex(die_puk) if isinstance(die_puk, str) else die_puk

        self.rtf = bytes.fromhex(rtf) if isinstance(rtf, str) else rtf
        self.had = bytes.fromhex(had) if isinstance(had, str) else had
        self.uuid = bytes.fromhex(uuid) if isinstance(uuid, str) else uuid
        self.version = (
            version.to_bytes(length=4, byteorder="big") if isinstance(version, int) else version
        )
        self.version_int = int.from_bytes(self.version, byteorder="big")
        self.challenge = bytes.fromhex(challenge) if isinstance(challenge, str) else challenge

        self.ca_signature: Optional[bytes]  # Mypy needs a bit of help sometimes
        if ca_signature:
            self.ca_signature = (
                bytes.fromhex(ca_signature) if isinstance(ca_signature, str) else ca_signature
            )
        else:
            self.ca_signature = None

        self.die_signature: Optional[bytes]  # Mypy needs a bit of help sometimes
        if die_signature:
            self.die_signature = (
                bytes.fromhex(die_signature) if isinstance(die_signature, str) else die_signature
            )
        else:
            self.die_signature = None

    def info(self) -> str:
        """Stringified information about the DICE response object."""
        return (
            f"RTF      : {self.rtf.hex()}\n"
            f"HAD      : {self.had.hex()}\n"
            f"DIE_PUK  : {self.die_puk.hex()}\n"
            f"CA_SIGN  : {self.ca_signature.hex() if self.ca_signature else 'N/A'}\n"
            f"UUID     : {self.uuid.hex()}\n"
            f"Version  : {self.version.hex()}\n"
            f"Challenge: {self.challenge.hex()}\n"
            f"DIE_SIGN : {self.die_signature.hex() if self.die_signature else 'N/A'}"
        )

    def sign(self, ca_prk: PrivateKeyEcc, die_prk: PrivateKeyEcc) -> None:
        """Sign the DICE Response."""
        data = bytes([0x03, 0x00, 0x17, 0x41, 0x04])
        data += self.die_puk
        self.ca_signature = ca_prk.sign(data=data)
        data = self._export_data_to_sign()
        self.die_signature = die_prk.sign(data=data)

    def verify(self, ca_puk: PublicKeyEcc) -> bool:
        """Verify DICE Response signature."""
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must be signed before signature verification!")
        if not self.verify_ca_signature(ca_puk=ca_puk):
            return False
        if not self.verify_die_signature():
            return False
        return True

    def verify_die_signature(self) -> bool:
        """Verify CSR DIE signatures."""
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must by signed before signature verification!")
        data = self._export_data_to_sign()
        die_puk = PublicKeyEcc.parse(self.die_puk)
        return die_puk.verify_signature(signature=self.die_signature, data=data)

    def verify_ca_signature(self, ca_puk: PublicKeyEcc) -> bool:
        """Verify CSR CA signatures."""
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("Dice Response must by signed before signature verification!")
        data = bytes([0x03, 0x00, 0x17, 0x41, 0x04])
        data += self.die_puk
        return ca_puk.verify_signature(signature=self.ca_signature, data=data)

    def export(self) -> bytes:
        """Serialize DICE Response object into bytes."""
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must be signed before export")
        return self._export_data_to_sign() + self.die_signature

    def _export_data_to_sign(self) -> bytes:
        if not self.ca_signature:
            raise SPSDKDICEError("DICE Response must be signed before export")
        return struct.pack(
            self.DATA_TO_SIGN,
            self.rtf,
            self.had,
            self.die_puk,
            self.ca_signature,
            self.uuid,
            self.version,
            self.challenge,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "DICEResponse":
        """De-serialize data into DICE Response object."""
        (rtf, had, die_puk, ca_sign, uuid, version, challenge, die_sign) = struct.unpack_from(
            cls.FORMAT, buffer=data, offset=offset
        )
        return DICEResponse(
            die_puk=die_puk,
            ca_signature=ca_sign,
            rtf=rtf,
            had=had,
            uuid=uuid,
            version=version,
            challenge=challenge,
            die_signature=die_sign,
        )

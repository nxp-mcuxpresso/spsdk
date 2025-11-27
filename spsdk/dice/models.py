#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DICE module data models and service interfaces.

This module defines the core data structures and abstract interfaces used
throughout the DICE (Device Identifier Composition Engine) implementation,
including API response models, verification services, and target definitions.
"""

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Union

from typing_extensions import Self

from spsdk.crypto.keys import PrivateKeyEcc, PublicKeyEcc
from spsdk.dice.exceptions import SPSDKDICEError


@dataclass
class APIResponse:
    """DICE verification service API response container.

    This class encapsulates the response data received from DICE verification
    services, including status information and optional Hardware Attestation
    Digest (HAD) comparison results.
    """

    api: str
    status: str
    message: str
    expected_had: Optional[str] = None
    actual_had: Optional[str] = None

    @property
    def success(self) -> bool:
        """Check if the response indicates a successful operation.

        The method evaluates the status field to determine if the response represents
        a successful outcome, considering both "OK" and "HAD_DIFF" as success states.

        :return: True if the response status indicates success, False otherwise.
        """
        return self.status in ["OK", "HAD_DIFF"]

    def __repr__(self) -> str:
        """Return string representation of APIResponse object.

        :return: String representation containing API, status, and message information.
        """
        return f"APIResponse(api={self.api}, status={self.status}, message={self.message})"


class DICEVerificationService(ABC):
    """DICE Verification Service interface.

    This abstract class defines the contract for DICE (Device Identifier Composition Engine)
    verification services, providing methods for CA public key registration, version
    management, challenge generation, and response verification.
    """

    @abstractmethod
    def register_dice_ca_puk(self, key_data: bytes) -> APIResponse:
        """Register DICE CA PUK in the service.

        :param key_data: The public key data in bytes format to be registered.
        :return: API response containing the result of the registration operation.
        """

    @abstractmethod
    def register_version(self, data: bytes) -> APIResponse:
        """Register new version or update existing one.

        The method processes binary data containing version information and either registers
        a new version entry or updates an existing version record in the system.

        :param data: Binary data containing version information to register or update.
        :return: API response object containing the result of the registration operation.
        """

    @abstractmethod
    def get_challenge(self, pre_set: Optional[str] = None) -> bytes:
        """Get challenge vector from the service.

        The method retrieves a challenge vector that can be used for cryptographic operations.
        If a pre-set value is provided, it will be used instead of generating a new challenge.

        :param pre_set: Optional pre-set challenge value to use instead of generating new one.
        :return: Challenge vector as bytes.
        """

    @abstractmethod
    def verify(self, data: bytes, reset_challenge: bool = False) -> APIResponse:
        """Submit DICE response for verification.

        The method processes the provided DICE response data and performs cryptographic
        verification against the current challenge state.

        :param data: The DICE response data to be verified.
        :param reset_challenge: Whether to reset the challenge after verification, defaults to False.
        :return: API response containing verification results.
        """


class DICETarget(ABC):
    """DICE Target interface for MCU communication.

    This abstract class defines the interface for communicating with DICE-enabled
    MCUs, providing methods for certificate authority public key retrieval and
    challenge-response authentication operations.
    """

    @abstractmethod
    def get_ca_puk(self, rkth: bytes, mldsa: bool = False) -> bytes:
        """Generate and return DICE CA PUK from the target.

        :param rkth: Root Key Table Hash used for CA PUK generation.
        :param mldsa: Flag to indicate if ML-DSA algorithm should be used, defaults to False.
        :return: Generated DICE CA Public Key as bytes.
        """

    @abstractmethod
    def get_dice_response(self, challenge: bytes) -> bytes:
        """Generate and return DICE response to challenge on the target.

        :param challenge: Challenge bytes to be processed by the DICE implementation.
        :return: DICE response bytes generated from the provided challenge.
        """


class DICEResponse:
    """DICE Response message handler for device attestation.

    This class represents and manages DICE (Device Identifier Composition Engine) response
    messages that contain device attestation data including hardware fingerprints,
    certificates, and cryptographic signatures for secure device verification.

    :cvar DATA_TO_SIGN: Binary format specification for signable data fields.
    :cvar FORMAT: Complete binary format including signature field.
    """

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

        Converts input parameters from various formats (strings, bytes, objects) to their
        appropriate internal byte representations for DICE attestation processing.

        :param die_puk: Die public key as hex string, bytes, or PublicKeyEcc object.
        :param rtf: Runtime fingerprint as hex string or bytes.
        :param had: Hardware Attestation Data as hex string or bytes.
        :param uuid: UUID of the chip as hex string or bytes.
        :param version: Version number as integer or bytes.
        :param challenge: Challenge vector from verification service as hex string or bytes.
        :param ca_signature: CA signature as hex string or bytes, defaults to None.
        :param die_signature: Die signature as hex string or bytes, defaults to None.
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
        """Get stringified information about the DICE response object.

        Returns a formatted string containing all DICE response fields including RTF, HAD,
        DIE_PUK, CA_SIGN, UUID, Version, Challenge, and DIE_SIGN in hexadecimal format.

        :return: Formatted string with DICE response object information.
        """
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
        """Sign the DICE Response with CA and DIE private keys.

        This method performs the signing process for DICE (Device Identifier Composition Engine)
        response by creating signatures using both Certificate Authority and Device Identity
        private keys. The CA signature is generated over the die public key data, while the
        DIE signature is generated over the exported response data.

        :param ca_prk: Certificate Authority private key used for CA signature generation.
        :param die_prk: Device Identity private key used for DIE signature generation.
        """
        data = bytes([0x03, 0x00, 0x17, 0x41, 0x04])
        data += self.die_puk
        self.ca_signature = ca_prk.sign(data=data)
        data = self._export_data_to_sign()
        self.die_signature = die_prk.sign(data=data)

    def verify(self, ca_puk: PublicKeyEcc) -> bool:
        """Verify DICE Response signature.

        This method verifies both the CA signature and DIE signature of the DICE Response.
        It ensures that both signatures are present and valid before confirming the overall
        verification status.

        :param ca_puk: CA public key used for CA signature verification.
        :raises SPSDKDICEError: DICE Response must be signed before signature verification.
        :return: True if both CA and DIE signatures are valid, False otherwise.
        """
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must be signed before signature verification!")
        if not self.verify_ca_signature(ca_puk=ca_puk):
            return False
        if not self.verify_die_signature():
            return False
        return True

    def verify_die_signature(self) -> bool:
        """Verify CSR DIE signatures.

        Validates the DIE signature against the DIE public key using the exported data that was
        signed during the CSR process.

        :raises SPSDKDICEError: When CA signature or DIE signature is missing.
        :return: True if signature verification succeeds, False otherwise.
        """
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must by signed before signature verification!")
        data = self._export_data_to_sign()
        die_puk = PublicKeyEcc.parse(self.die_puk)
        return die_puk.verify_signature(signature=self.die_signature, data=data)

    def verify_ca_signature(self, ca_puk: PublicKeyEcc) -> bool:
        """Verify CA signature of the DICE response.

        This method verifies the CA signature using the provided CA public key. The verification
        is performed on a data structure that includes a fixed header and the device's public key.

        :param ca_puk: CA public key used for signature verification.
        :raises SPSDKDICEError: If CA signature or die signature is missing.
        :return: True if signature verification succeeds, False otherwise.
        """
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("Dice Response must by signed before signature verification!")
        data = bytes([0x03, 0x00, 0x17, 0x41, 0x04])
        data += self.die_puk
        return ca_puk.verify_signature(signature=self.ca_signature, data=data)

    def export(self) -> bytes:
        """Export the DICE Response as bytes.

        The method exports the complete DICE Response including both the data and the die signature.
        The response must be properly signed before export can be performed.

        :raises SPSDKDICEError: DICE Response must be signed before export.
        :return: Exported DICE Response bytes including signature.
        """
        if not self.ca_signature or not self.die_signature:
            raise SPSDKDICEError("DICE Response must be signed before export")
        return self._export_data_to_sign() + self.die_signature

    def _export_data_to_sign(self) -> bytes:
        """Export DICE response data that needs to be signed.

        This method packs the DICE response data into a binary format suitable for signing.
        It validates that the CA signature is present before proceeding with the export.

        :raises SPSDKDICEError: If CA signature is not present in the DICE response.
        :return: Binary representation of the data to be signed.
        """
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
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse DICE Response from bytes.

        :param data: DICE Response in bytes format to be parsed.
        :param offset: Optional starting offset in the data buffer, defaults to 0.
        :return: Parsed DICEResponse instance.
        """
        (rtf, had, die_puk, ca_sign, uuid, version, challenge, die_sign) = struct.unpack_from(
            cls.FORMAT, buffer=data, offset=offset
        )
        return cls(
            die_puk=die_puk,
            ca_signature=ca_sign,
            rtf=rtf,
            had=had,
            uuid=uuid,
            version=version,
            challenge=challenge,
            die_signature=die_sign,
        )

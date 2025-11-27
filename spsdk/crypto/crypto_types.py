#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic type definitions and enumerations.

This module provides common cryptographic types, enumerations, and constants
used across SPSDK for cryptographic operations and certificate handling.
"""

from cryptography import utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.base import Version
from cryptography.x509.extensions import ExtensionOID, Extensions, KeyUsage
from cryptography.x509.name import Name, NameOID, ObjectIdentifier

from spsdk.exceptions import SPSDKError


class SPSDKEncoding(utils.Enum):
    """SPSDK cryptographic encoding enumeration.

    This enumeration extends the standard cryptography library encodings with
    NXP-specific encoding formats. It provides utilities for encoding detection,
    conversion between SPSDK and cryptography library formats, and validation
    of supported encoding types for cryptographic operations.
    """

    NXP = "NXP"
    PEM = "PEM"
    DER = "DER"

    @staticmethod
    def get_cryptography_encodings(encoding: "SPSDKEncoding") -> Encoding:
        """Get cryptography library encoding from SPSDK encoding.

        Converts SPSDK encoding enumeration to the corresponding cryptography library
        encoding format for use with cryptography operations.

        :param encoding: SPSDK encoding type to convert.
        :raises SPSDKError: If the encoding format is not supported by cryptography.
        :return: Corresponding cryptography library encoding.
        """
        cryptography_encoding = {
            SPSDKEncoding.PEM: Encoding.PEM,
            SPSDKEncoding.DER: Encoding.DER,
        }.get(encoding)
        if cryptography_encoding is None:
            raise SPSDKError(f"{encoding} format is not supported by cryptography.")
        return cryptography_encoding

    @staticmethod
    def get_file_encodings(data: bytes) -> "SPSDKEncoding":
        """Determine encoding type of cryptographic data.

        Analyzes the provided data to detect whether it uses PEM (text-based) or DER (binary)
        encoding format by checking for UTF-8 decodability and PEM markers.

        :param data: Raw bytes of the data file to analyze for encoding detection.
        :return: Detected encoding type (SPSDKEncoding.PEM or SPSDKEncoding.DER).
        """
        encoding = SPSDKEncoding.PEM
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            encoding = SPSDKEncoding.DER
        else:
            if decoded.find("----") == -1:
                encoding = SPSDKEncoding.DER
        return encoding

    @staticmethod
    def all() -> dict[str, "SPSDKEncoding"]:
        """Get all supported encodings.

        :return: Dictionary mapping encoding names to SPSDKEncoding enum values.
        """
        return {"NXP": SPSDKEncoding.NXP, "PEM": SPSDKEncoding.PEM, "DER": SPSDKEncoding.DER}

    @staticmethod
    def cryptography_encodings() -> dict[str, "SPSDKEncoding"]:
        """Get all supported encodings by cryptography.

        Returns a dictionary mapping encoding names to their corresponding SPSDKEncoding values
        that are supported by the cryptography library.

        :return: Dictionary with encoding names as keys and SPSDKEncoding enum values as values.
        """
        return {"PEM": SPSDKEncoding.PEM, "DER": SPSDKEncoding.DER}


SPSDKExtensions = Extensions
SPSDKExtensionOID = ExtensionOID
SPSDKNameOID = NameOID
SPSDKKeyUsage = KeyUsage
SPSDKName = Name
SPSDKVersion = Version
SPSDKObjectIdentifier = ObjectIdentifier

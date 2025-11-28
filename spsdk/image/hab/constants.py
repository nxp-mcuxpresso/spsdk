#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""HAB (High Assurance Boot) constants module.

This module contains enumeration constants used for HAB security operations including
algorithm types, certificate formats, engine plugins, and security commands.
"""

from spsdk.utils.spsdk_enum import SpsdkEnum


class EnumAlgorithm(SpsdkEnum):
    """HAB algorithm type enumeration.

    This enumeration defines algorithm identifiers used in High Assurance Boot (HAB)
    for cryptographic operations including hashing, signatures, ciphers, and key wrapping.
    Each algorithm is represented by a unique identifier, name, and description following
    the HAB specification standards.
    """

    ANY = (0x00, "ANY", "Algorithm type ANY")
    HASH = (0x01, "HASH", "Hash algorithm type")
    SIG = (0x02, "SIG", "Signature algorithm type")
    F = (0x03, "F", "Finite field arithmetic")
    EC = (0x04, "EC", "Elliptic curve arithmetic")
    CIPHER = (0x05, "CIPHER", "Cipher algorithm type")
    MODE = (0x06, "MODE", "Cipher/hash modes")
    WRAP = (0x07, "WRAP", "Key wrap algorithm type")
    # Hash algorithms
    SHA1 = (0x11, "SHA1", "SHA-1 algorithm ID")
    SHA256 = (0x17, "SHA256", "SHA-256 algorithm ID")
    SHA512 = (0x1B, "SHA512", "SHA-512 algorithm ID")
    # Signature algorithms
    PKCS1 = (0x21, "PKCS1", "PKCS#1 RSA signature algorithm")
    ECDSA = (0x27, "ECDSA", "NIST ECDSA signature algorithm")
    # Cipher algorithms
    AES = (0x55, "AES", "AES algorithm ID")
    # Cipher or hash modes
    CCM = (0x66, "CCM", "Counter with CBC-MAC")
    # Key wrap algorithms
    BLOB = (0x71, "BLOB", "SHW-specific key wrap")


class CertFormatEnum(SpsdkEnum):
    """HAB certificate format enumeration for secure boot operations.

    This enumeration defines the supported certificate and signature format types
    used in High Assurance Boot (HAB) operations, including various cryptographic
    formats and proprietary key wrapping mechanisms.
    """

    SRK = (0x03, "SRK", "SRK certificate format")
    X509 = (0x09, "X509", "X.509v3 certificate format")
    CMS = (0xC5, "CMS", "CMS/PKCS#7 signature format")
    BLOB = (0xBB, "BLOB", "SHW-specific wrapped key format")
    AEAD = (0xA3, "AEAD", "Proprietary AEAD MAC format")


class EngineEnum(SpsdkEnum):
    """HAB engine plugin enumeration for cryptographic and security operations.

    This enumeration defines the available engine plugins used in HAB (High Assurance Boot)
    for various cryptographic and security operations. Each engine represents a specific
    hardware or software component that can perform security-related functions during
    the boot process.
    """

    ANY = (
        0x00,
        "ANY",
        "First compatible engine will be selected (no engine configuration parameters are allowed)",
    )
    SCC = (0x03, "ANY", "Security controller")
    RTIC = (0x05, "RTIC", "Run-time integrity checker")
    SAHARA = (0x06, "SAHARA", "Crypto accelerator")
    CSU = (0x0A, "CSU", "Central Security Unit")
    SRTC = (0x0C, "SRTC", "Secure clock")
    DCP = (0x1B, "DCP", "Data Co-Processor")
    CAAM = (0x1D, "CAAM", "Cryptographic Acceleration and Assurance Module")
    SNVS = (0x1E, "SNVS", "Secure Non-Volatile Storage")
    OCOTP = (0x21, "OCOTP", "Fuse controller")
    DTCP = (0x22, "DTCP", "DTCP co-processor")
    ROM = (0x36, "ROM", "Protected ROM area")
    HDCP = (0x24, "HDCP", "HDCP co-processor")
    SW = (0xFF, "SW", "Software engine")


class CmdName(SpsdkEnum):
    """HAB CSF command enumeration.

    This enumeration defines all available Command Sequence File (CSF) commands
    used in High Assurance Boot (HAB) for secure boot operations including
    key installation, authentication, decryption, and engine configuration.
    """

    HEADER = (20, "Header", "Header")
    INSTALL_SRK = (21, "InstallSRK", "Install SRK")
    INSTALL_CSFK = (22, "InstallCSFK", "Install CSFK")
    INSTALL_NOCAK = (23, "InstallNOCAK", "Install NOCAK")
    AUTHENTICATE_CSF = (24, "AuthenticateCSF", "Authenticate CSF")
    INSTALL_KEY = (25, "InstallKey", "Install Key")
    AUTHENTICATE_DATA = (26, "AuthenticateData", "Authenticate data")
    INSTALL_SECRET_KEY = (27, "SecretKey", "Install Secret Key")
    DECRYPT_DATA = (28, "Decrypt", "Decrypt data")
    SET_ENGINE = (31, "SetEngine", "Set Engine")
    UNLOCK = (33, "Unlock", "Unlock")


class CmdTag(SpsdkEnum):
    """CSF/DCD Command Tag enumeration.

    This enumeration defines the command tags used in Command Sequence Files (CSF)
    and Device Configuration Data (DCD) for HAB (High Assurance Boot) operations.
    Each tag represents a specific command type with its corresponding opcode and
    description for secure boot operations.
    """

    SET = (0xB1, "SET", "Set")
    INS_KEY = (0xBE, "INS_KEY", "Install Key")
    AUT_DAT = (0xCA, "AUT_DAT", "Authenticate Data")
    WRT_DAT = (0xCC, "WRT_DAT", "Write Data")
    CHK_DAT = (0xCF, "CHK_DAT", "Check Data")
    NOP = (0xC0, "NOP", "No Operation (NOP)")
    INIT = (0xB4, "INIT", "Initialize")
    UNLK = (0xB2, "UNLK", "Unlock")

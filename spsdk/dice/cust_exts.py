#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK DICE custom X.509 v3 extensions and certificate management.

This module provides custom X.509 certificate extensions for DICE (Device Identifier
Composition Engine) implementation, including TCB (Trusted Computing Base) information
handling and TCG DICE-specific extensions for secure device provisioning.
"""

import abc

from cryptography import x509

from spsdk.dice.tcg_asn import (
    FWIDLIST,
    DiceTcbInfo,
    DiceTcbInfoSeq,
    OperationalFlags,
    OperationalFlagsMask,
    TcgUeid,
)


class TCBInfoTable(abc.ABC):
    """Abstract base class for DICE TCB (Trusted Computing Base) information tables.

    This class provides a foundation for managing TCB information including security
    version numbers and firmware ID hashes. It handles encoding of TCB data into
    ASN.1 format for DICE attestation purposes.

    :cvar descriptor_type: Type identifier for the TCB descriptor.
    :cvar descriptor_flags: Flags associated with the TCB descriptor.
    :cvar table_name: Name identifier for the specific TCB table type.
    """

    descriptor_type: int
    descriptor_flags: int
    table_name: str

    def __init__(self, svn: int, fwid_hashes: list[bytes]):
        """Initialize TCB info table with security version number and firmware ID hashes.

        The method initializes the TCB (Trusted Computing Base) info table by setting the
        security version number and processing firmware ID hashes to ensure they are properly
        zero-padded to 48 bytes.

        :param svn: Security version number used for rollback protection.
        :param fwid_hashes: List of firmware ID hash bytes to be stored in the table.
        """
        self.svn = svn
        self.fwid_hashes = [h.zfill(48) for h in fwid_hashes]

    def encode(self) -> bytes:
        """Encode the TCB info table into bytes.

        The method converts the TCB (Trusted Computing Base) info table to its ASN.1
        representation and then encodes it into a byte sequence for transmission or storage.

        :return: Encoded TCB info table as bytes.
        """
        tcb_info = self.asn1()
        tcb_data = tcb_info.encode()
        return tcb_data

    def asn1(self) -> DiceTcbInfo:
        """Create ASN.1 representation of the TCB info table.

        Converts the TCB (Trusted Computing Base) info table data into its
        corresponding ASN.1 DiceTcbInfo structure format.

        :return: ASN.1 DiceTcbInfo object containing the table name, SVN, and FWID hashes.
        """
        tcb_info = DiceTcbInfo()
        tcb_info.setComponentByName("type", self.table_name.encode("utf-8"))
        tcb_info.setComponentByName("svn", self.svn)
        tcb_info.setComponentByName("fwids", FWIDLIST.create(self.fwid_hashes))
        return tcb_info


class FMC_TCB(TCBInfoTable):
    """TCB information table for FMC (Flash Memory Controller).

    This class represents a specialized TCB (Trusted Computing Base) information table
    specifically designed for Flash Memory Controller operations in DICE attestation.

    :cvar descriptor_type: TCB descriptor type identifier for FMC.
    :cvar descriptor_flags: Configuration flags for FMC TCB descriptor.
    :cvar table_name: Human-readable name for the FMC information table.
    """

    descriptor_type = 1
    descriptor_flags = 0x48
    table_name = "FMC_INFO"


class CUST_TCB(TCBInfoTable):
    """SPSDK Customer TCB Information Table.

    This class represents a customer-specific Trusted Computing Base (TCB) information
    table that extends the standard TCB info with operational flags and masks for
    DICE attestation in NXP MCU devices.

    :cvar descriptor_type: TCB descriptor type identifier (2).
    :cvar descriptor_flags: TCB descriptor flags (0x4C0).
    :cvar table_name: Human-readable table name for identification.
    """

    descriptor_type = 2
    descriptor_flags = 0x4C0
    table_name = "CUST_INFO"

    def __init__(self, svn: int, fwid_hashes: list[bytes], flags: int, mask: int):
        """Initialize customer TCB info with SVN, firmware hashes, operational flags and mask.

        :param svn: Security version number
        :param fwid_hashes: List of firmware ID hashes
        :param flags: Operational flags
        :param mask: Operational flags mask
        """
        super().__init__(svn, fwid_hashes)
        self.flags = flags
        self.mask = mask

    def asn1(self) -> DiceTcbInfo:
        """Create ASN.1 representation of the customer TCB info table with flags.

        This method extends the base ASN.1 representation by adding operational flags
        and their corresponding mask to the DiceTcbInfo structure.

        :return: ASN.1 DiceTcbInfo object with flags and mask components set.
        """
        tcb_info = super().asn1()
        tcb_info.setComponentByName("flags", OperationalFlags.create(self.flags))
        tcb_info.setComponentByName("flagsMask", OperationalFlagsMask.create(self.mask))
        return tcb_info


class NXP_TCB(TCBInfoTable):
    """NXP TCB information table for DICE attestation.

    This class represents a Trusted Computing Base (TCB) information table
    specifically designed for NXP devices in DICE attestation scenarios.
    It extends the base TCBInfoTable with NXP-specific descriptor settings
    and table identification.

    :cvar descriptor_type: TCB descriptor type identifier (3).
    :cvar descriptor_flags: TCB descriptor flags configuration (0x48).
    :cvar table_name: Human-readable table identifier ("NXP_INFO").
    """

    descriptor_type = 3
    descriptor_flags = 0x48
    table_name = "NXP_INFO"


class TCGDiceUeid(x509.UnrecognizedExtension):
    """X.509 extension for TCG DICE Unique Entity Identifier.

    This class implements a custom X.509 extension that encapsulates the TCG DICE
    (Trusted Computing Group Device Identifier Composition Engine) Unique Entity
    Identifier, providing standardized device identification in certificate chains.

    :cvar oid: Object identifier for the TCG DICE UEID extension.
    """

    oid = x509.ObjectIdentifier(TcgUeid.oid)

    def __init__(self, value: bytes):
        """Initialize TCG DICE UEID extension with binary value.

        :param value: Binary value for the UEID.
        """
        super().__init__(oid=self.oid, value=TcgUeid.encode(value))


class TCGDiceTcbInfo(x509.UnrecognizedExtension):
    """X.509 extension for TCG DICE TCB information.

    This extension implements the Trusted Computing Group (TCG) DICE specification
    for encoding Trusted Computing Base (TCB) information in X.509 certificates.
    It encapsulates TCB measurements and metadata required for device attestation
    and secure boot verification.

    :cvar oid: Object identifier for the TCG DICE TCB info extension (2.23.133.5.4.1).
    """

    oid = x509.ObjectIdentifier("2.23.133.5.4.1")

    def __init__(self, value: TCBInfoTable):
        """Initialize TCG DICE TCB info extension with a TCB info table.

        :param value: TCB info table to encode in the extension.
        """
        super().__init__(oid=self.oid, value=value.encode())


class TCGDiceMultiTcbInfo(x509.UnrecognizedExtension):
    """TCG DICE Multi-TCB Information X.509 Extension.

    This class represents an X.509 extension that encodes multiple TCB (Trusted Computing Base)
    information tables according to the TCG DICE specification. It handles the ASN.1 encoding
    of TCB info tables for use in X.509 certificates.

    :cvar oid: Object identifier for the TCG DICE multi-TCB info extension (2.23.133.5.4.5).
    """

    oid = x509.ObjectIdentifier("2.23.133.5.4.5")

    def __init__(self, value: list[TCBInfoTable]):
        """Initialize TCG DICE multi-TCB info extension with a list of TCB info tables.

        :param value: List of TCB info tables to encode in the extension.
        """
        encoded_value = DiceTcbInfoSeq.encode(values=[v.asn1() for v in value])
        super().__init__(self.oid, encoded_value)

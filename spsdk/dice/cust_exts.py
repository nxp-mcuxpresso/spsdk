#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Custom x509 v3 extensions and their respective helper methods/classes."""

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
    """Abstract base class for TCB information tables."""

    descriptor_type: int
    descriptor_flags: int
    table_name: str

    def __init__(self, svn: int, fwid_hashes: list[bytes]):
        """Initialize TCB info table with security version number and firmware ID hashes.

        :param svn: Security version number
        :param fwid_hashes: List of firmware ID hashes
        """
        self.svn = svn
        self.fwid_hashes = [h.zfill(48) for h in fwid_hashes]

    def encode(self) -> bytes:
        """Encode the TCB info table into bytes.

        :return: Encoded TCB info table as bytes
        """
        tcb_info = self.asn1()
        tcb_data = tcb_info.encode()
        return tcb_data

    def asn1(self) -> DiceTcbInfo:
        """Create ASN.1 representation of the TCB info table.

        :return: ASN.1 DiceTcbInfo object
        """
        tcb_info = DiceTcbInfo()
        tcb_info.setComponentByName("type", self.table_name.encode("utf-8"))
        tcb_info.setComponentByName("svn", self.svn)
        tcb_info.setComponentByName("fwids", FWIDLIST.create(self.fwid_hashes))
        return tcb_info


class FMC_TCB(TCBInfoTable):
    """TCB information table for FMC (Flash Memory Controller)."""

    descriptor_type = 1
    descriptor_flags = 0x48
    table_name = "FMC_INFO"


class CUST_TCB(TCBInfoTable):
    """TCB information table for customer-specific data with operational flags."""

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

        :return: ASN.1 DiceTcbInfo object with flags
        """
        tcb_info = super().asn1()
        tcb_info.setComponentByName("flags", OperationalFlags.create(self.flags))
        tcb_info.setComponentByName("flagsMask", OperationalFlagsMask.create(self.mask))
        return tcb_info


class NXP_TCB(TCBInfoTable):
    """TCB information table for NXP-specific data."""

    descriptor_type = 3
    descriptor_flags = 0x48
    table_name = "NXP_INFO"


class TCGDiceUeid(x509.UnrecognizedExtension):
    """X.509 extension for TCG DICE Unique Entity Identifier."""

    oid = x509.ObjectIdentifier(TcgUeid.oid)

    def __init__(self, value: bytes):
        """Initialize TCG DICE UEID extension with binary value.

        :param value: Binary value for the UEID
        """
        super().__init__(oid=self.oid, value=TcgUeid.encode(value))


class TCGDiceTcbInfo(x509.UnrecognizedExtension):
    """X.509 extension for TCG DICE TCB information."""

    oid = x509.ObjectIdentifier("2.23.133.5.4.1")

    def __init__(self, value: TCBInfoTable):
        """Initialize TCG DICE TCB info extension with a TCB info table.

        :param value: TCB info table to encode in the extension
        """
        super().__init__(oid=self.oid, value=value.encode())


class TCGDiceMultiTcbInfo(x509.UnrecognizedExtension):
    """X.509 extension for TCG DICE multiple TCB information tables."""

    oid = x509.ObjectIdentifier("2.23.133.5.4.5")

    def __init__(self, value: list[TCBInfoTable]):
        """Initialize TCG DICE multi-TCB info extension with a list of TCB info tables.

        :param value: List of TCB info tables to encode in the extension
        """
        encoded_value = DiceTcbInfoSeq.encode(values=[v.asn1() for v in value])
        super().__init__(self.oid, encoded_value)

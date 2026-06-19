#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for dice/tcg_asn.py ASN.1 structures."""

from spsdk.dice.tcg_asn import (
    FWID,
    FWIDLIST,
    Certificate,
    DiceTcbInfo,
    DiceTcbInfoSeq,
    OperationalFlags,
    OperationalFlagsMask,
    TBSCertificate,
    TcgUeid,
    get_oid_for_key,
)

# ── FWID tests ────────────────────────────────────────────────────────────────


def test_fwid_create() -> None:
    """Test FWID.create sets hashAlg and digest (lines 106-109)."""
    digest = b"\xab" * 48
    fwid = FWID.create(digest)
    assert fwid.getComponentByName("digest").asOctets() == digest


def test_fwid_encode_returns_bytes() -> None:
    """Test FWID.encode returns DER bytes (lines 120-121)."""
    digest = b"\xcd" * 48
    data = FWID.encode(digest)
    assert isinstance(data, bytes)
    assert len(data) > 0


# ── FWIDLIST tests ─────────────────────────────────────────────────────────────


def test_fwidlist_create_single() -> None:
    """Test FWIDLIST.create with one digest (lines 146-150)."""
    digest = b"\x01" * 48
    fwidlist = FWIDLIST.create([digest])
    assert len(fwidlist) == 1


def test_fwidlist_create_multiple() -> None:
    """Test FWIDLIST.create with multiple digests."""
    digests = [b"\x01" * 48, b"\x02" * 48, b"\x03" * 48]
    fwidlist = FWIDLIST.create(digests)
    assert len(fwidlist) == 3


def test_fwidlist_encode() -> None:
    """Test FWIDLIST.encode returns bytes (lines 160-161)."""
    digests = [b"\xaa" * 48]
    data = FWIDLIST.encode(digests)
    assert isinstance(data, bytes)
    assert len(data) > 0


# ── OperationalFlags tests ────────────────────────────────────────────────────


def test_operational_flags_create() -> None:
    """Test OperationalFlags.create with an int value (lines 199-202)."""
    flags = OperationalFlags.create(0b11)
    assert flags is not None


def test_operational_flags_create_defaults() -> None:
    """Test OperationalFlags.create with zero."""
    flags = OperationalFlags.create(0)
    assert flags is not None


def test_operational_flags_mask_create() -> None:
    """Test OperationalFlagsMask.create with an int value (lines 236-239)."""
    mask = OperationalFlagsMask.create(0xFF)
    assert mask is not None


# ── DiceTcbInfo tests ─────────────────────────────────────────────────────────


def test_dice_tcb_info_create_minimal() -> None:
    """Test DiceTcbInfo with fwids manually set (lines 327+)."""
    from spsdk.dice.tcg_asn import FWIDLIST

    info = DiceTcbInfo()
    fwids = FWIDLIST.create([b"\x00" * 48])
    info.setComponentByName("fwids", fwids)
    assert info is not None


def test_dice_tcb_info_encode() -> None:
    """Test DiceTcbInfo encode to DER bytes (lines 352-355)."""
    from spsdk.dice.tcg_asn import FWIDLIST

    info = DiceTcbInfo()
    fwids = FWIDLIST.create([b"\xff" * 48])
    info.setComponentByName("fwids", fwids)
    data = info.encode()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_dice_tcb_info_seq_create() -> None:
    """Test DiceTcbInfoSeq with appended DiceTcbInfo (line 384)."""
    from spsdk.dice.tcg_asn import FWIDLIST

    info = DiceTcbInfo()
    info.setComponentByName("fwids", FWIDLIST.create([b"\x11" * 48]))
    seq = DiceTcbInfoSeq()
    seq.append(info)
    assert len(seq) == 1


# ── TcgUeid tests ─────────────────────────────────────────────────────────────


def test_tcg_ueid_create() -> None:
    """Test TcgUeid.encode with 16-byte UID (covers encode path)."""
    uid = b"\x12" * 16
    data = TcgUeid.encode(uid)
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_tcg_ueid_encode() -> None:
    """Test TcgUeid.encode."""
    uid = b"\x34" * 16
    data = TcgUeid.encode(uid)
    assert isinstance(data, bytes)


# ── TBSCertificate tests ──────────────────────────────────────────────────────


def test_tbs_certificate_create_ext() -> None:
    """Test TBSCertificate.create_ext builds Extension (lines 608-611)."""
    from cryptography import x509

    ext = x509.BasicConstraints(ca=False, path_length=None)
    result = TBSCertificate.create_ext(ext, critical=True)
    assert result is not None


def test_tbs_certificate_create_ext_non_critical() -> None:
    """Test TBSCertificate.create_ext with critical=False."""
    from cryptography import x509

    ext = x509.BasicConstraints(ca=False, path_length=None)
    result = TBSCertificate.create_ext(ext, critical=False)
    assert result is not None


def test_tbs_certificate_create() -> None:
    """Test TBSCertificate.create with ECC public key (lines 539-588)."""
    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
    from spsdk.dice.utils import get_x509_name

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    public_key = private_key.get_public_key()
    subject, _ = get_x509_name("test-subject", public_key)
    issuer, _ = get_x509_name("test-issuer", public_key)

    tbs = TBSCertificate.create(
        public_key=public_key,
        subject=subject,
        issuer=issuer,
        serial=12345,
    )
    assert tbs is not None


def test_tbs_certificate_encode() -> None:
    """Test TBSCertificate.encode returns DER bytes (line 595)."""
    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
    from spsdk.dice.utils import get_x509_name

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    public_key = private_key.get_public_key()
    subject, _ = get_x509_name("test-subject", public_key)

    tbs = TBSCertificate.create(
        public_key=public_key,
        subject=subject,
    )
    data = tbs.encode()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_tbs_certificate_create_with_extensions() -> None:
    """Test TBSCertificate.create with extensions (lines 576-586)."""
    from cryptography import x509

    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
    from spsdk.dice.utils import get_x509_name

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    public_key = private_key.get_public_key()
    subject, _ = get_x509_name("test-subject", public_key)

    ext = x509.BasicConstraints(ca=True, path_length=None)
    tbs = TBSCertificate.create(
        public_key=public_key,
        subject=subject,
        critical_extensions=[ext],
    )
    assert tbs is not None


# ── Certificate tests ─────────────────────────────────────────────────────────


def test_certificate_create_and_encode() -> None:
    """Test Certificate.create and encode (lines 643-686)."""
    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc
    from spsdk.dice.utils import get_x509_name

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    public_key = private_key.get_public_key()
    subject, _ = get_x509_name("test-subject", public_key)
    issuer, _ = get_x509_name("test-issuer", public_key)

    tbs = TBSCertificate.create(
        public_key=public_key,
        subject=subject,
        issuer=issuer,
    )
    cert = Certificate.create(tbs_certificate=tbs, signing_key=private_key)
    assert cert is not None

    data = cert.encode()
    assert isinstance(data, bytes)
    assert len(data) > 0


# ── get_oid_for_key tests ─────────────────────────────────────────────────────


def test_get_oid_for_key_ecc() -> None:
    """Test get_oid_for_key returns OID bytes for ECC key."""
    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    public_key = private_key.get_public_key()
    oid = get_oid_for_key(public_key)
    assert isinstance(oid, bytes)
    assert len(oid) > 0

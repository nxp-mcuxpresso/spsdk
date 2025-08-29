#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ASN1 related types and utilities for TCG DICE specification."""

from datetime import datetime, timezone
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.decoder import decode as decode
from pyasn1.codec.der.encoder import encode as encode
from pyasn1.type import char, namedtype, namedval, tag, univ, useful

from spsdk.crypto.keys import (
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyMLDSA,
    PublicKey,
    PublicKeyEcc,
    PublicKeyMLDSA,
    SPSDKEncoding,
)


def _OID(*components: Union[int, univ.ObjectIdentifier]) -> univ.ObjectIdentifier:
    """Create Object Identifier."""
    output = []
    for x in tuple(components):
        if isinstance(x, univ.ObjectIdentifier):
            output.extend(list(x))
        else:
            output.append(int(x))

    return univ.ObjectIdentifier(output)


tcg = _OID(2, 23, 133)


tcg_dice = _OID(tcg, 5, 4)


tcg_dice_MultiTcbInfo = _OID(tcg_dice, 5)


tcg_dice_TcbInfo = _OID(tcg_dice, 1)


tcg_dice_Ueid = _OID(tcg_dice, 4)

nist_sha384 = _OID(2, 16, 840, 1, 101, 3, 4, 2, 2)

sig_mldsa87 = _OID(2, 16, 840, 1, 101, 3, 4, 3, 19)

sig_ecdsa_with_sha384 = _OID(1, 2, 840, 10045, 4, 3, 3)


class FWID(univ.Sequence):
    """F/W Identifier (FWID) ASN.1 structure definition.

    FWID ::= SEQUENCE {
        hashAlg OBJECT IDENTIFIER,
        digest OCTET STRING
    }
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("hashAlg", univ.ObjectIdentifier()),
        namedtype.NamedType("digest", univ.OctetString()),
    )

    @classmethod
    def create(cls, digest: bytes) -> "FWID":
        """Create ASN1 structure for FWID."""
        fwid = cls()
        fwid.setComponentByName("hashAlg", nist_sha384)
        fwid.setComponentByName("digest", digest)
        return fwid

    @classmethod
    def encode(cls, digest: bytes) -> bytes:
        """Encode FWID ASN.1 structure to DER bytes."""
        fwid = cls.create(digest)
        return encode(fwid)


class FWIDLIST(univ.SequenceOf):
    """List of FWIDs.

    FWIDLIST ::= SEQUENCE SIZE (1..10) OF FWID
    """

    componentType = FWID()

    @classmethod
    def create(cls, fwid_list: list[bytes]) -> "FWIDLIST":
        """Create ASN1 structure for list of FWIDs."""
        fwidlist: FWIDLIST = cls().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )
        for digest in fwid_list:
            fwidlist.append(FWID.create(digest))
        return fwidlist

    @classmethod
    def encode(cls, fwid_list: list[bytes]) -> bytes:
        """Encode list of FWIDs to DER bytes."""
        fwidlist = cls.create(fwid_list)
        return encode(fwidlist)


class OperationalFlags(univ.BitString):
    """Operational flags."""

    namedValues = namedval.NamedValues(
        ("notConfigured", 0),
        ("notSecure", 1),
        ("recovery", 2),
        ("debug", 3),
        ("notReplayProtected", 4),
        ("notIntegrityProtected", 5),
        ("notRuntimeMeasured", 6),
        ("notImmutable", 7),
        ("notTcb", 8),
        ("fixedWidth", 31),
    )

    @classmethod
    def create(cls, value: int) -> "OperationalFlags":
        """Crate ASN1 structure for operation flags."""
        op_flags = univ.BitString(hexValue=f"{value:08x}").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
        )
        return op_flags


class OperationalFlagsMask(univ.BitString):
    """Operation flags mask indicates which operational flags are valid."""

    namedValues = namedval.NamedValues(
        ("notConfigured", 0),
        ("notSecure", 1),
        ("recovery", 2),
        ("debug", 3),
        ("notReplayProtected", 4),
        ("notIntegrityProtected", 5),
        ("notRuntimeMeasured", 6),
        ("notImmutable", 7),
        ("notTcb", 8),
        ("fixedWidth", 31),
    )

    @classmethod
    def create(cls, value: int) -> "OperationalFlagsMask":
        """Create ASN1 structure for operation flags mask."""
        op_flags_mask = univ.BitString(hexValue=f"{value:08x}").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)
        )
        return op_flags_mask


class DiceTcbInfo(univ.Sequence):
    """DICE TCB Info table."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "vendor",
            char.UTF8String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "model",
            char.UTF8String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
        namedtype.OptionalNamedType(
            "version",
            char.UTF8String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            ),
        ),
        namedtype.OptionalNamedType(
            "svn",
            univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            ),
        ),
        namedtype.OptionalNamedType(
            "layer",
            univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            ),
        ),
        namedtype.OptionalNamedType(
            "index",
            univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            ),
        ),
        namedtype.OptionalNamedType(
            "fwids",
            FWIDLIST().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6),
            ),
        ),
        namedtype.OptionalNamedType(
            "flags",
            OperationalFlags().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
            ),
        ),
        namedtype.OptionalNamedType(
            "vendorInfo",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)
            ),
        ),
        namedtype.OptionalNamedType(
            "type",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)
            ),
        ),
        namedtype.OptionalNamedType(
            "flagsMask",
            OperationalFlagsMask().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)
            ),
        ),
    )

    def encode(self) -> bytes:
        """Encode ASN1 structure into DER bytes."""
        return encode(self)


class DiceTcbInfoSeq(univ.SequenceOf):
    """List of DICE TCB Info structures."""

    componentType = DiceTcbInfo()

    @classmethod
    def encode(cls, values: list) -> bytes:
        """Encode ASN1 structure into DER bytes."""
        seq = cls()
        for value in values:
            seq.append(value)
        return encode(seq)


class TcgUeid(univ.Sequence):
    """TCG UEID (Unique Entity Identifier) ASN.1 structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("ueid", univ.OctetString()),
    )
    oid = str(tcg_dice_Ueid)

    @classmethod
    def encode(cls, ueid: bytes) -> bytes:
        """Encode ASN1 structure into DER bytes."""
        return encode(cls().setComponentByName("ueid", ueid.zfill(16)))


class Version(univ.Integer):
    """Certificate version."""

    namedValues = namedval.NamedValues(("v1", 0), ("v2", 1), ("v3", 2))


class CertificateSerialNumber(univ.Integer):
    """Certificate serial number."""


class AlgorithmIdentifier(univ.Sequence):
    """Certificate algorithm identifier."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class Time(univ.Choice):
    """Time representation in ASN.1 certificate."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("utcTime", useful.UTCTime()),
        namedtype.NamedType("generalTime", useful.GeneralizedTime()),
    )


class Validity(univ.Sequence):
    """Certificate validity period representation in ASN.1."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("notBefore", Time()), namedtype.NamedType("notAfter", Time())
    )


class Extension(univ.Sequence):
    """ANS1 representation of x509 v3 certificate extension."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("extensionID", univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType("critical", univ.Boolean().subtype(value=0)),
        namedtype.NamedType("extensionValue", univ.OctetString()),
    )


class Extensions(univ.SequenceOf):
    """List of x509 v3 certificate extensions."""

    componentType = Extension()


class TBSCertificate(univ.Sequence):
    """To-Be-Signed (TBS) Certificate data ASN.1 structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            Version().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("serialNumber", CertificateSerialNumber()),
        namedtype.NamedType("signature", AlgorithmIdentifier()),
        namedtype.OptionalNamedType("issuer", univ.Sequence()),  # Name()
        namedtype.NamedType("validity", Validity()),
        namedtype.NamedType("subject", univ.Sequence()),  # Name()
        namedtype.NamedType("subjectPublicKeyInfo", univ.Sequence()),  # SubjectPublicKeyInfo()
        namedtype.OptionalNamedType(
            "extensions",
            Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
        ),
    )

    @classmethod
    def create(
        cls,
        subject: x509.Name,
        public_key: PublicKey,
        serial: Optional[int] = None,
        issuer: Optional[x509.Name] = None,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
        extensions: Optional[list[x509.ExtensionType]] = None,
        critical_extensions: Optional[list[x509.ExtensionType]] = None,
    ) -> "TBSCertificate":
        """Create TBS ASN1 structure."""
        tbs = TBSCertificate()
        tbs.setComponentByName("version", 2)

        serial = serial or x509.random_serial_number()
        tbs.setComponentByName("serialNumber", serial)

        sign_algo = AlgorithmIdentifier()
        sign_oid = sig_ecdsa_with_sha384 if isinstance(public_key, PublicKeyEcc) else sig_mldsa87
        sign_algo.setComponentByName("algorithm", sign_oid)
        tbs.setComponentByName("signature", sign_algo)

        if issuer is not None:
            issuer_data = issuer.public_bytes()
            issuer_name, _ = decode(issuer_data, asn1Spec=univ.Sequence())
            tbs.setComponentByName("issuer", issuer_name)

        validity = Validity()
        not_before = not_before or datetime.now(timezone.utc)
        not_before_time = Time()
        not_before_time.setComponentByName("utcTime", useful.UTCTime.fromDateTime(not_before))
        not_after = not_after or datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        not_after_time = Time()
        not_after_time.setComponentByName(
            "generalTime", useful.GeneralizedTime.fromDateTime(not_after)
        )
        validity.setComponentByName("notBefore", not_before_time)
        validity.setComponentByName("notAfter", not_after_time)
        tbs.setComponentByName("validity", validity)

        subject_data = subject.public_bytes()
        subject_name, _ = decode(subject_data, asn1Spec=univ.Sequence())
        tbs.setComponentByName("subject", subject_name)

        puk_data = public_key.export(SPSDKEncoding.DER)
        spki, _ = decode(puk_data, asn1Spec=univ.Sequence())
        tbs.setComponentByName("subjectPublicKeyInfo", spki)

        if extensions or critical_extensions:
            ext_list: Extensions = Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
            if critical_extensions:
                for ext in critical_extensions:
                    ext_list.append(cls.create_ext(ext, critical=True))
            if extensions:
                for ext in extensions:
                    ext_list.append(cls.create_ext(ext, critical=False))
            tbs.setComponentByName("extensions", ext_list)

        return tbs

    def encode(self) -> bytes:
        """Encode ASN1 structure into DER bytes."""
        return encode(self)

    @classmethod
    def create_ext(cls, ext: x509.ExtensionType, critical: bool = False) -> Extension:
        """Convert a cryptography extension to ASN.1 Extension."""
        result = Extension()
        result.setComponentByName("extensionID", ext.oid.dotted_string)
        result.setComponentByName("critical", critical)
        result.setComponentByName("extensionValue", ext.public_bytes())
        return result


class Certificate(univ.Sequence):
    """x509 Certificate ASN.1 structure."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbsCertificate", TBSCertificate()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.BitString()),
    )

    @classmethod
    def create(cls, tbs_certificate: TBSCertificate, signing_key: PrivateKey) -> "Certificate":
        """Create x509 Certificate ASN.1 structure."""
        tbs_data = encode(tbs_certificate)

        if isinstance(signing_key, PrivateKeyEcc):
            signature = signing_key.key.sign(tbs_data, ec.ECDSA(hashes.SHA384()))
            signature_oid = sig_ecdsa_with_sha384
        else:
            signature = signing_key.sign(tbs_data, prehashed=True)
            signature_oid = sig_mldsa87

        signature_algorithm = AlgorithmIdentifier()
        signature_algorithm.setComponentByName("algorithm", signature_oid)

        signature_value = univ.BitString(hexValue=signature.hex())

        cert = Certificate()
        cert.setComponentByName("tbsCertificate", tbs_certificate)
        cert.setComponentByName("signatureAlgorithm", signature_algorithm)
        cert.setComponentByName("signatureValue", signature_value)

        return cert

    def encode(self) -> bytes:
        """Encode ASN1 structure into DER bytes."""
        return encode(self)


def get_oid_for_key(key: Union[PrivateKey, PublicKey]) -> bytes:
    """Get signature oid for given key."""
    if isinstance(key, (PublicKeyEcc, PrivateKeyEcc)):
        return encode(sig_ecdsa_with_sha384)
    if isinstance(key, (PublicKeyMLDSA, PrivateKeyMLDSA)):
        return encode(sig_mldsa87)
    raise ValueError(f"Unknown key type: {type(key)}")

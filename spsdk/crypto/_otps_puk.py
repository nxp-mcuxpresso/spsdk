#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ASN1 representation of OTPS encoded public keys."""

from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, namedtype, tag, univ

from spsdk.exceptions import SPSDKError


class AlgorithmIdentifier(univ.Sequence):
    """Key identification.

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm            OBJECT IDENTIFIER,
        parameters           ANY DEFINED BY algorithm  OPTIONAL
    }
    """


AlgorithmIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
    namedtype.OptionalNamedType("parameters", univ.Any()),
)


class SubjectPublicKeyInfo(univ.Sequence):
    """Key info with puk data itself.

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING
    }
    """


SubjectPublicKeyInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType("algorithm", AlgorithmIdentifier()),
    namedtype.NamedType("subjectPublicKey", univ.BitString()),
)


class IdentifiedSubjectPublicKeyInfo(univ.Sequence):
    """OTPS metadata and key info.

    IdentifiedSubjectPublicKeyInfo  ::=  SEQUENCE  {
        identifier           [0] IMPLICIT IA5String,
        version              [1] IMPLICIT INTEGER,
        typeName             [2] IMPLICIT IA5String,
        owner                [3] IMPLICIT IA5String OPTIONAL,
        usage                [4] IMPLICIT INTEGER,
        subjectPublicKeyInfo SubjectPublicKeyInfo
    }
    """


IdentifiedSubjectPublicKeyInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "identifier",
        char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "version",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType(
        "typeName",
        char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
    namedtype.OptionalNamedType(
        "owner",
        char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "usage",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
)


def nxp_otps_extract_puk(data: bytes) -> bytes:
    """Extract public key data from OTPS-encoded data."""
    try:
        data_s = data.decode("utf-8")
        data = bytes.fromhex(data_s)
        obj: IdentifiedSubjectPublicKeyInfo
        obj, _ = decode(data, asn1Spec=IdentifiedSubjectPublicKeyInfo())
        key_info: SubjectPublicKeyInfo = obj.getComponentByName("subjectPublicKeyInfo")
        key_data: univ.BitString = key_info.getComponentByName("subjectPublicKey")
        return key_data.asOctets()[1:]
    except (AttributeError, ValueError, UnicodeEncodeError, PyAsn1Error) as exc:
        raise SPSDKError(str(exc)) from exc

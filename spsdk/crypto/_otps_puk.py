#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ASN1 representation of OTPS encoded public keys."""

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ

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


def is_mldsa(key_info: SubjectPublicKeyInfo) -> bool:
    """Check if the key uses ML-DSA."""
    algorithm = key_info.getComponentByName("algorithm")
    oid = algorithm.getComponentByName("algorithm")
    return str(oid).startswith("2.16.840.1.101.3.4")


def repack_mldsa_puk(key_info: SubjectPublicKeyInfo) -> bytes:
    """Repack OTPS data into standardized form."""
    key_data: univ.BitString = key_info.getComponentByName("subjectPublicKey")
    puk_data_seq, _ = decode(key_data.asOctets(), asn1Spec=univ.Sequence())
    puk_data = bytes(puk_data_seq[0]) + bytes(puk_data_seq[1])
    puk_bitstring = univ.BitString(hexValue=puk_data.hex())

    algorithm = key_info.getComponentByName("algorithm")

    puk_obj = SubjectPublicKeyInfo()
    puk_obj.setComponentByPosition(0, algorithm)
    puk_obj.setComponentByPosition(1, puk_bitstring)

    encoded = encode(puk_obj)
    return encoded


def nxp_otps_extract_puk(data: bytes) -> bytes:
    """Extract public key data from OTPS-encoded data."""
    try:
        key_info: SubjectPublicKeyInfo
        key_info, _ = decode(data, asn1Spec=SubjectPublicKeyInfo())
        if is_mldsa(key_info):
            return repack_mldsa_puk(key_info)
        return encode(key_info)
    except (AttributeError, ValueError, UnicodeEncodeError, PyAsn1Error) as exc:
        raise SPSDKError(str(exc)) from exc

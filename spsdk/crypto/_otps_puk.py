#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK OTPS public key extraction and processing utilities.

This module provides ASN.1 representation and manipulation of OTPS (One-Time Programmable Storage)
encoded public keys, including support for ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
key formats and NXP-specific public key extraction operations.
"""

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ

from spsdk.exceptions import SPSDKError


class AlgorithmIdentifier(univ.Sequence):
    """ASN.1 Algorithm Identifier for cryptographic operations.

    This class represents an ASN.1 AlgorithmIdentifier structure used to identify
    cryptographic algorithms and their associated parameters in SPSDK operations.
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
    """ASN.1 Subject Public Key Information structure for cryptographic operations.

    This class represents the SubjectPublicKeyInfo ASN.1 structure used in X.509
    certificates and other cryptographic contexts to encapsulate public key data
    along with its algorithm identifier.
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
    """Check if the key uses ML-DSA algorithm.

    This method examines the algorithm identifier in the SubjectPublicKeyInfo structure
    to determine if it corresponds to a ML-DSA (Module-Lattice-Based Digital Signature
    Algorithm) key by checking if the OID starts with the ML-DSA prefix.

    :param key_info: Subject public key info structure containing algorithm information.
    :return: True if the key uses ML-DSA algorithm, False otherwise.
    """
    algorithm = key_info.getComponentByName("algorithm")
    oid = algorithm.getComponentByName("algorithm")
    return str(oid).startswith("2.16.840.1.101.3.4")


def repack_mldsa_puk(key_info: SubjectPublicKeyInfo) -> bytes:
    """Repack ML-DSA public key data into standardized ASN.1 form.

    This method extracts the public key data from the provided SubjectPublicKeyInfo,
    reconstructs it by concatenating the sequence components, and repackages it into
    a new standardized SubjectPublicKeyInfo structure with proper ASN.1 encoding.

    :param key_info: Subject public key information structure containing ML-DSA key data.
    :return: ASN.1 encoded bytes of the repacked public key information.
    """
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
    """Extract public key data from OTPS-encoded data.

    The method decodes ASN.1 encoded public key data and handles special processing for ML-DSA
    keys by repacking them, while other key types are re-encoded in standard format.

    :param data: OTPS-encoded public key data in bytes format.
    :return: Extracted and processed public key data as bytes.
    :raises SPSDKError: Invalid ASN.1 data format or decoding errors.
    """
    try:
        key_info: SubjectPublicKeyInfo
        key_info, _ = decode(data, asn1Spec=SubjectPublicKeyInfo())
        if is_mldsa(key_info):
            return repack_mldsa_puk(key_info)
        return encode(key_info)
    except (AttributeError, ValueError, UnicodeEncodeError, PyAsn1Error) as exc:
        raise SPSDKError(str(exc)) from exc

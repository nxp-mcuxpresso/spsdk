#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK OSCCA SM2 cryptographic key serialization utilities.

This module provides ASN.1 encoding and decoding functionality for OSCCA SM2
cryptographic keys and signatures. It handles serialization of public keys,
private keys, and digital signatures according to OSCCA standards.
"""

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, tag, univ

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

SM2_OID = univ.ObjectIdentifier("1.2.156.10197.1.301")


class KeySet(univ.Sequence):
    """OSCCA ASN.1 key set container for private and public key pairs.

    This class represents an ASN.1 sequence structure that encapsulates both
    private and public keys according to OSCCA (Office of State Commercial
    Cryptography Administration) standards. The structure includes a key
    identifier number, private key data, and public key data.
    ASN.1 Structure:
        KeySet ::= SEQUENCE {
            number  INTEGER,
            prk     OCTET STRING,
            puk     [1] EXPLICIT BIT STRING
        }
    """


KeySet.componentType = namedtype.NamedTypes(
    namedtype.NamedType("number", univ.Integer()),
    namedtype.NamedType("prk", univ.OctetString()),
    namedtype.NamedType(
        "puk",
        univ.BitString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1),
        ),
    ),
)


class Private(univ.Sequence):
    """OSCCA private key ASN.1 structure representation.

    This class represents the ASN.1 structure for OSCCA (Office of State Commercial Cryptography Administration)
    private keys, containing sequence number, object identifiers, and encrypted key data.
    ASN.1 Structure:
        Private ::= SEQUENCE {
            number      INTEGER,
            ids         SEQUENCE OF OBJECT IDENTIFIER,
            keyset      OCTET STRING (CONTAINING KeySet)
        }
    """


Private.componentType = namedtype.NamedTypes(
    namedtype.NamedType("number", univ.Integer()),
    namedtype.NamedType("ids", univ.SequenceOf(componentType=univ.ObjectIdentifier())),
    namedtype.NamedType("keyset", univ.OctetString()),
)


class Public(univ.Sequence):
    """OSCCA ASN.1 public key representation.

    This class represents a public key structure according to OSCCA (Office of State
    Commercial Cryptography Administration) ASN.1 encoding standards. The structure
    contains a sequence of object identifiers and the public key data as a bit string.
    ASN.1 Structure:
        Public ::= SEQUENCE {
            ids     SEQUENCE OF OBJECT IDENTIFIER,
            puk     BIT STRING
        }
    """


Public.componentType = namedtype.NamedTypes(
    namedtype.NamedType("ids", univ.SequenceOf(componentType=univ.ObjectIdentifier())),
    namedtype.NamedType("puk", univ.BitString()),
)


class Signature(univ.Sequence):
    """OSCCA cryptographic signature representation for ASN.1 encoding.

    This class represents a digital signature structure following OSCCA standards,
    containing two integer components (r and s) encoded as an ASN.1 sequence.
    The ASN.1 structure is defined as:
    Signature ::= SEQUENCE {
        r       INTEGER,
        s       INTEGER
    }
    """


Signature.componentType = namedtype.NamedTypes(
    namedtype.NamedType("r", univ.Integer()),
    namedtype.NamedType("s", univ.Integer()),
)


def encode_signature(data: bytes) -> bytes:
    """Encode raw r||s signature into BER format.

    Converts a 64-byte raw SM2 signature (32 bytes r + 32 bytes s) into
    ASN.1 BER encoded format using the OSCCA signature structure.

    :param data: Raw signature data containing r and s values (64 bytes total).
    :raises SPSDKError: Invalid signature length or ASN.1 encoding failure.
    :return: BER encoded signature bytes.
    """
    if len(data) != 64:
        raise SPSDKError("SM2 signature must be 64B long.")
    sig_data = {
        "r": int.from_bytes(data[:32], byteorder=Endianness.BIG.value),
        "s": int.from_bytes(data[32:], byteorder=Endianness.BIG.value),
    }
    try:
        return encode(sig_data, asn1Spec=Signature())
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def decode_signature(data: bytes) -> bytes:
    """Decode BER signature into r||s coordinates.

    The method decodes a BER-encoded signature and extracts the r and s coordinates,
    returning them as concatenated 32-byte values in big-endian format.

    :param data: BER-encoded signature data to decode.
    :raises SPSDKError: Invalid BER signature format or decoding error.
    :return: Concatenated r and s coordinates as 64 bytes (32 bytes each).
    """
    try:
        result, _ = decode(data, asn1Spec=Signature())
        r = int.to_bytes(int(result["r"]), length=32, byteorder=Endianness.BIG.value)
        s = int.to_bytes(int(result["s"]), length=32, byteorder=Endianness.BIG.value)
        return r + s
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def encode_public_key(data: str) -> bytes:
    """Encode public SM2 key from hex string data.

    The method creates an ASN.1 encoded public key structure using SM2 OIDs
    and the provided hex string data with '04' prefix for uncompressed point format.

    :param data: Hex string representation of the SM2 public key data.
    :raises SPSDKError: ASN.1 encoding operation failed.
    :return: ASN.1 encoded public key as bytes.
    """
    puk_data = {
        "ids": [SM2_OID, SM2_OID],
        "puk": univ.BitString(hexValue="04" + data),
    }
    try:
        return encode(puk_data, asn1Spec=Public())
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def decode_public_key(data: bytes) -> str:
    """Parse public SM2 key from ASN.1 encoded binary data.

    Decodes ASN.1 encoded public key data and extracts the SM2 public key,
    converting it from bit string format to hexadecimal representation.

    :param data: ASN.1 encoded binary data containing the public key.
    :raises SPSDKError: Invalid ASN.1 data format or decoding failure.
    :return: Public key as 128-character hexadecimal string.
    """
    try:
        result, _ = decode(data, asn1Spec=Public())
        # puk is bitstring thus removing initial 0x04 means removing 8 characters
        puk_str = str(result["puk"])[8:]
        return f"{int(puk_str, 2):0128x}"
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def encode_private_key(private: str, public: str) -> bytes:
    """Encode private SM2 key set from keyset.

    Creates an ASN.1 encoded private key structure containing both private and public
    SM2 key components with proper OID identifiers.

    :param private: Private key as hexadecimal string
    :param public: Public key as hexadecimal string
    :raises SPSDKError: When ASN.1 encoding fails
    :return: ASN.1 encoded private key structure as bytes
    """
    try:
        keyset_data = {
            "number": 1,
            "prk": univ.OctetString(hexValue=private),
            "puk": univ.BitString(hexValue="04" + public),
        }
        keyset = bytes(encode(keyset_data, asn1Spec=KeySet()))

        private_key = {"number": 0, "ids": [SM2_OID, SM2_OID], "keyset": keyset}
        return encode(private_key, asn1Spec=Private())
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def decode_private_key(data: bytes) -> tuple[str, str]:
    """Parse private SM2 key set from binary data.

    Decodes ASN.1 encoded private SM2 key data and extracts both private and public key components.
    The method handles the nested ASN.1 structure to retrieve the key set and convert the keys
    to hexadecimal format.

    :param data: Binary ASN.1 encoded private SM2 key data to decode.
    :return: Tuple containing private key and public key as hexadecimal strings.
    :raises SPSDKError: If ASN.1 decoding fails or data format is invalid.
    """
    try:
        result, _ = decode(data, asn1Spec=Private())
        key_set_data = bytes(result["keyset"])
        result, _ = decode(key_set_data, asn1Spec=KeySet())
        private = bytes(result["prk"]).hex()
        public_bin = str(result["puk"][8:])
        public = f"{int(public_bin, 2):0128x}"
        return private, public
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc

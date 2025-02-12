#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper functions for OSCCA SM2 keys serialization."""

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, tag, univ

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

SM2_OID = univ.ObjectIdentifier("1.2.156.10197.1.301")


class KeySet(univ.Sequence):
    """Set of both private and public keys.

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
    """Private key representation.

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
    """Public key representation.

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
    """Signature representation.

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
    """Encode raw r||s signature into BER format."""
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
    """Decode BER signature into r||s coordinates."""
    try:
        result, _ = decode(data, asn1Spec=Signature())
        r = int.to_bytes(int(result["r"]), length=32, byteorder=Endianness.BIG.value)
        s = int.to_bytes(int(result["s"]), length=32, byteorder=Endianness.BIG.value)
        return r + s
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def encode_public_key(data: str) -> bytes:
    """Encode public SM2 key from SM2PublicKey."""
    puk_data = {
        "ids": [SM2_OID, SM2_OID],
        "puk": univ.BitString(hexValue="04" + data),
    }
    try:
        return encode(puk_data, asn1Spec=Public())
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def decode_public_key(data: bytes) -> str:
    """Parse public SM2 key set from binary data."""
    try:
        result, _ = decode(data, asn1Spec=Public())
        # puk is bitstring thus removing initial 0x04 means removing 8 characters
        puk_str = str(result["puk"])[8:]
        return f"{int(puk_str, 2):0128x}"
    except PyAsn1Error as exc:
        raise SPSDKError(str(exc)) from exc


def encode_private_key(private: str, public: str) -> bytes:
    """Encode private SM2 key set from keyset."""
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
    """Parse private SM2 key set from binary data."""
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

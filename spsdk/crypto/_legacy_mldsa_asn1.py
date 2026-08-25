#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Legacy ML-DSA ASN.1 decoding helpers."""

from __future__ import annotations

import base64

from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ

from spsdk.exceptions import SPSDKError

LEGACY_MLDSA_OID_MAP = {
    "1.3.6.1.4.1.2.267.12.4.4": 2,
    "1.3.6.1.4.1.2.267.12.6.5": 3,
    "1.3.6.1.4.1.2.267.12.8.7": 5,
}


class LegacyKeyInfo(univ.Sequence):
    """Legacy key metadata envelope."""


LegacyKeyInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
    namedtype.OptionalNamedType("parameter", univ.Any()),
)


class LegacyPrivateKey(univ.OctetString):
    """Legacy raw private key payload."""


class LegacyPrivateKeyWithSeed(univ.Sequence):
    """Legacy private key payload carrying both seed and expanded secret key."""


LegacyPrivateKeyWithSeed.componentType = namedtype.NamedTypes(
    namedtype.NamedType("seed", univ.OctetString()),
    namedtype.NamedType("prk", univ.OctetString()),
)


class LegacyPrivateKeyEnvelope(univ.Sequence):
    """Legacy private key envelope."""


LegacyPrivateKeyEnvelope.componentType = namedtype.NamedTypes(
    namedtype.NamedType("version", univ.Integer()),
    namedtype.NamedType("info", LegacyKeyInfo()),
    namedtype.NamedType(
        "prkData",
        univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("prk", LegacyPrivateKey()),
                namedtype.NamedType("prkSeed", LegacyPrivateKeyWithSeed()),
            )
        ),
    ),
)


class LegacyPublicKey(univ.BitString):
    """Legacy raw public key payload."""


class LegacyPublicKeyEnvelope(univ.Sequence):
    """Legacy public key envelope."""


LegacyPublicKeyEnvelope.componentType = namedtype.NamedTypes(
    namedtype.NamedType("info", LegacyKeyInfo()),
    namedtype.NamedType("puk", LegacyPublicKey()),
)


def _pem_to_der(data: bytes) -> bytes:
    """Convert PEM-encoded data to DER."""
    if data.startswith(b"-----BEGIN "):
        lines = data.splitlines()
        return base64.b64decode(b"".join(lines[1:-1]))
    return data


def _get_legacy_level(oid: str) -> int:
    """Translate a legacy ML-DSA OID into an SPSDK level."""
    if oid not in LEGACY_MLDSA_OID_MAP:
        raise SPSDKError(f"Unsupported legacy ML-DSA OID: {oid}")
    return LEGACY_MLDSA_OID_MAP[oid]


def extract_legacy_mldsa_public(data: bytes) -> tuple[int, bytes]:
    """Extract raw public key bytes from a legacy ML-DSA public key envelope."""
    try:
        envelope, _ = decode(_pem_to_der(data), asn1Spec=LegacyPublicKeyEnvelope())
        oid = str(envelope["info"]["algorithm"])
        return _get_legacy_level(oid), envelope["puk"].asOctets()
    except (PyAsn1Error, ValueError) as exc:
        raise SPSDKError(str(exc)) from exc


def extract_legacy_mldsa_seed(data: bytes) -> tuple[int, bytes]:
    """Extract seed bytes from a seed-bearing legacy ML-DSA private key envelope."""
    try:
        envelope, _ = decode(_pem_to_der(data), asn1Spec=LegacyPrivateKeyEnvelope())
        oid = str(envelope["info"]["algorithm"])
        level = _get_legacy_level(oid)
        private_component = envelope["prkData"].getComponent()
        if isinstance(private_component, LegacyPrivateKeyWithSeed):
            private_with_seed = private_component
        else:
            private_with_seed, _ = decode(
                bytes(private_component), asn1Spec=LegacyPrivateKeyWithSeed()
            )
        return level, bytes(private_with_seed["seed"])
    except (PyAsn1Error, ValueError) as exc:
        raise SPSDKError(str(exc)) from exc

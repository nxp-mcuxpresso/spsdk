#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for public key extraction from certificates with unsupported algorithms.

Composite (hybrid) certificates carry a classic and a post-quantum public key inside a single
SubjectPublicKeyInfo. SPSDK cannot represent such a key, but it must fail with an actionable
SPSDKError instead of leaking the `cryptography` UnsupportedAlgorithm exception.
"""

import os

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from pyasn1.codec.der.encoder import encode
from pyasn1.type import char, tag, univ, useful

from spsdk.crypto.certificate import COMPOSITE_PUBLIC_KEY_OIDS, Certificate
from spsdk.exceptions import SPSDKError

# ML-DSA-65 (pure, non-composite) SubjectPublicKeyInfo algorithm OID
MLDSA65_OID = "2.16.840.1.101.3.4.3.18"
# Composite p384_mldsa65 OID, as produced by CST hybrid PKI
COMPOSITE_P384_MLDSA65_OID = "1.3.9999.7.7"
# id-ecPublicKey
ECC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"
# secp384r1 named curve
SECP384R1_OID = "1.3.132.0.34"
# ecdsa-with-SHA384
ECDSA_WITH_SHA384_OID = "1.2.840.10045.4.3.3"


def _oid(dotted: str) -> univ.ObjectIdentifier:
    """Build an ASN.1 OBJECT IDENTIFIER from a dotted string."""
    return univ.ObjectIdentifier(tuple(int(part) for part in dotted.split(".")))


def _algorithm_identifier(dotted: str, parameters: str | None = None) -> univ.Sequence:
    """Build an AlgorithmIdentifier, optionally carrying an OID parameter."""
    seq = univ.Sequence()
    seq.setComponentByPosition(0, _oid(dotted))
    if parameters is not None:
        seq.setComponentByPosition(1, _oid(parameters))
    return seq


def _name(common_name: str) -> univ.SequenceOf:
    """Build an X.501 Name holding a single commonName attribute."""
    attribute = univ.Sequence()
    attribute.setComponentByPosition(0, _oid("2.5.4.3"))
    attribute.setComponentByPosition(1, char.PrintableString(common_name))
    rdn = univ.SetOf(componentType=univ.Sequence())
    rdn.setComponentByPosition(0, attribute)
    rdn_sequence = univ.SequenceOf(componentType=univ.SetOf())
    rdn_sequence.setComponentByPosition(0, rdn)
    return rdn_sequence


def _utc_time(value: str) -> useful.UTCTime:
    """Build a DER UTCTime with the correct universal tag."""
    return useful.UTCTime(value).subtype(
        implicitTag=tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 23)
    )


def build_certificate(
    algorithm_oid: str,
    public_key_data: bytes,
    algorithm_parameters: str | None = None,
    signature_algorithm_oid: str | None = None,
) -> bytes:
    """Build a minimal DER X.509 certificate with the given SubjectPublicKeyInfo algorithm.

    The signature is random filler; these tests only exercise public key extraction, which
    never verifies the signature.

    :param algorithm_oid: Dotted OID placed in the SubjectPublicKeyInfo AlgorithmIdentifier.
    :param public_key_data: Raw bytes stored in the subjectPublicKey BIT STRING.
    :param algorithm_parameters: Optional dotted OID used as AlgorithmIdentifier parameters,
        required for algorithms such as id-ecPublicKey that name a curve.
    :param signature_algorithm_oid: Dotted OID of the signature algorithm. Defaults to
        `algorithm_oid`, which matches how composite and ML-DSA certificates are built.
    :return: DER-encoded certificate.
    """
    signature_algorithm = _algorithm_identifier(signature_algorithm_oid or algorithm_oid)

    subject_public_key_info = univ.Sequence()
    subject_public_key_info.setComponentByPosition(
        0, _algorithm_identifier(algorithm_oid, algorithm_parameters)
    )
    subject_public_key_info.setComponentByPosition(
        1, univ.BitString(hexValue=public_key_data.hex())
    )

    validity = univ.Sequence()
    validity.setComponentByPosition(0, _utc_time("250101000000Z"))
    validity.setComponentByPosition(1, _utc_time("350101000000Z"))

    tbs_certificate = univ.Sequence()
    tbs_certificate.setComponentByPosition(
        0,
        univ.Integer(2).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        ),
    )
    tbs_certificate.setComponentByPosition(1, univ.Integer(0x1234))
    tbs_certificate.setComponentByPosition(2, signature_algorithm)
    tbs_certificate.setComponentByPosition(3, _name("SPSDK test issuer"))
    tbs_certificate.setComponentByPosition(4, validity)
    tbs_certificate.setComponentByPosition(5, _name("SPSDK test subject"))
    tbs_certificate.setComponentByPosition(6, subject_public_key_info)

    certificate = univ.Sequence()
    certificate.setComponentByPosition(0, tbs_certificate)
    certificate.setComponentByPosition(1, signature_algorithm)
    certificate.setComponentByPosition(2, univ.BitString(hexValue=os.urandom(64).hex()))

    return encode(certificate)


def test_unsupported_algorithm_is_not_a_value_error() -> None:
    """Guard the root cause: UnsupportedAlgorithm does not derive from ValueError.

    `Certificate.get_public_key` used to catch only ValueError, so this exception escaped.
    """
    assert not issubclass(UnsupportedAlgorithm, ValueError)


def test_composite_certificate_raises_spsdk_error() -> None:
    """Composite certificate must raise SPSDKError, not cryptography's UnsupportedAlgorithm."""
    # Classic P-384 point (97 bytes) followed by an ML-DSA-65 public key (1952 bytes)
    public_key_data = b"\x04" + os.urandom(96) + os.urandom(1952)
    certificate = Certificate.parse(build_certificate(COMPOSITE_P384_MLDSA65_OID, public_key_data))

    with pytest.raises(SPSDKError) as exc_info:
        certificate.get_public_key()

    message = str(exc_info.value)
    assert COMPOSITE_P384_MLDSA65_OID in message
    assert "composite" in message.lower()
    # The message must point the user towards the supported dual SRK table configuration
    assert "srk_table_#2" in message
    assert "pqctool split" in message


def test_composite_certificate_reports_public_key_algorithm_oid() -> None:
    """The SubjectPublicKeyInfo OID is readable even though the key type is unsupported."""
    public_key_data = b"\x04" + os.urandom(96) + os.urandom(1952)
    certificate = Certificate.parse(build_certificate(COMPOSITE_P384_MLDSA65_OID, public_key_data))
    assert certificate.public_key_algorithm_oid == COMPOSITE_P384_MLDSA65_OID


@pytest.mark.parametrize("composite_oid", COMPOSITE_PUBLIC_KEY_OIDS)
def test_all_composite_oids_are_recognized(composite_oid: str) -> None:
    """Every known composite OID yields the dedicated composite guidance."""
    certificate = Certificate.parse(build_certificate(composite_oid, os.urandom(2049)))

    with pytest.raises(SPSDKError, match="composite"):
        certificate.get_public_key()

    assert certificate.public_key_algorithm_oid == composite_oid


def test_unknown_algorithm_raises_spsdk_error() -> None:
    """A non-composite unsupported algorithm still raises SPSDKError naming the OID."""
    unknown_oid = "1.2.3.4.5.6.7.8"
    certificate = Certificate.parse(build_certificate(unknown_oid, os.urandom(64)))

    with pytest.raises(SPSDKError) as exc_info:
        certificate.get_public_key()

    message = str(exc_info.value)
    assert unknown_oid in message
    assert "composite" not in message.lower()


def test_malformed_public_key_data_raises_spsdk_error() -> None:
    """Fallback ASN.1 decoding failures are reported as SPSDKError, not PyAsn1Error.

    `_extract_public_key` decodes raw DER and may raise pyasn1 errors, which must not escape.
    """
    certificate = Certificate.parse(
        build_certificate(
            ECC_PUBLIC_KEY_OID,
            b"\x00" * 32,  # not a valid EC point
            algorithm_parameters=SECP384R1_OID,
            signature_algorithm_oid=ECDSA_WITH_SHA384_OID,
        )
    )

    with pytest.raises(SPSDKError):
        certificate.get_public_key()


def test_mldsa_certificate_public_key_still_extracted() -> None:
    """Regression guard: the pure ML-DSA fallback extraction path keeps working."""
    from spsdk.crypto.keys import PrivateKeyMLDSA, PublicKeyMLDSA

    private_key = PrivateKeyMLDSA.generate_key(level=3)
    raw_public_key = private_key.get_public_key().export()

    certificate = Certificate.parse(build_certificate(MLDSA65_OID, raw_public_key))
    public_key = certificate.get_public_key()

    assert isinstance(public_key, PublicKeyMLDSA)
    assert public_key.export() == raw_public_key


def test_standard_certificate_public_key_unaffected() -> None:
    """Regression guard: ordinary ECC certificates are unaffected by the new error path."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PublicKeyEcc

    private_key = PrivateKeyEcc.generate_key(EccCurve.SECP384R1)
    # SubjectPublicKeyInfo stores the uncompressed EC point
    public_key_data = private_key.get_public_key().key.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )

    certificate = Certificate.parse(
        build_certificate(
            ECC_PUBLIC_KEY_OID,
            public_key_data,
            algorithm_parameters=SECP384R1_OID,
            signature_algorithm_oid=ECDSA_WITH_SHA384_OID,
        )
    )
    public_key = certificate.get_public_key()

    assert isinstance(public_key, PublicKeyEcc)
    assert certificate.public_key_algorithm_oid == ECC_PUBLIC_KEY_OID

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK ASN.1 types and utilities for TCG DICE specification.

This module provides ASN.1 data structures and utilities for implementing
the Trusted Computing Group (TCG) Device Identifier Composition Engine (DICE)
specification. It includes certificate management, DICE TCB info handling,
and cryptographic operations support.
"""

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
    """Create Object Identifier from components.

    Constructs an ASN.1 Object Identifier by combining integer components and existing
    ObjectIdentifier instances into a single OID.

    :param components: Variable number of integer values or ObjectIdentifier instances
                      to combine into a single OID
    :return: Combined Object Identifier instance
    """
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
    """TCG DICE Firmware Identifier ASN.1 structure.

    Represents a firmware identifier containing a hash algorithm identifier
    and digest value according to TCG DICE specifications. The structure
    follows the ASN.1 SEQUENCE format with hashAlg as OBJECT IDENTIFIER
    and digest as OCTET STRING.
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
        """Create ASN1 structure for FWID.

        Creates a new FWID (Firmware Identifier) ASN.1 structure with SHA-384 hash algorithm
        and the provided digest value.

        :param digest: The digest bytes to be included in the FWID structure.
        :return: New FWID instance with configured hash algorithm and digest.
        """
        fwid = cls()
        fwid.setComponentByName("hashAlg", nist_sha384)
        fwid.setComponentByName("digest", digest)
        return fwid

    @classmethod
    def encode(cls, digest: bytes) -> bytes:
        """Encode FWID ASN.1 structure to DER bytes.

        Creates a FWID structure from the provided digest and encodes it to DER format.

        :param digest: The digest bytes to be encoded in the FWID structure.
        :return: DER-encoded bytes of the FWID ASN.1 structure.
        """
        fwid = cls.create(digest)
        return encode(fwid)


class FWIDLIST(univ.SequenceOf):
    """ASN.1 sequence representing a list of Firmware Identifiers (FWIDs).

    This class implements the TCG DICE specification for FWIDLIST structure,
    which contains a sequence of 1 to 10 FWID elements used in device
    identity and attestation processes.

    :cvar componentType: Defines the type of elements in the sequence as FWID objects.
    """

    componentType = FWID()

    @classmethod
    def create(cls, fwid_list: list[bytes]) -> "FWIDLIST":
        """Create ASN1 structure for list of FWIDs.

        This class method constructs a FWIDLIST ASN1 structure containing multiple FWID entries
        from the provided list of firmware identifier digests.

        :param fwid_list: List of byte arrays representing firmware identifier digests.
        :return: FWIDLIST ASN1 structure containing all provided FWIDs.
        """
        fwidlist: FWIDLIST = cls().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )
        for digest in fwid_list:
            fwidlist.append(FWID.create(digest))
        return fwidlist

    @classmethod
    def encode(cls, fwid_list: list[bytes]) -> bytes:
        """Encode list of FWIDs to DER bytes.

        :param fwid_list: List of firmware identifiers as byte arrays.
        :return: DER-encoded bytes representation of the FWID list.
        """
        fwidlist = cls.create(fwid_list)
        return encode(fwidlist)


class OperationalFlags(univ.BitString):
    """ASN.1 BitString representation for TCG DICE operational flags.

    This class extends the ASN.1 BitString type to represent operational flags
    used in TCG DICE (Trusted Computing Group Device Identifier Composition Engine)
    specifications. It defines named bit positions for various security and
    configuration states of a device or component.

    :cvar namedValues: Named bit positions for operational flags including security,
                       configuration, and protection states.
    """

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
        """Create ASN1 structure for operation flags.

        This method creates a BitString with implicit context tag for representing operational flags
        in ASN.1 format.

        :param value: Integer value to be converted to hexadecimal BitString format.
        :return: ASN1 BitString structure with implicit context tag 7 for operational flags.
        """
        op_flags = univ.BitString(hexValue=f"{value:08x}").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
        )
        return op_flags


class OperationalFlagsMask(univ.BitString):
    """TCG DICE operational flags mask for ASN.1 encoding.

    This class represents a bit string that indicates which operational flags are valid
    in DICE (Device Identifier Composition Engine) attestation. It extends the ASN.1
    BitString type with predefined named values for various operational states.

    :cvar namedValues: Named bit positions for operational flags including security,
        configuration, debug, and protection states.
    """

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
        """Create ASN1 structure for operation flags mask.

        :param value: Integer value to be converted to ASN1 BitString format.
        :return: ASN1 BitString structure with implicit context tag for operational flags mask.
        """
        op_flags_mask = univ.BitString(hexValue=f"{value:08x}").subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)
        )
        return op_flags_mask


class DiceTcbInfo(univ.Sequence):
    """DICE TCB (Trusted Computing Base) Information ASN.1 sequence.

    This class represents the ASN.1 structure for DICE TCB information containing
    hardware and firmware identification data used in device identity and attestation.
    The structure includes optional fields for vendor, model, version, security
    version number, layer information, index, firmware identifiers, and operational flags.

    :cvar componentType: ASN.1 sequence component type definition with optional fields.
    """

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
        """Encode ASN1 structure into DER bytes.

        :return: DER encoded bytes representation of the ASN1 structure.
        """
        return encode(self)


class DiceTcbInfoSeq(univ.SequenceOf):
    """ASN.1 sequence container for DICE TCB Info structures.

    This class represents a sequence of DiceTcbInfo objects following ASN.1 encoding
    standards, providing functionality to encode multiple DICE TCB information
    structures into DER format for secure provisioning operations.

    :cvar componentType: ASN.1 component type definition for sequence elements.
    """

    componentType = DiceTcbInfo()

    @classmethod
    def encode(cls, values: list) -> bytes:
        """Encode ASN1 structure into DER bytes.

        Creates a new ASN1 sequence, appends all provided values to it, and encodes
        the sequence into DER (Distinguished Encoding Rules) format.

        :param values: List of ASN1 values to be encoded into the sequence.
        :return: DER-encoded bytes representation of the ASN1 sequence.
        """
        seq = cls()
        for value in values:
            seq.append(value)
        return encode(seq)


class TcgUeid(univ.Sequence):
    """TCG UEID (Unique Entity Identifier) ASN.1 structure.

    This class represents the TCG DICE UEID structure for encoding unique entity
    identifiers according to ASN.1 DER format. It provides functionality to encode
    UEID bytes into proper ASN.1 structure for TCG DICE attestation purposes.

    :cvar oid: Object identifier for TCG DICE UEID structure.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("ueid", univ.OctetString()),
    )
    oid = str(tcg_dice_Ueid)

    @classmethod
    def encode(cls, ueid: bytes) -> bytes:
        """Encode UEID into ASN.1 DER format.

        Encodes the provided UEID (Unique Entity Identifier) into an ASN.1 structure
        and returns it as DER (Distinguished Encoding Rules) bytes. The UEID is
        zero-padded to 16 bytes if necessary.

        :param ueid: The Unique Entity Identifier bytes to encode.
        :return: DER-encoded ASN.1 structure containing the UEID.
        """
        return encode(cls().setComponentByName("ueid", ueid.zfill(16)))


class Version(univ.Integer):
    """ASN.1 certificate version representation.

    This class extends the ASN.1 Integer type to represent X.509 certificate
    versions with named values for standard certificate versions (v1, v2, v3).

    :cvar namedValues: Named values mapping for certificate versions (v1=0, v2=1, v3=2).
    """

    namedValues = namedval.NamedValues(("v1", 0), ("v2", 1), ("v3", 2))


class CertificateSerialNumber(univ.Integer):
    """ASN.1 Certificate Serial Number representation.

    This class represents a certificate serial number as defined in X.509 standards,
    extending the ASN.1 Integer type for use in certificate structures and DICE
    attestation operations.
    """


class AlgorithmIdentifier(univ.Sequence):
    """ASN.1 Algorithm Identifier for cryptographic operations.

    This class represents the AlgorithmIdentifier structure as defined in ASN.1
    standards, used to identify cryptographic algorithms and their parameters
    in certificates and other cryptographic structures.

    :cvar componentType: ASN.1 structure definition with algorithm OID and optional parameters.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class Time(univ.Choice):
    """ASN.1 Time choice type for certificate time representation.

    This class provides a choice between UTC time and generalized time formats
    as defined in ASN.1 standards for use in certificates and other cryptographic
    structures.

    :cvar componentType: Named types defining UTC time and generalized time choices.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("utcTime", useful.UTCTime()),
        namedtype.NamedType("generalTime", useful.GeneralizedTime()),
    )


class Validity(univ.Sequence):
    """ASN.1 representation of X.509 certificate validity period.

    This class defines the ASN.1 structure for certificate validity periods,
    containing notBefore and notAfter time fields that specify when a certificate
    becomes valid and when it expires.

    :cvar componentType: ASN.1 sequence components defining notBefore and notAfter fields.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("notBefore", Time()), namedtype.NamedType("notAfter", Time())
    )


class Extension(univ.Sequence):
    """ASN.1 representation of X.509 v3 certificate extension.

    This class provides a structured representation of certificate extensions
    as defined in the X.509 v3 standard, including extension ID, criticality
    flag, and extension value components.

    :cvar componentType: ASN.1 component structure defining extension fields.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("extensionID", univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType("critical", univ.Boolean().subtype(value=0)),
        namedtype.NamedType("extensionValue", univ.OctetString()),
    )


class Extensions(univ.SequenceOf):
    """X.509 certificate extensions sequence container.

    This class represents a sequence of X.509 v3 certificate extensions used in
    TCG DICE attestation certificates, providing ASN.1 encoding/decoding capabilities.

    :cvar componentType: ASN.1 component type definition for extension elements.
    """

    componentType = Extension()


class TBSCertificate(univ.Sequence):
    """TBSCertificate ASN.1 structure for X.509 certificate data.

    This class represents the To-Be-Signed portion of an X.509 certificate
    according to ASN.1 encoding standards. It manages certificate metadata
    including version, serial number, signature algorithm, issuer, validity
    period, subject, public key information, and extensions.

    :cvar componentType: ASN.1 structure definition for TBS certificate fields.
    """

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
        """Create TBS (To Be Signed) ASN.1 certificate structure.

        Creates a TBS certificate structure with the provided subject, public key, and optional
        parameters like serial number, issuer, validity period, and extensions.

        :param subject: Certificate subject name.
        :param public_key: Public key to be included in the certificate.
        :param serial: Certificate serial number, random if not provided.
        :param issuer: Certificate issuer name, optional.
        :param not_before: Certificate validity start time, defaults to current time.
        :param not_after: Certificate validity end time, defaults to year 9999.
        :param extensions: List of non-critical extensions to include.
        :param critical_extensions: List of critical extensions to include.
        :return: TBS certificate ASN.1 structure.
        """
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
        """Encode ASN1 structure into DER bytes.

        :return: DER encoded bytes representation of the ASN1 structure.
        """
        return encode(self)

    @classmethod
    def create_ext(cls, ext: x509.ExtensionType, critical: bool = False) -> Extension:
        """Convert a cryptography extension to ASN.1 Extension.

        Creates an ASN.1 Extension object from a cryptography library extension,
        setting the extension ID, critical flag, and extension value.

        :param ext: The cryptography extension to convert.
        :param critical: Whether the extension should be marked as critical.
        :return: ASN.1 Extension object with populated fields.
        """
        result = Extension()
        result.setComponentByName("extensionID", ext.oid.dotted_string)
        result.setComponentByName("critical", critical)
        result.setComponentByName("extensionValue", ext.public_bytes())
        return result


class Certificate(univ.Sequence):
    """X.509 Certificate ASN.1 structure representation.

    This class provides ASN.1 encoding and decoding capabilities for X.509 certificates
    used in DICE (Device Identifier Composition Engine) operations. It handles certificate
    creation with digital signatures and DER encoding for secure provisioning workflows.

    :cvar componentType: ASN.1 structure definition for certificate components.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbsCertificate", TBSCertificate()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", univ.BitString()),
    )

    @classmethod
    def create(cls, tbs_certificate: TBSCertificate, signing_key: PrivateKey) -> "Certificate":
        """Create x509 Certificate ASN.1 structure.

        This method creates a complete X.509 certificate by combining the TBS (To Be Signed)
        certificate with a digital signature generated using the provided private key.
        Supports both ECC and ML-DSA signing algorithms.

        :param tbs_certificate: The TBS certificate structure to be signed.
        :param signing_key: Private key used for signing the certificate.
        :return: Complete X.509 certificate with signature.
        """
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
        """Encode ASN1 structure into DER bytes.

        :return: DER encoded bytes representation of the ASN1 structure.
        """
        return encode(self)


def get_oid_for_key(key: Union[PrivateKey, PublicKey]) -> bytes:
    """Get signature OID for given key.

    This method returns the appropriate signature algorithm Object Identifier (OID) based on the
    type of the provided cryptographic key.

    :param key: The cryptographic key (either private or public) to get the signature OID for.
    :raises ValueError: If the key type is not supported.
    :return: Encoded signature algorithm OID as bytes.
    """
    if isinstance(key, (PublicKeyEcc, PrivateKeyEcc)):
        return encode(sig_ecdsa_with_sha384)
    if isinstance(key, (PublicKeyMLDSA, PrivateKeyMLDSA)):
        return encode(sig_mldsa87)
    raise ValueError(f"Unknown key type: {type(key)}")

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate management utilities.

This module provides comprehensive functionality for X.509 certificate handling,
including certificate generation, validation, chain verification, and specialized
support for WPC Qi authentication certificates within the SPSDK framework.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.extensions import ExtensionNotFound
from typing_extensions import Self

from spsdk.crypto.crypto_types import (
    SPSDKEncoding,
    SPSDKExtensionOID,
    SPSDKExtensions,
    SPSDKName,
    SPSDKNameOID,
    SPSDKObjectIdentifier,
    SPSDKVersion,
)
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import IS_DILITHIUM_SUPPORTED, PrivateKey, PrivateKeyRsa, PublicKey
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import align_block, load_binary, write_file


class SPSDKExtensionNotFoundError(SPSDKError, ExtensionNotFound):
    """SPSDK extension not found error.

    Custom exception raised when a required X.509 certificate extension
    is not found during certificate processing or validation operations.
    """


class Certificate(BaseClass):
    """SPSDK Certificate wrapper for X.509 certificates.

    This class provides a unified interface for working with X.509 certificates
    in SPSDK operations, including certificate generation, validation, and
    cryptographic operations across NXP MCU portfolio.
    """

    def __init__(self, certificate: x509.Certificate) -> None:
        """Initialize SPSDK Certificate wrapper.

        Creates a new SPSDK Certificate instance from a cryptography library Certificate object.

        :param certificate: Cryptography Certificate representation to wrap.
        :raises AssertionError: If certificate is not an instance of x509.Certificate.
        """
        assert isinstance(certificate, x509.Certificate)
        self.cert = certificate

    @staticmethod
    def generate_certificate(
        subject: x509.Name,
        issuer: x509.Name,
        subject_public_key: PublicKey,
        issuer_private_key: PrivateKey,
        serial_number: Optional[int] = None,
        duration: Optional[int] = None,
        extensions: Optional[list[x509.ExtensionType]] = None,
        pss_padding: Optional[bool] = None,
    ) -> "Certificate":
        """Generate X.509 certificate with specified parameters.

        Creates a new X.509 certificate using the provided subject and issuer information,
        with configurable validity period, extensions, and RSA padding options.

        :param subject: Subject name that the CA issues the certificate to.
        :param issuer: Issuer name that issued the certificate.
        :param subject_public_key: Public key of the certificate subject.
        :param issuer_private_key: Private key of the certificate issuer for signing.
        :param serial_number: Certificate serial number, random if not specified.
        :param duration: Certificate validity period in days, defaults to very long period.
        :param extensions: List of X.509 extensions to include in the certificate.
        :param pss_padding: Use RSA-PSS padding instead of PKCS1v15, RSA keys only.
        :return: Generated X.509 certificate instance.
        """
        before = datetime.now(timezone.utc) if duration else datetime(2000, 1, 1)
        after = (
            datetime.now(timezone.utc) + timedelta(days=duration)
            if duration
            else datetime(9999, 12, 31)
        )
        crt = x509.CertificateBuilder(
            subject_name=subject,
            issuer_name=issuer,
            not_valid_before=before,
            not_valid_after=after,
            public_key=subject_public_key.key,
            # we don't pass extensions directly, need to handle the "critical" flag
            extensions=[],
            serial_number=serial_number or x509.random_serial_number(),
        )

        if extensions:
            for ext in extensions:
                crt = crt.add_extension(ext, critical=True)

        if not isinstance(issuer_private_key, PrivateKeyRsa):
            pss_padding = None
        if pss_padding is None:
            rsa_padding = None
        else:
            rsa_padding = (
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                )
                if pss_padding
                else padding.PKCS1v15()
            )
        return Certificate(
            crt.sign(issuer_private_key.key, hashes.SHA256(), rsa_padding=rsa_padding)
        )

    def save(
        self,
        file_path: str,
        encoding_type: SPSDKEncoding = SPSDKEncoding.PEM,
    ) -> None:
        """Save the certificate/CSR into file.

        :param file_path: Path to the file where certificate/CSR will be stored.
        :param encoding_type: Encoding type for the output file (PEM or DER).
        :raises SPSDKError: If file cannot be written or export fails.
        """
        write_file(self.export(encoding_type), file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str) -> Self:
        """Load the Certificate from the given file.

        :param file_path: Path to the file where the certificate is stored.
        :return: Certificate instance loaded from the file.
        """
        data = load_binary(file_path)
        return cls.parse(data=data)

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Export certificate to bytes in specified encoding format.

        The method supports multiple encoding formats including NXP-specific format
        which uses DER encoding aligned to 4-byte boundaries with zero padding.

        :param encoding: The encoding format to use for export (defaults to NXP format).
        :return: Certificate data as bytes in the specified encoding format.
        """
        if encoding == SPSDKEncoding.NXP:
            return align_block(self.export(SPSDKEncoding.DER), 4, "zeros")

        return self.cert.public_bytes(SPSDKEncoding.get_cryptography_encodings(encoding))

    def get_public_key(self) -> PublicKey:
        """Get public key from certificate.

        Extracts the public key from the certificate using the standard method,
        and falls back to manual extraction if the standard method fails.

        :return: Public key extracted from the certificate.
        """
        try:
            pub_key = self.cert.public_key()
            return PublicKey.create(pub_key)
        except ValueError:
            return self._extract_public_key()

    def _extract_public_key(self) -> PublicKey:
        """Extract public key from TBS certificate raw data using signature algorithm OID.

        The method parses the TBS (To Be Signed) certificate bytes to locate and extract
        the public key information. It supports both standard public keys and ML-DSA
        (Dilithium) keys when available.

        :raises SPSDKError: Invalid certificate data or unsupported key format.
        :return: Extracted public key object (standard or ML-DSA type).
        """
        from pyasn1.codec.der.decoder import decode
        from pyasn1.codec.der.encoder import encode
        from pyasn1.type import univ

        oid_str = self.cert.signature_algorithm_oid.dotted_string
        oid_nums = [int(x) for x in oid_str.split(".")]
        oid_bytes = encode(univ.ObjectIdentifier(oid_nums))

        oid_start = self.cert.tbs_certificate_bytes.rfind(oid_bytes)
        oid_end = oid_start + len(oid_bytes)

        pub_data, _ = decode(self.cert.tbs_certificate_bytes[oid_end:], univ.BitString())
        if IS_DILITHIUM_SUPPORTED and oid_str.startswith("2.16.840.1.101.3.4.3"):
            from spsdk.crypto.keys import PublicKeyMLDSA

            # Special handling for ML-DSA keys
            return PublicKeyMLDSA.parse(pub_data.asOctets())

        return PublicKey.parse(pub_data.asOctets())

    @property
    def version(self) -> SPSDKVersion:
        """Get the certificate version.

        :return: Certificate version information.
        """
        return self.cert.version

    @property
    def signature(self) -> bytes:
        """Get the signature bytes from the certificate.

        :return: The signature bytes of the certificate.
        """
        return self.cert.signature

    @property
    def tbs_certificate_bytes(self) -> bytes:
        """Get the tbsCertificate payload bytes as defined in RFC 5280.

        The tbsCertificate (to-be-signed certificate) contains the certificate data
        that is signed by the certificate authority.

        :return: Raw bytes of the tbsCertificate structure.
        """
        return self.cert.tbs_certificate_bytes

    @property
    def signature_hash_algorithm(
        self,
    ) -> Optional[hashes.HashAlgorithm]:
        """Get signature hash algorithm from certificate.

        Returns the hash algorithm used for signing the certificate digest.
        This method handles unsupported algorithms gracefully by returning None.

        :return: Hash algorithm instance if supported, None if algorithm is unsupported.
        """
        try:
            return self.cert.signature_hash_algorithm
        except UnsupportedAlgorithm:
            return None

    @property
    def extensions(self) -> SPSDKExtensions:
        """Get certificate extensions.

        Returns an Extensions object containing all X.509 certificate extensions such as
        key usage, subject alternative names, and other certificate attributes.

        :return: Extensions object with certificate extension data.
        """
        return self.cert.extensions

    @property
    def issuer(self) -> SPSDKName:
        """Get the certificate issuer name.

        Returns the issuer name object containing the distinguished name information
        of the certificate authority that issued this certificate.

        :return: Certificate issuer name object.
        """
        return self.cert.issuer

    @property
    def serial_number(self) -> int:
        """Get certificate serial number.

        :return: Serial number of the certificate.
        """
        return self.cert.serial_number

    @property
    def subject(self) -> SPSDKName:
        """Get the subject name object from the certificate.

        :return: Subject name object containing certificate subject information.
        """
        return self.cert.subject

    @property
    def signature_algorithm_oid(self) -> SPSDKObjectIdentifier:
        """Get the ObjectIdentifier of the signature algorithm.

        :return: Object identifier representing the signature algorithm used to sign this certificate.
        """
        return self.cert.signature_algorithm_oid

    @property
    def not_valid_before(self) -> datetime:
        """Get the certificate's not-valid-before timestamp.

        Returns the earliest date and time when the certificate becomes valid,
        represented as a UTC datetime object.

        :return: Certificate's not-valid-before time as UTC datetime.
        """
        # TODO Remove this workaround once cryptography > 42.0.0 is supported
        not_valid_before = (
            getattr(self.cert, "not_valid_before_utc")
            if hasattr(self.cert, "not_valid_before_utc")
            else getattr(self.cert, "not_valid_before")
        )
        assert isinstance(not_valid_before, datetime)
        return not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        """Get the certificate's expiration date and time.

        Returns the 'not valid after' timestamp from the X.509 certificate,
        indicating when the certificate expires. The datetime is always in UTC.

        :return: Certificate expiration datetime in UTC timezone.
        """
        # TODO Remove this workaround once cryptography > 42.0.0 is supported
        not_valid_after = (
            getattr(self.cert, "not_valid_after_utc")
            if hasattr(self.cert, "not_valid_after_utc")
            else getattr(self.cert, "not_valid_after")
        )
        assert isinstance(not_valid_after, datetime)
        return not_valid_after

    def validate_subject(self, subject_certificate: "Certificate") -> bool:
        """Validate subject certificate against this certificate.

        This method verifies the digital signature of the subject certificate using
        the public key from this certificate, confirming the certificate chain validity.

        :param subject_certificate: The certificate to be validated against this certificate.
        :raises SPSDKError: Unknown subject certificate's signature hash algorithm.
        :return: True if the certificate signature is valid, False otherwise.
        """
        if subject_certificate.signature_hash_algorithm is None:
            raise SPSDKError("Unknown Subject Certificate's signature hash algorithm")
        return self.get_public_key().verify_signature(
            subject_certificate.signature,
            subject_certificate.tbs_certificate_bytes,
            EnumHashAlgorithm.from_label(subject_certificate.signature_hash_algorithm.name),
        )

    def validate(self, issuer_certificate: "Certificate") -> bool:
        """Validate certificate against its issuer.

        The method verifies the certificate's signature using the issuer's public key
        and the certificate's signature hash algorithm.

        :param issuer_certificate: Issuer's certificate used for validation.
        :raises SPSDKError: Signature hash algorithm is unknown or unsupported key type.
        :return: True if certificate is valid, False otherwise.
        """
        if self.signature_hash_algorithm is None:
            raise SPSDKError("Signature hash algorithm is unknown")
        return issuer_certificate.get_public_key().verify_signature(
            self.signature,
            self.tbs_certificate_bytes,
            EnumHashAlgorithm.from_label(self.signature_hash_algorithm.name),
        )

    @property
    def ca(self) -> bool:
        """Check if CA flag is set in certificate.

        The method examines the Basic Constraints extension to determine if the certificate
        has Certificate Authority capabilities.

        :return: True if CA flag is set, False otherwise.
        """
        try:
            extension = self.extensions.get_extension_for_oid(SPSDKExtensionOID.BASIC_CONSTRAINTS)
            return extension.value.ca  # type: ignore # mypy can not handle property definition in cryptography
        except ExtensionNotFound:
            return False

    @property
    def self_signed(self) -> bool:
        """Check if the certificate is self-signed.

        A certificate is considered self-signed when it can be validated using its own public key,
        meaning the certificate was signed by the same entity that it represents.

        :return: True if the certificate is self-signed, False otherwise.
        """
        return self.validate(self)

    @property
    def raw_size(self) -> int:
        """Get raw size of the certificate in bytes.

        :return: Size of the certificate in bytes.
        """
        return len(self.export())

    def public_key_hash(self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
        """Get public key hash.

        Computes hash of the certificate's public key using the specified hash algorithm.

        :param algorithm: Hash algorithm to use for computing the key hash, defaults to SHA256.
        :return: Hash of the public key as bytes.
        """
        return self.get_public_key().key_hash(algorithm)

    def __repr__(self) -> str:
        """Get text representation of the Certificate object.

        Returns a short string representation containing the certificate's serial number
        in hexadecimal format.

        :return: String representation in format "Certificate, SN:0x<serial_number>".
        """
        return f"Certificate, SN:{hex(self.cert.serial_number)}"

    def __str__(self) -> str:
        """Get text representation of the certificate information.

        Returns a formatted string containing certificate details including certification
        authority status, serial number, validity range, signature algorithm, and
        self-issued status.

        :return: Formatted string with certificate information.
        """
        not_valid_before = self.not_valid_before.strftime("%d.%m.%Y (%H:%M:%S)")
        not_valid_after = self.not_valid_after.strftime("%d.%m.%Y (%H:%M:%S)")
        nfo = ""
        nfo += f"  Certification Authority:    {'YES' if self.ca else 'NO'}\n"
        nfo += f"  Serial Number:              {hex(self.cert.serial_number)}\n"
        nfo += f"  Validity Range:             {not_valid_before} - {not_valid_after}\n"
        if self.signature_hash_algorithm:
            nfo += f"  Signature Algorithm:        {self.signature_hash_algorithm.name}\n"
        nfo += f"  Self Issued:                {'YES' if self.self_signed else 'NO'}\n"

        return nfo

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse X.509 certificate from bytes array.

        The method automatically detects the certificate encoding (PEM or DER) and handles
        padded DER certificates by removing trailing null bytes if necessary.

        :param data: Certificate data in PEM or DER format.
        :return: Parsed certificate object.
        :raises SPSDKError: Cannot load certificate due to invalid format or data.
        :raises SPSDKValueError: Invalid certificate data structure.
        """

        def load_der_certificate(data: bytes) -> x509.Certificate:
            """Load the DER certificate from bytes.

            This function is designed to eliminate cryptography exception when the padded data is
            provided by automatically removing null byte padding.

            :param data: Data with DER certificate in bytes format.
            :return: Certificate object from cryptography library.
            :raises SPSDKValueError: Unsupported certificate format or invalid certificate data.
            """
            while True:
                try:
                    return x509.load_der_x509_certificate(data)
                except ValueError as exc:
                    if len(exc.args) and "kind: ExtraData" in exc.args[0] and data[-1:] == b"\00":
                        data = data[:-1]
                    else:
                        raise SPSDKValueError(str(exc)) from exc

        try:
            cert = {
                SPSDKEncoding.PEM: x509.load_pem_x509_certificate,
                SPSDKEncoding.DER: load_der_certificate,
            }[SPSDKEncoding.get_file_encodings(data)](
                data
            )  # type: ignore
            return Certificate(cert)  # type: ignore
        except ValueError as exc:
            raise SPSDKError(f"Cannot load certificate: ({str(exc)})") from exc


def validate_certificate_chain(chain_list: list[Certificate]) -> list[bool]:
    """Validate chain of certificates.

    Validates each certificate in the chain against its issuer certificate.
    Each certificate is verified using the public key of the next certificate
    in the chain (which should be its issuer).

    :param chain_list: List of certificates in chain, ordered from leaf to root.
    :return: List of boolean values indicating validation result for each certificate pair.
    :raises SPSDKError: When chain has less than two certificates.
    """
    if len(chain_list) <= 1:
        raise SPSDKError("The chain must have at least two certificates")
    result = []
    for i in range(len(chain_list) - 1):
        result.append(chain_list[i].validate(chain_list[i + 1]))
    return result


def validate_ca_flag_in_cert_chain(chain_list: list[Certificate]) -> bool:
    """Validate CA flag in certification chain.

    Checks whether the CA (Certificate Authority) flag is set in the first certificate
    of the provided certificate chain.

    :param chain_list: List of Certificate objects representing the certificate chain.
    :return: True if CA flag is set in the first certificate, False otherwise.
    """
    return chain_list[0].ca


X509NameConfig = Union[list[dict[str, str]], dict[str, Union[str, list[str]]]]


def generate_name(config: X509NameConfig) -> x509.Name:
    """Generate X.509 Name object from configuration.

    The method creates an X.509 Name object by processing the provided configuration
    which can be either a dictionary or list format. It handles multiple values
    for the same attribute and validates all attribute names against SPSDKNameOID.

    :param config: Configuration for X.509 name attributes in dictionary or list format.
    :raises SPSDKError: Invalid certificate attribute name provided.
    :return: X.509 Name object with configured attributes.
    """
    attributes: list[x509.NameAttribute] = []

    def _get_name_oid(name: str) -> x509.ObjectIdentifier:
        """Get object identifier for certificate name attribute.

        Retrieves the X.509 ObjectIdentifier corresponding to the given certificate
        name attribute from the SPSDKNameOID class.

        :param name: Name of the certificate attribute to get OID for.
        :raises SPSDKError: Invalid certificate attribute name.
        :return: X.509 ObjectIdentifier for the specified name attribute.
        """
        try:
            return getattr(SPSDKNameOID, name)
        except Exception as exc:
            raise SPSDKError(f"Invalid value of certificate attribute: {name}") from exc

    if isinstance(config, list):
        for item in config:
            for key, value in item.items():
                name_oid = _get_name_oid(key)
                attributes.append(x509.NameAttribute(name_oid, str(value)))

    if isinstance(config, dict):
        for key_second, value_second in config.items():
            name_oid = _get_name_oid(key_second)
            if isinstance(value_second, list):
                for value in value_second:
                    attributes.append(x509.NameAttribute(name_oid, str(value)))
            else:
                attributes.append(x509.NameAttribute(name_oid, str(value_second)))

    return x509.Name(attributes)


def generate_extensions(config: dict) -> list[x509.ExtensionType]:
    """Generate X.509 certificate extensions from configuration data.

    This method processes configuration dictionary and creates corresponding X.509 extensions
    including Basic Constraints, WPC QiAuth Policy, and WPC QiAuth RSID extensions.

    :param config: Dictionary containing extension configuration data with keys like
                   'BASIC_CONSTRAINTS', 'WPC_QIAUTH_POLICY', 'WPC_QIAUTH_RSID'
    :return: List of X.509 extension objects ready for certificate creation
    """
    extensions: list[x509.ExtensionType] = []

    for key, val in config.items():
        if key == "BASIC_CONSTRAINTS":
            ca = bool(val["ca"])
            extensions.append(
                x509.BasicConstraints(ca=ca, path_length=val.get("path_length") if ca else None)
            )
        if key == "WPC_QIAUTH_POLICY":
            extensions.append(WPCQiAuthPolicy(value=val["value"]))
        if key == "WPC_QIAUTH_RSID":
            extensions.append(WPCQiAuthRSID(value=val["value"]))
    return extensions


class WPCQiAuthPolicy(x509.UnrecognizedExtension):
    """WPC Qi Auth Policy x509 extension.

    This class represents a Wireless Power Consortium (WPC) Qi authentication policy
    extension for X.509 certificates, implementing the standardized OID for Qi wireless
    charging authentication mechanisms.

    :cvar oid: Object identifier for WPC Qi Auth Policy extension (2.23.148.1.1).
    """

    oid = x509.ObjectIdentifier("2.23.148.1.1")

    def __init__(self, value: int) -> None:
        """Initialize the extension with given policy number.

        :param value: Policy number to be encoded in the extension.
        :raises ValueError: If value cannot be converted to 4-byte big-endian format.
        """
        super().__init__(
            oid=self.oid,
            value=b"\x04\x04" + value.to_bytes(length=4, byteorder="big"),
        )


class WPCQiAuthRSID(x509.UnrecognizedExtension):
    """WPC Qi Auth RSID x509 extension.

    This class represents a Wireless Power Consortium (WPC) Qi Authentication
    Receiver System Identifier (RSID) as an X.509 certificate extension. It
    encapsulates the RSID value in the proper ASN.1 format for certificate
    embedding.

    :cvar oid: Object Identifier for WPC Qi Auth RSID extension (2.23.148.1.2).
    """

    oid = x509.ObjectIdentifier("2.23.148.1.2")

    def __init__(self, value: str) -> None:
        """Initialize the extension with given RSID in form of a hex-string.

        :param value: RSID value as hexadecimal string to be used in the extension.
        :raises ValueError: If the hex string cannot be converted to bytes.
        """
        super().__init__(
            oid=self.oid,
            value=b"\x04\x09" + bytes.fromhex(value).zfill(9),
        )

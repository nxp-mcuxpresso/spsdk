#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate Block management and processing utilities.

This module provides comprehensive functionality for handling various types of
certificate blocks used in NXP secure boot and authentication processes.
It supports multiple certificate block versions and formats including V1, V2.1,
Vx, and AHAB certificate blocks with their respective headers and structures.
"""

import logging
from struct import calcsize, pack, unpack_from
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.crypto.hash import get_hash
from spsdk.crypto.keys import PublicKeyEcc
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.image.cert_block.cert_blocks import CertBlock, convert_to_ecc_key
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import change_endianness, load_binary, split_data
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


########################################################################################################################
# Certificate Block Class for SB X
########################################################################################################################


class IskCertificateLite(BaseClass):
    """ISK Certificate Lite for secure boot operations.

    This class represents a lightweight version of an ISK (Image Signing Key) certificate
    used in NXP secure boot processes. It manages ISK public key data, constraints,
    and digital signatures for certificate validation and export operations.

    :cvar MAGIC: Certificate magic number identifier (0x4D43).
    :cvar VERSION: Certificate format version.
    :cvar ISK_PUB_KEY_LENGTH: Expected length of ISK public key data in bytes.
    :cvar ISK_SIGNATURE_SIZE: Expected size of ISK signature in bytes.
    """

    MAGIC = 0x4D43
    VERSION = 1
    HEADER_FORMAT = "<HHI"
    ISK_PUB_KEY_LENGTH = 64
    ISK_SIGNATURE_SIZE = 64
    SIGNATURE_OFFSET = 72

    def __init__(
        self,
        pub_key: Union[PublicKeyEcc, bytes],
        constraints: int = 1,
    ) -> None:
        """Constructor for ISK certificate.

        :param pub_key: ISK public key, either PublicKeyEcc object or raw bytes
        :param constraints: Certificate constraints (1 = self signed, 0 = NXP signed)
        """
        self.constraints = constraints
        self.pub_key = convert_to_ecc_key(pub_key)
        self.signature = bytes()
        self.isk_public_key_data = self.pub_key.export()

    @property
    def expected_size(self) -> int:
        """Get the expected size of the binary certificate block.

        Calculates the total size including magic number, version, constraints,
        ISK public key coordinates, and ISK blob signature.

        :return: Expected size in bytes of the binary certificate block.
        """
        return (
            +4  # magic + version
            + 4  # constraints
            + self.ISK_PUB_KEY_LENGTH  # isk public key coordinates
            + self.ISK_SIGNATURE_SIZE  # isk blob signature
        )

    def __repr__(self) -> str:
        """Return string representation of ISK Certificate lite.

        :return: String representation of the ISK Certificate lite object.
        """
        return "ISK Certificate lite"

    def __str__(self) -> str:
        """Get string representation of ISK certificate.

        Returns formatted information about the ISK certificate including constraints and public key
        details.

        :return: Formatted string containing ISK certificate information.
        """
        info = "ISK Certificate lite\n"
        info += f"Constraints:     {self.constraints}\n"
        info += f"Public Key:      {str(self.pub_key)}\n"
        return info

    def create_isk_signature(
        self, signature_provider: Optional[SignatureProvider], force: bool = False
    ) -> None:
        """Create ISK (Issuer Signing Key) signature for the certificate.

        This method generates a digital signature for the certificate using the provided
        signature provider. If a signature already exists, it will only be replaced
        when force parameter is set to True.

        :param signature_provider: Provider used to generate the digital signature
        :param force: Force regeneration of signature even if one already exists
        :raises SPSDKError: Signature provider is not specified
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")

        data = self.get_tbs_data()
        self.signature = signature_provider.get_signature(data)

    def get_tbs_data(self) -> bytes:
        """Get To-Be-Signed data for certificate block.

        Constructs the data that needs to be signed by packing the header information
        (magic, version, constraints) and appending the ISK public key data. Validates
        that the public key length and total data length match expected values.

        :raises SPSDKError: Invalid public key length or invalid TBS data length.
        :return: Packed binary data ready for signing.
        """
        data = pack(self.HEADER_FORMAT, self.MAGIC, self.VERSION, self.constraints)
        if len(self.isk_public_key_data) != self.ISK_PUB_KEY_LENGTH:
            raise SPSDKError(
                "Invalid public key length. "
                f"Expected: {self.ISK_PUB_KEY_LENGTH}, got: {len(self.isk_public_key_data)}"
            )
        data += self.isk_public_key_data
        if len(data) != self.SIGNATURE_OFFSET:
            raise SPSDKError(
                f"Invalid TBS data length. Expected: {self.SIGNATURE_OFFSET}, got: {len(data)}"
            )
        return data

    def export(self) -> bytes:
        """Export ISK certificate as bytes array.

        Serializes the ISK (Initial Secure Key) certificate into a binary format
        by combining the TBS (To Be Signed) data with the signature.

        :raises SPSDKError: Signature is not set or data size does not match expected size.
        :return: Binary representation of the ISK certificate.
        """
        if not self.signature:
            raise SPSDKError("Signature is not set.")

        data = self.get_tbs_data()
        data += self.signature

        if len(data) != self.expected_size:
            raise SPSDKError("ISK Cert data size does not match")

        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:  # pylint: disable=arguments-differ
        """Parse ISK certificate from bytes array.

        This method deserializes an ISK (Initial Secure Key) certificate from a binary data format,
        extracting the constraints, public key, and signature components.

        :param data: Input data as bytes array containing the serialized ISK certificate.
        :return: Parsed ISK certificate instance.
        """
        _, _, constraints = unpack_from(cls.HEADER_FORMAT, data)
        offset = calcsize(cls.HEADER_FORMAT)
        isk_pub_key_bytes = data[offset : offset + cls.ISK_PUB_KEY_LENGTH]
        offset += cls.ISK_PUB_KEY_LENGTH
        signature = data[offset : offset + cls.ISK_SIGNATURE_SIZE]
        certificate = cls(
            constraints=constraints,
            pub_key=isk_pub_key_bytes,
        )
        certificate.signature = signature
        return certificate

    def verify(self) -> Verifier:
        """Verify the ISK Certificate Lite configuration.

        Validates ISK certificate lite including magic, version, constraints,
        public key, and signature.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="ISK Certificate Lite",
            description="Validates ISK certificate lite structure and configuration",
        )

        # Verify magic number
        ver.add_record(
            name="Magic number",
            result=self.MAGIC == 0x4D43,
            value=f"Magic: 0x{self.MAGIC:04X} ({'valid' if self.MAGIC == 0x4D43 else 'INVALID, expected: 0x4D43'})",
        )

        # Verify version
        ver.add_record(
            name="Version",
            result=self.VERSION == 1,
            value=f"Version: {self.VERSION} ({'valid' if self.VERSION == 1 else 'INVALID, expected: 1'})",
        )

        # Verify constraints (should be 0 or 1)
        ver.add_record_range(
            name="Constraints",
            value=self.constraints,
            min_val=0,
            max_val=1,
        )

        # Verify constraint meaning
        constraint_type = "self-signed" if self.constraints == 1 else "NXP signed"
        ver.add_record(
            name="Certificate type",
            result=VerifierResult.SUCCEEDED,
            value=f"Constraints: {self.constraints} ({constraint_type})",
            important=False,
        )

        # Verify public key
        if self.pub_key is None:
            ver.add_record(
                name="Public key",
                result=VerifierResult.ERROR,
                value="Public key is not set (required)",
            )
        else:
            ver.add_record(
                name="Public key",
                result=VerifierResult.SUCCEEDED,
                value=f"Public key present ({self.pub_key.curve})",
            )

            # Verify public key curve (should be secp256r1 for lite version)
            expected_curve = "secp256r1"
            curve_valid = self.pub_key.curve in ["NIST P-256", "p256", "secp256r1"]
            ver.add_record(
                name="Public key curve",
                result=curve_valid,
                value=(
                    f"Curve: {self.pub_key.curve} "
                    f"({'valid' if curve_valid else f'INVALID, expected: {expected_curve}'})"
                ),
            )

        # Verify public key data length
        ver.add_record(
            name="Public key data length",
            result=len(self.isk_public_key_data) == self.ISK_PUB_KEY_LENGTH,
            value=f"Actual: {len(self.isk_public_key_data)} bytes, Expected: {self.ISK_PUB_KEY_LENGTH} bytes",
        )

        # Verify signature
        if not self.signature:
            ver.add_record(
                name="Signature",
                result=VerifierResult.WARNING,
                value="Signature not created yet (call create_isk_signature() first)",
            )
        else:
            ver.add_record(
                name="Signature length",
                result=len(self.signature) == self.ISK_SIGNATURE_SIZE,
                value=f"Actual: {len(self.signature)} bytes, Expected: {self.ISK_SIGNATURE_SIZE} bytes",
            )

        # Verify expected size calculation
        try:
            expected_size = self.expected_size
            ver.add_record(
                name="Expected size",
                result=expected_size == (4 + 4 + self.ISK_PUB_KEY_LENGTH + self.ISK_SIGNATURE_SIZE),
                value=f"Expected size: {expected_size} bytes",
            )
        except Exception as e:
            ver.add_record(
                name="Expected size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate expected size: {str(e)}",
            )

        # Verify signature offset
        ver.add_record(
            name="Signature offset",
            result=self.SIGNATURE_OFFSET == 72,
            value=(
                f"Signature offset: {self.SIGNATURE_OFFSET} bytes "
                f"({'valid' if self.SIGNATURE_OFFSET == 72 else 'INVALID'})"
            ),
        )

        # Verify export/parse round-trip if signature is present
        if self.signature and self.pub_key:
            try:
                exported = self.export()

                ver.add_record(
                    name="Export size consistency",
                    result=len(exported) == self.expected_size,
                    value=f"Exported: {len(exported)} bytes, Expected: {self.expected_size} bytes",
                )

                parsed = IskCertificateLite.parse(exported)

                roundtrip_valid = (
                    parsed.constraints == self.constraints
                    and len(parsed.isk_public_key_data) == len(self.isk_public_key_data)
                    and len(parsed.signature) == len(self.signature)
                )

                ver.add_record(
                    name="Export/Parse consistency",
                    result=roundtrip_valid,
                    value=(
                        "ISK Certificate Lite can be exported and parsed correctly"
                        if roundtrip_valid
                        else "Export/parse roundtrip FAILED"
                    ),
                )
            except Exception as e:
                ver.add_record(
                    name="Export/Parse consistency",
                    result=VerifierResult.ERROR,
                    value=f"Export/parse failed: {str(e)}",
                )

        return ver


class CertBlockVx(CertBlock):
    """Certificate block implementation for MC56xx family devices.

    This class provides certificate block functionality specifically designed for MC56xx
    microcontrollers, handling ISK (Intermediate Signing Key) certificate management,
    hash calculation, and binary export operations for secure boot processes.

    :cvar SUB_FEATURE: Feature identifier for certificate-based implementations.
    :cvar ISK_CERT_LENGTH: Standard length of ISK certificate in bytes.
    :cvar ISK_CERT_HASH_LENGTH: Length of ISK certificate hash in bytes.
    """

    SUB_FEATURE = "based_on_certx"

    ISK_CERT_LENGTH = 136
    ISK_CERT_HASH_LENGTH = 16  # [0:127]

    def __init__(
        self,
        family: FamilyRevision,
        isk_cert: Union[PublicKeyEcc, bytes],
        signature_provider: Optional[SignatureProvider] = None,
        self_signed: bool = True,
    ) -> None:
        """Initialize Certificate block with ISK certificate and signature provider.

        Creates a new certificate block instance with the specified family revision,
        ISK certificate, and optional signature provider for certificate operations.

        :param family: Target MCU family and revision information.
        :param isk_cert: ISK certificate as ECC public key or raw bytes.
        :param signature_provider: Optional provider for certificate signing operations.
        :param self_signed: Whether the certificate should be self-signed.
        """
        super().__init__(family)
        self.isk_cert_hash = bytes(self.ISK_CERT_HASH_LENGTH)
        self.isk_certificate = IskCertificateLite(pub_key=isk_cert, constraints=int(self_signed))
        self.signature_provider = signature_provider

    @property
    def expected_size(self) -> int:
        """Get expected size of binary block.

        :return: Expected size of the ISK certificate in bytes.
        """
        return self.isk_certificate.expected_size

    @property
    def cert_hash(self) -> bytes:
        """Calculate certificate hash from ISK certificate data.

        The method extracts the ISK certificate data and computes a hash, returning
        only the first 127 bytes of the calculated hash value.

        :return: First 127 bytes of the ISK certificate hash.
        """
        isk_cert_data = self.isk_certificate.export()
        return get_hash(isk_cert_data)[: self.ISK_CERT_HASH_LENGTH]

    def __repr__(self) -> str:
        """Return string representation of the certificate block.

        :return: String identifier for the certificate block version.
        """
        return "CertificateBlockVx"

    def __str__(self) -> str:
        """Get string representation of the Certificate block.

        Provides detailed information about the certificate block including version,
        ISK certificate details, and certificate hash.

        :return: Formatted string containing certificate block information.
        """
        msg = "Certificate block version x\n"
        msg += f"ISK Certificate:\n{str(self.isk_certificate)}\n"
        msg += f"Certificate hash: {self.cert_hash.hex()}"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array.

        Creates ISK signature using the configured signature provider and exports
        the ISK certificate data.

        :return: Certificate block data as bytes.
        """
        isk_cert_data = bytes()
        self.isk_certificate.create_isk_signature(self.signature_provider)
        isk_cert_data = self.isk_certificate.export()
        return isk_cert_data

    def get_tbs_data(self) -> bytes:
        """Get To-Be-Signed data from the ISK certificate.

        This method retrieves the To-Be-Signed (TBS) portion of the ISK (Intermediate Signing Key)
        certificate, which contains the certificate data that needs to be signed.

        :return: The TBS data as bytes from the ISK certificate.
        """
        return self.isk_certificate.get_tbs_data()

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse CertBlockVx from binary file.

        The method creates a Certificate Block instance by parsing the ISK certificate from the
        provided binary data and extracting the public key and signature information.

        :param data: Binary data containing the certificate block information.
        :param family: The MCU family revision for the certificate block.
        :return: Certificate Block instance with parsed ISK certificate data.
        :raises SPSDKError: Length of the data doesn't match Certificate Block length.
        """
        # IskCertificate
        isk_certificate = IskCertificateLite.parse(data)
        cert_block = cls(
            family=family,
            isk_cert=isk_certificate.isk_public_key_data,
            self_signed=bool(isk_certificate.constraints),
        )
        cert_block.isk_certificate.signature = isk_certificate.signature
        return cert_block

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for certificate blocks.

        The method retrieves and configures validation schemas including family-specific
        schema, certificate schema, and certificate block output schema. It updates the
        family schema with supported families for the given family revision.

        :param family: Family revision to configure validation schemas for.
        :return: List of validation schemas including family, certificate, and output schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        return [sch_family, sch_cfg["certificate_vx"], sch_cfg["cert_block_output"]]

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Certification block Image.

        :param data_path: Path to directory containing data files for configuration.
        :raises SPSDKNotImplementedError: Parsing of Cert Block Vx is not supported.
        """
        raise SPSDKNotImplementedError("Parsing of Cert Block Vx is not supported")

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create an instance of CertBlockVx from configuration.

        The method supports loading from binary file or creating from configuration parameters.
        It handles ISK certificates, signature providers, and family-specific settings.

        :param config: Input standard configuration containing certificate block settings.
        :return: CertBlockVx instance configured according to the provided configuration.
        :raises SPSDKError: If found gap in certificates from config file or invalid configuration.
        """
        if "certBlock" in config:
            family = FamilyRevision.load_from_config(config)
            try:
                return cls.parse(
                    load_binary(config.get_input_file_name("certBlock")), family=family
                )
            except (SPSDKError, TypeError):
                cert_block_cfg = config.load_sub_config("certBlock")
                cert_block_cfg["family"] = family.name
                cert_block_cfg["revision"] = family.revision
                cls.pre_check_config(cert_block_cfg)
                return cls.load_from_config(cert_block_cfg)

        isk_certificate = config.get("iskPublicKey", config.get("signingCertificateFile"))

        signature_provider = get_signature_provider(config)
        isk_cert = load_binary(isk_certificate, search_paths=config.search_paths)
        self_signed = config.get("selfSigned", True)
        family = FamilyRevision.load_from_config(config)
        cert_block = cls(
            family,
            signature_provider=signature_provider,
            isk_cert=isk_cert,
            self_signed=self_signed,
        )

        return cert_block

    def validate(self) -> None:
        """Validate the settings of certification block class members.

        This method checks if the ISK certificate configuration is valid, specifically
        verifying that when an ISK certificate exists without a signature, a proper
        signature provider must be available.

        :raises SPSDKError: Invalid ISK certificate configuration when certificate
            exists without signature but no valid signature provider is set.
        """
        if self.isk_certificate and not self.isk_certificate.signature:
            if not isinstance(self.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    def get_otp_script(self) -> str:
        """Generate OTP programming script for writing certificate hash to fuses.

        The method creates a blhost script that programs the ISK certificate hash
        into OTP fuses starting from index 12. The hash is split into 4-byte chunks
        with proper endianness conversion for fuse programming.

        :return: Blhost script content as string for OTP fuse programming.
        """
        ret = (
            "# BLHOST Cert Block Vx fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# ISK Cert hash [0:127]: {self.cert_hash.hex()} \n\n"
        )

        fuse_value = change_endianness(self.cert_hash)
        fuse_idx = 12  # Fuse start IDX
        for fuse_data in split_data(fuse_value, 4):
            ret += f"flash-program-once {hex(fuse_idx)} 4 {fuse_data.hex()}\n"
            fuse_idx += 1

        return ret

    def verify(self) -> Verifier:
        """Verify the Certificate Block Vx configuration.

        Validates the certificate block structure including ISK certificate lite,
        certificate hash, and expected size.

        :return: Verifier object for validation results.
        """
        ver = Verifier(
            name="Certificate Block Vx",
            description="Validates certificate block Vx structure and configuration for MC56xx family",
        )

        # Verify ISK certificate lite
        ver.add_child(self.isk_certificate.verify())

        # Verify expected size
        try:
            expected_size = self.expected_size
            ver.add_record(
                name="Expected size",
                result=expected_size == self.ISK_CERT_LENGTH,
                value=f"Expected size: {expected_size} bytes (should be {self.ISK_CERT_LENGTH} bytes)",
            )
        except Exception as e:
            ver.add_record(
                name="Expected size calculation",
                result=VerifierResult.ERROR,
                value=f"Failed to calculate expected size: {str(e)}",
            )

        # Verify certificate hash
        try:
            cert_hash = self.cert_hash
            ver.add_record(
                name="Certificate hash length",
                result=len(cert_hash) == self.ISK_CERT_HASH_LENGTH,
                value=f"Hash length: {len(cert_hash)} bytes (expected {self.ISK_CERT_HASH_LENGTH} bytes)",
            )

            ver.add_record(
                name="Certificate hash",
                result=VerifierResult.SUCCEEDED,
                value=f"Hash [0:127]: {cert_hash.hex().upper()}",
                important=False,
            )
        except Exception as e:
            ver.add_record(
                name="Certificate hash calculation",
                result=VerifierResult.WARNING,
                value=f"Failed to calculate certificate hash: {str(e)}, the ISK signature is not ready.",
            )

        # Verify signature provider
        if self.signature_provider:
            ver.add_record(
                name="Signature provider",
                result=VerifierResult.SUCCEEDED,
                value="Signature provider is configured",
            )
        else:
            ver.add_record(
                name="Signature provider",
                result=VerifierResult.WARNING,
                value="No signature provider configured",
            )

        # Verify export/parse round-trip
        try:
            exported = self.export()

            ver.add_record(
                name="Export size consistency",
                result=len(exported) == self.expected_size,
                value=f"Exported: {len(exported)} bytes, Expected: {self.expected_size} bytes",
            )

            parsed = CertBlockVx.parse(exported, self.family)

            roundtrip_valid = (
                parsed.isk_certificate.constraints == self.isk_certificate.constraints
                and len(parsed.isk_certificate.isk_public_key_data)
                == len(self.isk_certificate.isk_public_key_data)
                and len(parsed.isk_certificate.signature) == len(self.isk_certificate.signature)
            )

            ver.add_record(
                name="Export/Parse consistency",
                result=roundtrip_valid,
                value=(
                    "Certificate Block Vx can be exported and parsed correctly"
                    if roundtrip_valid
                    else "Export/parse roundtrip FAILED"
                ),
            )
        except Exception as e:
            ver.add_record(
                name="Export/Parse consistency",
                result=VerifierResult.ERROR,
                value=f"Export/parse failed: {str(e)}",
            )

        # Verify family
        ver.add_record(
            name="Target family",
            result=VerifierResult.SUCCEEDED,
            value=f"Family: {self.family}",
            important=False,
        )

        return ver

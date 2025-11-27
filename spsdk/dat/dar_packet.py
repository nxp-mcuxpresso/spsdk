#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Authentication Response (DAR) packet implementation.

This module provides classes for creating and handling Debug Authentication
Response packets used in the debug authentication process across NXP MCUs.
It supports multiple cryptographic algorithms including RSA and various ECC
curves, as well as EdgeLock Enclave V2 authentication responses.
"""

import logging
from struct import pack
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.debug_credential import (
    DebugCredentialCertificate,
    DebugCredentialEdgeLockEnclaveV2,
    ProtocolVersion,
)
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKValueError
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import load_binary, value_to_int
from spsdk.utils.verifier import Verifier, VerifierRecord, VerifierResult

logger = logging.getLogger(__name__)


class DebugAuthenticateResponse(FeatureBaseClass):
    """Debug Authenticate Response packet for secure debug authentication.

    This class manages the creation and processing of DAR (Debug Authenticate Response) packets
    used in NXP MCU secure debug authentication flow. It combines debug credentials,
    authentication challenges, and digital signatures to enable authorized debug access.

    :cvar FEATURE: Database manager feature identifier for DAT operations.
    """

    FEATURE = DatabaseManager.DAT

    def __init__(
        self,
        family: FamilyRevision,
        debug_credential: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        sign_provider: Optional[SignatureProvider],
    ) -> None:
        """Initialize the DebugAuthenticateResponse object.

        :param family: Family revision of the target chip for DAR processing.
        :param debug_credential: Debug credential certificate object containing authentication data.
        :param auth_beacon: Authentication beacon value (will be truncated to 16 bits if exceeds 0xFFFF).
        :param dac: Debug authentication challenge object.
        :param sign_provider: Optional signature provider for cryptographic operations.
        """
        self.debug_credential = debug_credential
        if auth_beacon > 0xFFFF:
            logger.warning(f"Authentication beacon value {hex(auth_beacon)} truncated to 16 bits")
            auth_beacon = auth_beacon & 0xFFFF
        self.auth_beacon = auth_beacon
        self.dac = dac
        self.family = family
        self.sign_provider = sign_provider

    def __repr__(self) -> str:
        """Return string representation of DAR packet.

        Provides a formatted string showing the DAC version and SOCC value in hexadecimal format.

        :return: String representation containing DAC version and SOCC value.
        """
        return f"DAR v{self.dac.version}, SOCC: 0x{self.dac.socc:08X}"

    def __str__(self) -> str:
        """String representation of DebugAuthenticateResponse.

        Creates a formatted string containing the Debug Authentication Certificate (DAC),
        Debug Credential (DC), and Authentication Beacon value for display purposes.

        :return: Formatted string representation of the DebugAuthenticateResponse object.
        """
        msg = f"DAC:\n{str(self.dac)}\n"
        msg += f"DC:\n{str(self.debug_credential)}\n"
        msg += f"Authentication Beacon: {hex(self.auth_beacon)}\n"
        return msg

    def _get_data_for_signature(self) -> bytes:
        """Collect the data for signature in bytes format.

        The method gathers common data and appends the DAC challenge to create
        the complete data payload that will be used for digital signature generation.

        :return: Combined data bytes ready for signature computation.
        """
        data = self._get_common_data()
        data += self.dac.challenge
        return data

    def _get_signature(self) -> bytes:
        """Get signature for the DAR packet data.

        This method uses the configured signature provider to sign the packet data
        that is prepared for signature. The signature provider must be set before
        calling this method.

        :raises SPSDKError: Signature provider is not set or signature generation failed.
        :return: Generated signature bytes for the packet data.
        """
        if not self.sign_provider:
            raise SPSDKError("Signature provider is not set")
        signature = self.sign_provider.sign(self._get_data_for_signature())
        if not signature:
            raise SPSDKError("Signature is not present")
        return signature

    def export(self) -> bytes:
        """Export DAR packet to binary form.

        Serializes the DAR packet by combining common data and signature into a binary representation
        suitable for transmission or storage.

        :return: Binary representation of the DAR packet.
        """
        data = self._get_common_data()
        data += self._get_signature()
        return data

    def _get_common_data(self) -> bytes:
        """Get common data by collecting debug credential and authentication beacon.

        The method exports the debug credential data and appends the authentication
        beacon value as a 4-byte little-endian unsigned integer.

        :return: Combined binary data containing debug credential and auth beacon.
        """
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse DAR packet from binary data.

        This is an abstract method that must be implemented by derived classes
        to handle specific DAR packet formats.

        :param data: Binary data containing the DAR packet to parse.
        :raises SPSDKNotImplementedError: Always raised as this is an abstract method.
        """
        raise SPSDKNotImplementedError("Derived class has to implement this method.")

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        dac: Optional[DebugAuthenticationChallenge] = None,
    ) -> Self:
        """Create Debug Authentication Response object from configuration.

        Loads and validates configuration parameters to construct a Debug Authentication
        Response (DAR) object with proper cryptographic setup and credentials.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Authentication Challenge object required for response creation.
        :raises SPSDKValueError: When DAC object is not provided.
        :return: Debug authentication response object.
        """
        if dac is None:
            raise SPSDKValueError("DAC object must be specified for proper DAR creating response.")
        family = FamilyRevision.load_from_config(config)
        auth_beacon = config.get_int("beacon", 0)
        dck = get_signature_provider(config, pss_padding=cls._use_pss_padding(family))
        dc = DebugCredentialCertificate.parse(
            load_binary(config.get_input_file_name("certificate")), family=family
        )
        return cls(
            family=family, debug_credential=dc, auth_beacon=auth_beacon, dac=dac, sign_provider=dck
        )

    @staticmethod
    def _use_pss_padding(family: FamilyRevision) -> bool:
        """Check if PSS padding should be used for the given family.

        The method checks the database for the specified family to determine if PSS padding
        is required for signing operations.

        :param family: Family revision to check PSS padding requirement for.
        :return: True if PSS padding should be used, False otherwise.
        """
        db = get_db(family)
        if DatabaseManager.SIGNING not in db.features:
            return False
        return db.get_bool(DatabaseManager.SIGNING, "pss_padding", False)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for DAR packet configuration.

        The method retrieves and configures validation schemas for DAR (Debug Authentication Response)
        packet based on the specified family. It combines general family schema with DAR-specific
        classic schema and updates family validation rules.

        :param family: Family description containing chip family and revision information.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas containing family and DAR classic schemas.
        """
        schemas = get_schema_file(DatabaseManager.DAT)
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families(), family=family
        )
        return [family_schema, schemas["dat_classic"]]

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration object containing family and device settings.
        :raises SPSDKError: Invalid configuration or unsupported family.
        :return: List of validation schema dictionaries for the specified configuration.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls._get_class_from_cfg(config).get_validation_schemas(family)

    @classmethod
    def _get_class_from_cfg(cls, config: Config) -> Type[Self]:
        """Get DAR class based on input configuration.

        This method determines the appropriate Debug Authentication Response (DAR) class
        by analyzing the family configuration and debug credential certificate. It handles
        special cases for EdgeLock Enclave V2 and falls back to protocol version-based
        class selection.

        :param config: Configuration of DAT containing family and certificate information.
        :return: Class type for Debug Authentication Response handling.
        """
        family = FamilyRevision.load_from_config(config)
        db = get_db(family)
        if (
            db.get_bool(DatabaseManager.DAT, "based_on_ele", False)
            and db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1) == 2
        ):
            return DebugAuthenticateResponseEdgelockEnclaveV2  # type: ignore

        dc = DebugCredentialCertificate.parse(
            load_binary(config.get_input_file_name("certificate")), family=family
        )

        return cls._get_class(family=family, protocol_version=dc.version)

    @classmethod
    def _get_class(cls, family: FamilyRevision, protocol_version: ProtocolVersion) -> Type[Self]:
        """Get the right Debug Authentication Response class by the protocol version.

        The method determines the appropriate DAR class based on the chip family's
        database configuration and protocol version. For EdgeLock Enclave v2 based
        families, it returns the specialized v2 class, otherwise maps to the
        protocol version.

        :param family: The chip family name
        :param protocol_version: DAT protocol version
        :return: Debug Authentication Response class type
        :raises KeyError: When protocol version is not found in version mapping
        """
        db = get_db(family)
        if (
            db.get_bool(DatabaseManager.DAT, "based_on_ele", False)
            and db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1) == 2
        ):
            return DebugAuthenticateResponseEdgelockEnclaveV2  # type: ignore

        return _version_mapping[protocol_version.version]  # type: ignore

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented in base class.
        """
        raise SPSDKNotImplementedError

    def _verify_rot_hash(self) -> VerifierRecord:
        """Verify Root of Trust Hash between DAC and DC.

        Compares the Root of Trust Key Hash (RKTH) from the Debug Authentication
        Certificate (DAC) with the calculated hash from the Debug Credential (DC).
        The verification considers family-specific RoT configurations.

        :return: VerifierRecord containing the RoT Hash verification result with
                 success/error status and relevant hash values or error details.
        """
        db = get_db(self.family)
        dac_rot_type = db.get_str(DatabaseManager.DAT, "dac_rot_type", "default")

        if dac_rot_type == "not_available":
            return VerifierRecord(
                name="RoT Hash", result=VerifierResult.SUCCEEDED, value="Not used"
            )

        dc_rotkh = self.debug_credential.calculate_hash()
        min_length = min(len(self.dac.rotid_rkth_hash), len(dc_rotkh))
        if dc_rotkh and self.dac.rotid_rkth_hash[:min_length] != dc_rotkh[:min_length]:
            return VerifierRecord(
                name="RoT Hash",
                result=VerifierResult.ERROR,
                value=(
                    "Invalid RKTH.\n"
                    f"DAC: {self.dac.rotid_rkth_hash.hex()}\nDC:  {dc_rotkh.hex()}"
                ),
            )

        return VerifierRecord(
            name="RoT Hash", result=VerifierResult.SUCCEEDED, value=dc_rotkh.hex()
        )

    def verify(self) -> Verifier:
        """Validate Debug Authentication Response against Debug Credential and Challenge data.

        This comprehensive validation method performs cross-verification of multiple debug authentication
        components to ensure data consistency and security compliance. The verifier systematically checks:
        - **Protocol Version Compatibility**: Ensures DAC (Debug Authentication Challenge) and DC
        (Debug Credential) use compatible protocol versions
        - **SoC Class (SOCC) Validation**: Verifies that the SoC Class values match between DAC, DC,
        and the target chip family specifications
        - **Device UUID Consistency**: Confirms that device unique identifiers are consistent across
        all authentication components, with special handling for general/wildcard UUIDs
        - **Root of Trust Hash Verification**: Validates that the Root of Trust Key Hash (RoTKH)
        matches between the challenge and credential data

        The method uses the DAR instance's debug_credential, dac, and family attributes to perform
        validation. It generates detailed verification results with specific error messages, warnings
        for non-critical issues (like general UUIDs), and success confirmations for valid components.

        :return: Verifier object containing detailed validation results and status for each checked
                 component.
        """
        db = get_db(self.family)
        ret = Verifier(
            name="DAC versus DC",
            description="This is verifier of Debug Authentication Challenge against Debug Credential",
        )
        # Verify protocol version
        if DebugCredentialCertificate.dat_based_on_ele(self.family):
            ret.add_record(
                "Protocol version",
                result=VerifierResult.WARNING,
                value=(
                    f"Not supported on {self.family.name}.\n"
                    f"DAC: {self.dac.version}\nDC:  {self.debug_credential.version}"
                ),
            )
        elif self.dac.version != self.debug_credential.version:
            ret.add_record(
                "Protocol version",
                result=VerifierResult.ERROR,
                value=f"Invalid protocol version.\nDAC: {self.dac.version}\nDC:  {self.debug_credential.version}",
            )
        else:
            ret.add_record(
                "Protocol version",
                result=VerifierResult.SUCCEEDED,
                value=str(self.debug_credential.version),
            )

        # Verify SOCC
        family_socc = db.get_int(DatabaseManager.DAT, "socc")
        if self.dac.socc != self.debug_credential.socc:
            ret.add_record(
                "SOCC",
                result=VerifierResult.ERROR,
                value=f"Different DAC and DC SOCC.\nDAC: {self.dac.socc:08X}\nDC:  {self.debug_credential.socc:08X}",
            )
        elif self.dac.socc != family_socc:
            ret.add_record(
                "SOCC",
                result=VerifierResult.ERROR,
                value=(
                    f"Invalid Family SOCC.\n Used: {self.dac.socc:08X}\n"
                    f" Family valid SOCC: {family_socc:08X}"
                ),
            )
        else:
            ret.add_record(
                "SOCC", result=VerifierResult.SUCCEEDED, value=f"{self.debug_credential.socc:08X}"
            )

        # Verify UUID
        if self.debug_credential.uuid == bytes(len(self.debug_credential.uuid)):
            ret.add_record(
                "UUID",
                result=VerifierResult.WARNING,
                value=f"The general UUID has been used. Fits for all {self.family.name} chips.",
            )
        elif self.dac.uuid != self.debug_credential.uuid:
            ret.add_record(
                "UUID",
                result=VerifierResult.ERROR,
                value=(
                    f"Different DAC and DC UUID.\nDAC: {self.dac.uuid.hex()}\n"
                    f"DC:  {self.debug_credential.uuid.hex()}"
                ),
            )
        else:
            ret.add_record("UUID", result=VerifierResult.SUCCEEDED, value=self.dac.uuid.hex())

        # Verify ROTH / SRKs using the extracted method
        ret.records.append(self._verify_rot_hash())

        return ret


class DebugAuthenticateResponseRSA(DebugAuthenticateResponse):
    """Debug Authenticate Response packet with RSA-specific implementation.

    This class extends the base DebugAuthenticateResponse to handle RSA cryptographic
    operations and data structures specific to RSA-based debug authentication protocols.
    """


class DebugAuthenticateResponseECC(DebugAuthenticateResponse):
    """Debug Authentication Response for Elliptic Curve Cryptography.

    This class implements the Debug Authentication Response (DAR) packet specifically
    for elliptic curve cryptographic operations, extending the base DAR functionality
    with ECC-specific key handling and signature generation.

    :cvar KEY_LENGTH: Length of the ECC key in bytes.
    :cvar CURVE: Default elliptic curve specification used for cryptographic operations.
    """

    KEY_LENGTH = 0
    CURVE = "secp256r1"

    def _get_common_data(self) -> bytes:
        """Get common data by collecting debug credential, auth beacon and UUID.

        This method exports the debug credential data and combines it with the
        authentication beacon and DAC UUID to create a common data structure.

        :return: Combined binary data containing debug credential, auth beacon and UUID.
        """
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        data += pack("<16s", self.dac.uuid)
        return data


class DebugAuthenticateResponseECC_256(DebugAuthenticateResponseECC):
    """Debug Authentication Response for ECC P-256 curve.

    This class implements Debug Authentication Response (DAR) functionality
    specifically for Elliptic Curve Cryptography using the P-256 curve with
    256-bit keys.

    :cvar KEY_LENGTH: Length of the cryptographic key in bytes (32 bytes for 256-bit keys).
    :cvar CURVE: The elliptic curve specification used for cryptographic operations.
    """

    KEY_LENGTH = 32
    CURVE = "secp256r1"


class DebugAuthenticateResponseECC_384(DebugAuthenticateResponseECC):
    """Debug Authentication Response handler for ECC P-384 curve operations.

    This class implements Debug Authentication Response (DAR) functionality
    specifically for elliptic curve cryptography using the NIST P-384 curve
    with 384-bit key sizes.

    :cvar KEY_LENGTH: Length of the cryptographic key in bytes (48 bytes for P-384).
    :cvar CURVE: The elliptic curve identifier used for cryptographic operations.
    """

    KEY_LENGTH = 48
    CURVE = "secp384r1"


class DebugAuthenticateResponseECC_521(DebugAuthenticateResponseECC):
    """Debug Authentication Response for ECC P-521 curve.

    This class implements debug authentication response handling specifically
    for elliptic curve cryptography using the NIST P-521 curve with 521-bit keys.

    :cvar KEY_LENGTH: Length of the ECC P-521 key in bytes (66 bytes).
    :cvar CURVE: The elliptic curve identifier for NIST P-521 curve.
    """

    KEY_LENGTH = 66
    CURVE = "secp521r1"


class DebugAuthenticateResponseEdgelockEnclaveV2(DebugAuthenticateResponse):
    """Debug Authentication Response for EdgeLock Enclave devices using AHAB v2.

    This class implements the Debug Authentication Response (DAR) protocol specifically
    for NXP devices equipped with EdgeLock Enclave security subsystem that utilize
    AHAB (Advanced High Assurance Boot) signed message format version 2. It handles
    the creation and export of authentication responses required for secure debug
    access to protected MCU resources.
    """

    def __init__(
        self,
        family: FamilyRevision,
        debug_credential: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        sign_message: SignedMessage,
    ) -> None:
        """Initialize DAR packet for EdgeLock Enclave devices with AHAB v2.

        Constructor for Debug Authentication Response (DAR) packet specifically designed
        for devices using EdgeLock Enclave with Authentication Header Boot (AHAB) version 2.

        :param family: Target MCU family and revision information
        :param debug_credential: Debug credential certificate for authentication
        :param auth_beacon: Authentication beacon value for the debug session
        :param dac: Debug authentication challenge data
        :param sign_message: Signed message containing authentication data
        """
        super().__init__(
            family,
            debug_credential,
            auth_beacon,
            dac,
            None,
        )
        self.sign_message = sign_message

    def __repr__(self) -> str:
        """Return string representation of the DAR packet.

        Provides a human-readable string representation showing the DAR packet
        is based on ELE v2 and includes the SOCC value in hexadecimal format.

        :return: String representation with ELE version and SOCC value.
        """
        return f"DAR based on ELE v2, SOCC: 0x{self.dac.socc:08X}"

    def export(self) -> bytes:
        """Export to binary form (serialization).

        The method updates the sign message fields and exports the object as bytes.

        :return: The exported bytes from object.
        """
        self.sign_message.update_fields()
        return self.sign_message.export()

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        dac: Optional[DebugAuthenticationChallenge] = None,
    ) -> Self:
        """Load debug authentication response from configuration.

        The method creates a Debug Authentication Response (DAR) object by processing
        the configuration and combining it with the Debug Authentication Challenge (DAC).
        It handles beacon configuration, loads debug credentials, and creates a signed
        message for the authentication response.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Authentication Challenge object containing UUID and challenge vector.
        :raises SPSDKValueError: If DAC object is not provided.
        :return: Debug authentication response object.
        """
        if dac is None:
            raise SPSDKValueError("DAC object must be specified for proper DAR creating response.")
        family = FamilyRevision.load_from_config(config)
        db = get_db(family=family)
        use_beacon = db.get_bool(DatabaseManager.DAT, "used_beacons_on_ele", False)
        auth_beacon = value_to_int(config.pop("beacon", 0)) if use_beacon else 0
        dc = DebugCredentialEdgeLockEnclaveV2.parse(
            load_binary(config.get_input_file_name("certificate")), family=family
        )
        # add missing parts to config from DC & DAC
        config["fuse_version"] = config.get_int("fuse_version", 0)
        config["sw_version"] = config.get_int("sw_version", 0)
        message = {
            "uuid": dac.uuid.hex(),
            "command": {
                "DAT_AUTHENTICATION_REQ": {
                    "challenge_vector": dac.challenge.hex(),
                    "authentication_beacon": auth_beacon,
                }
            },
        }
        config["message"] = message

        sign_msg = SignedMessage.load_from_config(config)

        return cls(
            family=family,
            debug_credential=dc,
            auth_beacon=auth_beacon,
            dac=dac,
            sign_message=sign_msg,
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schemas for DAR packet configuration.

        This method builds a list of validation schemas by combining family schema,
        modified SignedMessage schema, AHAB debug certificate schema, and optionally
        ELE authentication beacon schema based on family capabilities.

        :param family: Family description containing device family and revision information.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas for DAR packet configuration.
        """
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families(), family=family
        )

        schemas_smsg = SignedMessage.get_validation_schemas(family)[1]
        schemas_smsg["required"].remove("output")
        schemas_smsg["required"].remove("fuse_version")
        schemas_smsg["required"].remove("sw_version")
        schemas_smsg["required"].remove("message")
        schemas_smsg["required"].remove("srk_revoke_mask")

        schemas_smsg["properties"].pop("output")
        schemas_smsg["properties"].pop("fuse_version")
        schemas_smsg["properties"].pop("sw_version")
        schemas_smsg["properties"].pop("check_all_signatures")
        schemas_smsg["properties"].pop("iv_path")
        schemas_smsg["properties"].pop("message")
        schemas_smsg["properties"].pop("certificate")
        schemas_smsg["properties"].pop("srk_revoke_mask")

        ahab_dc_schema = get_schema_file(DatabaseManager.DAT)["ahab_debug_certificate"]

        ret = [family_schema, schemas_smsg, ahab_dc_schema]
        if get_db(family).get_bool(DatabaseManager.DAT, "used_beacons_on_ele", False):
            ret.append(get_schema_file(DatabaseManager.DAT)["ele_auth_beacon"])
        return ret

    def _verify_rot_hash(self) -> VerifierRecord:
        """Verify Root of Trust Hash between DAC and DC.

        The method compares the Root of Trust Key Hash (RKTH) from the DAC with the
        calculated hash from the signing message. It handles different RoT types including
        ECC and ECC+PQC combinations based on the device family configuration.

        :return: VerifierRecord containing the RoT Hash verification result with success
                 or error status and corresponding hash values.
        """
        db = get_db(self.family)
        dac_rot_type = db.get_str(DatabaseManager.DAT, "dac_rot_type", "default")

        if dac_rot_type == "not_available":
            return VerifierRecord(
                name="RoT Hash", result=VerifierResult.SUCCEEDED, value="Not used"
            )

        srkh_len = len(self.dac.rotid_rkth_hash)
        srkh0 = self.sign_message.get_srk_hash(0)
        used_rotkh = srkh0[:srkh_len]
        ver_name = f"RoT Hash(ECC RKTH[:{srkh_len}])"
        if dac_rot_type == "ecc_pqc_sha521_truncated" and self.sign_message.srk_count == 2:
            srkh1 = self.sign_message.get_srk_hash(1)
            used_rotkh = get_hash(srkh0[:48] + srkh1[:48], EnumHashAlgorithm.SHA512)[:srkh_len]
            ver_name = f"RoT Hash(SHA521(ECC RKTH[:48]+PQC[:48])[:{srkh_len}])"

        if used_rotkh != self.dac.rotid_rkth_hash:
            return VerifierRecord(
                name=ver_name,
                result=VerifierResult.ERROR,
                value=(
                    "Invalid RKTH.\n"
                    f"DAC: {self.dac.rotid_rkth_hash.hex()}\nDAR:  {used_rotkh.hex()}"
                ),
            )

        return VerifierRecord(
            name=ver_name, result=VerifierResult.SUCCEEDED, value=used_rotkh.hex()
        )


_version_mapping = {
    "1.0": DebugAuthenticateResponseRSA,
    "1.1": DebugAuthenticateResponseRSA,
    "2.0": DebugAuthenticateResponseECC_256,
    "2.1": DebugAuthenticateResponseECC_384,
    "2.2": DebugAuthenticateResponseECC_521,
    "3.1": DebugAuthenticateResponseECC_256,
    "3.2": DebugAuthenticateResponseEdgelockEnclaveV2,
}

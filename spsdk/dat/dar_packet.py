#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication Response (DAR) Packet."""

import logging
from struct import pack
from typing import Any, Optional, Type

from typing_extensions import Self

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

logger = logging.getLogger(__name__)


class DebugAuthenticateResponse(FeatureBaseClass):
    """Class for DAR packet."""

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

        :param family: Family name of used chip for DAR
        :param debug_credential: the path, where the dc is store
        :param auth_beacon: authentication beacon value
        :param dac: the path, where the dac is store
        :param path_dck_private: the path, where the dck private key is store
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
        return f"DAR v{self.dac.version}, SOCC: 0x{self.dac.socc:08X}"

    def __str__(self) -> str:
        """String representation of DebugAuthenticateResponse."""
        msg = f"DAC:\n{str(self.dac)}\n"
        msg += f"DC:\n{str(self.debug_credential)}\n"
        msg += f"Authentication Beacon: {hex(self.auth_beacon)}\n"
        return msg

    def _get_data_for_signature(self) -> bytes:
        """Collects the data for signature in bytes format."""
        data = self._get_common_data()
        data += self.dac.challenge
        return data

    def _get_signature(self) -> bytes:
        if not self.sign_provider:
            raise SPSDKError("Signature provider is not set")
        signature = self.sign_provider.sign(self._get_data_for_signature())
        if not signature:
            raise SPSDKError("Signature is not present")
        return signature

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        data = self._get_common_data()
        data += self._get_signature()
        return data

    def _get_common_data(self) -> bytes:
        """Collects dc, auth_beacon."""
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse the DAR."""
        raise SPSDKNotImplementedError("Derived class has to implement this method.")

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        dac: Optional[DebugAuthenticationChallenge] = None,
    ) -> Self:
        """Converts the configuration option into an Debug authentication response object.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Credential Challenge
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
        """Check if it's needed to use PSS padding."""
        db = get_db(family)
        if DatabaseManager.SIGNING not in db.features:
            return False
        return db.get_bool(DatabaseManager.SIGNING, "pss_padding", False)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
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

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls._get_class_from_cfg(config).get_validation_schemas(family)

    @classmethod
    def _get_class_from_cfg(cls, config: Config) -> Type[Self]:
        """Get DAR class based on input configuration.

        :param config: CConfiguration of DAT
        :return: Class of DAR
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

        :param family: The chip family name
        :param protocol_version: DAT protocol version
        """
        db = get_db(family)
        if (
            db.get_bool(DatabaseManager.DAT, "based_on_ele", False)
            and db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1) == 2
        ):
            return DebugAuthenticateResponseEdgelockEnclaveV2  # type: ignore

        return _version_mapping[protocol_version.version]  # type: ignore

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError


class DebugAuthenticateResponseRSA(DebugAuthenticateResponse):
    """Class for RSA specifics of DAR packet."""


class DebugAuthenticateResponseECC(DebugAuthenticateResponse):
    """Class for DAR, using Elliptic curve keys."""

    KEY_LENGTH = 0
    CURVE = "secp256r1"

    def _get_common_data(self) -> bytes:
        """Collects dc, auth_beacon and UUID."""
        data = self.debug_credential.export()
        data += pack("<L", self.auth_beacon)
        data += pack("<16s", self.dac.uuid)
        return data


class DebugAuthenticateResponseECC_256(DebugAuthenticateResponseECC):
    """Class for DAR, using Elliptic curve, 256 bits sized keys."""

    KEY_LENGTH = 32
    CURVE = "secp256r1"


class DebugAuthenticateResponseECC_384(DebugAuthenticateResponseECC):
    """Class for DAR, using Elliptic curve, 384 bits sized keys."""

    KEY_LENGTH = 48
    CURVE = "secp384r1"


class DebugAuthenticateResponseECC_521(DebugAuthenticateResponseECC):
    """Class for DAR, using Elliptic curve, 521 bits sized keys."""

    KEY_LENGTH = 66
    CURVE = "secp521r1"


class DebugAuthenticateResponseEdgelockEnclaveV2(DebugAuthenticateResponse):
    """Class for DAR, using AHAB Signed message version 2."""

    def __init__(
        self,
        family: FamilyRevision,
        debug_credential: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        sign_message: SignedMessage,
    ) -> None:
        """Constructor of DAR for devices that using EdgeLock Enclave with AHAB v2."""
        super().__init__(
            family,
            debug_credential,
            auth_beacon,
            dac,
            None,
        )
        self.sign_message = sign_message

    def __repr__(self) -> str:
        return f"DAR based on ELE v2, SOCC: 0x{self.dac.socc:08X}"

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        self.sign_message.update_fields()
        return self.sign_message.export()

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        dac: Optional[DebugAuthenticationChallenge] = None,
    ) -> Self:
        """Converts the configuration option into an Debug authentication response object.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Credential Challenge
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
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
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
        schemas_smsg["properties"].pop("output")
        schemas_smsg["properties"].pop("check_all_signatures")
        schemas_smsg["properties"].pop("iv_path")
        schemas_smsg["properties"].pop("message")
        schemas_smsg["properties"].pop("certificate")

        ahab_dc_schema = get_schema_file(DatabaseManager.DAT)["ahab_debug_certificate"]

        ret = [family_schema, schemas_smsg, ahab_dc_schema]
        if get_db(family).get_bool(DatabaseManager.DAT, "used_beacons_on_ele", False):
            ret.append(get_schema_file(DatabaseManager.DAT)["ele_auth_beacon"])
        return ret


_version_mapping = {
    "1.0": DebugAuthenticateResponseRSA,
    "1.1": DebugAuthenticateResponseRSA,
    "2.0": DebugAuthenticateResponseECC_256,
    "2.1": DebugAuthenticateResponseECC_384,
    "2.2": DebugAuthenticateResponseECC_521,
    "3.1": DebugAuthenticateResponseECC_256,
    "3.2": DebugAuthenticateResponseEdgelockEnclaveV2,
}

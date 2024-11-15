#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module with Debug Authentication Response (DAR) Packet."""

import os
from struct import pack
from typing import Any, Optional, Type, cast

from typing_extensions import Self

from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.dat.debug_credential import (
    DebugCredentialCertificate,
    DebugCredentialEdgeLockEnclaveV2,
    ProtocolVersion,
)
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file
from spsdk.utils.misc import load_binary
from spsdk.utils.schema_validator import CommentedConfig


class DebugAuthenticateResponse:
    """Class for DAR packet."""

    def __init__(
        self,
        family: str,
        debug_credential: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        sign_provider: Optional[SignatureProvider],
        revision: str = "latest",
    ) -> None:
        """Initialize the DebugAuthenticateResponse object.

        :param family: Family name of used chip for DAR
        :param debug_credential: the path, where the dc is store
        :param auth_beacon: authentication beacon value
        :param dac: the path, where the dac is store
        :param path_dck_private: the path, where the dck private key is store
        :param revision: Chip revision, if not specified the latest revision is used
        """
        self.debug_credential = debug_credential
        self.auth_beacon = auth_beacon
        self.dac = dac
        self.family = family
        self.sign_provider = sign_provider
        db = get_db(family, revision=revision)
        self.revision = db.name

    def __repr__(self) -> str:
        return f"DAR v{self.dac.version}, SOCC: 0x{self.dac.socc:08X}"

    def __str__(self) -> str:
        """String representation of DebugAuthenticateResponse."""
        msg = f"DAC:\n{str(self.dac)}\n"
        msg += f"DC:\n{str(self.debug_credential)}\n"
        msg += f"Authentication Beacon: {self.auth_beacon}\n"
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
        """Parse the DAR.

        :param data: Raw data as bytes
        :return: DebugAuthenticateResponse object
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @staticmethod
    def _get_class(
        family: str, protocol_version: ProtocolVersion, revision: str = "latest"
    ) -> "Type[DebugAuthenticateResponse]":
        """Get the right Debug Authentication Response class by the protocol version.

        :param version: DAT protocol version
        """
        db = get_db(family, revision)
        if (
            db.get_bool(DatabaseManager.DAT, "based_on_ele", False)
            and db.get_int(DatabaseManager.DAT, "ele_cnt_version", 1) == 2
        ):
            return DebugAuthenticateResponseEdgelockEnclaveV2

        return _version_mapping[protocol_version.version]

    @classmethod
    def load_from_config(
        cls,
        config: dict[str, Any],
        dac: DebugAuthenticationChallenge,
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Converts the configuration option into an Debug authentication response object.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Credential Challenge
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Debug authentication response object.
        """
        dc = DebugCredentialCertificate.parse(load_binary(config["certificate"], search_paths))
        if isinstance(dc, DebugCredentialEdgeLockEnclaveV2):
            klass: Type[DebugAuthenticateResponse] = DebugAuthenticateResponseEdgelockEnclaveV2
        else:
            klass = DebugAuthenticateResponse._get_class(
                family=config["family"],
                protocol_version=dc.version,
                revision=config.get("revision", "latest"),
            )
        return klass._load_from_config(config, dc, dac, search_paths)  # type:ignore

    @staticmethod
    def _use_pss_padding(family: str) -> bool:
        """Check if it's needed to use PSS padding."""
        db = get_db(family)
        if DatabaseManager.SIGNING not in db.features:
            return False
        return db.get_bool(DatabaseManager.SIGNING, "pss_padding", False)

    @classmethod
    def _load_from_config(
        cls,
        config: dict[str, Any],
        dc: DebugCredentialCertificate,
        dac: DebugAuthenticationChallenge,
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Converts the configuration option into an Debug authentication response object.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Credential Challenge
        :param dc: Debug Credential Certificate
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Debug authentication response object.
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        auth_beacon = config.get("beacon", 0)
        dck = get_signature_provider(
            sp_cfg=config.get("sign_provider"),
            local_file_key=config.get("dck_private_key"),
            pss_padding=cls._use_pss_padding(family),
            search_paths=search_paths,
        )
        return cls(
            family=family,
            debug_credential=dc,
            auth_beacon=auth_beacon,
            dac=dac,
            sign_provider=dck,
            revision=revision,
        )

    @classmethod
    def create(
        cls,
        family: Optional[str],
        version: Optional[ProtocolVersion],
        dc: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        dck: str,
    ) -> "DebugAuthenticateResponse":
        """Create a dar object out of input parameters.

        :param family: Family name of the used chip
        :param version: protocol version
        :param dc: debug credential object
        :param auth_beacon: authentication beacon value
        :param dac: DebugAuthenticationChallenge object
        :param dck: string containing path to dck key
        :return: DAR object
        """
        if not family:
            families_socc = dc.get_socc_list()
            family = list(families_socc[dc.socc].keys())[0]

        if isinstance(dc, DebugCredentialEdgeLockEnclaveV2):
            klass: Type[DebugAuthenticateResponse] = DebugAuthenticateResponseEdgelockEnclaveV2
        else:
            klass = DebugAuthenticateResponse._get_class(
                family=family, protocol_version=version or dc.version
            )
        sp_cfg = None
        local_file_key = None
        if os.path.isfile(dck):
            local_file_key = dck
        else:
            sp_cfg = dck

        dck_sign_provider = get_signature_provider(
            sp_cfg=sp_cfg,
            local_file_key=local_file_key,
            pss_padding=cls._use_pss_padding(family),
        )
        dar_obj = klass(
            family=family,
            debug_credential=dc,
            auth_beacon=auth_beacon,
            dac=dac,
            sign_provider=dck_sign_provider,
        )
        return dar_obj

    @classmethod
    def _get_family_validation_schemas(
        cls, family: str, revision: str = "latest"
    ) -> dict[str, Any]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        schemas = get_schema_file("general")["family"]
        schemas["properties"]["family"]["template_value"] = family
        schemas["properties"]["revision"]["template_value"] = revision
        return schemas

    @classmethod
    def _get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        schemas = get_schema_file(DatabaseManager.DAT)
        return [cls._get_family_validation_schemas(family, revision), schemas["dat_classic"]]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        # The version for validation schemas is not important
        return cls._get_class(family, ProtocolVersion("1.0"), revision)._get_validation_schemas(
            family, revision
        )

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :param revision: Family revision of chip.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = DebugAuthenticateResponse.get_validation_schemas(family, revision)

        yaml_data = CommentedConfig(
            f"Debug Authentication Configuration template for {family}.", val_schemas
        ).get_template()

        return yaml_data


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
        family: str,
        debug_credential: DebugCredentialCertificate,
        auth_beacon: int,
        dac: DebugAuthenticationChallenge,
        sign_message: SignedMessage,
        revision: str = "latest",
    ) -> None:
        """Constructor of DAR for devices that using EdgeLock Enclave with AHAB v2."""
        super().__init__(
            family,
            debug_credential,
            auth_beacon,
            dac,
            None,
            revision,
        )
        self.sign_message = sign_message

    def __repr__(self) -> str:
        return f"DAR based on ELE v2, SOCC: 0x{self.dac.socc:08X}"

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: the exported bytes from object
        """
        self.sign_message.update_fields()
        self.sign_message.verify().validate()
        return self.sign_message.export()

    @classmethod
    def _load_from_config(
        cls,
        config: dict[str, Any],
        dc: DebugCredentialCertificate,
        dac: DebugAuthenticationChallenge,
        search_paths: Optional[list[str]] = None,
    ) -> Self:
        """Converts the configuration option into an Debug authentication response object.

        :param config: Debug authentication response configuration dictionaries.
        :param dac: Debug Credential Challenge
        :param dc: Debug Credential Certificate
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Debug authentication response object.
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        auth_beacon = config.get("beacon", 0)
        dc_correct = cast(DebugCredentialEdgeLockEnclaveV2, dc)
        # add missing parts to config from DC & DAC
        config["fuse_version"] = dc_correct.certificate.fuse_version
        config["sw_version"] = 0
        message = {
            "uuid": dc_correct.uuid.hex(),
            "command": {
                "DAT_AUTHENTICATION_REQ": {
                    "challenge_vector": dac.challenge.hex(),
                    "authentication_beacon": auth_beacon,
                }
            },
        }
        config["message"] = message

        sign_msg = SignedMessage.load_from_config(config, search_paths)

        return cls(
            family=family,
            debug_credential=dc,
            auth_beacon=auth_beacon,
            dac=dac,
            sign_message=sign_msg,
            revision=revision,
        )

    @classmethod
    def _get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        schemas_smsg = SignedMessage.get_validation_schemas(family, revision)[1]
        schemas_smsg["required"].remove("output")
        schemas_smsg["required"].remove("fuse_version")
        schemas_smsg["required"].remove("sw_version")
        schemas_smsg["required"].remove("message")
        schemas_smsg["required"].append("certificate")
        schemas_smsg["properties"].pop("output")
        schemas_smsg["properties"].pop("fuse_version")
        schemas_smsg["properties"].pop("sw_version")
        schemas_smsg["properties"].pop("check_all_signatures")
        schemas_smsg["properties"].pop("iv_path")
        schemas_smsg["properties"].pop("message")

        return [cls._get_family_validation_schemas(family, revision), schemas_smsg]


_version_mapping = {
    "1.0": DebugAuthenticateResponseRSA,
    "1.1": DebugAuthenticateResponseRSA,
    "2.0": DebugAuthenticateResponseECC_256,
    "2.1": DebugAuthenticateResponseECC_384,
    "2.2": DebugAuthenticateResponseECC_521,
}

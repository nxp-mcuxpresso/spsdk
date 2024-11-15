#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains code related to CSF commands."""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Type, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.crypto.signature_provider import PlainFileSP, SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKFileNotFoundError, SPSDKKeyError, SPSDKTypeError, SPSDKValueError
from spsdk.image.commands import (
    UNLOCK_COMMANDS_MAPPING,
    CmdAuthData,
    CmdBase,
    CmdInstallKey,
    CmdSet,
    CmdUnlockAbstract,
    EnumAuthDat,
    EnumCertFormat,
    EnumEngine,
    EnumInsKey,
    Header,
)
from spsdk.image.hab.commands.commands_enum import SecCommand
from spsdk.image.hab.hab_config import CommandOptions, HabConfig
from spsdk.image.header import SegTag
from spsdk.image.secret import CertificateImg, EnumAlgorithm, Signature, SrkTable
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


@dataclass
class ImageBlock:
    """Single image block."""

    base_address: int
    start: int
    size: int


def parse_version(version: Union[str, int]) -> int:
    """Parse version from string to actual integer.

    An example: "4.2" -> 0x42 -> 64

    :param version: Version as string or int
    :raises SPSDKTypeError: Input version if wrong type.
    :return: Version as int value
    """
    if not isinstance(version, (str, int)):
        raise SPSDKTypeError("Version can be either int or string")
    if isinstance(version, str):
        int_version = int(version.replace(".", ""), 16)
    else:
        int_version = version
    return int_version


def determine_private_key_path(cert_file_path: str) -> Optional[str]:
    """Determine private key path the same way as legacy CST tool does.

    :param cert_file_path: Path to certificate file
    :return: Path to private key file
    """
    logger.debug("Trying to determine the private key path.")
    directory, cert_file_name = os.path.split(cert_file_path)
    keys_dir = directory[:-4] + "keys" if directory.endswith("crts") else directory
    cert_file, cert_extension = os.path.splitext(cert_file_name)
    if cert_file.endswith("crt"):
        key_file_name = cert_file[:-3] + "key" + cert_extension
        return os.path.join(keys_dir, key_file_name)
    return None


def get_hab_signature_provider(
    sp_cfg: Optional[str] = None, local_file_key: Optional[str] = None, **kwargs: Any
) -> SignatureProvider:
    """Get the HAB signature provider from configuration."""
    signature_provider = get_signature_provider(sp_cfg, local_file_key, **kwargs)
    if isinstance(signature_provider, PlainFileSP):
        if isinstance(signature_provider.private_key, PrivateKeyEcc):
            signature_provider.hash_alg = EnumHashAlgorithm.SHA256
    return signature_provider


class SecCommandBase(ABC):
    """Sec command abstract class."""

    PARAMS: dict[str, bool]

    def __init__(self, cmd: CmdBase) -> None:
        """Install SRK class constructor.

        :param srk_table: SRK table
        :param source_index: Source index
        :raises SPSDKValueError: Srk table is not defined .
        :raises SPSDKValueError: Source index is not defined .
        """
        self.cmd = cmd

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Loaded command instance
        """

    def export(self) -> bytes:
        """Export command to binary form."""
        return self.cmd.export()

    @classmethod
    def check_config_section_params(cls, command_options: CommandOptions) -> None:
        """Check if options contains only accepted arguments.

        :param command_options: Command options object
        :raises SPSDKValueError: If mandatory parameter is not present
        :raises SPSDKValueError: If unexpected key is present
        """
        for param, is_mandatory in cls.PARAMS.items():
            if is_mandatory and command_options.get(param) is None:
                raise SPSDKValueError(f"Mandatory parameter {param} is not defined")

        additional_params = list(
            set(key.lower() for key in command_options.keys())
            - set(key.lower() for key in cls.PARAMS.keys())
        )
        if additional_params:
            raise SPSDKValueError(f"Unexpected arguments {additional_params}")


class SecCsfHeader:
    """CSF header command."""

    PARAMS = {
        "Header_Version": True,
        "Header_HashAlgorithm": False,
        "Header_Engine": True,
        "Header_EngineConfiguration": True,
        "Header_CertificateFormat": False,
        "Header_SignatureFormat": True,
    }

    def __init__(self, cmd: Header) -> None:
        """CSF header class constructor.

        :param version: Header version
        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        :param hash_algorithm: Hash algorithm type
        :param certificate_format: Certificate format tag
        :param signature_format: Signature format
        :raises SPSDKValueError: Invalid combination of input parameters.
        :raises SPSDKValueError: Invalid signature format.
        """
        self.cmd = cmd
        self.version = self.cmd.param

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        header_params = config.commands.get_command_params(SecCommand.HEADER)

        signature_format = header_params.get("Header_SignatureFormat")
        if isinstance(signature_format, str) and signature_format.lower() != "cms":
            raise SPSDKValueError(f"Invalid signature format: {signature_format}")

        version = parse_version(header_params["Header_Version"])
        cmd = Header(SegTag.CSF.tag, param=version)
        return cls(cmd)


class SecCsfInstallSrk(SecCommandBase):
    """Install SRK command."""

    PARAMS = {"InstallSRK_Table": True, "InstallSRK_SourceIndex": True}

    def __init__(self, cmd: CmdInstallKey) -> None:
        """Install SRK class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.INSTALL_SRK)
        cls.check_config_section_params(command_params)
        source_index = int(command_params["InstallSRK_SourceIndex"])
        srk_table = load_binary(command_params["InstallSRK_Table"], search_paths=search_paths)

        cmd = CmdInstallKey(flags=EnumInsKey.CLR, hash_alg=EnumAlgorithm.SHA256, tgt_index=0)
        cmd.certificate_ref = SrkTable.parse(srk_table)
        cmd.source_index = source_index
        return cls(cmd)


class SecCsfInstallCsfk(SecCommandBase):
    """Install CSFK command."""

    PARAMS = {"InstallCSFK_File": True, "InstallCSFK_CertificateFormat": False}

    def __init__(self, cmd: CmdInstallKey) -> None:
        """Install CSF class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.INSTALL_CSFK)
        cls.check_config_section_params(command_params)

        header_params = config.commands.get_command_params(SecCommand.HEADER)
        version = parse_version(header_params["Header_Version"])

        csfk_certificate_bin = load_binary(
            command_params["InstallCSFK_File"], search_paths=search_paths
        )
        csfk_certificate = Certificate.parse(csfk_certificate_bin)

        cert_format = EnumCertFormat.from_label(
            command_params.get("InstallCSFK_CertificateFormat", "X509")
        )
        if cert_format == EnumCertFormat.SRK:
            raise SPSDKValueError(f"Invalid certificate format: {EnumCertFormat.SRK}")

        cmd = CmdInstallKey(flags=EnumInsKey.CSF, tgt_index=1, cert_fmt=cert_format)
        cmd.certificate_ref = CertificateImg(
            version=version, data=csfk_certificate.export(SPSDKEncoding.DER)
        )
        return cls(cmd)


class SecCsfAuthenticateCsf(SecCommandBase):
    """Authenticate CSFK command."""

    PARAMS = {
        "AuthenticateCsf_PrivateKeyFile": False,
        "AuthenticateCsf_SignProvider": False,
    }
    SIGNED_DATA_SIZE = 768

    def __init__(self, cmd: CmdAuthData) -> None:
        """Authenticate CSFK class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.AUTHENTICATE_CSF)
        cls.check_config_section_params(command_params)

        header_params = config.commands.get_command_params(SecCommand.HEADER)
        version = parse_version(header_params["Header_Version"])
        engine = EnumEngine.from_label(header_params["Header_Engine"])

        # determine the key path, depending on if HAB is configured in normal or fast authentication mode
        try:
            install_csfk_params = config.commands.get_command_params(SecCommand.INSTALL_CSFK)
            cert_path_param = "InstallCSFK_File"
        except SPSDKValueError:  # in case of Fast Authentication, look for the NOCAK command
            install_csfk_params = config.commands.get_command_params(SecCommand.INSTALL_NOCAK)
            cert_path_param = "InstallNOCAK_File"

        certificate = Certificate.parse(
            load_binary(install_csfk_params[cert_path_param], search_paths)
        )

        if command_params.get("AuthenticateCsf_KeyPass"):
            logger.warning(
                "AuthenticateCsf_KeyPass option is deprecated. The interactive prompt will be used instead."
            )

        try:
            signature_provider = get_hab_signature_provider(
                sp_cfg=command_params.get("AuthenticateCsf_SignProvider"),
                local_file_key=command_params.get("AuthenticateCsf_PrivateKeyFile"),
                search_paths=search_paths,
            )
        except SPSDKValueError as exc:
            # Keep the backwards compatibility with CSF tool and try to determine the path from certificate path
            private_key_path = determine_private_key_path(install_csfk_params[cert_path_param])
            if not private_key_path:
                raise SPSDKFileNotFoundError("Private key could not be determined.") from exc
            signature_provider = get_hab_signature_provider(
                local_file_key=private_key_path, search_paths=search_paths
            )

        cmd = CmdAuthData(certificate=certificate)
        if engine is not None:
            cmd.engine = engine

        cmd.signature_provider = signature_provider
        cmd.signature = Signature(version=version)
        return cls(cmd)


class SecCsfInstallKey(SecCommandBase):
    """Install key command."""

    PARAMS = {
        "InstallKey_File": True,
        "InstallKey_VerificationIndex": True,
        "InstallKey_TargetIndex": True,
    }

    def __init__(self, cmd: CmdInstallKey) -> None:
        """Install key class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.INSTALL_KEY)
        cls.check_config_section_params(command_params)

        header_params = config.commands.get_command_params(SecCommand.HEADER)
        version = parse_version(header_params["Header_Version"])

        certificate = Certificate.parse(
            load_binary(command_params["InstallKey_File"], search_paths)
        )
        source_index = int(command_params["InstallKey_VerificationIndex"])
        target_index = int(command_params["InstallKey_TargetIndex"])

        cmd = CmdInstallKey(
            cert_fmt=EnumCertFormat.X509, src_index=source_index, tgt_index=target_index
        )
        cmd.certificate_ref = CertificateImg(
            version=version, data=certificate.export(SPSDKEncoding.DER)
        )

        return cls(cmd)


class SecCsfAuthenticateData(SecCommandBase):
    """Authenticate data command."""

    KEY_IDX_AUT_DAT_FAST_AUTH = 0
    KEY_IDX_AUT_DAT_MIN = 2
    KEY_IDX_AUT_DAT_MAX = 5
    PARAMS = {
        "AuthenticateData_VerificationIndex": True,
        "AuthenticateData_Engine": True,
        "AuthenticateData_EngineConfiguration": True,
        "AuthenticateData_PrivateKeyFile": False,
        "AuthenticateData_SignProvider": False,
    }

    def __init__(self, cmd: CmdAuthData) -> None:
        """Authenticate data class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.AUTHENTICATE_DATA)
        cls.check_config_section_params(command_params)

        header_params = config.commands.get_command_params(SecCommand.HEADER)
        version = parse_version(header_params["Header_Version"])

        # determine the key path, depending on if HAB is configured in normal or fast authentication mode
        try:
            install_key_params = config.commands.get_command_params(SecCommand.INSTALL_KEY)
            cert_path_param = "InstallKey_File"
        except SPSDKValueError:  # in case of Fast Authentication, look for the NOCAK command
            install_key_params = config.commands.get_command_params(SecCommand.INSTALL_NOCAK)
            cert_path_param = "InstallNOCAK_File"

        certificate = Certificate.parse(
            load_binary(install_key_params[cert_path_param], search_paths)
        )

        engine = EnumEngine.from_label(command_params["AuthenticateData_Engine"])
        engine_config = int(command_params["AuthenticateData_EngineConfiguration"])
        if engine == EnumEngine.ANY and engine_config != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_config}")

        verification_index = int(command_params["AuthenticateData_VerificationIndex"])
        if verification_index != cls.KEY_IDX_AUT_DAT_FAST_AUTH and (
            verification_index < cls.KEY_IDX_AUT_DAT_MIN
            or verification_index > cls.KEY_IDX_AUT_DAT_MAX
        ):
            raise SPSDKValueError("Key index does not have valid value.")

        if command_params.get("AuthenticateData_KeyPass"):
            logger.warning(
                "AuthenticateData_KeyPass option is deprecated. The interactive prompt will be used instead."
            )
        try:
            signature_provider = get_hab_signature_provider(
                sp_cfg=command_params.get("AuthenticateData_SignProvider"),
                local_file_key=command_params.get("AuthenticateData_PrivateKeyFile"),
                search_paths=search_paths,
            )
        except SPSDKValueError as exc:
            # Keep the backwards compatibility with CSF tool and try to determine the path from certificate path
            private_key_path = determine_private_key_path(install_key_params[cert_path_param])
            if not private_key_path:
                raise SPSDKFileNotFoundError("Private key could not be determined.") from exc
            signature_provider = get_hab_signature_provider(
                local_file_key=private_key_path, search_paths=search_paths
            )

        cmd = CmdAuthData(
            engine=engine,
            engine_cfg=engine_config,
            key_index=verification_index,
            signature_provider=signature_provider,
        )
        cmd.certificate = certificate
        cmd.signature = Signature(version=version)
        return cls(cmd)


class SecSetEngine(SecCommandBase):
    """Set engine command."""

    PARAMS = {
        "SetEngine_HashAlgorithm": False,
        "SetEngine_Engine": False,
        "SetEngine_EngineConfiguration": False,
    }

    def __init__(self, cmd: CmdSet) -> None:
        """Set engine class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.SET_ENGINE)
        cls.check_config_section_params(command_params)

        hash_algorithm = command_params.get("SetEngine_HashAlgorithm")
        hash_algorithm = (
            EnumAlgorithm.from_label(hash_algorithm) if hash_algorithm is not None else None
        )

        engine = command_params.get("SetEngine_Engine")
        engine = EnumEngine.from_label(engine) if engine is not None else None

        engine_cfg = command_params.get("SetEngine_EngineConfiguration")
        engine_cfg = int(engine_cfg) if engine_cfg is not None else None

        cmd = CmdSet()
        if hash_algorithm is not None:
            cmd.hash_algorithm = hash_algorithm
        if engine is not None:
            cmd.engine = engine
        if engine_cfg is not None:
            cmd.engine_cfg = engine_cfg
        return cls(cmd)


class SecUnlock(SecCommandBase):
    """Unlock engine command."""

    PARAMS = {"Unlock_Engine": True, "Unlock_Features": False, "Unlock_UID": False}

    def __init__(self, cmd: CmdUnlockAbstract) -> None:
        """Unlock class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKKeyError: Unknown engine.
        """
        command_params = config.commands.get_command_params(SecCommand.UNLOCK)
        cls.check_config_section_params(command_params)

        unlock_engine = EnumEngine.from_label(command_params["Unlock_Engine"])
        if unlock_engine not in UNLOCK_COMMANDS_MAPPING:
            raise SPSDKKeyError(f"Unknown engine {unlock_engine}")
        klass = UNLOCK_COMMANDS_MAPPING[unlock_engine]
        kwargs = {}
        unlock_features: str = command_params.get("Unlock_Features")
        if unlock_features is not None:
            # features may be defined as single feature of coma separated list of features
            features = [
                klass.FEATURES.from_label(feature.strip()).tag
                for feature in unlock_features.split(",")
            ]
            kwargs["features"] = cls.calc_features_value(features)
        unlock_uid: str = command_params.get("Unlock_UID")
        if unlock_uid:
            uids = [int(uid.strip(), 0) for uid in unlock_uid.split(",")]
            kwargs["uid"] = cls.calc_uid(uids)
        cmd = klass(**kwargs)
        return cls(cmd)

    @classmethod
    def calc_features_value(cls, features: list[int]) -> int:
        """Calculate the unlock features value."""
        result = 0
        for feature in features:
            result |= feature
        return result

    @classmethod
    def calc_uid(cls, uid_values: list[int]) -> int:
        """Calculate the unlock uid value."""
        result = 0
        for uid in uid_values:
            result = (result << 8) | uid
        return result


class SecInstallSecretKey(SecCommandBase):
    """Set engine command."""

    PARAMS = {
        "SecretKey_Name": True,
        "SecretKey_Length": False,
        "SecretKey_VerifyIndex": False,
        "SecretKey_TargetIndex": True,
        "SecretKey_ReuseDek": False,
    }

    def __init__(self, cmd: CmdInstallKey) -> None:
        """Set install secret key class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.INSTALL_SECRET_KEY)
        cls.check_config_section_params(command_params)
        location = cls.calculate_location(config)

        source_index = int(command_params.get("SecretKey_VerifyIndex", 0))
        if source_index > 3:
            raise SPSDKValueError("Source index must be equal or lower than 3")
        target_index = int(command_params["SecretKey_TargetIndex"])

        cmd = CmdInstallKey(
            flags=EnumInsKey.ABS,
            cert_fmt=EnumCertFormat.BLOB,
            hash_alg=EnumAlgorithm.ANY,
            location=location,
        )
        cmd.source_index = source_index
        cmd.target_index = target_index
        return cls(cmd)

    @staticmethod
    def calculate_location(config: HabConfig) -> int:
        """Get CSF segment location."""
        image_len = config.options.get_initial_load_size() + len(config.app_image)
        # align to 0x1000
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000

        location = config.options.start_address + csf_offset + 0x2000
        return location


class SecDecryptData(SecCommandBase):
    """Set engine command."""

    PARAMS = {
        "Decrypt_Engine": False,
        "Decrypt_EngineConfiguration": False,
        "Decrypt_VerifyIndex": True,
        "Decrypt_MacBytes": False,
        "Decrypt_Nonce": False,
    }

    def __init__(
        self,
        cmd: CmdAuthData,
    ) -> None:
        """Decrypt data class constructor."""
        super().__init__(cmd)

    @classmethod
    def load_from_config(cls, config: HabConfig, search_paths: Optional[list[str]] = None) -> Self:
        """Load configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        command_params = config.commands.get_command_params(SecCommand.DECRYPT_DATA)
        cls.check_config_section_params(command_params)

        engine = command_params.get("Decrypt_Engine", "ANY")
        engine = EnumEngine.from_label(engine)

        engine_cfg = int(command_params.get("Decrypt_EngineConfiguration", 0))

        if engine == EnumEngine.ANY and engine_cfg != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_cfg}")

        verification_index = int(command_params["Decrypt_VerifyIndex"])
        if verification_index >= 6:
            raise SPSDKValueError("Verification index must be lower than 6.")

        cmd = CmdAuthData(flags=EnumAuthDat.CLR, sig_format=EnumCertFormat.AEAD)
        cmd.engine = engine
        cmd.engine_cfg = engine_cfg
        cmd.key_index = verification_index

        return cls(cmd)


COMMANDS_MAPPING: Mapping[SecCommand, Type[SecCommandBase]] = {
    SecCommand.INSTALL_SRK: SecCsfInstallSrk,
    SecCommand.INSTALL_CSFK: SecCsfInstallCsfk,
    SecCommand.AUTHENTICATE_CSF: SecCsfAuthenticateCsf,
    SecCommand.INSTALL_KEY: SecCsfInstallKey,
    SecCommand.AUTHENTICATE_DATA: SecCsfAuthenticateData,
    SecCommand.INSTALL_SECRET_KEY: SecInstallSecretKey,
    SecCommand.DECRYPT_DATA: SecDecryptData,
    SecCommand.SET_ENGINE: SecSetEngine,
    SecCommand.UNLOCK: SecUnlock,
}

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
import os
from typing import Any, Iterable, Optional, Type, Union

from typing_extensions import Self

from spsdk.crypto.keys import PublicKey, PublicKeyEcc
from spsdk.crypto.signature_provider import get_signature_provider
from spsdk.crypto.utils import extract_public_key, extract_public_key_from_data, get_matching_key_id
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import find_file, load_binary, load_configuration, value_to_int

logger = logging.getLogger(__name__)


class CertBlock(FeatureBaseClass):
    """Certificate Block base class for secure boot authentication.

    This class provides a unified interface for managing different versions of
    certificate blocks used in NXP MCU secure boot processes. It handles
    certificate validation, root key management, and family-specific
    implementations across the SPSDK-supported device portfolio.

    :cvar FEATURE: Database manager feature identifier for certificate blocks.
    """

    FEATURE = DatabaseManager.CERT_BLOCK

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize certificate block with family revision.

        :param family: Family revision specification for the certificate block.
        """
        self.family = family

    @classmethod
    def get_cert_block_class(cls, family: FamilyRevision) -> Type["CertBlock"]:
        """Get certification block class by family name.

        Retrieves the appropriate certification block class that supports the specified
        chip family from all available certification block classes.

        :param family: Chip family to find certification block class for.
        :raises SPSDKError: No certification block class found for given family.
        :return: Certification block class that supports the specified family.
        """
        for cert_block_class in cls.get_cert_block_classes():
            if family in cert_block_class.get_supported_families():
                return cert_block_class
        raise SPSDKError(f"Family '{family}' is not supported in any certification block.")

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method validates the provided configuration against basic schemas, extracts
        the family information, and returns the appropriate validation schemas for the
        specific certificate block class.

        :param config: Valid configuration object containing family and other settings.
        :return: List of validation schema dictionaries for the certificate block.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls.get_cert_block_class(family).get_validation_schemas(family)

    @classmethod
    def get_all_supported_families(cls) -> list[FamilyRevision]:
        """Get supported families for all certification blocks.

        This class method aggregates and returns all supported family revisions
        from all available certification block types in the SPSDK library.

        :return: List of all supported family revisions across all cert block types.
        """
        from spsdk.image.cert_block.cert_block_ahab import CertBlockAhab
        from spsdk.image.cert_block.cert_block_v1 import CertBlockV1
        from spsdk.image.cert_block.cert_block_v21 import CertBlockV21
        from spsdk.image.cert_block.cert_block_vx import CertBlockVx

        return (
            CertBlockV1.get_supported_families()
            + CertBlockV21.get_supported_families()
            + CertBlockVx.get_supported_families()
            + CertBlockAhab.get_supported_families()
        )

    @classmethod
    def get_cert_block_classes(cls) -> list[Type["CertBlock"]]:
        """Get list of all certificate block classes.

        This method returns all subclasses of CertBlock that are currently loaded
        in the system.

        :return: List of all certificate block class types.
        """
        from spsdk.image.cert_block.cert_block_ahab import CertBlockAhab
        from spsdk.image.cert_block.cert_block_v1 import CertBlockV1
        from spsdk.image.cert_block.cert_block_v21 import CertBlockV21
        from spsdk.image.cert_block.cert_block_vx import CertBlockVx

        return [CertBlockV1, CertBlockV21, CertBlockVx, CertBlockAhab]

    @property
    def rkth(self) -> bytes:
        """Get Root Key Table Hash.

        Returns a 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys.

        :return: Root Key Table Hash as bytes.
        """
        return bytes()

    @classmethod
    def find_main_cert_index(cls, config: Config) -> Optional[int]:
        """Find the index of the main certificate that matches the private key.

        Searches through all root certificates in the configuration to find the one
        whose public key corresponds to the configured signature provider's private key.

        :param config: Configuration object containing certificate and signature provider settings.
        :return: Index of the matching certificate, or None if no match is found.
        """
        try:
            signature_provider = get_signature_provider(config)
        except SPSDKError as exc:
            logger.debug(f"A signature provider could not be created: {exc}")
            return None
        root_certificates = find_root_certificates(config)
        public_keys = []
        for root_crt_file in root_certificates:
            try:
                public_key = extract_public_key(root_crt_file, search_paths=config.search_paths)
                public_keys.append(public_key)
            except SPSDKError:
                continue
        try:
            idx = get_matching_key_id(public_keys, signature_provider)
            return idx
        except (SPSDKValueError, SPSDKUnsupportedOperation) as exc:
            logger.debug(f"Main cert index could not be found: {exc}")
            return None

    @classmethod
    def get_main_cert_index(cls, config: Config) -> int:
        """Gets main certificate index from configuration.

        The method retrieves the main root certificate ID from the configuration and validates
        it against the found certificate index. If no root certificate ID is specified in
        the configuration, it attempts to find one automatically.

        :param config: Input standard configuration containing certificate settings.
        :return: Certificate index of the main certificate.
        :raises SPSDKError: If invalid configuration is provided.
        :raises SPSDKError: If correct certificate could not be identified.
        :raises SPSDKValueError: If certificate is not of correct type.
        """
        root_cert_id = config.get("mainRootCertId")
        found_cert_id = cls.find_main_cert_index(config=config)
        if root_cert_id is None:
            if found_cert_id is not None:
                return found_cert_id
            raise SPSDKError("Certificate could not be found")
        # root_cert_id may be 0 which is falsy value, therefore 'or' cannot be used
        cert_id = value_to_int(root_cert_id)
        if found_cert_id is not None and found_cert_id != cert_id:
            logger.warning("Defined certificate does not match the private key.")
        return cert_id

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("Unknown")) -> Self:
        """Parse Certification block from binary file.

        :param data: Binary data of certification block
        :param family: Chip family
        :raises SPSDKNotImplementedError: The method is not implemented in sub class
        """
        raise SPSDKNotImplementedError()

    def get_root_public_key(self) -> PublicKey:
        """Get the root public key from the certificate block.

        :raises SPSDKNotImplementedError: When called on the base class (this method must be
            implemented by subclasses).
        """
        raise SPSDKNotImplementedError()


def convert_to_ecc_key(key: Union[PublicKeyEcc, bytes]) -> PublicKeyEcc:
    """Convert key into ECC key instance.

    Converts various key formats (bytes or existing ECC key) into a standardized
    PublicKeyEcc instance for consistent handling within the certificate block.

    :param key: Input key data as either existing ECC key instance or raw bytes.
    :raises SPSDKError: When the provided key is not an ECC key type.
    :return: Standardized ECC public key instance.
    """
    if isinstance(key, PublicKeyEcc):
        return key
    try:
        pub_key = extract_public_key_from_data(key)
        if not isinstance(pub_key, PublicKeyEcc):
            raise SPSDKError("Not ECC key")
        return pub_key
    except Exception:
        pass
    # Just recreate public key from the parsed data
    return PublicKeyEcc.parse(key)


def find_root_certificates(config: dict[str, Any]) -> list[str]:
    """Find all root certificates in configuration.

    Searches for root certificate file paths in the configuration dictionary by looking for
    keys matching the pattern 'rootCertificateXFile' where X is 0-3. Validates that there
    are no gaps in the certificate numbering sequence.

    :param config: Configuration dictionary containing certificate file paths.
    :raises SPSDKError: If there are gaps in rootCertificateXFile definition sequence.
    :return: List of root certificate file paths found in configuration.
    """
    root_certificates_loaded: list[Optional[str]] = [
        config.get(f"rootCertificate{idx}File") for idx in range(4)
    ]
    # filter out None and empty values
    root_certificates = list(filter(None, root_certificates_loaded))
    for org, filtered in zip(root_certificates_loaded, root_certificates):
        if org != filtered:
            raise SPSDKError("There are gaps in rootCertificateXFile definition")
    return root_certificates


def get_keys_or_rotkh_from_certblock_config(
    rot: Optional[str], family: Optional[FamilyRevision]
) -> tuple[Optional[Iterable[str]], Optional[bytes]]:
    """Get keys or ROTKH value from ROT config.

    ROT config might be cert block config or MBI config.
    There are four cases how cert block might be configured:
    1. MBI with certBlock property pointing to YAML file
    2. MBI with certBlock property pointing to BIN file
    3. YAML configuration of cert block
    4. Binary cert block

    :param rot: Path to ROT configuration (MBI or cert block) or path to binary cert block.
    :param family: MCU family.
    :raises SPSDKError: In case the ROTKH or keys cannot be parsed.
    :return: Tuple containing root of trust (list of paths to keys) or ROTKH in case of binary
        cert block.
    """
    root_of_trust = None
    rotkh = None
    if rot and family:
        logger.info("Loading configuration from cert block/MBI file...")
        config_dir = os.path.dirname(rot)
        try:
            config_data = load_configuration(rot, search_paths=[config_dir])
            if "certBlock" in config_data:
                try:
                    config_data = load_configuration(
                        config_data["certBlock"], search_paths=[config_dir]
                    )
                except SPSDKError:
                    cert_block = load_binary(config_data["certBlock"], search_paths=[config_dir])
                    parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                    rotkh = parsed_cert_block.rkth
            public_keys = find_root_certificates(config_data)
            root_of_trust = tuple((find_file(x, search_paths=[config_dir]) for x in public_keys))
        except SPSDKError:
            logger.debug("Parsing ROT from config did not succeed, trying it as binary")
            try:
                cert_block = load_binary(rot, search_paths=[config_dir])
                parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                rotkh = parsed_cert_block.rkth
            except SPSDKError as e:
                raise SPSDKError(f"Parsing of binary cert block failed with {e}") from e

    return root_of_trust, rotkh

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK WPC target model for certificate chain injection.

This module provides the WPCTargetModel class that represents a target device
for Wireless Power Consortium (WPC) certificate chain injection operations.
"""

import logging
import os
from typing import Any

from typing_extensions import Self

from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision
from spsdk.wpc.wpc import SPSDKWPCError, WPCCertChain, WPCIdType, WPCTarget

logger = logging.getLogger(__name__)


class WPCTargetModel(WPCTarget):
    """WPC Target Software Model implementation.

    This class provides a software-based model for WPC (Wireless Power Consortium)
    targets, enabling simulation and testing of WPC operations without physical
    hardware. It manages model configuration, cryptographic operations, and
    certificate handling for WPC compliance testing.

    :cvar identifier: Target model type identifier set to "model".
    """

    identifier = "model"

    def __init__(self, family: FamilyRevision, model_dir: str) -> None:
        """Initialize SW Model for WPC target.

        :param family: Target family name and revision information.
        :param model_dir: Directory path containing model configuration files.
        :raises SPSDKError: If config.yaml file is not found in model directory.
        :raises SPSDKError: If private key file cannot be loaded from configuration.
        """
        super().__init__(family=family)
        self.model_dir = model_dir
        self.config = Config.create_from_file(os.path.join(self.model_dir, "config.yaml"))
        self.private_key = PrivateKeyEcc.load(self.config.get_input_file_name("prk_key"))

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create instance of this class based on configuration data.

        The method extracts model directory path from configuration and initializes the class
        with family revision data and model directory. Uses cls.CONFIG_PARAMS to limit the
        scope of configuration data.

        :param config: Configuration data containing family and model directory information.
        :return: Instance of this class initialized with configuration data.
        """
        model_dir = config.get_output_file_name(f"{cls.CONFIG_PARAMS}/model_dir")
        return cls(family=FamilyRevision.load_from_config(config), model_dir=model_dir)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get JSON schema for validating configuration data.

        Retrieves the WPC model validation schema from the database manager
        to validate configuration data structure and content.

        :param family: Family revision information for schema selection.
        :return: List containing the model validation schema dictionary.
        """
        schema = get_schema_file(DatabaseManager.WPC)
        return [schema["model"]]

    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target.

        Generates the WPC ID based on the configured ID type. For COMPUTED_CSR type,
        it combines UUID, public key, and signature data.

        :raises NotImplementedError: When WPC ID type is not COMPUTED_CSR.
        :return: The lower-level WPC ID as bytes containing UUID, public key and signature.
        """
        logger.info("Reading low level WPC ID")
        if self.wpc_id_type == WPCIdType.COMPUTED_CSR:
            puk = self.private_key.get_public_key()
            data = bytes.fromhex(self.config["uuid"][:16])
            data += puk.export()
            data += self.private_key.sign(data=data)
            return data
        raise NotImplementedError()

    def wpc_insert_cert(self, cert_chain: WPCCertChain) -> bool:
        """Insert the WPC Certificate Chain into the target.

        Validates the certificate chain against the target's private key and RSID configuration,
        then saves all certificate components to their respective file paths in the model directory.

        :param cert_chain: WPC certificate chain containing product unit, manufacturer and root certificates.
        :raises SPSDKWPCError: When product unit certificate contains incorrect public key or RSID.
        :return: True if certificate chain was successfully inserted.
        """
        logger.info("Inserting WPC certificate")
        puk = cert_chain.product_unit_cert.get_public_key()
        if self.private_key.get_public_key() != puk:
            raise SPSDKWPCError("Product unit certificate contains incorrect public key")
        rsid = self.config.get("rsid")
        if rsid and bytes.fromhex(rsid) != cert_chain.get_rsid():
            raise SPSDKWPCError("Product unit certificate contains incorrect RSID")
        cert_chain.save(
            chain_path=os.path.join(self.model_dir, self.config["cert_chain"]),
            root_hash_path=os.path.join(self.model_dir, self.config["ca_root_hash"]),
            manufacturer_path=os.path.join(self.model_dir, self.config["manufacturer_cert"]),
            product_unit_path=os.path.join(self.model_dir, self.config["product_unit_cert"]),
        )
        return True

    def sign(self, data: bytes) -> bytes:
        """Sign data using the target's private key.

        This method signs the provided data using the target's private key, typically
        used for signing Certificate Signing Request (CSR) To-Be-Signed (TBS) data.

        :param data: The data to be signed.
        :return: The signature bytes generated by the private key.
        """
        logger.info("Signing CSR-TBS data")
        return self.private_key.sign(data=data)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Model of a target for injecting WPC certificate chain."""

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
    """SW Model representing a WPC target."""

    identifier = "model"

    def __init__(self, family: FamilyRevision, model_dir: str) -> None:
        """Initialize SW Model for WPC target.

        :param family: Target family name
        :param model_dir: Directory with model files
        """
        super().__init__(family=family)
        self.model_dir = model_dir
        self.config = Config.create_from_file(os.path.join(self.model_dir, "config.yaml"))
        self.private_key = PrivateKeyEcc.load(self.config.get_input_file_name("prk_key"))

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config.
        To limit the scope of data, set cls.CONFIG_PARAMS (key in config data).

        :param config: Configuration data
        :return: Instance of this class
        """
        model_dir = config.get_output_file_name(f"{cls.CONFIG_PARAMS}/model_dir")
        return cls(family=FamilyRevision.load_from_config(config), model_dir=model_dir)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get JSON schema for validating configuration data."""
        schema = get_schema_file(DatabaseManager.WPC)
        return [schema["model"]]

    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target."""
        logger.info("Reading low level WPC ID")
        if self.wpc_id_type == WPCIdType.COMPUTED_CSR:
            puk = self.private_key.get_public_key()
            data = bytes.fromhex(self.config["uuid"][:16])
            data += puk.export()
            data += self.private_key.sign(data=data)
            return data
        raise NotImplementedError()

    def wpc_insert_cert(self, cert_chain: WPCCertChain) -> bool:
        """Insert the WPC Certificate Chain into the target."""
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
        """Sign data by the target."""
        logger.info("Signing CSR-TBS data")
        return self.private_key.sign(data=data)

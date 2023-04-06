#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for parsing original elf2sb configuration files."""

from typing import List, Optional

from spsdk import SPSDKError
from spsdk.image import MBIMG_SCH_FILE
from spsdk.utils.crypto import CRYPTO_SCH_FILE
from spsdk.utils.crypto.cert_blocks import find_root_certificates, get_main_cert_index
from spsdk.utils.schema_validator import ValidationSchemas, check_config


class RootOfTrustInfo:  # pylint: disable=too-few-public-methods
    """Filters out Root Of Trust information given to elf2sb application."""

    def __init__(self, data: dict, search_paths: Optional[List[str]] = None) -> None:
        """Create object out of data loaded from elf2sb configuration file.

        :param data: Configuration data.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: If not valid configuration is detected.
        """
        # Validate input
        sch_cfg = ValidationSchemas.get_schema_file(MBIMG_SCH_FILE)
        sch_crypto_cfg = ValidationSchemas.get_schema_file(CRYPTO_SCH_FILE)
        val_schemas = [sch_cfg[x] for x in ["cert_prv_key", "signing_root_prv_key"]]
        val_schemas.append(sch_crypto_cfg["certificate_root_keys"])
        check_config(data, val_schemas, search_paths=search_paths)

        self.config_data = data
        self.private_key = data.get("mainCertPrivateKeyFile") or data.get(
            "mainRootCertPrivateKeyFile"
        )
        if not self.private_key:
            raise SPSDKError(
                "Private key not specified (mainCertPrivateKeyFile or mainRootCertPrivateKeyFile)"
            )
        self.public_keys = find_root_certificates(data)
        data_main_cert_index = get_main_cert_index(data, search_paths=search_paths)
        root_cert_file = data.get(f"rootCertificate{data_main_cert_index}File")
        if not root_cert_file:
            raise SPSDKError(f"rootCertificate{data_main_cert_index}File doesn't exist")
        self.public_key_index = self.public_keys.index(root_cert_file)

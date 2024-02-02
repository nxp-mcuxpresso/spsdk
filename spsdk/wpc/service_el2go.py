#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""WPC certificate service using EL2GO."""

import base64
import json
import logging
import os
from typing import List, Optional, Union

import requests
from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import find_file

from .utils import SPSDKError, SPSDKWPCError, WPCCertChain, WPCCertificateService, WPCIdType

logger = logging.getLogger(__name__)


class WPCCertificateServiceEL2GO(WPCCertificateService):
    """EdgeLock2GO adapter providing WPC Certificate Chain."""

    NAME = "el2go"

    def __init__(
        self,
        url: str,
        qi_id: Union[str, int],
        api_key: str,
        correlation_id: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        """Initialize the EL2GO adapter.

        :param url: URL to EL2GO WPC service
        :param qi_id: Customer's Qi ID
        :param api_key: Customer's EL2GO REST API access token
        :param correlation_id: Customer's EL2GO Correlation ID, defaults to None
        :param timeout: REST API request timeout in seconds
        """
        self.base_url = url
        self.qi_id = int(qi_id)
        self.api_key = api_key
        self.correlation_id = correlation_id
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "EL2G-API-Key": self.api_key,
        }
        if self.correlation_id:
            self.headers["EL2G-Correlation-ID"] = self.correlation_id

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        schema = get_schema_file(DatabaseManager.WPC)
        return schema["el2go"]

    @classmethod
    def from_config(cls, config_data: dict, search_paths: Optional[List[str]] = None) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config_data.
        To limit the scope of data, set cls.CONFIG_PARAMS (key in config data).

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        :return: Instance of this class
        """
        if cls.CONFIG_PARAMS in config_data:
            config_data = config_data[cls.CONFIG_PARAMS]
        cls.validate_config(config_data=config_data, search_paths=search_paths)
        api_key = config_data.pop("api_key")
        # value of api_key may contain '~' for user home or '$' for environment variable
        api_key = os.path.expanduser(os.path.expandvars(api_key))
        try:
            api_key_file = find_file(file_path=api_key, search_paths=search_paths)
            with open(api_key_file) as f:
                api_key = f.readline().strip()
        except SPSDKError:
            pass
        return cls(api_key=api_key, **config_data)

    def _handle_request(self, method: str, url: str, payload: dict) -> dict:
        final_url = f"{self.base_url}{url}"
        logger.info(f"Handling url: {final_url}")
        response = requests.request(
            method=method, url=final_url, headers=self.headers, json=payload, timeout=self.timeout
        )
        logger.debug(response)
        json_response = response.json()
        if response.status_code >= 400:
            raise SPSDKWPCError(
                f"Error during '{url}': {response.reason} ({response.status_code})\n"
                f"Service response:\n{json.dumps(json_response, indent=2)}"
            )
        logger.info(f"Service response:\n{json.dumps(json_response, indent=2)}")
        return json_response

    def get_wpc_cert(
        self, wpc_id_data: str, wpc_id_type: Optional[WPCIdType] = None
    ) -> WPCCertChain:
        """Obtain the WPC Certificate Chain."""
        url = f"/api/v1/wpc/product-unit-certificate/{self.qi_id:06}/request-puc"
        data = {
            "pucRequestType": {
                "requestType": "CSR",
                "requests": [
                    {"csr": base64.b64encode(wpc_id_data.encode("utf-8")).decode("utf-8")}
                ],
            }
        }
        response = self._handle_request(method="POST", url=url, payload=data)
        root_ca_hash = bytes.fromhex(response["pucType"]["rootCaHash"].replace(":", ""))
        manufacturer_cert = Certificate.parse(
            response["pucType"]["productManufacturingCertificate"].encode("utf-8"),
        )
        product_unit_cert = Certificate.parse(
            response["pucType"]["certificate"].encode("utf-8"),
        )
        return WPCCertChain(
            root_ca_hash=root_ca_hash,
            manufacturer_cert=manufacturer_cert,
            product_unit_cert=product_unit_cert,
        )

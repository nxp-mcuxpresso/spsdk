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
import uuid
from typing import Optional, Union

import requests
from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import load_secret
from spsdk.wpc.utils import SPSDKWPCError, WPCCertChain, WPCCertificateService, WPCIdType

logger = logging.getLogger(__name__)


class EL2GoWPCError(SPSDKWPCError):
    """Error thrown by EL2Go during WPC operation."""

    def __init__(self, response: requests.Response, desc: Optional[str] = None) -> None:
        """Initialize the EL2GO WPC error.

        :param response: Response from the EL2GO
        :param desc: Custom description of the error, defaults to None
        """
        super().__init__(desc)
        self.response = response


class WPCCertificateServiceEL2GO(WPCCertificateService):
    """EdgeLock2GO adapter providing WPC Certificate Chain."""

    identifier = "el2go"

    def __init__(
        self,
        url: str,
        qi_id: Union[str, int],
        api_key: str,
        family: str,
        timeout: int = 60,
    ) -> None:
        """Initialize the EL2GO adapter.

        :param url: URL to EL2GO WPC service
        :param qi_id: Customer's Qi ID
        :param api_key: Customer's EL2GO REST API access token
        :param correlation_id: Customer's EL2GO Correlation ID, defaults to None
        :param timeout: REST API request timeout in seconds
        """
        super().__init__(family=family)
        self.base_url = url
        self.qi_id = int(qi_id)
        self.api_key = api_key
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "EL2G-API-Key": self.api_key,
        }

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        schema = get_schema_file(DatabaseManager.WPC)
        return schema["el2go"]

    @classmethod
    def from_config(cls, config_data: dict, search_paths: Optional[list[str]] = None) -> Self:
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
        api_key = load_secret(api_key, search_paths=search_paths)
        return cls(api_key=api_key, **config_data)

    def _handle_request(self, method: str, url: str, payload: dict) -> dict:
        final_url = f"{self.base_url}{url}"
        logger.info(f"Handling url: {final_url}")
        correlation_id = str(uuid.uuid4())
        logger.info(f"EL2G-Correlation-ID: {correlation_id}")
        self.headers["EL2G-Correlation-ID"] = correlation_id
        logger.debug(f"Request body:\n{json.dumps(payload, indent=2)}")
        response = requests.request(
            method=method, url=final_url, headers=self.headers, json=payload, timeout=self.timeout
        )
        logger.debug(response)
        json_response = response.json()
        if response.status_code >= 400:
            raise EL2GoWPCError(
                response,
                f"Error during '{url}': {response.reason} ({response.status_code})\n"
                f"Service response:\n{json.dumps(json_response, indent=2)}\n"
                f"EL2G-Correlation-ID: {correlation_id}",
            )
        logger.info(f"Service response:\n{json.dumps(json_response, indent=2)}")
        return json_response

    def get_wpc_cert(self, wpc_id_data: bytes) -> WPCCertChain:
        """Obtain the WPC Certificate Chain."""
        url = f"/api/v1/wpc/product-unit-certificate/{self.qi_id:06}/request-puc"
        if self.wpc_id_type == WPCIdType.COMPUTED_CSR:
            data = {
                "pucRequestType": {
                    "requestType": "CSR",
                    "requests": [
                        {"csr": base64.b64encode(wpc_id_data).decode("utf-8")},
                    ],
                }
            }
        elif self.wpc_id_type == WPCIdType.RSID:
            # wpc_id_data should be in the form of TP-Data-Container v2
            # however there's a bug in HW, so we fetch RSID directly (hoping no one will change the offsets)
            rsid = wpc_id_data[16:25]
            device_id = rsid.hex()
            data = {
                "pucRequestType": {
                    "requestType": "PUBLIC_KEY",
                    "deviceIds": [device_id],
                },
            }
        else:
            raise SPSDKWPCError(f"WPC ID type: '{self.wpc_id_type.value}' is not supported")

        try:
            response = self._handle_request(method="POST", url=url, payload=data)
        except EL2GoWPCError as e:
            # error 422 means that the certificate already exists
            if e.response.status_code == 422 and self.wpc_id_type == WPCIdType.RSID:
                logger.info(e.description)
                logger.warning("Requested WPC Certificate already exists. Attempting download")

                # This is just a temporary workaround until a proper API is delivered.
                import re

                try:
                    response_json = e.response.json()
                    desc = response_json["fieldErrors"][-1]["description"]
                except (KeyError, json.JSONDecodeError):
                    raise SPSDKWPCError("Response format is invalid") from e

                pattern = r".*PUC ID: (?P<puc_id>\d+).*"
                m = re.match(pattern=pattern, string=desc)
                if not m:
                    raise SPSDKWPCError("Unable to parse PUC ID from error description") from e
                puc_id = int(m.group("puc_id"))
                url = f"/api/v1/wpc/product-unit-certificate/{puc_id}"
                response = self._handle_request(method="GET", url=url, payload={})
            else:
                raise
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

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO client for secure provisioning services.

This module provides a unified client interface for communicating with NXP's
EL2GO (EdgeLock 2GO) secure provisioning service. It handles API communication,
response processing, and cleanup operations for device provisioning workflows.
"""

import json
import logging
import uuid
from enum import Enum
from typing import Optional

from typing_extensions import Self

from spsdk.utils.config import Config
from spsdk.utils.http_client import HTTPClientBase, SPSDKHTTPClientError
from spsdk.utils.misc import find_file

logger = logging.getLogger(__name__)


class CleanMethod(str, Enum):
    """EL2GO cleanup method enumeration.

    This enumeration defines the available cleanup methods that can be used
    during EL2GO provisioning operations to clean up device state.
    """

    ERASE_CMPA = "erase_cmpa"
    NONE = "none"


class EL2GOApiResponse:
    """EdgeLock 2GO API Response.

    This class represents a response from the EdgeLock 2GO API service,
    encapsulating the HTTP status code and JSON response body for further
    processing and validation.
    """

    def __init__(self, status_code: int, json_body: dict) -> None:
        """Initialize EdgeLock 2GO API Response.

        :param status_code: HTTP status code of the API response.
        :param json_body: JSON response body containing the API response data.
        """
        self.status_code = status_code
        self.json_body = json_body


class EL2GOClient(HTTPClientBase):
    """HTTP client for EdgeLock 2GO secure provisioning service.

    This class provides a specialized HTTP client for communicating with NXP's
    EdgeLock 2GO cloud service, handling authentication, request correlation,
    and API-specific communication patterns for secure device provisioning.

    :cvar api_version: EdgeLock 2GO API version supported by this client.
    """

    api_version = "1.0.0"

    def __init__(
        self,
        api_key: str,
        url: str = "https://api.edgelock2go.com",
        timeout: int = 60,
        raise_exceptions: bool = True,
        **kwargs: str,
    ) -> None:
        """Initialize EL2GO client for TP.

        :param api_key: User EL2GO API key
        :param url: EL2GO API server address, defaults to "https://api.edgelock2go.com"
        :param timeout: Timeout for each API call, defaults to 60
        :param raise_exceptions: Raise exception if response status code is >=400, defaults to True
        :param kwargs: Additional keyword arguments passed to parent class
        """
        super().__init__(
            host=url,
            port=433,
            use_ssl=True,
            url_prefix=None,
            timeout=timeout,
            raise_exceptions=raise_exceptions,
            **kwargs,
        )

        self.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "EL2G-API-Key": api_key,
            }
        )
        self.correlation_id = ""

    def _handle_el2go_request(
        self,
        method: HTTPClientBase.Method,
        url: str,
        param_data: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> EL2GOApiResponse:
        """Handle EL2GO API request with correlation ID tracking and error handling.

        This method extends the base HTTP client functionality by adding EL2GO-specific
        correlation ID headers for request tracking and provides specialized response
        handling for different EL2GO API endpoints.

        :param method: HTTP method to use for the request.
        :param url: Target URL for the API request.
        :param param_data: Optional URL parameters to include in the request.
        :param json_data: Optional JSON data to send in the request body.
        :raises SPSDKHTTPClientError: When API response is not OK and raise_exceptions
            is enabled.
        :return: EL2GO API response object containing status code and JSON body.
        """
        self.correlation_id = str(uuid.uuid4())
        logger.info(f"EL2G-Correlation-ID: {self.correlation_id}")
        self.headers["EL2G-Correlation-ID"] = self.correlation_id
        api_response = super()._handle_request(
            method=method, url=url, param_data=param_data, json_data=json_data
        )

        if not api_response.ok:
            logger.info(f"Response status is not OK: {api_response}")
            if self.raise_exceptions:
                try:
                    extra_data = api_response.json()
                except json.JSONDecodeError as json_decode_error:
                    extra_data = {}
                    raise SPSDKHTTPClientError(
                        api_response.status_code,
                        extra_data,
                        f"Error {api_response.status_code} ({api_response.reason}) occurred when calling {url}\n"
                        f"Extra response data: {extra_data or 'N/A'}",
                    ) from json_decode_error
            response = EL2GOApiResponse(
                status_code=api_response.status_code, json_body=api_response.json()
            )
            return response

        if api_response.url.endswith("register-devices"):
            return EL2GOApiResponse(
                status_code=api_response.status_code, json_body={"jobId": api_response.text}
            )
        if api_response.text == "":
            return EL2GOApiResponse(status_code=api_response.status_code, json_body={})

        return EL2GOApiResponse(status_code=api_response.status_code, json_body=api_response.json())

    @classmethod
    def load_from_config(cls, config_data: Config) -> Self:
        """Create instance of this class based on configuration data.

        The method validates configuration data, extracts API key and file paths, handles backward
        compatibility for bootloader path parameters, and initializes the class with processed
        configuration values.

        :param config_data: Configuration data containing API key, file paths, and other settings
        :return: Instance of this class initialized with the configuration data
        """
        cls.validate_config(config_data=config_data)
        api_key = config_data.load_secret("api_key")
        config_data.pop("api_key")
        prov_fw_path = config_data.pop("prov_fw_path", None)
        if prov_fw_path:
            prov_fw_path = find_file(file_path=prov_fw_path, search_paths=config_data.search_paths)

        config_data["family"] = config_data.get_family()
        config_data.pop("revision", "")

        # Handle both old and new bootloader path names for backward compatibility
        imx_bootloader_path = config_data.pop("imx_bootloader_path", None)
        uboot_path = config_data.pop("uboot_path", None)

        # Prioritize new name, fall back to old name
        bootloader_path = imx_bootloader_path or uboot_path

        if bootloader_path:
            bootloader_path = find_file(
                file_path=bootloader_path, search_paths=config_data.search_paths
            )
            # Pass as the new parameter name to maintain consistency
            config_data["imx_bootloader_path"] = bootloader_path

        # Log deprecation warning if old name is used
        if uboot_path and not imx_bootloader_path:
            logger.warning(
                "Configuration parameter 'uboot_path' is deprecated. "
                "Please use 'imx_bootloader_path' instead."
            )

        return cls(api_key=api_key, prov_fw_path=prov_fw_path, **config_data)

    @classmethod
    def validate_config(cls, config_data: Config) -> None:
        """Validate configuration data using family-specific schema.

        This method performs comprehensive validation of the provided configuration
        data by retrieving the appropriate validation schema for the specified family
        and checking the configuration against it, including validation of unknown
        properties.

        :param config_data: Configuration data object containing family information
                           and settings to be validated.
        :raises SPSDKError: Invalid configuration data or schema validation failure.
        """
        family = config_data.get_family()
        # the upper layer is responsible for family-specific validation schema
        schema = cls.get_validation_schemas(family=family)
        config_data.check(schema, check_unknown_props=True)

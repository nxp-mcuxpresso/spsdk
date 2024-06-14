#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Generic EL2Go client."""

import json
import logging
import uuid
from typing import List, Optional

from typing_extensions import Self

from spsdk.utils.http_client import HTTPClientBase, HTTPClientError
from spsdk.utils.misc import load_secret

logger = logging.getLogger(__name__)


class EL2GOApiResponse:
    """EdgeLock 2GO API Response."""

    def __init__(self, status_code: int, json_body: dict) -> None:
        """Initialize EdgeLock 2GO API Response."""
        self.status_code = status_code
        self.json_body = json_body


class EL2GOClient(HTTPClientBase):
    """Generic HTTP client for EL2GO."""

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
        :param host: EL2GO API server address, defaults to "https://api.edgelock2go.com"
        :param timeout: Timeout for each API call, defaults to 60
        :param raise_exceptions: Raise exception if response status code is >=400, defaults to True
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

    def _handle_el2go_request(
        self,
        method: HTTPClientBase.Method,
        url: str,
        param_data: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> EL2GOApiResponse:
        correlation_id = str(uuid.uuid4())
        logger.info(f"EL2G-Correlation-ID: {correlation_id}")
        self.headers["EL2G-Correlation-ID"] = correlation_id
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
                    raise HTTPClientError(
                        api_response.status_code,
                        extra_data,
                        f"Error {api_response.status_code} ({api_response.reason}) occurred when calling {url}\n"
                        f"Extra response data: {extra_data or 'N/A'}",
                    ) from json_decode_error
            response = EL2GOApiResponse(
                status_code=api_response.status_code, json_body=api_response.json()
            )
            return response

        if api_response.text == "":
            response = EL2GOApiResponse(status_code=api_response.status_code, json_body={})
        else:
            response = EL2GOApiResponse(
                status_code=api_response.status_code, json_body=api_response.json()
            )

        return response

    @classmethod
    def from_config(cls, config_data: dict, search_paths: Optional[List[str]] = None) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config_data.

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        :return: Instance of this class
        """
        cls.validate_config(config_data=config_data, search_paths=search_paths)
        api_key = config_data.pop("api_key")
        api_key = load_secret(api_key, search_paths=search_paths)
        return cls(api_key=api_key, **config_data)

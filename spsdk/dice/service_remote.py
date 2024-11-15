#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for communicating with a remote DICE attestation service."""

import logging
from typing import Optional

import requests

from spsdk.dice.models import APIResponse, DICEVerificationService

logger = logging.getLogger(__name__)


class RemoteDICEVerificationService(DICEVerificationService):
    """DICE Verification adapter for communicating with remote verification service."""

    def __init__(self, base_url: str) -> None:
        """Initialize the Remote DICE verification communication adapter.

        :param base_url: URL of the remote service (e.g.: http://localhost:8000)
        """
        self.base_url = base_url

    def _handle_request(
        self, method: str, url: str, payload: Optional[dict[str, str]] = None
    ) -> APIResponse:
        """Handle REST API call.

        :param method: HTTP method to use (e.g.: GET, POST, etc.)
        :param url: URL of the REST API (e.g.: /api/v1/verify)
        :param payload: Data dictionary to send to REST API endpoint, defaults to None
        :return: Result of the REST API call
        """
        full_url = self.base_url + url
        response = requests.request(method=method, url=full_url, data=payload, timeout=5)
        logger.debug(response)
        if response.status_code >= 500:
            return APIResponse(api=url, status="SERVER_ERROR", message=response.reason)
        json_response: dict = response.json()
        logger.debug(json_response)
        api_response = APIResponse(
            api=url,
            status=json_response.get("status", f"{response.reason} [{response.status_code}]"),
            message=json_response.get("message", "\n".join(json_response.get("data", []))),
            expected_had=json_response.get("expected_had"),
            actual_had=json_response.get("actual_had"),
        )
        logger.info(api_response)
        return api_response

    def register_dice_ca_puk(self, key_data: bytes) -> APIResponse:
        """Register DICE CA PUK in the service."""
        logger.info("Registering DICE CA PUK")
        response = self._handle_request(
            method="post",
            url="/api/v1/register-dice-ca-puk",
            payload={"data": key_data.hex()},
        )
        return response

    def register_version(self, data: bytes) -> APIResponse:
        """Register new version of FW, RTF, and HAD."""
        logger.info("Registering new version of FW, RTF, and HAD")
        response = self._handle_request(
            method="post",
            url="/api/v1/register-version",
            payload={"data": data.hex()},
        )
        return response

    def get_challenge(self, pre_set: Optional[str] = None) -> bytes:
        """Get challenge vector from the service."""
        logger.info("Retrieving DICE challenge")
        if pre_set:
            raise NotImplementedError("Remote service doesn't support pre-set challenges.")
        response = self._handle_request(
            method="get",
            url="/api/v1/get-challenge",
        )
        challenge = response.message
        return bytes.fromhex(challenge)

    def verify(self, data: bytes, reset_challenge: bool = False) -> APIResponse:
        """Submit DICE response for verification."""
        logger.info("Submitting DICE Response for verification")
        response = self._handle_request(
            method="post",
            url="/api/v1/verify",
            payload={
                "data": data.hex(),
                "reset_challenge": reset_challenge,  # type: ignore[dict-item]
            },
        )
        return response

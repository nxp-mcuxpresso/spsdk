#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK remote DICE attestation service communication utilities.

This module provides functionality for communicating with remote DICE (Device
Identifier Composition Engine) attestation services over network protocols.
The main component is RemoteDICEVerificationService class that implements
the DICEVerificationService interface for remote attestation operations.
"""

import logging
from typing import Optional

import requests

from spsdk.dice.models import APIResponse, DICEVerificationService

logger = logging.getLogger(__name__)


class RemoteDICEVerificationService(DICEVerificationService):
    """Remote DICE Verification Service adapter.

    This class provides an interface for communicating with remote DICE verification
    services over HTTP REST API. It handles registration of DICE CA public keys,
    firmware versions, and verification operations by translating local method calls
    into appropriate HTTP requests to the remote service endpoint.
    """

    def __init__(self, base_url: str) -> None:
        """Initialize the Remote DICE verification communication adapter.

        :param base_url: URL of the remote service (e.g.: http://localhost:8000)
        """
        self.base_url = base_url

    def _handle_request(
        self, method: str, url: str, payload: Optional[dict[str, str]] = None
    ) -> APIResponse:
        """Handle REST API call.

        The method sends HTTP request to the remote service endpoint and processes
        the response into standardized APIResponse format.

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
        """Register DICE CA PUK in the service.

        This method sends a POST request to register a DICE Certificate Authority
        Public Key with the remote service.

        :param key_data: The DICE CA public key data as raw bytes.
        :return: API response containing the registration result.
        """
        logger.info("Registering DICE CA PUK")
        response = self._handle_request(
            method="post",
            url="/api/v1/register-dice-ca-puk",
            payload={"data": key_data.hex()},
        )
        return response

    def register_version(self, data: bytes) -> APIResponse:
        """Register new version of FW, RTF, and HAD.

        This method sends firmware, RTF (Runtime Firmware), and HAD (Hardware Attestation Data)
        version information to the remote DICE service for registration.

        :param data: Binary data containing the version information to be registered.
        :return: API response object containing the registration result.
        """
        logger.info("Registering new version of FW, RTF, and HAD")
        response = self._handle_request(
            method="post",
            url="/api/v1/register-version",
            payload={"data": data.hex()},
        )
        return response

    def get_challenge(self, pre_set: Optional[str] = None) -> bytes:
        """Get challenge vector from the service.

        Retrieves a challenge vector from the remote DICE service for authentication purposes.

        :param pre_set: Pre-set challenge string (not supported by remote service).
        :raises NotImplementedError: When pre_set parameter is provided.
        :return: Challenge vector as bytes.
        """
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
        """Submit DICE response for verification.

        Sends the DICE response data to the remote service for verification and
        optionally resets the challenge state.

        :param data: DICE response data to be verified.
        :param reset_challenge: Whether to reset the challenge after verification.
        :return: API response containing verification results.
        """
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

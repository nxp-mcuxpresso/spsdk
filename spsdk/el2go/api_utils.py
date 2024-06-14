#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""API for communicating with the EL2GO server."""

import base64
import logging
import time
import uuid
from enum import Enum
from typing import List, Tuple, Union

from spsdk.el2go.client import EL2GOApiResponse, EL2GOClient
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)


class GenStatus(List, Enum):  # type: ignore
    """Provisioning generation status."""

    GENERATION_TRIGGERED = ["GENERATION_TRIGGERED", "Creation of Secure Objects was started"]
    GENERATION_COMPLETED = ["GENERATION_COMPLETED", "Creation of Secure Objects is completed"]
    GENERATION_FAILED = ["GENERATION_FAILED", "Creation of Secure Objects failed"]
    PROVISIONING_COMPLETED = [
        "PROVISIONING_COMPLETED",
        "Secure Objects were provisioned successfully",
    ]
    PROVISIONING_FAILED = ["PROVISIONING_FAILED", "Provisioning of Secure Objects failed"]
    GENERATION_ON_CONNECTION = [
        "GENERATION_ON_CONNECTION",
        "Secure Object generation is triggered when a device request it",
    ]


class EL2GOTPClient(EL2GOClient):
    """EL2GO HTTP Client for TP operations."""

    def __init__(
        self,
        api_key: str,
        nc12: int,
        device_group_id: int,
        family: str,
        revision: str = "latest",
        url: str = "https://api.edgelock2go.com",
        timeout: int = 60,
        download_timeout: int = 300,
        delay: int = 5,
        **kwargs: str,
    ) -> None:
        """Initialize EL2GO TP HTTP Client.

        :param api_key: User EL2GO API key
        :param nc12: Product (12NC) number
        :param device_group_id: Device group to work with
        :param family: Target chip family
        :param revision: Target chip silicon revision, defaults to "latest"
        :param url: EL2GO Server API URL, defaults to "https://api.edgelock2go.com"
        :param timeout: Timeout for each API call, defaults to 60
        :param download_timeout: Timeout for donwloading Provionings, defaults to 300
        :param delay: Delay between API calls when downloading Provisionings, defaults to 5
        """
        super().__init__(api_key=api_key, url=url, timeout=timeout, raise_exceptions=True, **kwargs)
        self.nc12 = nc12
        self.device_group_id = device_group_id
        self.hardware_family_type = get_db(device=family, revision=revision).get_str(
            DatabaseManager.EL2GO_TP, "el2go_name"
        )
        self.delay = delay
        self.download_timeout = download_timeout

    def response_handling(self, status_code: int, url: str) -> None:
        """Handle an error response."""
        if status_code == 403:
            logger.error("Potential usage of invalid API key.")
        if status_code >= 400:
            raise SPSDKError(
                f"Operation failed with status code {status_code} when calling {url}."
                f"Correlation id is {str(uuid.uuid4())}"
            )

    def assign_device_to_devicegroup(self, device_id: str) -> None:
        """Assign a device to the configured group."""
        response, url = self._assign_device_to_group(device_id=device_id)
        if response.status_code == 422:
            device_group = self._find_device_group_id(device_id=device_id)
            if device_group == self.device_group_id:
                logger.warning(
                    "Device is already assigned in the desired Device Group, Secure Objects will be downloaded"
                )
            elif device_group != self.device_group_id:
                raise SPSDKError(
                    f"Device {device_id} is already assigned to Device Group {device_group}"
                )
        else:
            self.response_handling(response.status_code, url)

    def get_generation_status(self, device_id: str) -> GenStatus:
        """Get status of Provisionings creation for given device."""
        url = f"/api/v1/rtp/devices/{device_id}/secure-object-provisionings"
        data = {"hardware-family-type": [self.hardware_family_type]}
        response = self._handle_el2go_request(method=self.Method.GET, url=url, param_data=data)
        self.response_handling(status_code=response.status_code, url=url)
        for provisioning in response.json_body["content"]:
            if provisioning["provisioningState"] != GenStatus.GENERATION_COMPLETED.value[0]:
                return GenStatus[provisioning["provisioningState"]]
        return GenStatus.GENERATION_COMPLETED

    def download_provisionings(self, device_id: str) -> dict:
        """Download provisionings for given device."""
        url = f"/api/v1/rtp/device-groups/{self.device_group_id}/devices/download-provisionings"
        data = {
            "productHardwareFamilyType": self.hardware_family_type,
            "deviceIds": [device_id],
        }
        response = self._handle_el2go_request(method=self.Method.POST, url=url, json_data=data)
        self.response_handling(status_code=response.status_code, url=url)
        return response.json_body

    def download_secure_objects(self, device_id: str) -> Union[bytes, GenStatus]:
        """Download all secure objects for given device."""
        time.sleep(2)
        timeout = Timeout(self.download_timeout)
        while not timeout.overflow():
            gen_status = self.get_generation_status(device_id=device_id)
            if gen_status == GenStatus.GENERATION_COMPLETED:
                data = bytes()
                provisionings = self.download_provisionings(device_id=device_id)
                for dev_prov in provisionings:
                    for rtp_prov in dev_prov["rtpProvisionings"]:
                        data += base64.b64decode(rtp_prov["apdus"]["createApdu"]["apdu"])
                return data
            if gen_status == GenStatus.GENERATION_TRIGGERED:
                time.sleep(self.delay)
                continue
            break
        return gen_status

    def _find_device_group_id(self, device_id: str) -> str:
        """Find GROUP_ID in which the given device is assigned."""
        url = f"/api/v1/products/{self.nc12}/device-groups"
        response = self._handle_el2go_request(method=self.Method.GET, url=url)
        self.response_handling(status_code=response.status_code, url=url)
        for device_group in response.json_body["content"]:
            check_id = device_group["id"]
            url = f"/api/v1/products/{self.nc12}/device-groups/{check_id}/devices/{device_id}"
            response = self._handle_el2go_request(method=self.Method.GET, url=url)
            if response.status_code == 200:
                return check_id

            if response.status_code == 404:
                continue
            else:
                self.response_handling(status_code=response.status_code, url=url)
        raise SPSDKError(f"Device {device_id} was not found in product {self.nc12}")

    def _assign_device_to_group(self, device_id: str) -> Tuple[EL2GOApiResponse, str]:
        """Assign a device to the configured group."""
        url = f"/api/v1/products/{self.nc12}/device-groups/{self.device_group_id}/devices"
        data = {"deviceIds": [device_id]}
        response = self._handle_el2go_request(method=self.Method.POST, url=url, json_data=data)
        return response, url

    def test_connection(self) -> None:
        """Test connection to EL2GO service."""
        url = f"/api/v1/products/{self.nc12}/device-groups/{self.device_group_id}/devices"
        response = self._handle_el2go_request(method=self.Method.GET, url=url)
        self.response_handling(response.status_code, url)

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        return get_schema_file(DatabaseManager.EL2GO_TP)["el2go_tp"]

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get family names supported by WPCTarget."""
        return get_families(DatabaseManager.EL2GO_TP)

    @classmethod
    # type: ignore[override]
    # pylint: disable=arguments-differ
    def generate_config_template(cls, family: str) -> str:
        """Generate configuration YAML template for given family."""
        schema = cls.get_validation_schema()
        schema["properties"]["family"]["template_value"] = family
        return super().generate_config_template(
            schemas=[schema],
            title=f"Configuration of EdgeLock 2GO Offline Provisioning flow for {family}",
        )

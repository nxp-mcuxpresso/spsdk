#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Adapter for BLHost/Mboot communication layer covering DICE operations."""
import logging

from spsdk.dice.exceptions import SPSDKDICEError
from spsdk.dice.models import DICETarget
from spsdk.mboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.database import DatabaseManager, get_db

logger = logging.getLogger(__name__)


class BlhostDICETarget(DICETarget):
    """BLHost/MBoot adapter for DICE operations."""

    def __init__(self, family: str, interface: MbootProtocolBase) -> None:
        """Initialize Mboot adapter."""
        super().__init__()
        self.family = family
        self.interface = interface
        self.database = get_db(device=self.family)

    def load_dice_fw(self, firmware: str) -> bool:
        """Prepare MCU for DICE firmware and load the FW itself."""
        raise NotImplementedError(
            "This functionality is not yet implemented. Use SEC tool instead."
        )

    def get_ca_puk(self, rkth: bytes) -> bytes:
        """Generate and return NXP_CUST_DICE_CA_PUK from the target."""
        logger.info("Generating NXP_CUST_DICE_CA_PUK")
        buffer_address = self.database.get_int(DatabaseManager.DICE, "buffer_address")
        ca_puk_length = self.database.get_int(DatabaseManager.DICE, "ca_puk_length")
        with McuBoot(interface=self.interface) as mboot:
            if not mboot.write_memory(address=buffer_address, data=rkth):
                raise SPSDKDICEError(f"Writing RKTH failed. Error: {mboot.status_string}")
            puk_length = mboot.tp_oem_get_cust_cert_dice_puk(
                oem_rkth_input_addr=buffer_address,
                oem_rkth_input_size=len(rkth),
                oem_cust_cert_dice_puk_output_addr=buffer_address + 0x1000,
                oem_cust_cert_dice_puk_output_size=ca_puk_length,
            )
            if not puk_length:
                raise SPSDKDICEError(
                    f"Creating NXP_CUST_DICE_CA_PUK failed. Error: {mboot.status_string}"
                )
            if puk_length != ca_puk_length:
                raise SPSDKDICEError(
                    f"Unexpected NXP_CUST_DICE_CA_PUK length. Expected {ca_puk_length}, got {puk_length}"
                )
            ca_puk = mboot.read_memory(address=buffer_address + 0x1000, length=ca_puk_length)
            if not ca_puk:
                raise SPSDKDICEError(
                    f"Reading NXP_CUST_DICE_CA_PUK failed. Error: {mboot.status_string}"
                )
            return ca_puk

    def get_csr(self) -> bytes:
        """Get CSR from the target."""
        logger.info("Generating CSR")
        csr_address = self.database.get_int(DatabaseManager.DICE, "csr_address")
        csr_length = self.database.get_int(DatabaseManager.DICE, "csr_length")
        with McuBoot(interface=self.interface) as mboot:
            csr = mboot.read_memory(address=csr_address, length=csr_length)
            if not csr:
                raise SPSDKDICEError(f"Reading CSR failed. Error: {mboot.status_string}")
            return csr

    def get_dice_response(self, challenge: bytes) -> bytes:
        """Generate and return DICE response to challenge on the target."""
        logger.info("Generating DICE Response")
        buffer_address = self.database.get_int(DatabaseManager.DICE, "buffer_address")
        expected_length = self.database.get_int(DatabaseManager.DICE, "response_length")
        with McuBoot(interface=self.interface) as mboot:
            if not mboot.write_memory(address=buffer_address, data=challenge):
                raise SPSDKDICEError(f"Writing challenge failed. Error: {mboot.status_string}")
            response_length = mboot.tp_oem_get_cust_dice_response(
                challenge_addr=buffer_address,
                challenge_size=len(challenge),
                response_addr=buffer_address + 0x1000,
                response_size=expected_length,
            )
            if not response_length:
                raise SPSDKDICEError(f"Creating DICE response failed. Error: {mboot.status_string}")
            if response_length != expected_length:
                raise SPSDKDICEError(
                    f"Unexpected DICE response length. Expected {expected_length}, got {response_length}"
                )
            response = mboot.read_memory(address=buffer_address + 0x1000, length=response_length)
            if not response:
                raise SPSDKDICEError(f"Reading DICE response failed. Error: {mboot.status_string}")
            if self.database.get_bool(DatabaseManager.DICE, "need_reset"):
                logger.info("Starting reset without re-opening the port.")
                mboot.reset(reopen=False)
            return response

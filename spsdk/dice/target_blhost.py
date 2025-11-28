#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK DICE operations adapter for BLHost/Mboot communication.

This module provides the BlhostDICETarget class that implements DICE (Device Identifier
Composition Engine) operations using the BLHost/Mboot communication protocol for secure
device provisioning and management.
"""

import logging

from spsdk.dice.exceptions import SPSDKDICEError
from spsdk.dice.models import DICETarget
from spsdk.mboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db

logger = logging.getLogger(__name__)


class BlhostDICETarget(DICETarget):
    """BLHost/MBoot adapter for DICE operations.

    This class provides an interface to perform DICE (Device Identifier Composition Engine)
    operations on NXP MCUs through the BLHost/MBoot protocol. It handles communication
    with the target device to generate cryptographic keys, certificates, and perform
    DICE-related provisioning tasks.
    """

    def __init__(self, family: FamilyRevision, interface: MbootProtocolBase) -> None:
        """Initialize Mboot adapter for DICE target communication.

        Creates a new instance of the Mboot target adapter with the specified family
        and communication interface.

        :param family: MCU family and revision information for target device.
        :param interface: Mboot protocol interface for communication with target.
        """
        super().__init__()
        self.family = family
        self.interface = interface
        self.database = get_db(self.family)

    def load_dice_fw(self, firmware: str) -> bool:
        """Prepare MCU for DICE firmware and load the FW itself.

        This method handles the preparation of the MCU for DICE (Device Identifier Composition Engine)
        firmware and performs the actual firmware loading process.

        :param firmware: Path to the DICE firmware file to be loaded.
        :raises NotImplementedError: This functionality is not yet implemented.
        :return: True if firmware loading was successful, False otherwise.
        """
        raise NotImplementedError(
            "This functionality is not yet implemented. Use SEC tool instead."
        )

    def get_ca_puk(self, rkth: bytes, mldsa: bool = False) -> bytes:
        """Generate and return NXP_CUST_DICE_CA_PUK from the target.

        This method writes the provided RKTH to target memory, generates the customer DICE CA
        public key using the target's OEM functionality, and returns the generated public key.

        :param rkth: Root Key Table Hash bytes used for public key generation.
        :param mldsa: Flag to enable ML-DSA algorithm support, defaults to False.
        :raises SPSDKDICEError: If RKTH length is invalid, memory operations fail, or public
                                key generation fails.
        :return: Generated NXP customer DICE CA public key as bytes.
        """
        logger.info("Generating NXP_CUST_DICE_CA_PUK")
        buffer_address = self.database.get_int(DatabaseManager.DICE, "buffer_address")
        buffer_size = self.database.get_int(DatabaseManager.DICE, "buffer_size")
        rkth_length = self.database.get_int(DatabaseManager.DICE, "rkth_length")
        rkth_truncated_length = self.database.get_int(DatabaseManager.DICE, "rkth_truncated_length")

        if len(rkth) not in [rkth_length, rkth_truncated_length]:
            length_message = (
                f"{rkth_length}"
                if rkth_length == rkth_truncated_length
                else f"either {rkth_length} or {rkth_truncated_length}"
            )
            raise SPSDKDICEError(f"Invalid RKTH length. Expected {length_message} bytes.")

        with McuBoot(interface=self.interface, family=self.family) as mboot:
            if not mboot.write_memory(address=buffer_address, data=rkth):
                raise SPSDKDICEError(f"Writing RKTH failed. Error: {mboot.status_string}")
            puk_length = mboot.tp_oem_get_cust_cert_dice_puk(
                oem_rkth_input_addr=buffer_address,
                oem_rkth_input_size=len(rkth),
                oem_cust_cert_dice_puk_output_addr=buffer_address + 0x1000,
                oem_cust_cert_dice_puk_output_size=buffer_size,
                mldsa=mldsa,
            )
            if not puk_length:
                raise SPSDKDICEError(
                    f"Creating NXP_CUST_DICE_CA_PUK failed. Error: {mboot.status_string}"
                )
            ca_puk = mboot.read_memory(address=buffer_address + 0x1000, length=puk_length)
            if not ca_puk:
                raise SPSDKDICEError(
                    f"Reading NXP_CUST_DICE_CA_PUK failed. Error: {mboot.status_string}"
                )
            return ca_puk

    def get_csr(self) -> bytes:
        """Get CSR from the target.

        Reads Certificate Signing Request (CSR) data from the target device memory
        using the configured interface and family settings.

        :raises SPSDKDICEError: When reading CSR from target memory fails.
        :return: Raw CSR data as bytes.
        """
        logger.info("Generating CSR")
        csr_address = self.database.get_int(DatabaseManager.DICE, "csr_address")
        csr_length = self.database.get_int(DatabaseManager.DICE, "csr_length")
        with McuBoot(interface=self.interface, family=self.family) as mboot:
            csr = mboot.read_memory(address=csr_address, length=csr_length)
            if not csr:
                raise SPSDKDICEError(f"Reading CSR failed. Error: {mboot.status_string}")
            return csr

    def get_dice_response(self, challenge: bytes) -> bytes:
        """Generate and return DICE response to challenge on the target.

        The method writes the challenge to target memory, generates a DICE response using
        the target's OEM function, validates the response length, and reads back the result.
        Optionally performs a reset if required by the target configuration.

        :param challenge: Challenge bytes to send to the target for DICE response generation.
        :raises SPSDKDICEError: When writing challenge, generating response, or reading fails.
        :raises SPSDKDICEError: When response length doesn't match expected length.
        :return: DICE response bytes generated by the target.
        """
        logger.info("Generating DICE Response")
        buffer_address = self.database.get_int(DatabaseManager.DICE, "buffer_address")
        expected_length = self.database.get_int(DatabaseManager.DICE, "response_length")
        with McuBoot(interface=self.interface, family=self.family) as mboot:
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

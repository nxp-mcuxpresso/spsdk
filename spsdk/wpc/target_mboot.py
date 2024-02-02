#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Model of a target for injecting WPC certificate chain."""

import logging

from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.scanner import get_mboot_interface
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file

from .utils import SPSDKWPCError, WPCCertChain, WPCTarget

logger = logging.getLogger(__name__)


class WPCTargetMBoot(WPCTarget):
    """WPC Target adapter using MBoot interface."""

    NAME = "mboot"

    def __init__(self, family: str, port: str) -> None:
        """Initialize WPC Target adapter.

        :param family: Target family name
        :param port: Serial port used for communication with the target
        """
        super().__init__(family)
        self.interface = get_mboot_interface(port=port)
        self.buffer_address = get_db(device=family).get_int(DatabaseManager.COMM_BUFFER, "address")

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        schema = get_schema_file(DatabaseManager.WPC)
        return schema["mboot"]

    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target."""
        logger.info("Reading low level WPC ID")
        with McuBoot(interface=self.interface) as mboot:
            pre_csr_data = mboot.read_memory(
                address=self.buffer_address,
                length=136,
            )
            if not pre_csr_data:
                raise SPSDKWPCError(f"Unable to read WPC_ID. Error: {mboot.status_string}")
        return pre_csr_data

    def sign(self, data: bytes) -> bytes:
        """Sign data by the target."""
        logger.info("Signing CSR-TBS data")
        with McuBoot(interface=self.interface) as mboot:
            if not mboot.write_memory(
                address=self.buffer_address + 0x100,
                data=data,
            ):
                raise SPSDKWPCError(f"Unable to write memory. Error: {mboot.status_string}")
            if not mboot.wpc_sign_csr(
                csr_tbs_addr=self.buffer_address + 0x100,
                csr_tbs_len=len(data),
                signature_addr=self.buffer_address + 0x300,
                signature_len=64,
            ):
                raise SPSDKWPCError(f"Unable to sign CSR. Error: {mboot.status_string}")
            signature = mboot.read_memory(
                address=self.buffer_address + 0x300,
                length=64,
            )
            if not signature:
                raise SPSDKWPCError(f"Unable to read CSR signature. Error: {mboot.status_string}")
        return signature

    def wpc_insert_cert(self, cert_chain: WPCCertChain) -> bool:
        """Insert the WPC Certificate Chain into the target.

        :param cert_chain: Certificate chain to insert into the target
        :raises SPSDKWPCError: Error during certificate chain insertion
        :return: True if operation finishes successfully
        """
        logger.info("Inserting WPC certificate")
        data = cert_chain.export()
        puk_offset = cert_chain.get_puk_offset()
        rsid_offset = cert_chain.get_rsid_offset()

        with McuBoot(interface=self.interface) as mboot:
            if not mboot.write_memory(
                address=self.buffer_address + 0x400,
                data=data,
            ):
                raise SPSDKWPCError(f"Unable to write memory. Error: {mboot.status_string}")
            result = mboot.wpc_insert_cert(
                wpc_cert_addr=self.buffer_address + 0x400,
                wpc_cert_len=len(data),
                ec_id_offset=rsid_offset,
                wpc_puk_offset=puk_offset,
            )
            if result is None:
                raise SPSDKWPCError(f"Unable to insert cert. Error: {mboot.status_string}")
        return True

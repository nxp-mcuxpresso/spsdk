#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Model of a target for injecting WPC certificate chain."""

import logging
from typing import Any

from typing_extensions import Self

from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.wpc.wpc import SPSDKEncoding, SPSDKWPCError, WPCCertChain, WPCIdType, WPCTarget

logger = logging.getLogger(__name__)


def _get_interface(params: dict) -> MbootProtocolBase:
    """A helper function to obtain Mboot interface from user settings."""
    if_params = load_interface_config(cli_params=params)
    if_class = MbootProtocolBase.get_interface_class(identifier=if_params.IDENTIFIER)
    interface = if_class.scan_single(**if_params.get_scan_args())
    return interface


class WPCTargetMBoot(WPCTarget):
    """WPC Target adapter using MBoot interface."""

    identifier = "mboot"

    def __init__(self, family: FamilyRevision, mboot_interface: dict[str, str]) -> None:
        """Initialize WPC Target adapter.

        :param family: Target family name
        :param mboot_interface: Dictionary containing interface definition.
            Examples: "port": "com4", "usb":"0x1fc9:0x014f", "plugin": "identifier=my_plugin,param1=value1"
        """
        super().__init__(family)
        self.interface = _get_interface(params=mboot_interface)
        db = get_db(family)
        self.buffer_address = db.get_int(DatabaseManager.COMM_BUFFER, "address")
        self.id_length = db.get_int(DatabaseManager.WPC, "id_length")
        self.need_reset = db.get_bool(DatabaseManager.WPC, "need_reset")
        self.check_lifecycle = db.get_int(DatabaseManager.WPC, "check_lifecycle")
        self.insert_puc_only = db.get_bool(DatabaseManager.WPC, "insert_puc_only")
        self.need_address_adjust = db.get_bool(DatabaseManager.WPC, "need_address_adjust")

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config_data.
        To limit the scope of data, set cls.CONFIG_PARAMS (key in config data).

        :param config: Configuration data
        :return: Instance of this class
        """
        family = FamilyRevision.load_from_config(config)
        mboot_interface = config.get(cls.CONFIG_PARAMS)
        return cls(family=family, mboot_interface=mboot_interface)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get JSON schema for validating configuration data."""
        schema = get_schema_file(DatabaseManager.WPC)
        return [schema["mboot"]]

    def get_low_level_wpc_id(self) -> bytes:
        """Get the lower-level WPC ID from the target."""
        logger.info("Reading low level WPC ID")
        if self.wpc_id_type == WPCIdType.COMPUTED_CSR:
            with McuBoot(interface=self.interface, family=self.family) as mboot:
                pre_csr_data = mboot.read_memory(
                    address=self.buffer_address,
                    length=self.id_length,
                )
                if not pre_csr_data:
                    raise SPSDKWPCError(f"Unable to read WPC_ID. Error: {mboot.status_string}")
            return pre_csr_data

        if self.wpc_id_type == WPCIdType.RSID:
            with McuBoot(interface=self.interface, family=self.family) as mboot:
                actual_size = mboot.wpc_get_id(
                    wpc_id_blob_addr=self.buffer_address, wpc_id_blob_size=self.id_length
                )
                if not actual_size:
                    raise SPSDKWPCError(f"Generating WPC ID failed. Error: {mboot.status_string}")
                if actual_size != self.id_length:
                    raise SPSDKWPCError(
                        f"Unexpected WPC ID length. Expected {self.id_length}, got {actual_size}"
                    )
                data = mboot.read_memory(address=self.buffer_address, length=actual_size)
                if not data:
                    raise SPSDKWPCError(f"Failed to read WPC ID. Error: {mboot.status_string}")
            return data

        raise SPSDKWPCError(f"WPC ID type: '{self.wpc_id_type.value}' is not supported")

    def sign(self, data: bytes) -> bytes:
        """Sign data by the target."""
        logger.info("Signing CSR-TBS data")
        with McuBoot(interface=self.interface, family=self.family) as mboot:
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

    def wpc_insert_cert(self, cert_chain: WPCCertChain, reset: bool = True) -> bool:
        """Insert the WPC Certificate Chain into the target.

        :param cert_chain: Certificate chain to insert into the target
        :param reset: Perform reset if the target requires it.
            With this option you may disable required reset (for testing purposes)
        :raises SPSDKWPCError: Error during certificate chain insertion
        :return: True if operation finishes successfully
        """
        logger.info("Inserting WPC certificate")
        if self.insert_puc_only:
            logger.info("Using PUC certificate only")
            data = cert_chain.product_unit_cert.export(encoding=SPSDKEncoding.DER)
        else:
            data = cert_chain.export()
        puk_offset = cert_chain.get_puk_offset(pu_cert_only=self.insert_puc_only)
        rsid_offset = cert_chain.get_rsid_offset(pu_cert_only=self.insert_puc_only)

        with McuBoot(interface=self.interface, family=self.family) as mboot:
            if self.check_lifecycle:
                logger.info("Checking lifecycle")
                lifecycle = mboot.get_property(prop_tag=PropertyTag.FLASH_SECURITY_STATE)
                if lifecycle is None:
                    raise SPSDKWPCError(
                        f"Unable to get device's lifecycle. Error: {mboot.status_string}"
                    )
                if lifecycle[1] > self.check_lifecycle:
                    raise SPSDKWPCError(
                        f"Invalid lifecycle: Expected <= {self.check_lifecycle}, got: {lifecycle[1]}"
                    )

            if self.need_reset and reset:
                logger.info("Resetting device")
                mboot.reset(reopen=True)

            address = self.buffer_address + 0x400
            # we need to make sure the PUK is on a even address on some platforms
            if self.need_address_adjust and puk_offset % 2:
                logger.info("Adjusting memory address to align PUK offset")
                address += 1

            if not mboot.write_memory(address=address, data=data):
                raise SPSDKWPCError(f"Unable to write memory. Error: {mboot.status_string}")
            result = mboot.wpc_insert_cert(
                wpc_cert_addr=address,
                wpc_cert_len=len(data),
                ec_id_offset=rsid_offset,
                wpc_puk_offset=puk_offset,
            )
            if result is None:
                raise SPSDKWPCError(f"Unable to insert cert. Error: {mboot.status_string}")
        return True

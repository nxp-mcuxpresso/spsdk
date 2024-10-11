#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SBx file."""

import logging
import os
from typing import Callable, Optional

from spsdk.apps.utils.utils import format_raw_data
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sbx.images import SecureBinaryX
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import load_configuration
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)


class DevHsmSBx(DevHsm):
    """Class to handle device HSM provisioning procedure for SBx."""

    DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE = 52
    DEVBUFF_SB_SIGNATURE_SIZE = 32

    def __init__(
        self,
        mboot: McuBoot,
        family: str,
        oem_share_input: Optional[bytes] = None,
        oem_enc_master_share_input: Optional[bytes] = None,
        cust_mk_sk: Optional[bytes] = None,
        container_conf: Optional[str] = None,
        workspace: Optional[str] = None,
        initial_reset: Optional[bool] = False,
        final_reset: Optional[bool] = True,
        buffer_address: Optional[int] = None,
        info_print: Optional[Callable] = None,
    ) -> None:
        """Initialization of device HSM class. It's designed to create provisioned sbx file.

        :param mboot: mBoot communication interface.
        :param family: chip family
        :param oem_share_input: OEM share input data. Default: random 16 bytes.
        :param oem_enc_master_share_input: Used for setting the OEM share (recreating security session)
        :param cust_mk_sk: Customer Master Key Symmetric Key.
        :param container_conf: Optional configuration file (to specify user list of SB commands).
        :param workspace: Optional folder to store middle results.
        :param initial_reset: Reset device before DevHSM creation of SB3 file.
        :param final_reset: Reset device after DevHSM creation of SB3 file.
        :param buffer_address: Override the default buffer address.
        :param info_print: Method for printing out info messages. Default: built-in print
        :raises SPSDKError: In case of any problem.
        """
        if cust_mk_sk:
            raise SPSDKError("Customer master key is not supported for SBx HSM")

        if not container_conf:
            raise SPSDKError("Container configuration must be provided for SBx")

        if buffer_address is not None:
            raise SPSDKError("Overriding buffer address for SBx is not supported")

        self.mboot = mboot
        self.oem_share_input = oem_share_input or random_bytes(16)
        self.oem_enc_master_share_input = oem_enc_master_share_input
        self.info_print = info_print or print
        self.workspace = workspace
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        self.family = DatabaseManager().quick_info.devices.get_correct_name(family)

        config_data = load_configuration(container_conf)
        family_from_cfg = config_data.get("family")
        if family_from_cfg:
            family_from_cfg = DatabaseManager().quick_info.devices.get_correct_name(family_from_cfg)
        if self.family != family_from_cfg:
            raise SPSDKError(
                f"Family from json configuration file: {family_from_cfg} "
                f"differs from the family parameter {self.family}"
            )

        config_dir = os.path.dirname(container_conf)
        schemas = SecureBinaryX.get_validation_schemas(self.family, include_test_configuration=True)
        check_config(config_data, schemas, search_paths=[config_dir])

        self.sbx = SecureBinaryX.load_from_config(config_data, search_paths=[config_dir])

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        self.store_temp_res("OEM_SHARE_INPUT.BIN", self.oem_share_input)

        self.final_sb = bytes()
        super().__init__(self.family, workspace)

    @classmethod
    def generate_config_template(cls, family: str) -> str:
        """Generate configuration for selected family."""
        return SecureBinaryX.generate_config_template(
            DatabaseManager().quick_info.devices.get_correct_name(family)
        )

    def __repr__(self) -> str:
        return "SBx DevHSM"

    def __str__(self) -> str:
        return f"SBx DevHSM for {self.family}"

    def create_sb(self) -> None:
        """Do device hsm process to create provisioning SBX file."""
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate OEM share
        self.info_print(" 2: Generating OEM master share.")
        oem_enc_share, *_ = self.oem_generate_master_share(self.oem_share_input)

        # 3: Create SBx header
        self.info_print(" 3: Creating SBx header.")
        self.sbx.load_tphsm(oem_enc_share)

        # 4: Export unencrypted SBx data blocks
        self.info_print(" 4: Created unencrypted SBx data")
        logger.info(f"\n SBx data: \n{str(self.sbx)}\n")
        # 4.1: Get sbx file data part individual chunks
        data_cmd_blocks = self.sbx.sb_commands.get_cmd_blocks_to_export()
        # 4.2: Get sbx header without signature
        sbx_header_no_sign = self.sbx.export_header()
        # add blank signature
        sbx_header_no_sign += bytes(self.DEVBUFF_SB_SIGNATURE_SIZE)

        # 5: Call hsm_enc_blk to encrypt all the data chunks from step 6. Use FW encryption key from step 3.
        self.info_print(" 5: Encrypting SBx data on device")
        sbx_enc_data = self.encrypt_data_blocks(sbx_header_no_sign, data_cmd_blocks)

        # 5.1: Calculate SHA-256 hashes of encrypted data
        self.info_print(" 5.1: Calculating SHA-256 hashes of encrypted data.")
        enc_final_data = self.sbx.sb_commands.process_cmd_blocks_to_export(sbx_enc_data)
        self.store_temp_res("Final_data.bin", enc_final_data, "to_merge")

        # 5.2: Update the sbx pre-prepared header with current data
        self.info_print(" 5.2: Updating SBx header with current data.")
        self.sbx.update_header()

        # 5.3: Compose header that will be signed with final hash
        sbx_header = self.sbx.export_header(self.sbx.sb_commands.final_hash)
        self.store_temp_res("sbx_header_hash.bin", sbx_header, "to_sign")

        # 6: Get signature of sbx file manifest

        if self.sbx.isk_signed and self.sbx.signature_provider:
            self.info_print(" 6: Creating SBx signature using ISK certificate.")
            header_signature = self.sbx.signature_provider.get_signature(sbx_header)
        else:
            self.info_print(" 6: Creating SBx signature on device.")
            header_signature = self.sign_data_blob(sbx_header)
        logger.debug(
            f" 6: The SBx header signature data:\n{format_raw_data(header_signature, use_hexdump=True)}."
        )

        # 7: Merge all parts together
        self.info_print(" 7: Composing final SBx file.")
        self.final_sb = bytes()
        self.final_sb += sbx_header
        self.final_sb += header_signature
        self.final_sb += enc_final_data
        self.store_temp_res("final_sbx.sbx", self.final_sb)
        logger.debug(
            f" 7: The final SBx file data:\n{format_raw_data(self.final_sb, use_hexdump=True)}."
        )

        # 8: Final reset to ensure followup operations (e.g. receive-sb-file) work correctly
        if self.final_reset:
            self.info_print(" 8: Resetting the target device - device will be in ISP mode.")
            self.mboot.reset(timeout=self.RESET_TIMEOUT, reopen=True)
        else:
            self.info_print(" 8: Final target reset disabled")

    def export(self) -> bytes:
        """Get the Final SB file.

        :return: Final SB file in bytes.
        """
        return self.final_sb

    def oem_generate_master_share(
        self, oem_share_input: Optional[bytes] = None
    ) -> tuple[bytes, bytes, bytes]:
        """Generate on device Encrypted OEM master share outputs.

        :param oem_share_input: OEM input (randomize seed)
        :raises SPSDKError: In case of any vulnerability.
        :return: Tuple with OEM generate master share outputs.
        """
        share_input = oem_share_input or self.oem_share_input
        if not share_input:
            raise SPSDKError("OEM SHARE INPUT is not defined")
        if not self.mboot.write_memory(self.get_devbuff_base_address(0), share_input):
            raise SPSDKError("Cannot write OEM SHARE INPUT into device.")

        oem_gen_master_share_res = self.mboot.dsc_hsm_create_session(
            self.get_devbuff_base_address(0),
            self.DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE,
            self.get_devbuff_base_address(1),
            self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE,
        )

        if not oem_gen_master_share_res:
            raise SPSDKError(
                "OEM generate master share command failed,"
                " device probably needs reset due to doubled call of this command."
            )

        oem_enc_share = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE,
        )
        if not oem_enc_share:
            raise SPSDKError("Cannot read OEM ENCRYPTED SHARE OUTPUT from device.")
        self.store_temp_res("ENC_OEM_SHARE.bin", oem_enc_share)

        return oem_enc_share, bytes(), bytes()

    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device."""
        raise SPSDKNotImplementedError("Not implemented")

    def sign_data_blob(self, data_to_sign: bytes) -> bytes:
        """Get HSM encryption sign for data blob.

        :param data_to_sign: Input data to sign.
        :raises SPSDKError: In case of any error.
        :return: Data blob signature (64 bytes).
        """
        if not self.mboot.write_memory(self.get_devbuff_base_address(0), data_to_sign):
            raise SPSDKError("Cannot write Data to sign into device.")

        hsm_gen_key_res = self.mboot.dsc_hsm_enc_sign(
            self.get_devbuff_base_address(0),
            len(data_to_sign),
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )

        if hsm_gen_key_res != self.DEVBUFF_SB_SIGNATURE_SIZE:
            raise SPSDKError("HSM signing command failed.")

        signature = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )
        if not signature:
            raise SPSDKError("Cannot read generated signature from device.")

        self.store_temp_res("sbx_sign.bin", signature, "to_merge")

        return signature

    def encrypt_data_blocks(self, sbx_header: bytes, data_cmd_blocks: list[bytes]) -> list[bytes]:
        """Encrypt all data blocks on device.

        :param sbx_header: Un Encrypted sbx file header.
        :param data_cmd_blocks: List of un-encrypted sbx file command blocks.
        :raises SPSDKError: In case of any vulnerability.
        :return: List of encrypted command blocks on device.
        """
        self.store_temp_res("sbx_header.bin", sbx_header, "to_encrypt")
        if not self.mboot.write_memory(self.get_devbuff_base_address(0), sbx_header):
            raise SPSDKError("Cannot write sbx header into device.")

        encrypted_blocks = []
        for data_cmd_block_ix, data_cmd_block in enumerate(data_cmd_blocks, start=1):
            self.store_temp_res(f"sbx_block_{data_cmd_block_ix}.bin", data_cmd_block, "to_encrypt")
            if not self.mboot.write_memory(self.get_devbuff_base_address(1), data_cmd_block):
                raise SPSDKError(f"Cannot write sbx data block{data_cmd_block_ix} into device.")

            if not self.mboot.dsc_hsm_enc_blk(
                self.get_devbuff_base_address(0),
                len(sbx_header),
                data_cmd_block_ix,
                self.get_devbuff_base_address(1),
                self.DEVBUFF_DATA_BLOCK_SIZE,
            ):
                raise SPSDKError(
                    f"Cannot run sbx data block_{data_cmd_block_ix} HSM Encryption in device."
                )

            encrypted_block = self.mboot.read_memory(
                self.get_devbuff_base_address(1),
                self.DEVBUFF_DATA_BLOCK_SIZE,
            )
            if not encrypted_block:
                raise SPSDKError(f"Cannot read sbx data block_{data_cmd_block_ix} from device.")

            self.store_temp_res(f"sbx_block_{data_cmd_block_ix}.bin", encrypted_block, "encrypted")

            encrypted_blocks.append(encrypted_block)

        return encrypted_blocks

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DevHSM SBx file generation utilities.

This module provides functionality for generating initialization SBx files
for development Hardware Security Module (HSM) operations within the SPSDK
framework.
"""

import logging
from typing import Any, Callable, Optional

from typing_extensions import Self

from spsdk.apps.utils.utils import format_raw_data
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sbx.images import SecureBinaryX
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family

logger = logging.getLogger(__name__)


class DevHsmSBx(DevHsm):
    """Device HSM provisioning manager for SBx containers.

    This class handles the complete device Hardware Security Module (HSM) provisioning
    workflow for SBx secure binary containers, including OEM share management,
    data encryption, signing operations, and secure binary creation.

    :cvar SUB_FEATURE: Identifier for the DevHSM SBx sub-feature.
    :cvar DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE: Buffer size for master encryption share output.
    :cvar DEVBUFF_SB_SIGNATURE_SIZE: Buffer size for secure binary signature data.
    """

    SUB_FEATURE = "DevHsmSBx"

    DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE = 52
    DEVBUFF_SB_SIGNATURE_SIZE = 32

    def __init__(
        self,
        mboot: McuBoot,
        family: FamilyRevision,
        oem_share_input: Optional[bytes] = None,
        oem_enc_master_share_input: Optional[bytes] = None,
        sbx: Optional[SecureBinaryX] = None,
        workspace: Optional[str] = None,
        initial_reset: Optional[bool] = False,
        final_reset: Optional[bool] = True,
        buffer_address: Optional[int] = None,
        info_print: Optional[Callable] = None,
    ) -> None:
        """Initialize device HSM class for creating provisioned SBX files.

        The DeviceHSM class provides functionality to create secure binary files
        using device-based Hardware Security Module capabilities.

        :param mboot: mBoot communication interface for device interaction.
        :param family: Target chip family and revision information.
        :param oem_share_input: OEM share input data, defaults to random 16 bytes if not provided.
        :param oem_enc_master_share_input: OEM encryption master share for recreating security session.
        :param sbx: SBX container object to be processed.
        :param workspace: Optional directory path for storing intermediate results.
        :param initial_reset: Whether to reset device before DevHSM SB3 file creation.
        :param final_reset: Whether to reset device after DevHSM SB3 file creation.
        :param buffer_address: Custom buffer address to override the default value.
        :param info_print: Custom function for printing info messages, defaults to built-in print.
        :raises SPSDKError: When SBX container is not provided or other initialization errors occur.
        """
        if not sbx:
            raise SPSDKError("SBx must be provided")

        super().__init__(family, workspace)

        self.mboot = mboot
        self.oem_share_input = oem_share_input or random_bytes(16)
        self.oem_enc_master_share_input = oem_enc_master_share_input
        self.info_print = info_print or print
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        self.sbx = sbx

        # Override the default buffer address
        if buffer_address is not None:
            self.devbuff_base = buffer_address

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        self.store_temp_res("OEM_SHARE_INPUT.BIN", self.oem_share_input)

        self.final_sb = bytes()

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for DevHSM configuration.

        The method builds validation schemas by combining family-specific schemas, DevHSM common
        configuration schemas, and SBX-related schemas. It also updates the buffer address and
        removes OEM encryption share properties as needed.

        :param family: Family description containing chip family and revision information.
        :return: List of validation schema dictionaries for configuration validation.
        """
        schemas: list[dict[str, Any]] = []
        devhsm_sch_cfg = get_schema_file(DatabaseManager.DEVHSM)
        sbx_sch_cfg = get_schema_file(DatabaseManager.SBX)
        family_sch = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_sch["properties"], cls.get_supported_families(), family
        )
        comm_address = get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        devhsm_sch_cfg["common"]["properties"]["bufferAddress"]["template_value"] = hex(
            comm_address
        )
        devhsm_sch_cfg["common"]["properties"].pop("oemEncShare", None)
        schemas.append(family_sch)
        schemas.append(devhsm_sch_cfg["common"])

        schemas.extend(
            [
                sbx_sch_cfg[x]
                for x in [
                    "sbx",
                    "signer",
                    "sbx_commands",
                ]
            ]
        )

        return schemas

    def __repr__(self) -> str:
        """Return string representation of SBx DevHSM object.

        :return: String identifier for the SBx DevHSM instance.
        """
        return "SBx DevHSM"

    def __str__(self) -> str:
        """Return string representation of the SBx DevHSM instance.

        :return: String containing the family name for which this DevHSM is configured.
        """
        return f"SBx DevHSM for {self.family}"

    def create_sb(self) -> None:
        """Create provisioning SBX file using device HSM process.

        This method orchestrates the complete device HSM workflow to generate a secure
        provisioning SBX file. The process includes target reset, OEM master share
        generation/setting, SBX header creation, data encryption, signature generation,
        and final file composition.

        :raises SPSDKError: When OEM_SHARE or OEM_ENC_MASTER_SHARE is not provided but
                           required for OEM master share creation.
        """
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate OEM share
        if self.oem_enc_master_share_input and self.oem_share_input:
            self.info_print(" 2: Setting OEM master share.")
            oem_enc_share = self.oem_set_master_share(
                oem_seed=self.oem_share_input, enc_oem_share=self.oem_enc_master_share_input
            )
        elif self.oem_share_input:
            self.info_print(" 2: Generating OEM master share.")
            oem_enc_share, _, _ = self.oem_generate_master_share(self.oem_share_input)
        else:
            raise SPSDKError(
                "Creation of OEM MASTER SHARE is enabled but OEM_SHARE (OEM_ENC_MASTER_SHARE) not provided."
            )

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
        """Get the final SB file.

        :return: Final SB file in bytes.
        """
        return self.final_sb

    def oem_generate_master_share(
        self, oem_share_input: Optional[bytes] = None
    ) -> tuple[bytes, bytes, bytes]:
        """Generate on device Encrypted OEM master share outputs.

        This method creates an encrypted OEM master share by writing the input to device memory,
        executing the HSM create session command, and reading back the encrypted share output.

        :param oem_share_input: OEM input data used as randomization seed, if None uses default.
        :raises SPSDKError: If OEM share input is not defined, memory operations fail, or HSM
                            command execution fails.
        :return: Tuple containing encrypted OEM share, empty bytes, and empty bytes.
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
        """Set OEM Master share on the device.

        This method configures the OEM (Original Equipment Manufacturer) master share
        on the target device using either an OEM seed or an encrypted OEM share.

        :param oem_seed: Optional seed value for generating the OEM master share.
        :param enc_oem_share: Optional encrypted OEM share data to be set on device.
        :raises SPSDKNotImplementedError: Method is not yet implemented.
        """
        raise SPSDKNotImplementedError("Not implemented")

    def sign_data_blob(self, data_to_sign: bytes) -> bytes:
        """Sign data blob using HSM encryption.

        This method writes the input data to device buffer, performs HSM encryption signing
        operation, and retrieves the generated signature from the device.

        :param data_to_sign: Input data bytes to be signed by HSM.
        :raises SPSDKError: If writing data to device fails, HSM signing command fails,
            or reading signature from device fails.
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
        """Encrypt all data blocks using device HSM functionality.

        The method writes the SBX header and each data command block to device memory,
        performs HSM encryption on each block, and retrieves the encrypted results.
        Temporary files are stored for debugging purposes during the encryption process.

        :param sbx_header: Unencrypted SBX file header bytes.
        :param data_cmd_blocks: List of unencrypted SBX file command blocks.
        :raises SPSDKError: Memory write/read operation failure or HSM encryption failure.
        :return: List of encrypted command blocks from device.
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

    @classmethod
    def load_from_config(
        cls, config: Config, mboot: Optional[McuBoot] = None, info_print: Optional[Callable] = None
    ) -> Self:
        """Load the class from configuration.

        Creates a DEVHSM SB3.1 instance from the provided configuration, extracting all necessary
        parameters including family settings, cryptographic keys, and operational parameters.

        :param config: DEVHSM configuration file containing all setup parameters.
        :param mboot: Optional mBoot interface object for device communication.
        :param info_print: Optional callback function for printing informational messages.
        :raises SPSDKError: When mboot parameter is not provided.
        :return: Configured DEVHSM SB3.1 class instance.
        """
        if not mboot:
            raise SPSDKError("Mboot must be defined to load DEVHSM SB3.1 class.")

        family = FamilyRevision.load_from_config(config)

        oem_share_in = (
            config.load_symmetric_key(
                key="oemRandomShare", expected_size=16, name="OEM SHARE INPUT"
            )
            if "oemRandomShare" in config
            else None
        )
        enc_oem_master_share_in = (
            config.load_symmetric_key(
                key="oemEncMasterShare", expected_size=64, name="OEM ENC MASTER SHARE"
            )
            if "oemEncMasterShare" in config
            else None
        )

        buffer_address = config.get_int(
            "bufferAddress", get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        )

        sbx = SecureBinaryX.load_from_config(config)
        return cls(
            mboot=mboot,
            family=family,
            oem_share_input=oem_share_in,
            oem_enc_master_share_input=enc_oem_master_share_in,
            sbx=sbx,
            workspace=config.get_output_file_name("workspace") if "workspace" in config else None,
            initial_reset=config.get("initialReset", False),
            final_reset=config.get("finalReset", True),
            buffer_address=buffer_address,
            info_print=info_print,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented in base class.
        """
        raise SPSDKNotImplementedError()

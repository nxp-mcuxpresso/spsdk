#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SBc file."""

import logging
from typing import Any, Callable, Optional

from typing_extensions import Self

from spsdk.apps.utils.utils import format_raw_data
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.image.cert_block.cert_blocks import CertificateBlockHeaderV2_2
from spsdk.mboot.commands import TrustProvOemKeyType, TrustProvOperation
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sb31.commands import CmdLoadKeyBlob
from spsdk.sbfile.sbc.images import SecureBinaryC, SecureBinaryCHeader
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


class DevHsmSBc(DevHsm):
    """Class to handle device HSM provisioning procedure for SBc."""

    SUB_FEATURE = "DevHsmSBc"

    # Buffer sizes and offsets
    SIGNATURE_SIZE = 16
    OEM_SHARE_OUTPUT_SIZE = 48
    KEY_SIZE = 24
    KEY_WRAPPING_OVERHEAD = 8

    def __init__(
        self,
        mboot: McuBoot,
        family: FamilyRevision,
        oem_share_input: Optional[bytes] = None,
        sbc: Optional[SecureBinaryC] = None,
        workspace: Optional[str] = None,
        initial_reset: Optional[bool] = False,
        final_reset: Optional[bool] = True,
        buffer_address: Optional[int] = None,
        info_print: Optional[Callable] = None,
    ) -> None:
        """Initialization of device HSM class. It's designed to create provisioned sbc file.

        :param mboot: mBoot communication interface.
        :param family: chip family
        :param oem_share_input: OEM share input - either the provided value or a randomly generated 16 bytes seed
        :param sbc: SBC container.
        :param workspace: Optional folder to store middle results.
        :param initial_reset: Reset device before DevHSM creation of SBc file.
        :param final_reset: Reset device after DevHSM creation of SBc file.
        :param buffer_address: Override the default buffer address.
        :param info_print: Method for printing out info messages. Default: built-in print
        :raises SPSDKError: In case of any problem.
        """
        if not sbc:
            raise SPSDKError("SBc must be provided")

        super().__init__(family, workspace)

        self.mboot = mboot
        self.oem_share_input = oem_share_input or random_bytes(16)

        self.info_print = info_print or print
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        self.sbc = sbc

        # Override the default buffer address
        if buffer_address is not None:
            self.devbuff_base = buffer_address

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        self.store_temp_res("OEM_SHARE_INPUT.bin", self.oem_share_input)

        self.final_sb = bytes()

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
        """
        schemas: list[dict[str, Any]] = []
        sbc_sch_cfg = get_schema_file(DatabaseManager.SBC)
        family_sch = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_sch["properties"], cls.get_supported_families(), family
        )
        comm_address = get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        sbc_sch_cfg["common"]["properties"]["bufferAddress"]["template_value"] = hex(comm_address)
        schemas.append(family_sch)
        schemas.append(sbc_sch_cfg["common"])

        schemas.extend(
            [
                sbc_sch_cfg[x]
                for x in [
                    "sbc_commands",
                ]
            ]
        )

        return schemas

    def create_sb(self) -> None:
        """Do device hsm process to create provisioning SBC file."""
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate OEM share
        if self.oem_share_input:
            self.info_print(" 2: Generating OEM master share.")
            oem_enc_share, _, _ = self.oem_generate_master_share(self.oem_share_input)
        else:
            raise SPSDKError("Generation of OEM MASTER SHARE failed.")

        # 3: Call hsm_gen_key to generate signing key
        self.info_print(" 3: Generating signing key.")
        cust_fw_auth = self.generate_key(
            TrustProvOemKeyType.MFWISK, self.get_devbuff_base_address(4), "CUST_FW_AUTH"
        )

        # 4: Call hsm_gen_key to generate encryption key
        self.info_print(" 4: Generating encryption key.")
        cust_fw_enc = self.generate_key(
            TrustProvOemKeyType.ENCKEY, self.get_devbuff_base_address(6), "CUST_FW_ENC_SK"
        )

        # 5: Create SBc header
        self.info_print(" 5: Creating template SBc header.")

        sbc_header = SecureBinaryCHeader()
        sbc_header_exported = sbc_header.export()
        logger.debug(f" 5.1: The template SBc header: \n{str(sbc_header)} \n")
        self.store_temp_res("sbc_header.bin", sbc_header_exported)

        # 6: Create dummy certificati block header part of SBc
        self.info_print(" 6: Creating dummy certificate block header part of SBc.")
        cb_header = CertificateBlockHeaderV2_2()
        cb_header_exported = cb_header.export()
        cb_header_exported += oem_enc_share
        logger.debug(f" 6.1: The dummy certificate block has been created:\n{str(cb_header)}.")
        logger.debug(
            f" 6.2: The template cert: \n{str(cb_header)} \n Length:{len(cb_header_exported)}"
        )
        self.store_temp_res("cb_header.bin", cb_header_exported)

        # 7: Export unencrypted SBc data blocks
        self.info_print(" 7: Created unencrypted SBc data")
        logger.info(f"\n SBc data: \n{str(self.sbc)}\n")
        # 7.1: Handle load key blob commands
        for command in self.sbc.sb_commands.commands:
            if isinstance(command, CmdLoadKeyBlob):
                self.info_print(" 7.1: Handle load key blob commands")
                command.data = self.wrap_key(command.data)
                self.store_temp_res("wrapped_key.bin", command.data, "wrapped_key")
        # 7.2: Get sbc file data part individual chunks
        self.info_print(" 7.2: Get SBc file data part individual chunks")
        data_cmd_blocks = self.sbc.sb_commands.get_cmd_blocks_to_export()

        # 7.2: Get sbc header without signature
        sbc_header_no_sign = self.sbc.export_header()
        # add blank signature
        sbc_header_no_sign += bytes(self.SIGNATURE_SIZE)
        self.store_temp_res("sbc_header_no_sign.bin", sbc_header_no_sign, "sbc_header_no_sign")
        # 8: Call hsm_enc_blk to encrypt all the data chunks from step 7.2. Use FW encryption key from step 4.
        self.info_print(" 8: Encrypting SBc data on device")
        sbc_enc_data = self.encrypt_data_blocks(
            cust_fw_enc, (sbc_header_no_sign + cb_header_exported), data_cmd_blocks
        )

        # 8.1: Calculate SHA-256 hashes of encrypted data
        self.info_print(" 8.1: Calculating SHA-256 hashes of encrypted data.")
        enc_final_data = self.sbc.sb_commands.process_cmd_blocks_to_export(sbc_enc_data)
        self.store_temp_res("Final_data.bin", enc_final_data, "to_merge")

        # 8.2: Update the sbc pre-prepared header with current data
        self.info_print(" 8.2: Updating SBc header with current data.")
        self.sbc.update_header()

        # 8.3: Compose header that will be signed with final hash
        self.info_print(" 8.2: Compose header with final hash.")
        sbc_header_to_be_signed = self.sbc.export_header(self.sbc.sb_commands.final_hash)
        self.store_temp_res("sbc_header_hash.bin", sbc_header_to_be_signed, "to_sign")

        # 9: Get signature of sbc file manifest
        self.info_print(" 9: Creating SBc signature on device.")

        header_signature = self.sign_data_blob(
            sbc_header_to_be_signed + cb_header_exported, cust_fw_auth
        )
        logger.debug(
            f" 9.1: The SBc header signature data:\n{format_raw_data(header_signature, use_hexdump=True)}."
        )

        # 10: Merge all parts together
        self.info_print(" 10: Composing final SBc file.")
        self.final_sb = bytes()
        self.final_sb += sbc_header_to_be_signed
        self.final_sb += cb_header_exported
        self.final_sb += header_signature
        self.final_sb += enc_final_data
        self.store_temp_res("final_sbc.bin", self.final_sb)
        logger.debug(
            f" 10.1: The final SBc file data:\n{format_raw_data(self.final_sb, use_hexdump=True)}."
        )

        # 11: Final reset to ensure followup operations (e.g. receive-sb-file) work correctly
        if self.final_reset:
            self.info_print(" 11: Resetting the target device - device will be in ISP mode.")
            self.mboot.reset(timeout=self.RESET_TIMEOUT, reopen=True)
        else:
            self.info_print(" 11: Final target reset disabled")

    def wrap_key(self, key_data: bytes) -> bytes:
        """Wrap key data for secure transmission.

        :param key_data: Raw key data to be wrapped
        :return: Wrapped key data
        :raises SPSDKError: If wrapping fails or returning None
        """
        if not self.mboot.write_memory(self.get_devbuff_base_address(4), key_data):
            raise SPSDKError("Cannot write into device.")
        oem_hsm_store_key_resp = self.mboot.tp_hsm_store_key(
            key_type=TrustProvOperation.HSM_ENC_BLOCK.tag,
            key_property=0,
            key_input_addr=self.get_devbuff_base_address(4),
            key_input_size=len(key_data),
            key_blob_output_addr=self.get_devbuff_base_address(5),
            key_blob_output_size=len(key_data) + self.KEY_WRAPPING_OVERHEAD,
        )
        if not oem_hsm_store_key_resp:
            raise SPSDKError(f"Cannot store key in HSM device. Error: {self.mboot.status_string}")
        wrapped_key = self.mboot.read_memory(
            self.get_devbuff_base_address(5),
            len(key_data) + self.KEY_WRAPPING_OVERHEAD,
        )
        if wrapped_key is None:
            raise SPSDKError("Failed to read wrapped key from device")
        return wrapped_key

    def export(self) -> bytes:
        """Get the Final SB file.

        :return: Final SB file in bytes.
        """
        return self.final_sb

    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device.

        :raises SPSDKNotImplementedError: Always raised as this operation is not supported.
        """
        raise SPSDKNotImplementedError("Not supported for SBc provisioning")

    def oem_generate_master_share(self, oem_share_input: bytes) -> tuple[bytes, bytes, bytes]:
        """Generate on device Encrypted OEM master share outputs.

        :param oem_share_input: OEM input (randomize seed)
        :raises SPSDKError: In case of any vulnerability.
        :return: Tuple with OEM generate master share outputs.
        """
        if not oem_share_input:
            raise SPSDKError("OEM SHARE INPUT is not defined")
        if not self.mboot.write_memory(self.devbuff_base, oem_share_input):
            raise SPSDKError("Cannot write OEM SHARE INPUT into device.")

        oem_gen_master_share_res = self.mboot.tp_oem_gen_master_share(
            oem_share_input_addr=self.devbuff_base,
            oem_share_input_size=self.DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE,
            oem_enc_share_output_addr=self.get_devbuff_base_address(1),
            oem_enc_share_output_size=self.OEM_SHARE_OUTPUT_SIZE,
            oem_enc_master_share_output_addr=self.get_devbuff_base_address(2),
            oem_enc_master_share_output_size=self.DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE,
            oem_cust_cert_puk_output_addr=0,
            oem_cust_cert_puk_output_size=0,
        )
        if not oem_gen_master_share_res:
            raise SPSDKError(
                "OEM generate master share command failed,"
                " device probably needs reset due to doubled call of this command."
            )

        oem_enc_share = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.OEM_SHARE_OUTPUT_SIZE,
        )
        if not oem_enc_share:
            raise SPSDKError(
                f"Failed to read OEM encrypted share from address {self.get_devbuff_base_address(1)}. "
                f"Device status: {self.mboot.status_string}"
            )
        self.store_temp_res("ENC_OEM_SHARE.bin", oem_enc_share)

        return oem_enc_share, bytes(), bytes()

    def sign_data_blob(self, data_to_sign: bytes, key: bytes) -> bytes:
        """Get HSM encryption sign for data blob.

        :param data_to_sign: Input data to sign.
        :param key: Signing key.
        :raises SPSDKError: In case of any error.
        :return: Data blob signature (64 bytes).
        """
        self.mboot.write_memory(self.get_devbuff_base_address(7), key)
        if not self.mboot.write_memory(self.get_devbuff_base_address(8), data_to_sign):
            raise SPSDKError("Cannot write Data to sign into device.")

        hsm_gen_key_res = self.mboot.tp_hsm_enc_sign(
            key_blob_input_addr=self.get_devbuff_base_address(7),
            key_blob_input_size=len(key),
            block_data_input_addr=self.get_devbuff_base_address(8),
            block_data_input_size=len(data_to_sign),
            signature_output_addr=self.get_devbuff_base_address(9),
            signature_output_size=self.SIGNATURE_SIZE,
        )

        if hsm_gen_key_res != self.SIGNATURE_SIZE:
            raise SPSDKError("HSM signing command failed.")

        signature = self.mboot.read_memory(
            self.get_devbuff_base_address(9),
            self.SIGNATURE_SIZE,
        )
        if not signature:
            raise SPSDKError("Cannot read generated signature from device.")

        self.store_temp_res("sbc_sign.bin", signature, "to_merge")

        return signature

    def encrypt_data_blocks(
        self, cust_fw_enc_key: bytes, sbc_header: bytes, data_cmd_blocks: list[bytes]
    ) -> list[bytes]:
        """Encrypt all data blocks on device.

        :param sbc_header: Un Encrypted sbc file header.
        :param cust_fw_enc_key: Firmware encryption key.
        :param data_cmd_blocks: List of un-encrypted sbc file command blocks.
        :raises SPSDKError: In case of any vulnerability.
        :return: List of encrypted command blocks on device.
        """
        if not self.mboot.write_memory(self.get_devbuff_base_address(9), cust_fw_enc_key):
            raise SPSDKError(
                f"Cannot write customer fw encryption key into device. Error: {self.mboot.status_string}"
            )
        self.store_temp_res("sbc_header.bin", sbc_header, "to_encrypt")
        if not self.mboot.write_memory(self.get_devbuff_base_address(0), sbc_header):
            raise SPSDKError("Cannot write sbc header into device.")

        encrypted_blocks = []
        for data_cmd_block_ix, data_cmd_block in enumerate(data_cmd_blocks, start=1):
            self.store_temp_res(f"sbc_block_{data_cmd_block_ix}.bin", data_cmd_block, "to_encrypt")
            if not self.mboot.write_memory(self.get_devbuff_base_address(1), data_cmd_block):
                raise SPSDKError(f"Cannot write sbc data block{data_cmd_block_ix} into device.")

            key_id = CmdLoadKeyBlob.get_key_id(
                self.family, CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_INT_SK
            )

            if not self.mboot.tp_hsm_enc_blk(
                mfg_cust_mk_sk_0_blob_input_addr=self.get_devbuff_base_address(9),
                mfg_cust_mk_sk_0_blob_input_size=len(cust_fw_enc_key),
                kek_id=key_id,
                sb3_header_input_addr=self.devbuff_base,
                sb3_header_input_size=len(sbc_header),
                block_num=data_cmd_block_ix,
                block_data_addr=self.get_devbuff_base_address(1),
                block_data_size=self.DEVBUFF_DATA_BLOCK_SIZE,
            ):
                raise SPSDKError(
                    f"Cannot run sbc data block_{data_cmd_block_ix} HSM Encryption in device."
                )

            encrypted_block = self.mboot.read_memory(
                self.get_devbuff_base_address(1),
                self.DEVBUFF_DATA_BLOCK_SIZE,
            )
            if not encrypted_block:
                raise SPSDKError(f"Cannot read sbc data block_{data_cmd_block_ix} from device.")

            self.store_temp_res(f"sbc_block_{data_cmd_block_ix}.bin", encrypted_block, "encrypted")

            encrypted_blocks.append(encrypted_block)

        return encrypted_blocks

    @classmethod
    def load_from_config(
        cls, config: Config, mboot: Optional[McuBoot] = None, info_print: Optional[Callable] = None
    ) -> Self:
        """Load the class from configuration.

        :param config: DEVHSM configuration file
        :param mboot: mBoot object
        :param info_print: Optional info print method
        :return: DEVHSM SBc class
        """
        if not mboot:
            raise SPSDKError("Mboot must be defined to load DEVHSM SBc class.")

        family = FamilyRevision.load_from_config(config)

        buffer_address = config.get_int(
            "bufferAddress", get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        )

        oem_share_input = (
            load_binary(config.get_input_file_name("oemRandomShare"))
            if "oemRandomShare" in config
            else None
        )
        sbc = SecureBinaryC.load_from_config(config)
        return cls(
            mboot=mboot,
            family=family,
            sbc=sbc,
            oem_share_input=oem_share_input,
            workspace=config.get_output_file_name("workspace") if "workspace" in config else None,
            initial_reset=config.get("initialReset", False),
            final_reset=config.get("finalReset", False),
            buffer_address=buffer_address,
            info_print=info_print,
        )

    def generate_key(
        self, key_type: TrustProvOemKeyType, address: int, key_name: Optional[str] = None
    ) -> bytes:
        """Generate on device key of provided type.

        :param key_type: Type of generated key.
        :param address: Keyblob output address.
        :param key_name: Optional name for storing temporary files.
        :raises SPSDKError: In case of any vulnerability.
        :return: Key.
        """
        hsm_gen_key_res = self.mboot.tp_hsm_gen_key(
            key_type=key_type.tag,
            reserved=0,
            key_blob_output_addr=address,
            key_blob_output_size=self.KEY_SIZE,
            ecdsa_puk_output_addr=0x0,
            ecdsa_puk_output_size=0x0,
        )

        if not hsm_gen_key_res:
            raise SPSDKError(f"HSM generate key command failed. Error: {self.mboot.status_string}")

        key = self.mboot.read_memory(
            address,
            self.KEY_SIZE,
        )
        if not key:
            raise SPSDKError(
                f"Cannot read generated key from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res((key_name or key_type.label) + "_key.bin", key)

        return key

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError()

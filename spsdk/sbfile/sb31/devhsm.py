#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SB file."""

import copy
import logging
from typing import Any, Callable, Optional

from typing_extensions import Self

from spsdk.apps.utils.utils import format_raw_data
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.image.cert_block.cert_blocks import CertificateBlockHeader
from spsdk.mboot.commands import TrustProvKeyType, TrustProvOemKeyType
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sb31.commands import BaseCmd, CmdLoadKeyBlob
from spsdk.sbfile.sb31.constants import EnumDevHSMType
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Commands, SecureBinary31Header
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class DevHsmSB31(DevHsm):
    """Class to handle device HSM provisioning procedure for SB3.1."""

    SUB_FEATURE = "DevHsmSB31"

    def __init__(
        self,
        mboot: McuBoot,
        family: FamilyRevision,
        oem_share_input: Optional[bytes] = None,
        oem_enc_master_share_input: Optional[bytes] = None,
        cust_mk_sk: Optional[bytes] = None,
        commands: Optional[list[BaseCmd]] = None,
        workspace: Optional[str] = None,
        initial_reset: Optional[bool] = False,
        final_reset: Optional[bool] = True,
        buffer_address: Optional[int] = None,
        info_print: Optional[Callable] = None,
    ) -> None:
        """Initialization of device HSM class. Its design to create provisioned SB3 file.

        :param mboot: mBoot communication interface.
        :param family: chip family
        :param oem_share_input: OEM share input data (if None a random input will be generated).
        :param oem_enc_master_share_input: Used for setting the OEM share (recreating security session)
        :param cust_mk_sk: Customer Master Key Symmetric Key.
        :param commands: Optional user list of SB commands.
        :param workspace: Optional folder to store middle results.
        :param initial_reset: Reset device before DevHSM creation of SB3 file.
        :param final_reset: Reset device after DevHSM creation of SB3 file.
        :param buffer_address: Override the default buffer address.
        :param info_print: Method for printing out info messages. Default: print
        :raises SPSDKError: In case of any problem.
        """
        super().__init__(family, workspace)
        self.mboot = mboot
        self.cust_mk_sk = cust_mk_sk
        self.oem_share_input = oem_share_input or random_bytes(16)
        self.oem_enc_master_share_input = oem_enc_master_share_input
        self.info_print = info_print or print
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        # Check the configuration file and options to update by user config
        self.sb3_fw_ver = 0
        self.sb3_descr = "SB 3.1"
        self.additional_commands = commands
        self.timestamp: Optional[int] = None

        # Override the default buffer address
        if buffer_address is not None:
            self.devbuff_base = buffer_address

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        if self.oem_share_input:
            self.store_temp_res("OEM_SHARE_INPUT.BIN", self.oem_share_input)

        self.wrapped_cust_mk_sk = bytes()
        self.final_sb = bytes()

    def __repr__(self) -> str:
        return "SB 3.1 DevHSM"

    def __str__(self) -> str:
        return f"SB 3.1 DevHSM for {self.family}"

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, include_test_configuration: bool = False
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas.
        """
        schemas: list[dict[str, Any]] = []
        common_schema = cls.get_validation_schemas_common(family=family)
        schemas.extend(common_schema)

        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        schemas.extend(SecureBinary31.get_devhsm_commands_validation_schemas(family))

        if include_test_configuration:
            schemas.append(sb3_sch_cfg["sb3_test"])

        return schemas

    @classmethod
    def get_validation_schemas_common(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation with common DevHSM settings (without commands)."""
        devhsm_sch_cfg = get_schema_file(DatabaseManager.DEVHSM)
        family_sch = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_sch["properties"], cls.get_supported_families(), family
        )
        comm_address = get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        devhsm_sch_cfg["common"]["properties"]["bufferAddress"]["template_value"] = hex(
            comm_address
        )
        devhsm_sch_cfg["common"]["properties"].pop("oemEncShare", None)
        return [family_sch, devhsm_sch_cfg["common"], devhsm_sch_cfg["cust_mk_sk"]]

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get feature configuration template.

        :param family: Family for which the template should be generated.
        :return: Template file string representation.
        """
        try:
            recommended_flow = get_db(family).get_list(DatabaseManager.DEVHSM, "recommended_flow")
            schemas = cls.get_validation_schemas_common(family=family)
        except SPSDKError:
            recommended_flow = None
            schemas = cls.get_validation_schemas(family)

        yaml_data = CommentedConfig(
            f"DEVHSM procedure Secure Binary v3.1 Configuration template for {family}.",
            schemas,
        ).get_template()

        if recommended_flow:
            yaml_data += cls.render_recommended_flow(flow=recommended_flow)
            yaml_data += cls.render_available_commands(family=family)

        return yaml_data

    @classmethod
    def render_recommended_flow(cls, flow: list[dict]) -> str:
        """Textual rendering of steps in recommended flow."""
        templates = get_schema_file(DatabaseManager.DEVHSM)
        result = "\n" + templates["subTitle"]
        # we meed a copy or else the .popitem will corrupt the database
        for step in copy.deepcopy(flow):
            name, params = step.popitem()
            temp: Optional[str] = templates.get(name)
            if not temp:
                raise SPSDKError(f"Template for step {step} not found in database")
            result += temp.format(**params)
        return result

    @classmethod
    def render_available_commands(cls, family: FamilyRevision) -> str:
        """Textual rendering of available commands."""
        # sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        sb31_schemas = SecureBinary31.get_devhsm_commands_validation_schemas(family)
        schemas: list[dict] = sb31_schemas[0]["properties"]["commands"]["items"]["oneOf"]
        for sh in schemas:
            sh.pop("required")
        yaml_data = CommentedConfig("Available commands", schemas).get_template().splitlines()
        for _ in range(3):
            yaml_data.pop(2)
        yaml_data = [line if line.startswith("#") else f"# {line}" for line in yaml_data]
        return "\n" + "\n".join(yaml_data)

    def create_sb(self) -> None:
        """Do device hsm process to create SB_KEK provisioning SB file."""
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate encOemShare.bin (ENC_OEM_SHARE will be later put in place of ISK)
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

        # 3: Call hsm_gen_key to generate 48 bytes FW signing key
        self.info_print(" 3: Generating 48 bytes FW signing keys.")
        cust_fw_auth_prk, cust_fw_auth_puk = self.generate_key(
            TrustProvOemKeyType.MFWISK, "CUST_FW_AUTH"
        )

        # 4: Call hsm_gen_key to generate 48 bytes FW encryption key
        self.info_print(" 4: Generating 48 bytes FW encryption keys.")
        cust_fw_enc_prk, _ = self.generate_key(TrustProvOemKeyType.MFWENCK, "CUST_FW_ENC_SK")

        # 5: Generate template sb3 fw, sb3ImageType=6
        self.info_print(" 5: Creating template un-encrypted SB3 header and data blobs.")
        # 5.1: Generate SB3.1 header template
        self.info_print(" 5.1: Creating template SB3 header.")
        sb3_header = SecureBinary31Header(
            firmware_version=self.sb3_fw_ver,
            hash_type=EnumHashAlgorithm.SHA256,
            description=self.sb3_descr,
            flags=0x01,  # Bit0: PROV_MFW: when set, the SB3 file encrypts provisioning firmware
        )
        self.timestamp = sb3_header.timestamp
        sb3_header_exported = sb3_header.export()
        logger.debug(
            f" 5.1: The template SB3 header: \n{str(sb3_header)} \n Length:{len(sb3_header_exported)}"
        )

        # 5.2: Create SB3 file un-encrypted data part
        self.info_print(" 5.2: Creating un-encrypted SB3 data.")
        sb3_data = SecureBinary31Commands(family=self.family, hash_type=EnumHashAlgorithm.SHA256)
        if self.additional_commands:
            for cmd in self.additional_commands:
                sb3_data.add_command(cmd)

        cust_mk_sk_blob_found = False
        self.info_print(" 5.3 Looking for plaintext keys to wrap")
        for command in sb3_data.commands:
            if isinstance(command, CmdLoadKeyBlob):
                if command.plain_input:
                    self.info_print(" 5.3.1 PlainText keyblob found, performing key wrapping")
                    command.data = self.wrap_key(command.data)
                if command.address == self.get_keyblob_offset():
                    cust_mk_sk_blob_found = True

        self.info_print(" 5.4 Handling CUST_MK_SK/SBKEK keyblob")
        if cust_mk_sk_blob_found:
            self.info_print(" 5.4.1 CUST_MK_SK/SBKEK key blob found in configuration")
        elif self.cust_mk_sk:
            self.info_print(" 5.4.1 Injecting wrapped key")

            self.info_print(" 5.4.2: Wrapping CUST_MK_SK key.")
            self.wrapped_cust_mk_sk = self.wrap_key(self.cust_mk_sk)
            self.info_print(" 5.4.3: Adding wrapped CUST_MK_SK LoadKeyBlob command into SB file.")
            sb3_data.insert_command(
                index=self.get_keyblob_position(),
                command=CmdLoadKeyBlob(
                    offset=self.get_keyblob_offset(),
                    data=self.wrapped_cust_mk_sk,
                    key_wrap_id=CmdLoadKeyBlob.get_key_id(
                        family=self.family, key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK
                    ),
                ),
            )
        else:
            self.info_print(" 5.4: CUST_MK_SK/SBKEK not provided. Key provisioning is skipped.")
            logger.warning((" 5.4 CUST_MK_SK/SBKEK not provided. Key provisioning is skipped."))

        logger.debug(f" 5.5: Created un-encrypted SB3 data: \n{str(sb3_data)}")
        # 5.4: Get SB3 file data part individual chunks
        data_cmd_blocks = sb3_data.get_cmd_blocks_to_export()

        # 6: Call hsm_enc_blk to encrypt all the data chunks from step 5. Use FW encryption key from step 3.
        self.info_print(" 6: Encrypting SB3 data on device")
        sb3_enc_data = self.encrypt_data_blocks(
            cust_fw_enc_prk, sb3_header_exported, data_cmd_blocks
        )
        # 6.1: Add to encrypted data parts SHA256 hashes
        self.info_print(" 6.1: Enriching encrypted SB3 data by mandatory hashes.")
        enc_final_data = sb3_data.process_cmd_blocks_to_export(sb3_enc_data)
        self.store_temp_res("Final_data.bin", enc_final_data, "to_merge")

        # 6.2: Create dummy certification part of SB3 manifest
        self.info_print(" 6.2: Creating dummy certificate block.")
        cb_header = CertificateBlockHeader()
        cb_header.cert_block_size = (
            cb_header.SIZE + 68 + self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE
        )
        logger.debug(f" 6.2: The dummy certificate block has been created:\n{str(cb_header)}.")

        # 6.3: Update the SB3 pre-prepared header by current data
        self.info_print(" 6.3: Updating SB3 header by valid values.")
        sb3_header.block_count = sb3_data.block_count
        sb3_header.image_total_length += (
            len(sb3_data.final_hash) + cb_header.cert_block_size + self.DEVBUFF_SB_SIGNATURE_SIZE
        )
        logger.debug(f" 6.3: The SB3 header has been updated by valid values:\n{str(sb3_header)}.")

        # 6.4: Compose manifest that will be signed
        self.info_print(" 6.4: Preparing SB3 manifest to sign.")
        manifest_to_sign = bytes()
        if self.database.get_int(self.F_DEVHSM, "flag") == EnumDevHSMType.EXTERNAL.tag:
            sb3_header.flags = EnumDevHSMType.EXTERNAL.tag
        manifest_to_sign += sb3_header.export()
        manifest_to_sign += sb3_data.final_hash
        manifest_to_sign += cb_header.export()
        manifest_to_sign += (
            b"\x11\x00\x00\x80"  # 0x80000011  Cert Flags: CA Flag, 1 certificate and NIST P-256
        )
        manifest_to_sign += cust_fw_auth_puk
        manifest_to_sign += oem_enc_share
        self.store_temp_res("manifest_to_sign.bin", manifest_to_sign, "to_merge")
        logger.debug(
            f" 6.4: The SB3 manifest data to sign:\n{format_raw_data(manifest_to_sign, use_hexdump=True)}."
        )

        # 7: Get sign of SB3 file manifest
        self.info_print(" 7: Creating SB3 manifest signature on device.")
        manifest_signature = self.sign_data_blob(manifest_to_sign, cust_fw_auth_prk)
        logger.debug(
            f" 7: The SB3 manifest signature data:\n{format_raw_data(manifest_signature, use_hexdump=True)}."
        )

        # 8: Merge all parts together
        self.info_print(" 8: Composing final SB3 file.")
        self.final_sb = bytes()
        self.final_sb += manifest_to_sign
        self.final_sb += manifest_signature
        self.final_sb += enc_final_data
        self.store_temp_res("Final_SB3.sb3", self.final_sb)
        logger.debug(
            f" 8: The final SB3 file data:\n{format_raw_data(self.final_sb, use_hexdump=True)}."
        )

        # 9: Final reset to ensure followup operations (e.g. receive-sb-file) work correctly
        if self.final_reset:
            self.info_print(" 9: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT, reopen=False)
        else:
            self.info_print(" 9: Final target reset disabled")

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
        if not self.mboot.write_memory(self.devbuff_base, share_input):
            raise SPSDKError(
                f"Cannot write OEM SHARE INPUT into device. Error: {self.mboot.status_string}"
            )

        oem_gen_master_share_res = self.mboot.tp_oem_gen_master_share(
            self.devbuff_base,
            self.DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE,
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SIZE,
            self.get_devbuff_base_address(2),
            self.DEVBUFF_SIZE,
            self.get_devbuff_base_address(3),
            self.DEVBUFF_SIZE,
        )

        if not oem_gen_master_share_res:
            raise SPSDKError(
                f"OEM generate master share command failed. Error: {self.mboot.status_string}\n"
                "Device probably needs reset due to doubled call of this command."
            )

        if (
            oem_gen_master_share_res[0] != self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE
            and oem_gen_master_share_res[1] != self.DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE
            and oem_gen_master_share_res[2] != self.DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE
        ):
            raise SPSDKError("OEM generate master share command has invalid results.")

        oem_enc_share = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE,
        )
        if not oem_enc_share:
            raise SPSDKError(
                f"Cannot read OEM ENCRYPTED SHARE OUTPUT from device. Error: {self.mboot.status_string}"
            )
        self.store_temp_res("ENC_OEM_SHARE.bin", oem_enc_share)

        oem_enc_master_share = self.mboot.read_memory(
            self.get_devbuff_base_address(2),
            self.DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE,
        )
        if not oem_enc_master_share:
            raise SPSDKError(
                f"Cannot read OEM ENCRYPTED MASTER SHARE OUTPUT from device. Error: {self.mboot.status_string}"
            )
        self.store_temp_res("ENC_OEM_MASTER_SHARE.bin", oem_enc_master_share)

        oem_cert = self.mboot.read_memory(
            self.get_devbuff_base_address(3),
            self.DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE,
        )
        if not oem_cert:
            raise SPSDKError(
                f"Cannot read OEM CERTIFICATE from device. Error: {self.mboot.status_string}"
            )
        self.store_temp_res("OEM_CERT.bin", oem_cert)

        return oem_enc_share, oem_enc_master_share, oem_cert

    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device."""
        oem_seed_input = oem_seed or self.oem_share_input
        oem_master_input = enc_oem_share or self.oem_enc_master_share_input
        if not oem_seed_input or not oem_master_input:
            raise SPSDKError("OEM SHARE INPUT and/or OEM ENC MASTER SHARE is/are not defined.")
        if not self.mboot.write_memory(
            address=self.get_devbuff_base_address(0), data=oem_seed_input
        ):
            raise SPSDKError(
                f"Cannot write OEM SHARE INPUT into device. Error: {self.mboot.status_string}"
            )
        if not self.mboot.write_memory(
            address=self.get_devbuff_base_address(1), data=oem_master_input
        ):
            raise SPSDKError(
                f"Cannot write OEM ENC MASTER SHARE into device. Error: {self.mboot.status_string}"
            )

        result = self.mboot.tp_oem_set_master_share(
            oem_share_input_addr=self.get_devbuff_base_address(0),
            oem_share_input_size=self.DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE,
            oem_enc_master_share_input_addr=self.get_devbuff_base_address(1),
            oem_enc_master_share_input_size=self.DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE,
        )
        if not result:
            raise SPSDKError(f"Cannot set OEM SHARE. Error: {self.mboot.status_string}")

        return oem_master_input[: self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE]

    def generate_key(
        self, key_type: TrustProvOemKeyType, key_name: Optional[str] = None
    ) -> tuple[bytes, bytes]:
        """Generate on device key pairs of provided type.

        :param key_type: Type of generated key pairs.
        :param key_name: optional name for storing temporary files.
        :raises SPSDKError: In case of any vulnerability.
        :return: Tuple with Private and Public key.
        """
        hsm_gen_key_res = self.mboot.tp_hsm_gen_key(
            key_type.tag,
            0,
            self.devbuff_base,
            self.DEVBUFF_SIZE,
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SIZE,
        )

        if not hsm_gen_key_res:
            raise SPSDKError(f"HSM generate key command failed. Error: {self.mboot.status_string}")

        if (
            hsm_gen_key_res[0] != self.DEVBUFF_HSM_GENKEY_KEYBLOB_SIZE
            and hsm_gen_key_res[1] != self.DEVBUFF_HSM_GENKEY_KEYBLOB_PUK_SIZE
        ):
            raise SPSDKError("OEM generate master share command has invalid results.")

        prk = self.mboot.read_memory(
            self.devbuff_base,
            self.DEVBUFF_HSM_GENKEY_KEYBLOB_SIZE,
        )
        if not prk:
            raise SPSDKError(
                f"Cannot read generated private key from device. Error: {self.mboot.status_string}"
            )

        puk = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_HSM_GENKEY_KEYBLOB_PUK_SIZE,
        )
        if not puk:
            raise SPSDKError(
                f"Cannot read generated public key from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res((key_name or key_type.label) + "_PRK.bin", prk)
        self.store_temp_res((key_name or key_type.label) + "_PUK.bin", puk)

        return prk, puk

    def wrap_key(self, cust_mk_sk: bytes) -> bytes:
        """Wrap the CUST_MK_SK key.

        :param cust_mk_sk : Customer Master Key Symmetric Key
        :raises SPSDKError: In case of any error.
        :return: Wrapped CUST_MK_SK by RFC3396.
        """
        if not self.mboot.write_memory(self.devbuff_base, cust_mk_sk):
            raise SPSDKError(
                f"Cannot write CUST_MK_SK into device. Error: {self.mboot.status_string}"
            )

        hsm_store_key_res = self.mboot.tp_hsm_store_key(
            TrustProvKeyType.CKDFK.tag,
            0x01,
            self.devbuff_base,
            self.DEVBUFF_CUST_MK_SK_KEY_SIZE,
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SIZE,
        )

        if not hsm_store_key_res:
            raise SPSDKError(f"HSM Store Key command failed. Error: {self.mboot.status_string}")

        wrapped_key_size = self.get_devbuff_wrapped_cust_mk_sk_key_size()

        if hsm_store_key_res[1] != wrapped_key_size:
            raise SPSDKError("HSM Store Key command has invalid results.")

        wrapped_cust_mk_sk = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            wrapped_key_size,
        )

        if not wrapped_cust_mk_sk:
            raise SPSDKError(
                f"Cannot read WRAPPED CUST_MK_SK from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res("CUST_MK_SK.bin", wrapped_cust_mk_sk)

        return wrapped_cust_mk_sk

    def sign_data_blob(self, data_to_sign: bytes, key: bytes) -> bytes:
        """Get HSM encryption sign for data blob.

        :param data_to_sign: Input data to sign.
        :param key: FW signing key (MFWISK).
        :raises SPSDKError: In case of any problem.
        :return: Data blob signature (64 bytes).
        """
        if not self.mboot.write_memory(self.devbuff_base, key):
            raise SPSDKError(
                f"Cannot write signing key into device. Error: {self.mboot.status_string}"
            )
        if not self.mboot.write_memory(self.get_devbuff_base_address(1), data_to_sign):
            raise SPSDKError(
                f"Cannot write Data to sign into device. Error: {self.mboot.status_string}"
            )
        hsm_gen_key_res = self.mboot.tp_hsm_enc_sign(
            self.devbuff_base,
            len(key),
            self.get_devbuff_base_address(1),
            len(data_to_sign),
            self.get_devbuff_base_address(2),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )

        if hsm_gen_key_res != self.DEVBUFF_SB_SIGNATURE_SIZE:
            raise SPSDKError(
                f"HSM signing command failed. Invalid signature size: {hsm_gen_key_res} "
                f"MBoot Status: {self.mboot.status_string}"
            )

        signature = self.mboot.read_memory(
            self.get_devbuff_base_address(2),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )
        if not signature:
            raise SPSDKError(
                f"Cannot read generated signature from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res("SB3_sign.bin", signature, "to_merge")

        return signature

    def encrypt_data_blocks(
        self, cust_fw_enc_key: bytes, sb3_header: bytes, data_cmd_blocks: list[bytes]
    ) -> list[bytes]:
        """Encrypt all data blocks on device.

        :param cust_fw_enc_key: Firmware encryption key.
        :param sb3_header: Un Encrypted SB3 file header.
        :param data_cmd_blocks: List of un-encrypted SB3 file command blocks.
        :raises SPSDKError: In case of any vulnerability.
        :return: List of encrypted command blocks on device.
        """
        if not self.mboot.write_memory(self.devbuff_base, cust_fw_enc_key):
            raise SPSDKError(
                f"Cannot write customer fw encryption key into device. Error: {self.mboot.status_string}"
            )
        self.store_temp_res("SB3_header.bin", sb3_header, "to_encrypt")
        if not self.mboot.write_memory(self.get_devbuff_base_address(1), sb3_header):
            raise SPSDKError(
                f"Cannot write SB3 header into device. Error: {self.mboot.status_string}"
            )

        encrypted_blocks = []
        for data_cmd_block_ix, data_cmd_block in enumerate(data_cmd_blocks, start=1):
            self.store_temp_res(f"SB3_block_{data_cmd_block_ix}.bin", data_cmd_block, "to_encrypt")
            if not self.mboot.write_memory(self.get_devbuff_base_address(2), data_cmd_block):
                raise SPSDKError(
                    f"Cannot write SB3 data block{data_cmd_block_ix} into device. "
                    f"Error: {self.mboot.status_string}"
                )
            key_id = CmdLoadKeyBlob.get_key_id(
                self.family, CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_INT_SK
            )
            if not self.mboot.tp_hsm_enc_blk(
                self.devbuff_base,
                len(cust_fw_enc_key),
                key_id,
                self.get_devbuff_base_address(1),
                len(sb3_header),
                data_cmd_block_ix,
                self.get_devbuff_base_address(2),
                self.DEVBUFF_DATA_BLOCK_SIZE,
            ):
                raise SPSDKError(
                    f"Cannot run SB3 data block_{data_cmd_block_ix} HSM Encryption in device. "
                    f"Error: {self.mboot.status_string}"
                )

            encrypted_block = self.mboot.read_memory(
                self.get_devbuff_base_address(2),
                self.DEVBUFF_DATA_BLOCK_SIZE,
            )
            if not encrypted_block:
                raise SPSDKError(
                    f"Cannot read SB3 data block_{data_cmd_block_ix} from device. "
                    f"Error: {self.mboot.status_string}"
                )

            self.store_temp_res(f"SB3_block_{data_cmd_block_ix}.bin", encrypted_block, "encrypted")

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
        :return: DEVHSM SB3.1 class
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
        cust_mk_sk = (
            config.load_symmetric_key(
                key="containerKeyBlobEncryptionKey", expected_size=32, name="CUST_MK_SK INPUT"
            )
            if "containerKeyBlobEncryptionKey" in config
            else None
        )

        buffer_address = config.get_int(
            "bufferAddress", get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        )

        sb3_data = SecureBinary31Commands.load_from_config(
            config, hash_type=EnumHashAlgorithm.SHA256, load_just_commands=True
        )

        return cls(
            mboot=mboot,
            family=family,
            oem_share_input=oem_share_in,
            oem_enc_master_share_input=enc_oem_master_share_in,
            cust_mk_sk=cust_mk_sk,
            commands=sb3_data.commands,
            workspace=config.get_output_file_name("workspace") if "workspace" in config else None,
            initial_reset=config.get("initialReset", False),
            final_reset=config.get("finalReset", True),
            buffer_address=buffer_address,
            info_print=info_print,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError()

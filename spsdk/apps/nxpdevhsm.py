#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module is used to generate initialization SB file."""

import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

import click

from spsdk import SPSDK_DATA_FOLDER, SPSDKError, SPSDKValueError
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    isp_interfaces,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import catch_spsdk_error, format_raw_data, get_interface
from spsdk.image import MBIMG_SCH_FILE
from spsdk.mboot.commands import TrustProvKeyType, TrustProvOemKeyType
from spsdk.mboot.interfaces import MBootInterface
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.sb31.commands import CmdLoadKeyBlob
from spsdk.sbfile.sb31.images import (
    SB3_SCH_FILE,
    SecureBinary31,
    SecureBinary31Commands,
    SecureBinary31Header,
)
from spsdk.utils.crypto.cert_blocks import CertificateBlockHeader
from spsdk.utils.crypto.common import crypto_backend
from spsdk.utils.database import Database
from spsdk.utils.misc import (
    load_binary,
    load_configuration,
    value_to_bool,
    value_to_int,
    write_file,
)
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas, check_config

logger = logging.getLogger(__name__)

NXPDEVHSM_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpdevhsm")
NXPDEVHSM_DATABASE_FILE: str = os.path.join(NXPDEVHSM_DATA_FOLDER, "database.yaml")


class DeviceHsm:
    """Class to handle device HSM provisioning procedure."""

    DEVBUFF_SIZE = 0x100
    DEVBUFF_GEN_MASTER_SHARE_INPUT_SIZE = 16
    DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE = 48
    DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE = 64
    DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE = 64
    DEVBUFF_HSM_GENKEY_KEYBLOB_SIZE = 48
    DEVBUFF_HSM_GENKEY_KEYBLOB_PUK_SIZE = 64
    DEVBUFF_CUST_MK_SK_KEY_SIZE = 32
    DEVBUFF_WRAPPED_CUST_MK_SK_KEY_SIZE = 48
    DEVBUFF_DATA_BLOCK_SIZE = 256
    DEVBUFF_SB3_SIGNATURE_SIZE = 64

    RESET_TIMEOUT = 500  # timeout for reset in milliseconds

    def __init__(
        self,
        mboot: McuBoot,
        cust_mk_sk: bytes,
        oem_share_input: bytes,
        info_print: Callable,
        family: str,
        container_conf: Optional[str] = None,
        workspace: Optional[str] = None,
        initial_reset: bool = False,
        final_reset: bool = True,
    ) -> None:
        """Initialization of device HSM class. Its design to create provisioned SB3 file.

        :param mboot: mBoot communication interface.
        :param oem_share_input: OEM share input data.
        :param cust_mk_sk: Customer Master Key Symmetric Key.
        :param family: chip family
        :param container_conf: Optional elftosb configuration file (to specify user list of SB commands).
        :param workspace: Optional folder to store middle results.
        :param initial_reset: Reset device before DevHSM creation of SB3 file.
        :param final_reset: Reset device after DevHSM creation of SB3 file.
        :raises SPSDKError: In case of any vulnerability.
        """
        self.database = Database(NXPDEVHSM_DATABASE_FILE)
        self.mboot = mboot
        self.cust_mk_sk = cust_mk_sk
        self.oem_share_input = oem_share_input
        self.info_print = info_print
        self.workspace = workspace
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        self.container_conf_dir = os.path.dirname(container_conf) if container_conf else None
        if self.workspace and not os.path.isdir(self.workspace):
            os.mkdir(self.workspace)

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        self.store_temp_res("OEM_SHARE_INPUT.BIN", self.oem_share_input)

        # Default value that could be given from SB3 configuration container
        self.timestamp = None
        self.sb3_descr = "SB3 SB_KEK"
        self.sb3_fw_ver = 0

        # Check the configuration file and options to update by user config
        self.config_data = None
        if container_conf:
            config_data = load_configuration(container_conf)
            # validate input configuration
            check_config(
                config_data,
                DeviceHsm.get_validation_schemas(family, include_test_configuration=True),
                search_paths=[os.path.dirname(container_conf)],
            )
            self.config_data = config_data
            self.sb3_fw_ver = config_data.get("firmwareVersion") or self.sb3_fw_ver
            self.sb3_descr = config_data.get("description") or self.sb3_descr
            if "timestamp" in config_data:
                self.timestamp = value_to_int(str(config_data.get("timestamp")))

        self.wrapped_cust_mk_sk = bytes()
        self.final_sb = bytes()
        self.family = family
        self.devbuff_base = value_to_int(
            self.database.get_device_value("devbuff_base_address", self.family)
        )

    def get_devbuff_base_address(self, index: int) -> int:
        """Get devbuff base address."""
        assert index < 4 and index >= 0
        return self.devbuff_base + index * self.DEVBUFF_SIZE

    def update_keyblob_offset(self) -> int:
        """Update keyblob offset based on family."""
        return value_to_int(self.database.get_device_value("key_blob_offset", self.family))

    def command_order(self) -> bool:
        """Update command order based on family."""
        return value_to_bool(self.database.get_device_value("order", self.family))

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get the list of supported families by Device HSM.

        :return: List of supported families.
        """
        return Database(NXPDEVHSM_DATABASE_FILE).devices.device_names

    @classmethod
    def get_validation_schemas(
        cls, family: str, include_test_configuration: bool = False
    ) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas.
        """
        mbi_sch_cfg = ValidationSchemas().get_schema_file(MBIMG_SCH_FILE)
        sb3_sch_cfg = ValidationSchemas().get_schema_file(SB3_SCH_FILE)

        schemas: List[Dict[str, Any]] = []
        schemas.append(mbi_sch_cfg["firmware_version"])
        schemas.append(sb3_sch_cfg["sb3_family"])
        schemas.append(sb3_sch_cfg["sb3_description"])
        schemas.extend(SecureBinary31.get_commands_validation_schemas(family))
        if include_test_configuration:
            schemas.append(sb3_sch_cfg["sb3_test"])
        # find family
        for schema in schemas:
            if "properties" in schema and "family" in schema["properties"]:
                schema["properties"]["family"]["enum"] = cls.get_supported_families()
                break
        return schemas

    @classmethod
    def generate_config_template(cls, family: str) -> Dict[str, str]:
        """Generate configuration for selected family.

        :param family: Family description.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: Dict[str, str] = {}

        if family in cls.get_supported_families():
            schemas = cls.get_validation_schemas(family)
            schemas.append(ValidationSchemas.get_schema_file(SB3_SCH_FILE)["sb3_output"])
            override = {}
            override["family"] = family

            yaml_data = ConfigTemplate(
                f"DEVHSM procedure Secure Binary v3.1 Configuration template for {family}.",
                schemas,
                override,
            ).export_to_yaml()

            ret[f"sb31_{family}_devhsm"] = yaml_data

        return ret

    def create_sb3(self) -> None:
        """Do device hsm process to create SB_KEK provisioning SB file."""
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate encOemShare.bin (ENC_OEM_SHARE will be later put in place of ISK)
        self.info_print(" 2: Generating OEM master share.")
        oem_enc_share, _, _ = self.oem_generate_master_share(self.oem_share_input)

        # 3: Call hsm_gen_key to generate 48 bytes FW signing key
        self.info_print(" 3: Generating 48 bytes FW signing keys.")
        cust_fw_auth_prk, cust_fw_auth_puk = self.generate_key(
            TrustProvOemKeyType.MFWISK, "CUST_FW_AUTH"
        )

        # 4: Call hsm_gen_key to generate 48 bytes FW encryption key
        self.info_print(" 4: Generating 48 bytes FW encryption keys.")
        cust_fw_enc_prk, _ = self.generate_key(TrustProvOemKeyType.MFWENCK, "CUST_FW_ENC_SK")

        # 5: Call hsm_store_key to generate user defined CUST_MK_SK.
        # Will be stored into PFR using loadKeyBlob SB3 command.
        # Use NXP_CUST_KEK_EXT_SK in SB json
        self.info_print(" 5: Wrapping CUST_MK_SK key.")
        self.wrapped_cust_mk_sk = self.wrap_key(self.cust_mk_sk)

        # 6: Generate template sb3 fw, sb3ImageType=6
        self.info_print(" 6: Creating template un-encrypted SB3 header and data blobs.")
        # 6.1: Generate SB3.1 header template
        self.info_print(" 6.1: Creating template SB3 header.")
        sb3_header = SecureBinary31Header(
            firmware_version=self.sb3_fw_ver,
            curve_name="secp256r1",
            description=self.sb3_descr,
            timestamp=self.timestamp,
            flags=0x01,  # Bit0: PROV_MFW: when set, the SB3 file encrypts provisioning firmware
        )
        self.timestamp = sb3_header.timestamp
        sb3_header_exported = sb3_header.export()
        logger.debug(
            f" 6.1: The template SB3 header: \n{sb3_header.info()} \n Length:{len(sb3_header_exported)}"
        )

        # 6.2: Create SB3 file un-encrypted data part
        self.info_print(" 6.2: Creating un-encrypted SB3 data.")
        sb3_data = SecureBinary31Commands(
            family=self.family, curve_name="secp256r1", is_encrypted=False, timestamp=self.timestamp
        )

        if self.container_conf_dir is not None:
            sb3_data.load_from_config(
                self.get_cmd_from_config(), search_paths=[self.container_conf_dir]
            )
        key_blob_command_position = value_to_int(
            self.database.get_device_value("key_blob_command_position", self.family)
        )
        sb3_data.insert_command(
            index=key_blob_command_position,
            command=CmdLoadKeyBlob(
                offset=self.update_keyblob_offset(),
                data=self.wrapped_cust_mk_sk,
                key_wrap_id=CmdLoadKeyBlob.get_key_id(
                    family=self.family, key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK
                ),
            ),
        )

        logger.debug(f" 6.2: Created un-encrypted SB3 data: \n{sb3_data.info()}")
        # 6.3: Get SB3 file data part individual chunks
        data_cmd_blocks = sb3_data.get_cmd_blocks_to_export()

        # 7: Call hsm_enc_blk to encrypt all the data chunks from step 6. Use FW encryption key from step 3.
        self.info_print(" 7: Encrypting SB3 data on device")
        sb3_enc_data = self.encrypt_data_blocks(
            cust_fw_enc_prk, sb3_header_exported, data_cmd_blocks
        )
        # 7.1: Add to encrypted data parts SHA256 hashes
        self.info_print(" 7.1: Enriching encrypted SB3 data by mandatory hashes.")
        enc_final_data = sb3_data.process_cmd_blocks_to_export(sb3_enc_data)
        self.store_temp_res("Final_data.bin", enc_final_data, "to_merge")

        # 7.2: Create dummy certification part of SB3 manifest
        self.info_print(" 7.2: Creating dummy certificate block.")
        cb_header = CertificateBlockHeader()
        cb_header.cert_block_size = (
            cb_header.SIZE + 68 + self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE
        )
        logger.debug(f" 7.2: The dummy certificate block has been created:\n{cb_header.info()}.")

        # 7.3: Update the SB3 pre-prepared header by current data
        self.info_print(" 7.3: Updating SB3 header by valid values.")
        sb3_header.block_count = sb3_data.block_count
        sb3_header.image_total_length += (
            len(sb3_data.final_hash) + cb_header.cert_block_size + self.DEVBUFF_SB3_SIGNATURE_SIZE
        )
        logger.debug(
            f" 7.3: The SB3 header has been updated by valid values:\n{sb3_header.info()}."
        )

        # 7.4: Compose manifest that will be signed
        self.info_print(" 7.4: Preparing SB3 manifest to sign.")
        manifest_to_sign = bytes()
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
            f" 7.4: The SB3 manifest data to sign:\n{format_raw_data(manifest_to_sign, use_hexdump=True)}."
        )

        # 8: Get sign of SB3 file manifest
        self.info_print(" 8: Creating SB3 manifest signature on device.")
        manifest_signature = self.sign_data_blob(manifest_to_sign, cust_fw_auth_prk)
        logger.debug(
            f" 8: The SB3 manifest signature data:\n{format_raw_data(manifest_signature, use_hexdump=True)}."
        )

        # 9: Merge all parts together
        self.info_print(" 9: Composing final SB3 file.")
        self.final_sb = bytes()
        self.final_sb += manifest_to_sign
        self.final_sb += manifest_signature
        self.final_sb += enc_final_data
        self.store_temp_res("Final_SB3.sb3", self.final_sb)
        logger.debug(
            f" 9: The final SB3 file data:\n{format_raw_data(self.final_sb, use_hexdump=True)}."
        )

        # 10: Final reset to ensure followup operations (e.g. receive-sb-file) work correctly
        if self.final_reset:
            self.info_print("10: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT, reopen=False)
        else:
            self.info_print("10: Final target reset disabled")

    def export(self) -> bytes:
        """Get the Final SB file.

        :return: Final SB file in bytes.
        """
        return self.final_sb

    def oem_generate_master_share(self, oem_share_input: bytes) -> Tuple[bytes, bytes, bytes]:
        """Generate on device Encrypted OEM master share outputs.

        :param oem_share_input: OEM input (randomize seed)
        :raises SPSDKError: In case of any vulnerability.
        :return: Tuple with OEM generate master share outputs.
        """
        if not self.mboot.write_memory(self.devbuff_base, oem_share_input):
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

    def generate_key(
        self, key_type: TrustProvOemKeyType, key_name: Optional[str] = None
    ) -> Tuple[bytes, bytes]:
        """Generate on device key pairs of provided type.

        :param key_type: Type of generated key pairs.
        :param key_name: optional name for storing temporary files.
        :raises SPSDKError: In case of any vulnerability.
        :return: Tuple with Private and Public key.
        """
        hsm_gen_key_res = self.mboot.tp_hsm_gen_key(
            key_type,
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

        self.store_temp_res((key_name or str(TrustProvOemKeyType[str(key_type)])) + "_PRK.bin", prk)
        self.store_temp_res((key_name or str(TrustProvOemKeyType[str(key_type)])) + "_PUK.bin", puk)

        return prk, puk

    def wrap_key(self, cust_mk_sk: bytes) -> bytes:
        """Wrap the CUST_MK_SK key.

        :param cust_mk_sk : Customer Master Key Symmetric Key
        :raises SPSDKError: In case of any vulnerability.
        :return: Wrapped CUST_MK_SK by RFC3396.
        """
        if not self.mboot.write_memory(self.devbuff_base, cust_mk_sk):
            raise SPSDKError(
                f"Cannot write CUST_MK_SK into device. Error: {self.mboot.status_string}"
            )

        hsm_store_key_res = self.mboot.tp_hsm_store_key(
            TrustProvKeyType.CKDFK,
            0x01,
            self.devbuff_base,
            self.DEVBUFF_CUST_MK_SK_KEY_SIZE,
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SIZE,
        )

        if not hsm_store_key_res:
            raise SPSDKError(f"HSM Store Key command failed. Error: {self.mboot.status_string}")

        if hsm_store_key_res[1] != self.DEVBUFF_WRAPPED_CUST_MK_SK_KEY_SIZE:
            raise SPSDKError("HSM Store Key command has invalid results.")

        wrapped_cust_mk_sk = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_WRAPPED_CUST_MK_SK_KEY_SIZE,
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
        :raises SPSDKError: In case of any vulnerability.
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
            self.DEVBUFF_SB3_SIGNATURE_SIZE,
        )

        if hsm_gen_key_res != self.DEVBUFF_SB3_SIGNATURE_SIZE:
            raise SPSDKError(
                f"HSM signing command failed. Invalid signature size: {hsm_gen_key_res} "
                f"MBoot Status: {self.mboot.status_string}"
            )

        signature = self.mboot.read_memory(
            self.get_devbuff_base_address(2),
            self.DEVBUFF_SB3_SIGNATURE_SIZE,
        )
        if not signature:
            raise SPSDKError(
                f"Cannot read generated signature from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res("SB3_sign.bin", signature, "to_merge")

        return signature

    def store_temp_res(self, file_name: str, data: bytes, group: Optional[str] = None) -> None:
        """Storing temporary files into workspace.

        :param file_name: Name of file to store the data.
        :param data: Data to store.
        :param group: Subfolder name, defaults to None
        """
        if not self.workspace:
            return
        group_dir = os.path.join(self.workspace, group or "")
        if not os.path.isdir(group_dir):
            os.mkdir(group_dir)

        filename = os.path.join(self.workspace, group or "", file_name)
        write_file(data, filename, mode="wb")

    def get_cmd_from_config(self) -> List[Dict[str, Any]]:
        """Process command description into a command object.

        :return: Modified list of commands
        :raises SPSDKError: Unknown command
        """
        cfg_commands: List[Dict[str, Any]] = []
        if self.config_data and self.config_data.get("commands"):
            cfg_commands = self.config_data["commands"]
            for cmd in cfg_commands:
                cmd_cpy: Dict = cmd.copy()
                name, args = cmd_cpy.popitem()
                if name == "loadKeyBlob" and value_to_int(str(args["offset"])) == 0x04:
                    raise SPSDKError(
                        f"""The duplicated 'loadKeyBlob' on offset 0x04 from
                    configuration file:\n {args}."""
                    )

        return cfg_commands

    def encrypt_data_blocks(
        self, cust_fw_enc_key: bytes, sb3_header: bytes, data_cmd_blocks: List[bytes]
    ) -> List[bytes]:
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


def get_cust_mk_sk(key: str) -> bytes:
    """Get binary from text or binary file.

    :param key: Binary customer master key symmetric key file.
    :return: Binary array loaded from file.
    :raises SPSDKValueError: When invalid input value is recognized.
    """
    cust_mk_sk = load_binary(key)

    if len(cust_mk_sk) != 32:
        raise SPSDKValueError(
            f"Invalid length of CUST_MK_SK INPUT ({len(cust_mk_sk )} not equal to 32)."
        )

    return cust_mk_sk


def get_oem_share_input(binary: str) -> bytes:
    """Get binary from text or binary file.

    :param binary: Path to binary file.
    :return: Binary array loaded from file.
    :raises SPSDKValueError: When invalid input value is recognized.
    """
    if binary:
        oem_share_input = load_binary(binary)
    else:
        oem_share_input = crypto_backend().random_bytes(16)

    if len(oem_share_input) != 16:
        raise SPSDKValueError(
            f"Invalid length of OEM SHARE INPUT ({len(oem_share_input)} not equal to 16)."
        )

    return oem_share_input


@click.group(name="nxpdevhsm", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Nxpdevhsm application is designed to create SB3 provisioning file for initial provisioning of device by OEM."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(no_args_is_help=True)
@isp_interfaces(uart=True, usb=True, sdio=True, lpcusbsio=True, buspal=True, json_option=False)
@click.option(
    "-k",
    "--key",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
    help="""Customer Master Key Symmetric Key secret file (32-bytes long binary file).
    CUST_MK_SK (provisioned by OEM, known by OEM).
    This is a 256-bit pre-shared AES key provisioned by OEM. CUST_MK_SK is used to derive FW image encryption keys.""",
)
@click.option(
    "-o",
    "--oem-share-input",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="OEM share input file to use as a seed to randomize the provisioning process (16-bytes long binary file).",
)
@click.option(
    "-w",
    "--workspace",
    type=click.Path(file_okay=False),
    required=False,
    help="Workspace folder to store temporary files, that could be used for future review.",
)
@click.option(
    "-j",
    "--container-conf",
    type=click.Path(exists=True),
    required=False,
    help="""JSON/YAML container configuration file to produce secure binary v3.x.
    This configuration file must contain family, list of commands and description""",
)
@click.option(
    "-f",
    "--family",
    required=True,
    help="Select the chip family.",
    type=click.Choice(DeviceHsm.get_supported_families(), case_sensitive=False),
)
@click.option(
    "-ir/-IR",
    "--initial-reset/--no-init-reset",
    default=False,
    help=(
        "Reset device BEFORE DevHSM operation. The DevHSM operation can run only once between resets. "
        "Do not enable this option on Linux/Mac when using USB. By default this reset is DISABLED."
    ),
)
@click.option(
    "-fr/-FR",
    "--final-reset/--no-final-reset",
    default=True,
    help=(
        "Reset device AFTER DevHSM operation. This reset is required if you need to use the device "
        "after DevHSM operation for other security related operations (e.g. receive-sb-file). "
        "By default this reset is ENABLED."
    ),
)
@click.argument("output-path", type=click.Path())
def generate(
    port: str,
    usb: str,
    sdio: str,
    buspal: str,
    lpcusbsio: str,
    oem_share_input: str,
    key: str,
    output_path: str,
    workspace: str,
    container_conf: str,
    timeout: int,
    family: str,
    initial_reset: bool,
    final_reset: bool,
) -> None:
    """Generate provisioning SB3.1 file.

    \b
    PATH    - output file path, where the final provisioned SB file will be stored.
    """
    interface = get_interface(
        module="mboot", port=port, usb=usb, lpcusbsio=lpcusbsio, timeout=timeout, buspal=buspal
    )
    assert isinstance(interface, MBootInterface)

    oem_share_in = get_oem_share_input(oem_share_input)
    cust_mk_sk = get_cust_mk_sk(key)
    if container_conf:
        family_from_cfg = load_configuration(container_conf).get("family")
        if not isinstance(family_from_cfg, str):
            raise SPSDKError("Family parameter is not provided in the container configuration")
    if (family and container_conf) and (family != family_from_cfg):
        raise SPSDKError(
            f"Family from json configuration file: {family_from_cfg} differs from the family parameter {family}"
        )

    with McuBoot(interface) as mboot:
        devhsm = DeviceHsm(
            mboot=mboot,
            cust_mk_sk=cust_mk_sk,
            oem_share_input=oem_share_in,
            info_print=click.echo,
            container_conf=container_conf,
            workspace=workspace,
            family=family,
            initial_reset=initial_reset,
            final_reset=final_reset,
        )
        devhsm.create_sb3()
        write_file(devhsm.export(), output_path, "wb")

    click.echo(f"Final SB3 file has been written: {os.path.abspath(output_path)}")


@main.command(name="get-template", no_args_is_help=True)
@click.option(
    "-f",
    "--family",
    required=True,
    help="Select the chip family.",
    type=click.Choice(DeviceHsm.get_supported_families(), case_sensitive=False),
)
@click.option(
    "-o",
    "--overwrite",
    default=False,
    type=bool,
    is_flag=True,
    help="Allow overwriting existing template file.",
)
@click.argument("output", type=click.Path(resolve_path=True))
def get_template_command(family: str, overwrite: bool, output: str) -> None:
    """Create template of configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    get_template(family, overwrite, output)


def get_template(family: str, overwrite: bool, output: str) -> None:
    """Create template of configuration in YAML format."""
    if not os.path.isfile(output) or overwrite:
        click.echo(f"Creating {output} template file.")
        write_file(DeviceHsm.generate_config_template(family)[f"sb31_{family}_devhsm"], output)
    else:
        click.echo(f"Skip creating {output}, this file already exists.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB4 development HSM utilities for secure boot file generation.

This module provides DevHsmSB4 class for creating and managing SB4 (Secure Binary 4)
initialization files using development HSM (Hardware Security Module) functionality.
"""

import copy
import logging
from typing import Any, Callable, Optional

from typing_extensions import Self

from spsdk.apps.utils.utils import format_raw_data
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.image.ahab.ahab_container import AHABContainerV2
from spsdk.image.ahab.ahab_data import AHABSignHashAlgorithmV2, SignatureType, create_chip_config
from spsdk.image.ahab.ahab_iae import ImageArrayEntryV2
from spsdk.image.ahab.ahab_sign_block import SignatureBlockV2
from spsdk.image.ahab.ahab_signature import ContainerSignature
from spsdk.mboot.commands import TrustProvKeyType
from spsdk.mboot.mcuboot import McuBoot
from spsdk.sbfile.devhsm.devhsm import DevHsm
from spsdk.sbfile.sb4.images import SecureBinary4, SecureBinary4Commands, SecureBinary4Descr
from spsdk.sbfile.sb31.commands import BaseCmd, CmdLoadKeyBlob
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import align, align_block
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class DevHsmSB4(DevHsm):
    """Device HSM provisioning manager for SB4 files.

    This class handles the complete device Hardware Security Module (HSM) provisioning
    procedure specifically for Secure Binary 4 (SB4) files. It manages the communication
    with the target device through mBoot interface and orchestrates the creation of
    provisioned SB4 files using device-generated cryptographic materials.

    :cvar DEVBUFF_SIZE: Default device buffer size for HSM operations.
    :cvar DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE: Output size for master encryption share.
    :cvar DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE: Output size for master share.
    :cvar DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE: Output size for customer certificate.
    :cvar DEVBUFF_SB_SIGNATURE_SIZE: Size of SB signature buffer.
    """

    SUB_FEATURE = "DevHsmSB4"
    DEVBUFF_SIZE = 1024

    DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE = 64
    DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE = 96
    DEVBUFF_GEN_MASTER_CUST_CERT_PUK_OUTPUT_SIZE = 256
    DEVBUFF_SB_SIGNATURE_SIZE = 16

    def __init__(
        self,
        mboot: McuBoot,
        family: FamilyRevision,
        commands: list[BaseCmd],
        oem_share_input: Optional[bytes] = None,
        oem_enc_master_share_input: Optional[bytes] = None,
        oem_enc_share_input: Optional[bytes] = None,
        cust_mk_sk: Optional[bytes] = None,
        workspace: Optional[str] = None,
        initial_reset: Optional[bool] = False,
        final_reset: Optional[bool] = True,
        buffer_address: Optional[int] = None,
        info_print: Optional[Callable] = None,
    ) -> None:
        """Initialize device HSM class for creating provisioned SB4 files.

        This class provides functionality to create SB4 files using device HSM capabilities
        with secure provisioning features.

        :param mboot: mBoot communication interface.
        :param family: Chip family and revision information.
        :param commands: User list of SB commands to be executed.
        :param oem_share_input: OEM share input data (if None a random input will be generated).
        :param oem_enc_master_share_input: Used for setting the OEM share (recreating security
            session).
        :param oem_enc_share_input: OEM encryption share input data.
        :param cust_mk_sk: Customer Master Key Symmetric Key.
        :param workspace: Optional folder to store intermediate results.
        :param initial_reset: Reset device before DevHSM creation of SB4 file.
        :param final_reset: Reset device after DevHSM creation of SB4 file.
        :param buffer_address: Override the default buffer address.
        :param info_print: Method for printing out info messages. Default: print function.
        :raises SPSDKError: In case of incomplete OEM share inputs or other initialization
            problems.
        """
        super().__init__(family, workspace)
        self.mboot = mboot
        self.oem_share_input = oem_share_input or random_bytes(16)
        self.oem_enc_master_share_input = oem_enc_master_share_input
        self.oem_enc_share_input = oem_enc_share_input
        self.cust_mk_sk = cust_mk_sk
        self.info_print = info_print or print
        self.initial_reset = initial_reset
        self.final_reset = final_reset
        # Check the configuration file and options to update by user config
        self.sb4_fw_ver = 0
        self.sb4_descr = "SB 4 - DevHSM"
        self.sb4_commands = commands
        self.timestamp: Optional[int] = None

        # Override the default buffer address
        if buffer_address is not None:
            self.devbuff_base = buffer_address

        # store input of OEM_SHARE_INPUT to workspace in case that is generated randomly
        if self.oem_share_input:
            self.store_temp_res("OEM_SHARE_INPUT.BIN", self.oem_share_input)

        self.wrapped_cust_mk_sk = bytes()
        self.final_sb = bytes()

        if self.oem_enc_share_input and (
            bool(self.oem_enc_master_share_input) ^ bool(self.oem_enc_share_input)
        ):
            raise SPSDKError(
                "Incomplete OEM SHARE inputs. "
                "Either provide both OEM SHARE inputs to recreate secure session, "
                "or do not provide any of them to create a new session."
            )

    def __repr__(self) -> str:
        """Return string representation of SB4 DevHSM object.

        :return: String representation of the DevHSM instance.
        """
        return "SB4 DevHSM"

    def __str__(self) -> str:
        """Return string representation of SB4 DevHSM instance.

        :return: String containing family information for the DevHSM instance.
        """
        return f"SB4 DevHSM for {self.family}"

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, include_test_configuration: bool = False
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SB4 configuration.

        The method combines common validation schemas with SB4-specific schemas and optionally
        includes test configuration schemas for development purposes.

        :param family: Family description containing MCU family and revision information.
        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas for SB4 configuration validation.
        """
        schemas: list[dict[str, Any]] = []
        common_schema = cls.get_validation_schemas_common(family=family)
        schemas.extend(common_schema)

        sb4_sch_cfg = get_schema_file(DatabaseManager.SB40)
        schemas.extend(SecureBinary31.get_devhsm_commands_validation_schemas(family))

        if include_test_configuration:
            schemas.append(sb4_sch_cfg["sb4_test"])

        return schemas

    @classmethod
    def get_validation_schemas_common(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for common DevHSM settings.

        Retrieves validation schemas for DevHSM configuration including family schema,
        common DevHSM settings, and customer master key/secure key settings. The method
        excludes command-specific schemas and updates the buffer address template value
        based on the target family's communication buffer configuration.

        :param family: Target family and revision for schema validation.
        :return: List containing family schema, common DevHSM schema, and customer
                 master key/secure key schema dictionaries.
        """
        devhsm_sch_cfg = get_schema_file(DatabaseManager.DEVHSM)
        family_sch = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_sch["properties"], cls.get_supported_families(), family
        )
        comm_address = get_db(family).get_int(DatabaseManager.COMM_BUFFER, "address")
        devhsm_sch_cfg["common"]["properties"]["bufferAddress"]["template_value"] = hex(
            comm_address
        )
        return [family_sch, devhsm_sch_cfg["common"], devhsm_sch_cfg["cust_mk_sk"]]

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get DEVHSM configuration template for specified family.

        Generates a YAML configuration template for DEVHSM procedure Secure Binary v4.0.
        The method attempts to use recommended flow and common validation schemas if available,
        otherwise falls back to standard validation schemas.

        :param family: Family revision for which the template should be generated.
        :return: YAML configuration template as string.
        """
        try:
            recommended_flow = get_db(family).get_list(DatabaseManager.DEVHSM, "recommended_flow")
            schemas = cls.get_validation_schemas_common(family=family)
        except SPSDKError:
            recommended_flow = None
            schemas = cls.get_validation_schemas(family)

        yaml_data = CommentedConfig(
            f"DEVHSM procedure Secure Binary v4.0 Configuration template for {family}.",
            schemas,
        ).get_template()

        if recommended_flow:
            yaml_data += cls.render_recommended_flow(flow=recommended_flow)
            yaml_data += cls.render_available_commands(family=family)

        return yaml_data

    @classmethod
    def render_recommended_flow(cls, flow: list[dict]) -> str:
        """Render textual representation of recommended flow steps.

        The method processes a list of flow steps and formats them using templates
        from the DevHSM database schema. Each step is rendered according to its
        corresponding template with parameter substitution.

        :param flow: List of dictionaries containing flow step definitions, where each
                     dictionary has a single key-value pair representing the step name
                     and its parameters.
        :raises SPSDKError: When template for a flow step is not found in database.
        :return: Formatted string representation of the complete flow with steps
                 rendered according to their templates.
        """
        templates = get_schema_file(DatabaseManager.DEVHSM)
        result = "\n" + templates["subTitle"]
        # we need a copy or else the .popitem will corrupt the database
        for step in copy.deepcopy(flow):
            name, params = step.popitem()
            temp: Optional[str] = templates.get(name)
            if not temp:
                raise SPSDKError(f"Template for step {step} not found in database")
            result += temp.format(**params)
        return result

    @classmethod
    def render_available_commands(cls, family: FamilyRevision) -> str:
        """Render textual representation of available DevHSM commands for given family.

        The method retrieves validation schemas for DevHSM commands, processes them by removing
        required fields, and formats the output as commented YAML template for user reference.

        :param family: Target MCU family and revision for command schema retrieval.
        :return: Formatted string containing available commands as commented YAML template.
        """
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
        """Create provisioning SB4 file using device HSM process.

        This method orchestrates the complete device HSM workflow to generate a secure
        provisioning SB4 file. The process includes target reset, OEM master share
        generation/setting, SB4 template creation with key wrapping, data encryption,
        manifest signing, and final file composition.

        :raises SPSDKError: When OEM_SHARE is not provided but OEM MASTER SHARE creation is enabled.
        """
        # 1: Initial target reset to ensure OEM_MASTER_SHARE works properly (not tainted by previous run)
        if self.initial_reset:
            self.info_print(" 1: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT)
        else:
            self.info_print(" 1: Initial target reset is disabled ")

        # 2: Call GEN_OEM_MASTER_SHARE to generate encOemShare.bin (ENC_OEM_SHARE will be later put in place of ISK)
        if self.oem_enc_master_share_input and self.oem_share_input and self.oem_enc_share_input:
            self.info_print(" 2: Setting OEM master share.")
            _ = self.oem_set_master_share(
                oem_seed=self.oem_share_input, enc_oem_share=self.oem_enc_master_share_input
            )
            oem_enc_share = self.oem_enc_share_input
        elif self.oem_share_input:
            self.info_print(" 2: Generating OEM master share.")
            oem_enc_share, _, _ = self.oem_generate_master_share(self.oem_share_input)
        else:
            raise SPSDKError(
                "Creation of OEM MASTER SHARE is enabled but OEM_SHARE (OEM_ENC_MASTER_SHARE) not provided."
            )
        self.store_temp_res("oem_encryption_share.bin", oem_enc_share)

        # 3: Generate template of SB4 header and data blobs
        self.info_print(" 3: Creating template un-encrypted SB4 header and data blobs.")
        # 3.1: Create SB4 file un-encrypted data part
        self.info_print(" 3.1: Creating un-encrypted SB4 data.")
        sb4_data = SecureBinary4Commands(family=self.family, hash_type=EnumHashAlgorithm.SHA384)

        for cmd in self.sb4_commands:
            sb4_data.add_command(cmd)

        cust_mk_sk_blob_found = False
        self.info_print(" 3.2 Looking for plaintext keys to wrap")
        for command in sb4_data.commands:
            if isinstance(command, CmdLoadKeyBlob):
                if command.plain_input:
                    self.info_print(" 3.2.1 PlainText keyblob found, performing key wrapping")
                    command.data = self.wrap_key(command.data)
                if command.address == self.get_keyblob_offset():
                    cust_mk_sk_blob_found = True

        self.info_print(" 3.3 Handling CUST_MK_SK/SBKEK keyblob")
        if cust_mk_sk_blob_found:
            self.info_print(" 3.3.1 CUST_MK_SK/SBKEK key blob found in configuration")
        elif self.cust_mk_sk:
            self.info_print(" 3.3.1 Injecting wrapped key")

            self.info_print(" 3.3.2: Wrapping CUST_MK_SK key.")
            self.wrapped_cust_mk_sk = self.wrap_key(self.cust_mk_sk)
            self.info_print(" 3.3.3: Adding wrapped CUST_MK_SK LoadKeyBlob command into SB file.")
            sb4_data.insert_command(
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
            self.info_print(" 3.3: CUST_MK_SK/SBKEK not provided. Key provisioning is skipped.")
            logger.warning((" 3.3 CUST_MK_SK/SBKEK not provided. Key provisioning is skipped."))
        sb4_data.validate()

        # 3.4: Get SB4 file data part individual chunks
        data_cmd_blocks = sb4_data.get_cmd_blocks_to_export()
        self.info_print(" 3.4: Get SB4 file data part individual chunks.")
        # 3.5: Generate SB4 Descriptor
        self.info_print(" 3.5: Creating template SB4 header.")
        sb4_descriptor = SecureBinary4Descr(
            hash_type=EnumHashAlgorithm.SHA384, description=self.sb4_descr
        )
        sb4_descriptor.oem_share_block = oem_enc_share
        sb4_descriptor.update(sb4_data)

        chip_config = create_chip_config(
            self.family, feature=SecureBinary4.FEATURE, base_key=["ahab"]
        )
        # 3.4: Generate SB4 Ahab container
        ahab = AHABContainerV2(chip_config)
        signature_block = SignatureBlockV2(
            chip_config=ahab.chip_config,
            container_signature=ContainerSignature(
                signature_data=bytes(16), signature_type=SignatureType.CMAC
            ),
        )
        ahab.signature_block = signature_block
        # 3.5 Set ahab container SRk set to DEVHSM
        ahab.set_flags(srk_set="devhsm")
        core_id = chip_config.core_ids.from_label("cortex-m33")
        # 3.6 Add SB4 descriptor as a AHAB image
        data_iae_flags = ImageArrayEntryV2.create_flags(
            image_type=ImageArrayEntryV2.get_image_types(ahab.chip_config, core_id.tag)
            .from_label("secure_binary_4")
            .tag,
            core_id=core_id.tag,
            hash_type=AHABSignHashAlgorithmV2.from_label(EnumHashAlgorithm.SHA384.label.upper()),
        )
        data_image = ImageArrayEntryV2(
            chip_config=ahab.chip_config,
            image=sb4_descriptor.export(),
            image_offset=0,
            load_address=0,
            entry_point=0,
            flags=data_iae_flags,
            image_name="Secure Binary 4.0",
        )

        ahab.image_array.append(data_image)
        self.timestamp = sb4_descriptor.timestamp

        ahab.update_fields()
        ahab.image_array[0].image_offset = align(
            ahab.header_length(), alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT
        )
        ahab.update_fields()

        # 3.7: Export SB4 header and prepare for encryption
        sb4_header_exported = align_block(
            ahab.export(), alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT
        )

        # 3.8 Export SB4 descriptor
        sb4_header_exported += align_block(
            ahab.image_array[0].image, alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT
        )

        logger.debug(
            " 3.9: The template SB4 header + descriptor: "
            f"\n{ahab}, \n{str(sb4_descriptor)} \n Length:{len(sb4_header_exported)}"
        )

        # 4: Call hsm_enc_blk to encrypt all the data chunks from step 5. Use FW encryption key from step 3.
        self.info_print(" 4: Encrypting SB4 data on device")
        self.store_temp_res("sb4_header_exported_non_signed.bin", sb4_header_exported)
        sb4_enc_data = self.encrypt_data_blocks(sb4_header_exported, data_cmd_blocks)
        # 4.1: Add to encrypted data parts SHA384 hashes
        self.info_print(" 4.1: Enriching encrypted SB4 data by mandatory hashes.")
        enc_final_data = sb4_data.process_cmd_blocks_to_export(sb4_enc_data)
        self.store_temp_res("Final_data.bin", enc_final_data, "to_merge")

        # 4.2: Update the SB4 pre-prepared header by current data
        self.info_print(" 4.2: Updating SB4 header by valid values.")
        sb4_descriptor.update(sb4_data)
        logger.debug(
            f" 4.2: The SB4 header has been updated by valid values:\n{str(sb4_descriptor)}."
        )

        # 4.3: Compose manifest that will be signed
        self.info_print(" 4.3: Preparing SB4 manifest to sign.")
        sb_descriptor_data = sb4_descriptor.export()
        ahab.image_array[0].image = sb_descriptor_data
        ahab.image_array[0].image_hash = None
        ahab.image_array[0].image_offset = align(
            ahab.header_length(), alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT
        )
        ahab.update_fields()
        data_to_sign = ahab.get_signature_data()
        self.store_temp_res("manifest_to_sign.bin", data_to_sign, "to_merge")
        logger.debug(
            f" 4.4: The SB4 manifest data to sign:\n{format_raw_data(data_to_sign, use_hexdump=True)}."
        )
        # 5: Get sign of SB4 file manifest
        self.info_print(" 5: Creating SB4 manifest signature on device.")
        assert ahab.signature_block.signature
        hash_to_sign = get_hash(data_to_sign, EnumHashAlgorithm.SHA384)
        logger.info(f" 5.1: Hash to sign: {hash_to_sign.hex()}")
        ahab.signature_block.signature.signature_data = self.sign_data_blob(hash_to_sign)
        logger.debug(
            " 5.2: The SB4 manifest signature data:\n"
            f"{format_raw_data(ahab.signature_block.signature.signature_data, use_hexdump=True)}."
        )

        # 6: Merge all parts together
        self.info_print(" 6: Composing final SB4 file.")
        self.final_sb = align_block(ahab.export(), alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT)
        self.final_sb += align_block(
            sb_descriptor_data, alignment=SecureBinary4.SB4_BLOCK_ALIGNMENT
        )
        self.final_sb += enc_final_data
        self.store_temp_res("Final_SB4.sb4", self.final_sb)
        logger.debug(
            f" 6.1: The final SB4 file data:\n{format_raw_data(self.final_sb, use_hexdump=True)}."
        )

        # 7: Final reset to ensure followup operations (e.g. receive-sb-file) work correctly
        if self.final_reset:
            self.info_print(" 7: Resetting the target device")
            self.mboot.reset(timeout=self.RESET_TIMEOUT, reopen=False)
        else:
            self.info_print(" 7: Final target reset disabled")

    def export(self) -> bytes:
        """Export the final SB4 file as bytes.

        This method returns the complete SB4 (Secure Binary version 4) file that has been
        built and is ready for deployment or further processing.

        :return: Complete SB4 file content as bytes.
        """
        return self.final_sb

    def oem_generate_master_share(
        self, oem_share_input: Optional[bytes] = None
    ) -> tuple[bytes, bytes, bytes]:
        """Generate on device encrypted OEM master share outputs.

        This method writes the OEM share input to device memory, executes the OEM generate
        master share command, and retrieves the encrypted share and master share outputs.
        The results are also stored as temporary files for debugging purposes.

        :param oem_share_input: OEM input data used as randomization seed, if None uses
                               the instance's oem_share_input
        :raises SPSDKError: Memory write/read failure, command execution failure, or
                           invalid command results
        :return: Tuple containing (encrypted OEM share, encrypted OEM master share,
                 empty bytes placeholder)
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
            0x40,
            self.get_devbuff_base_address(2),
            0x60,
            0,
            0,
        )

        if not oem_gen_master_share_res:
            raise SPSDKError(
                f"OEM generate master share command failed. Error: {self.mboot.status_string}\n"
                "Device probably needs reset due to doubled call of this command."
            )

        if (
            oem_gen_master_share_res[0] != self.DEVBUFF_GEN_MASTER_ENC_SHARE_OUTPUT_SIZE
            or oem_gen_master_share_res[1] != self.DEVBUFF_GEN_MASTER_ENC_MASTER_SHARE_OUTPUT_SIZE
            or oem_gen_master_share_res[2] != 0
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

        return oem_enc_share, oem_enc_master_share, bytes(0)

    def oem_set_master_share(
        self, oem_seed: Optional[bytes] = None, enc_oem_share: Optional[bytes] = None
    ) -> bytes:
        """Set OEM Master share on the device.

        Writes the OEM seed and encrypted master share to device memory and configures
        the OEM master share through the trusted provisioning interface.

        :param oem_seed: OEM seed data, uses instance default if not provided
        :param enc_oem_share: Encrypted OEM master share data, uses instance default if not provided
        :raises SPSDKError: When OEM share inputs are not defined, memory write fails, or OEM share
                            setting operation fails
        :return: Truncated OEM master input data
        """
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

    def wrap_key(self, cust_mk_sk: bytes) -> bytes:
        """Wrap the Customer Master Key Symmetric Key using device HSM.

        This method writes the CUST_MK_SK to device buffer, uses HSM store key command
        to wrap it according to RFC3396 standard, and retrieves the wrapped result.

        :param cust_mk_sk: Customer Master Key Symmetric Key to be wrapped.
        :raises SPSDKError: If memory write/read fails or HSM store key command fails.
        :return: Wrapped CUST_MK_SK key according to RFC3396 standard.
        """
        if not self.mboot.write_memory(self.devbuff_base, cust_mk_sk):
            raise SPSDKError(
                f"Cannot write CUST_MK_SK into device. Error: {self.mboot.status_string}"
            )
        wrapped_key_size = self.get_devbuff_wrapped_cust_mk_sk_key_size()
        hsm_store_key_res = self.mboot.tp_hsm_store_key(
            TrustProvKeyType.CKDFK.tag,
            0x01,
            self.devbuff_base,
            self.DEVBUFF_CUST_MK_SK_KEY_SIZE,
            self.get_devbuff_base_address(1),
            wrapped_key_size,
        )

        if not hsm_store_key_res:
            raise SPSDKError(f"HSM Store Key command failed. Error: {self.mboot.status_string}")

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

    def sign_data_blob(self, data_to_sign: bytes) -> bytes:
        """Sign data blob using HSM encryption.

        The method writes the input data to device buffer, performs HSM encryption signing
        using CMAC algorithm, and retrieves the generated signature from the device.

        :param data_to_sign: Input data bytes to be signed.
        :raises SPSDKError: If writing data to device fails, HSM signing command fails,
            or reading signature from device fails.
        :return: Data blob signature (64 bytes).
        """
        if not self.mboot.write_memory(self.get_devbuff_base_address(0), data_to_sign):
            raise SPSDKError(
                f"Cannot write Data to sign into device. Error: {self.mboot.status_string}"
            )
        hsm_gen_key_res = self.mboot.tp_hsm_enc_sign(
            0,  # The key is not used with CMAC signing
            0,  # The key is not used with CMAC signing
            self.get_devbuff_base_address(0),
            len(data_to_sign),
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )

        if hsm_gen_key_res != self.DEVBUFF_SB_SIGNATURE_SIZE:
            raise SPSDKError(
                f"HSM signing command failed. Invalid signature size: {hsm_gen_key_res} "
                f"MBoot Status: {self.mboot.status_string}"
            )

        signature = self.mboot.read_memory(
            self.get_devbuff_base_address(1),
            self.DEVBUFF_SB_SIGNATURE_SIZE,
        )
        if not signature:
            raise SPSDKError(
                f"Cannot read generated signature from device. Error: {self.mboot.status_string}"
            )

        self.store_temp_res("SB4_sign.bin", signature, "to_merge")

        return signature

    def encrypt_data_blocks(self, sb4_header: bytes, data_cmd_blocks: list[bytes]) -> list[bytes]:
        """Encrypt all data blocks using device HSM functionality.

        The method writes the SB4 header and each data command block to device memory,
        then uses the device's HSM encryption capability to encrypt each block. The
        encrypted blocks are read back and stored for debugging purposes.

        :param sb4_header: Unencrypted SB4 file header bytes.
        :param data_cmd_blocks: List of unencrypted SB4 file command blocks.
        :raises SPSDKError: Memory write/read operation fails or HSM encryption fails.
        :return: List of encrypted command blocks.
        """
        self.store_temp_res("SB4_header.bin", sb4_header, "to_encrypt")
        if not self.mboot.write_memory(
            self.get_devbuff_base_address(0), sb4_header
        ):  # SB4 Container + manifest
            raise SPSDKError(
                f"Cannot write SB4 header into device. Error: {self.mboot.status_string}"
            )

        encrypted_blocks = []
        for data_cmd_block_ix, data_cmd_block in enumerate(data_cmd_blocks, start=1):
            self.store_temp_res(f"SB4_block_{data_cmd_block_ix}.bin", data_cmd_block, "to_encrypt")
            if not self.mboot.write_memory(self.get_devbuff_base_address(1), data_cmd_block):
                raise SPSDKError(
                    f"Cannot write SB4 data block{data_cmd_block_ix} into device. "
                    f"Error: {self.mboot.status_string}"
                )
            if not self.mboot.tp_hsm_enc_blk(
                0,  # Firmware Encryption key is not handled over PC
                0,  # Firmware Encryption key is not handled over PC
                0,  # KekID is not used in SB4
                self.get_devbuff_base_address(0),
                len(sb4_header),
                data_cmd_block_ix,
                self.get_devbuff_base_address(1),
                len(data_cmd_block),
            ):
                raise SPSDKError(
                    f"Cannot run SB4 data block_{data_cmd_block_ix} HSM Encryption in device. "
                    f"Error: {self.mboot.status_string}"
                )

            encrypted_block = self.mboot.read_memory(
                self.get_devbuff_base_address(1),
                len(data_cmd_block),
            )
            if not encrypted_block:
                raise SPSDKError(
                    f"Cannot read SB4 data block_{data_cmd_block_ix} from device. "
                    f"Error: {self.mboot.status_string}"
                )

            self.store_temp_res(f"SB4_block_{data_cmd_block_ix}.bin", encrypted_block, "encrypted")

            encrypted_blocks.append(encrypted_block)

        return encrypted_blocks

    @classmethod
    def load_from_config(
        cls, config: Config, mboot: Optional[McuBoot] = None, info_print: Optional[Callable] = None
    ) -> Self:
        """Load the class from configuration.

        Creates a DEVHSM SB4 instance from configuration data, loading encryption keys,
        buffer settings, and SB4 commands as specified in the config.

        :param config: DEVHSM configuration file containing keys and settings.
        :param mboot: mBoot communication interface object.
        :param info_print: Optional callback function for printing information messages.
        :raises SPSDKError: When mboot parameter is not provided.
        :return: DEVHSM SB4 class instance configured with loaded parameters.
        """
        if not mboot:
            raise SPSDKError("Mboot must be defined to load DEVHSM SB4 class.")

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
                key="oemEncMasterShare", expected_size=96, name="OEM ENC MASTER SHARE"
            )
            if "oemEncMasterShare" in config
            else None
        )
        enc_oem_share_in = (
            config.load_symmetric_key(key="oemEncShare", expected_size=64, name="OEM ENC SHARE")
            if "oemEncShare" in config
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

        sb4_data = SecureBinary4Commands.load_from_config(
            config, hash_type=EnumHashAlgorithm.SHA384, load_just_commands=True
        )

        return cls(
            mboot=mboot,
            family=family,
            oem_share_input=oem_share_in,
            oem_enc_master_share_input=enc_oem_master_share_in,
            oem_enc_share_input=enc_oem_share_in,
            cust_mk_sk=cust_mk_sk,
            commands=sb4_data.commands,
            workspace=config.get_output_file_name("workspace") if "workspace" in config else None,
            initial_reset=config.get("initialReset", False),
            final_reset=config.get("finalReset", True),
            buffer_address=buffer_address,
            info_print=info_print,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented.
        """
        raise SPSDKNotImplementedError()

#!/usr/bin/env python
#
# Copyright 2022-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK nxpdevhsm application functionality.

This module contains comprehensive unit tests for the nxpdevhsm application,
which provides secure provisioning capabilities for NXP development HSM devices.
Tests cover command generation, template handling, device factory operations,
and SBX device integration.
"""

import logging
import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from spsdk.apps import nxpdevhsm
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_container import AHABContainerV2
from spsdk.image.ahab.ahab_data import create_chip_config
from spsdk.mboot.commands import TrustProvKeyType
from spsdk.sbfile.devhsm.utils import get_devhsm_class
from spsdk.sbfile.sb4.devhsm import DevHsmSB4
from spsdk.sbfile.sb4.images import SecureBinary4, SecureBinary4Commands
from spsdk.sbfile.sb31.commands import CmdErase, CmdLoadKeyBlob, CmdReset, CmdWriteIfr
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sb31.images import SecureBinary31Commands
from spsdk.sbfile.sbc.devhsm import DevHsmSBc
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.sbfile.sbx.images import SecureBinaryXType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import load_binary, use_working_directory, write_file
from tests.cli_runner import CliRunner


def test_nxpdevhsm_run_generate(cli_runner: CliRunner, data_dir: str, tmpdir: Any) -> None:
    """Test nxpdevhsm CLI generate command with invalid COM port.

    This test verifies that the nxpdevhsm generate command properly handles
    the case when an invalid or non-existent COM port is specified. It expects
    the command to fail with a specific error message indicating no devices
    were found for the given UART interface parameters.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for test output files.
    """
    with use_working_directory(data_dir):
        cmd = (
            "generate -p COMx "
            "-oc family=lpc55s3x "
            "-oc containerKeyBlobEncryptionKey=test_bin.bin "
            "-oc oemRandomShare=test_bin.bin "
            f"-oc containerOutputFile={tmpdir}/bootable_images/cust_mk_sk.sb"
        )
        result = cli_runner.invoke(nxpdevhsm.main, cmd.split(), expected_code=1)
        assert (
            "No devices for given interface 'uart' and parameters 'port=COMx, timeout=5000' was found."
            == str(result.exception)
        )


def test_nxpdevhsm_parent_debug_log_level_reaches_subcommand(
    cli_runner: CliRunner, data_dir: str, tmpdir: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that parent -vv log level is applied before subcommand interface scan.

    This is a regression test for CLI commands where verbosity is defined on the parent
    command group but the mboot interface is resolved in a subcommand decorator.
    """
    with use_working_directory(data_dir):
        cmd = (
            "-vv generate -p COMx "
            "-oc family=lpc55s3x "
            "-oc containerKeyBlobEncryptionKey=test_bin.bin "
            "-oc oemRandomShare=test_bin.bin "
            f"-oc containerOutputFile={tmpdir}/bootable_images/cust_mk_sk.sb"
        )
        with caplog.at_level(logging.DEBUG, logger="spsdk"):
            cli_runner.invoke(nxpdevhsm.main, cmd.split(), expected_code=1)
        assert any(
            record.levelno == logging.DEBUG
            and "Checking port: COMx, baudrate: 57600, timeout: 5000" in record.message
            for record in caplog.records
        )


@pytest.mark.parametrize(
    "config,n_cmds,nf_cmds",
    [
        ("cfg_sb3_load.yaml", 1, 2),
        ("cfg_sb3_keyblob.yaml", 2, 3),
    ],
)
def test_load_commands(data_dir: str, config: str, n_cmds: int, nf_cmds: int) -> None:
    """Test loading commands from SB3.1 config file.

    This test verifies that commands can be properly loaded from a configuration file,
    added to a SecureBinary31Commands object, and processed correctly. It checks that
    the expected number of commands are loaded and that the final processed data
    contains the expected binary content.

    :param data_dir: Directory path containing test data files.
    :param config: Path to the SB3.1 configuration file to load.
    :param n_cmds: Expected number of additional commands to be loaded.
    :param nf_cmds: Expected total number of commands after adding all commands.
    """

    with use_working_directory(data_dir):
        devhsm = DevHsmSB31.load_from_config(Config.create_from_file(config), mboot=1)  # type: ignore
        cmds = devhsm.additional_commands
        assert cmds is not None
        assert len(cmds) == n_cmds

        sb3_data = SecureBinary31Commands(
            family=FamilyRevision("lpc55s3x"), hash_type=EnumHashAlgorithm.SHA256
        )
        sb3_data.add_command(
            CmdLoadKeyBlob(
                offset=0x04,
                data=b"0123456789012345",
                key_wrap_id=CmdLoadKeyBlob.get_key_id(
                    family=FamilyRevision("lpc55s3x"),
                    key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK,
                ),
            )
        )
        for cmd in cmds:
            sb3_data.add_command(cmd)

        assert len(sb3_data.commands) == nf_cmds
        cmd_blocks = sb3_data.get_cmd_blocks_to_export()
        processed = sb3_data.process_cmd_blocks_to_export(cmd_blocks)
        assert load_binary("test_bin.bin") in processed


@pytest.mark.parametrize(
    "family,expected_cls",
    [
        ("lpc55s3x", DevHsmSB31),
        ("mc56f818xx", DevHsmSBx),
        ("mcxa366", DevHsmSBc),
    ],
)
def test_devhsm_factory(family: str, expected_cls: Any) -> None:
    """Test nxpdevhsm factory method.

    Verifies that the get_devhsm_class factory function returns the correct
    DevHSM class for a given family revision.

    :param family: The family name to test with the factory method.
    :param expected_cls: The expected DevHSM class that should be returned by the factory.
    """
    devhsm_cls = get_devhsm_class(FamilyRevision(family))
    assert devhsm_cls == expected_cls


def test_kw43_devhsm_sb4_keyblob_injected_before_write_ifr() -> None:
    """Test that DevHSM-injected KW43 SB4 keyblob is placed before WriteIFR."""
    family_revision = FamilyRevision("kw43l43z97")
    sb4_commands = SecureBinary4Commands(family=family_revision, hash_type=EnumHashAlgorithm.SHA384)
    sb4_commands.add_command(
        CmdWriteIfr(
            address=0,
            data=bytes(16),
            ifr_type=CmdWriteIfr.WriteIfrType.CFPA_AND_CMPA,
        )
    )
    sb4_commands.add_command(CmdReset())

    sb4_commands.insert_command(
        index=get_db(family_revision).get_int("devhsm", "key_blob_command_position"),
        command=CmdLoadKeyBlob(
            offset=0,
            data=bytes(40),
            key_wrap_id=CmdLoadKeyBlob.get_key_id(
                family=family_revision,
                key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK,
            ),
        ),
    )

    assert [command.CMD_TAG.label for command in sb4_commands.commands] == [
        "loadKeyBlob",
        "writeIFR",
        "reset",
    ]


@pytest.mark.parametrize(
    "commands,expected",
    [
        ([], ["loadKeyBlob"]),
        (["erase"], ["erase", "loadKeyBlob"]),
        (["erase", "reset"], ["erase", "loadKeyBlob", "reset"]),
        (["reset", "erase", "reset", "reset"], ["reset", "erase", "loadKeyBlob", "reset", "reset"]),
        (["reset"], ["loadKeyBlob", "reset"]),
    ],
)
@pytest.mark.parametrize(
    "devhsm_cls,commands_cls,family,hash_type",
    [
        (DevHsmSB31, SecureBinary31Commands, "lpc55s3x", EnumHashAlgorithm.SHA256),
        (DevHsmSB4, SecureBinary4Commands, "mimxrtl3450", EnumHashAlgorithm.SHA384),
    ],
)
def test_devhsm_keyblob_injected_before_trailing_reset(
    devhsm_cls: Any,
    commands_cls: Any,
    family: str,
    hash_type: EnumHashAlgorithm,
    commands: list[str],
    expected: list[str],
) -> None:
    """Test that the injected CUST_MK_SK keyblob is placed before the trailing reset commands.

    Commands placed after a reset command are never executed, so the keyblob that belongs
    to the end of the command list must be inserted before the trailing reset commands.

    :param devhsm_cls: DevHSM class to test.
    :param commands_cls: SB commands container class matching the DevHSM class.
    :param family: Device family name.
    :param hash_type: Hash algorithm used by the SB file.
    :param commands: Labels of the commands present in the configuration.
    :param expected: Expected labels of the commands after the keyblob injection.
    """
    family_revision = FamilyRevision(family)
    sb_commands = commands_cls(family=family_revision, hash_type=hash_type)
    for label in commands:
        sb_commands.add_command(
            CmdReset() if label == "reset" else CmdErase(address=0, length=0x1000)
        )
    devhsm = devhsm_cls(
        mboot=MagicMock(),
        family=family_revision,
        commands=[],
        workspace=None,
        info_print=lambda *args: None,
    )
    sb_commands.insert_command(
        index=devhsm.get_keyblob_index(sb_commands.commands),
        command=CmdLoadKeyBlob(
            offset=devhsm.get_keyblob_offset(),
            data=bytes(48),
            key_wrap_id=CmdLoadKeyBlob.get_key_id(
                family=family_revision, key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK
            ),
        ),
    )

    assert [command.CMD_TAG.label for command in sb_commands.commands] == expected


def test_devhsm_sb4_create_sb_keeps_reset_last(tmpdir: Any) -> None:
    """Test that DevHSM SB4 creation keeps the reset command at the end of the command list.

    :param tmpdir: Temporary directory used as DevHSM workspace.
    """
    devhsm = DevHsmSB4(
        mboot=MagicMock(),
        family=FamilyRevision("mimxrtl3450"),
        cust_mk_sk=bytes(32),
        commands=[CmdErase(address=0, length=0x1000), CmdReset()],
        workspace=str(tmpdir),
        final_reset=False,
        info_print=lambda *args: None,
    )
    devhsm.oem_generate_master_share = MagicMock(  # type: ignore[method-assign]
        return_value=(bytes(64), bytes(96), bytes(16))
    )
    devhsm.wrap_key = MagicMock(return_value=bytes(48))  # type: ignore[method-assign]
    devhsm.encrypt_data_blocks = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda header, blocks: blocks
    )
    devhsm.sign_data_blob = MagicMock(return_value=bytes(16))  # type: ignore[method-assign]
    exported_commands: list[str] = []
    original_export = SecureBinary4Commands.get_cmd_blocks_to_export

    def get_cmd_blocks_to_export(self: SecureBinary4Commands) -> list[bytes]:
        exported_commands.extend(command.CMD_TAG.label for command in self.commands)
        return original_export(self)

    with patch.object(SecureBinary4Commands, "get_cmd_blocks_to_export", get_cmd_blocks_to_export):
        devhsm.create_sb()

    assert exported_commands == ["erase", "loadKeyBlob", "reset"]


@pytest.mark.parametrize("family", ["mimxrtl3450", "kw43l43z97"])
def test_devhsm_sb4_create_sb_uses_boot_core_id(family: str, tmpdir: Any) -> None:
    """Test that DevHSM SB4 container is created with the family specific boot core ID.

    The device side HSM operations are mocked, so the test covers creation of the SB4
    AHAB container also for families without the Cortex-M33 core (Cortex-M55).

    :param family: Device family name to create the DevHSM SB4 file for.
    :param tmpdir: Temporary directory used as DevHSM workspace.
    """
    family_revision = FamilyRevision(family)
    devhsm = DevHsmSB4(
        mboot=MagicMock(),
        family=family_revision,
        commands=[],
        workspace=str(tmpdir),
        final_reset=False,
        info_print=lambda *args: None,
    )
    devhsm.oem_generate_master_share = MagicMock(  # type: ignore[method-assign]
        return_value=(bytes(64), bytes(96), bytes(16))
    )
    devhsm.encrypt_data_blocks = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda header, blocks: blocks
    )
    devhsm.sign_data_blob = MagicMock(return_value=bytes(16))  # type: ignore[method-assign]

    devhsm.create_sb()

    chip_config = create_chip_config(
        family_revision, feature=SecureBinary4.FEATURE, base_key=["ahab"]
    )
    ahab = AHABContainerV2.parse(devhsm.export(), chip_config, offset=0, container_offset=0)
    assert ahab.image_array[0].flags_core_id.label == chip_config.core_ids.labels()[0]


def test_sbx_devhsm(data_dir: str) -> None:
    """Test SBx DevHSM functionality with configuration file.

    This test verifies that the DevHsmSBx class can properly load from a YAML
    configuration file and validates the resulting secure binary properties
    including commands, image type, signing status, and block size.

    :param data_dir: Directory path containing test data and configuration files
    """
    with use_working_directory(data_dir):
        devhsm = DevHsmSBx.load_from_config(Config.create_from_file("cfg_sbx_load.yaml"), mboot=1)  # type: ignore

    assert "ERASE: Address=0x00000000, Length=4096, Memory ID=0\n" in str(devhsm.sbx.sb_commands)
    assert devhsm.sbx.image_type == SecureBinaryXType.OEM_PROVISIONING
    assert not devhsm.sbx.isk_signed
    assert devhsm.sbx.sb_header.block_size == 292


@pytest.mark.parametrize(
    "family",
    [
        ("lpc55s3x"),
        ("mc56f818xx"),
        ("mcxn9xx"),
        ("mwct20d2"),
        ("rw61x"),
        ("mcxa255"),
        ("mcxa256"),
        ("mcxa366"),
        ("mcxa365"),
        ("mcxa457"),
        ("kw43l43z97"),
    ],
)
def test_nxpdevhsm_get_template(cli_runner: CliRunner, tmpdir: Any, family: str) -> None:
    """Test NXPDEVHSM CLI get-template command functionality.

    Verifies that the get-template command generates a valid configuration file
    for the specified device family and saves it to the expected output location.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory fixture for test file operations
    :param family: Device family name to generate template for
    :raises AssertionError: If the generated configuration file does not exist
    """
    cmd = ["get-template", "-f", family, "--output", f"{tmpdir}/devhsm.yml"]
    cli_runner.invoke(nxpdevhsm.main, cmd)
    assert os.path.isfile(f"{tmpdir}/devhsm.yml")


def test_devhsm_commands_are_optional(tmpdir: Any, data_dir: str) -> None:
    """Test that DevHSM commands are optional in configuration.

    Verifies that the DevHsmSB31 factory method correctly handles configurations
    without additional commands, ensuring the additional_commands attribute is empty
    when no commands are specified in the configuration file.

    :param tmpdir: Temporary directory for test files (unused in this test).
    :param data_dir: Path to the directory containing test data files.
    """
    config_file = "cfg_sb3_no_cmds.yaml"
    configuration = Config.create_from_file(os.path.join(data_dir, config_file))

    assert not DevHsmSB31.load_from_config(configuration, mboot=1).additional_commands  # type: ignore


@pytest.mark.parametrize(
    "key_type,key_properties,expected_key_type,expected_properties",
    [
        (None, None, TrustProvKeyType.CKDFK, None),
        ("AESK", None, TrustProvKeyType.AESK, None),
        ("hmack", "0xC0000001", TrustProvKeyType.HMACK, 0xC0000001),
        ("KUOK", 1, TrustProvKeyType.KUOK, 1),
    ],
)
def test_load_key_blob_plain_key_config(
    tmpdir: Any,
    key_type: str | None,
    key_properties: str | int | None,
    expected_key_type: TrustProvKeyType,
    expected_properties: int | None,
) -> None:
    """Test loading of plain user key settings of loadKeyBlob command from configuration.

    :param tmpdir: Temporary directory for the key file.
    :param key_type: Key type in configuration.
    :param key_properties: Key properties in configuration.
    :param expected_key_type: Expected key type of the command.
    :param expected_properties: Expected key properties of the command.
    """
    write_file(bytes(range(32)), os.path.join(tmpdir, "key.bin"), mode="wb")
    cfg: dict[str, Any] = {
        "family": "rw612",
        "offset": 0,
        "wrappingKeyId": "NXP_CUST_KEK_EXT_SK",
        "file": "key.bin",
        "plainInput": "bin",
    }
    if key_type is not None:
        cfg["keyType"] = key_type
    if key_properties is not None:
        cfg["keyProperties"] = key_properties
    config = Config(cfg)
    config.search_paths = [str(tmpdir)]
    cmd = CmdLoadKeyBlob.load_from_config(config)[0]
    assert cmd.plain_input
    assert cmd.data == bytes(range(32))
    assert cmd.key_type == expected_key_type
    assert cmd.key_properties == expected_properties

    cmd_cfg = cmd.get_config_context(str(tmpdir))
    assert cmd_cfg["keyType"] == expected_key_type.label
    assert cmd_cfg.get("keyProperties") == (
        None if expected_properties is None else f"0x{expected_properties:08X}"
    )
    cmd_cfg.search_paths = [str(tmpdir)]
    cmd_cfg["family"] = "rw612"
    assert CmdLoadKeyBlob.load_from_config(cmd_cfg)[0] == cmd


@pytest.mark.parametrize(
    "key_length,key_properties,expected_properties",
    [
        (32, None, 0x01),
        (16, None, 0x00),
        (32, 0xC0000001, 0xC0000001),
        (16, 0x40000000, 0x40000000),
    ],
)
def test_plain_key_properties(
    key_length: int, key_properties: int | None, expected_properties: int
) -> None:
    """Test derivation of HSM_STORE_KEY key properties for plain keys.

    :param key_length: Length of the plain key.
    :param key_properties: Requested key properties.
    :param expected_properties: Expected key properties.
    """
    key = bytes(key_length)
    assert CmdLoadKeyBlob.get_plain_key_properties(key, key_properties) == expected_properties


@pytest.mark.parametrize(
    "key_length,key_properties",
    [
        (24, None),  # unsupported key length
        (16, 0x01),  # 256-bit key size for 128-bit key
        (32, 0x00),  # 128-bit key size for 256-bit key
        (32, 0x03),  # reserved bit set
    ],
)
def test_plain_key_properties_invalid(key_length: int, key_properties: int | None) -> None:
    """Test invalid plain key length or key properties are refused.

    :param key_length: Length of the plain key.
    :param key_properties: Requested key properties.
    """
    with pytest.raises(SPSDKValueError):
        CmdLoadKeyBlob.get_plain_key_properties(bytes(key_length), key_properties)


@pytest.mark.parametrize(
    "devhsm_cls,family,wrapped_cust_mk_sk_size",
    [
        (DevHsmSB31, "rw612", 0x30),
        (DevHsmSB31, "mcxa457", 0x28),
        (DevHsmSB4, "mimxrtl3450", 0x30),
    ],
)
@pytest.mark.parametrize(
    "key_length,key_type,key_properties,expected_properties",
    [
        (32, TrustProvKeyType.CKDFK, None, 0x01),
        (16, TrustProvKeyType.AESK, None, 0x00),
        (32, TrustProvKeyType.HMACK, 0xC0000001, 0xC0000001),
    ],
)
def test_devhsm_wrap_user_key(
    tmpdir: Any,
    devhsm_cls: Any,
    family: str,
    wrapped_cust_mk_sk_size: int,
    key_length: int,
    key_type: TrustProvKeyType,
    key_properties: int | None,
    expected_properties: int,
) -> None:
    """Test DevHSM wraps plain keys of any type by HSM_STORE_KEY with the right parameters.

    :param tmpdir: Temporary directory used as DevHSM workspace.
    :param devhsm_cls: DevHSM class to test.
    :param family: Device family name.
    :param wrapped_cust_mk_sk_size: Size of the wrapped 256-bit key blob for the family.
    :param key_length: Length of the plain key.
    :param key_type: Type of the plain key.
    :param key_properties: Requested key properties.
    :param expected_properties: Key properties expected in the HSM_STORE_KEY command.
    """
    wrapped_size = wrapped_cust_mk_sk_size - 32 + key_length
    mboot = MagicMock()
    mboot.tp_hsm_store_key.return_value = [0, wrapped_size]
    mboot.read_memory.return_value = bytes(wrapped_size)
    devhsm = devhsm_cls(
        mboot=mboot, family=FamilyRevision(family), commands=[], workspace=str(tmpdir)
    )
    key = bytes(range(key_length))

    wrapped = devhsm.wrap_key(key, key_type, key_properties)

    assert wrapped == bytes(wrapped_size)
    mboot.write_memory.assert_called_once_with(devhsm.devbuff_base, key)
    args = mboot.tp_hsm_store_key.call_args[0]
    assert args[:4] == (key_type.tag, expected_properties, devhsm.devbuff_base, key_length)
    mboot.read_memory.assert_called_once_with(devhsm.get_devbuff_base_address(1), wrapped_size)


def test_devhsm_sb31_wraps_plain_user_key_command(tmpdir: Any) -> None:
    """Test DevHSM SB3.1 flow wraps plain loadKeyBlob user key with its key type.

    :param tmpdir: Temporary directory used as DevHSM workspace.
    """
    family = FamilyRevision("rw612")
    key_wrap_id = CmdLoadKeyBlob.get_key_id(family, CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK)
    user_key_cmd = CmdLoadKeyBlob(
        offset=0x10,
        data=bytes(16),
        key_wrap_id=key_wrap_id,
        plain_input=True,
        key_type=TrustProvKeyType.AESK,
        key_properties=0x80000000,
    )
    devhsm = DevHsmSB31(
        mboot=MagicMock(),
        family=family,
        cust_mk_sk=bytes(32),
        commands=[user_key_cmd],
        workspace=str(tmpdir),
        final_reset=False,
        info_print=lambda *args: None,
    )
    devhsm.oem_share_input = bytes(16)
    devhsm.wrap_key = MagicMock(return_value=bytes(0x20))  # type: ignore[method-assign]
    devhsm.oem_generate_master_share = MagicMock(  # type: ignore[method-assign]
        return_value=(bytes(64), bytes(96), bytes(16))
    )
    devhsm.generate_key = MagicMock(return_value=(bytes(48), bytes(64)))  # type: ignore
    # stop the flow once the SB commands have been prepared
    devhsm.get_cust_fw_auth = MagicMock(side_effect=SPSDKError("stop"))  # type: ignore
    devhsm.encrypt_data_blocks = MagicMock(side_effect=SPSDKError("stop"))  # type: ignore

    with pytest.raises(SPSDKError, match="stop"):
        devhsm.create_sb()

    devhsm.wrap_key.assert_any_call(bytes(16), TrustProvKeyType.AESK, 0x80000000)
    assert user_key_cmd.data == bytes(0x20)

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""
import filecmp
import os
import shutil

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.keys import IS_OSCCA_SUPPORTED
from spsdk.exceptions import SPSDKValueError
from spsdk.image.ahab.ahab_container import AHABImage
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner
from tests.nxpimage.test_nxpimage_cert_block import process_config_file


@pytest.mark.parametrize(
    "config_file",
    [
        ("config_ctcm.yaml"),
    ],
)
def test_nxpimage_ahab_export(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(os.path.join(data_dir, "ahab", ref_binary), new_binary, shallow=False)


@pytest.mark.parametrize(
    "config_file",
    [
        ("ctcm_cm33_signed_img.yaml"),
        ("ctcm_cm33_signed.yaml"),
        ("ctcm_cm33_signed_nx.yaml"),
        ("ctcm_cm33_signed_sb.yaml"),
        ("ctcm_cm33_signed_sb_mx93.yaml"),
        ("ctcm_cm33_signed_nand.yaml"),
        ("ctcm_cm33_signed_certificate.yaml"),
        ("ctcm_cm33_encrypted_img.yaml"),
    ],
)
def test_nxpimage_ahab_export_signed_encrypted(
    cli_runner: CliRunner, tmpdir, data_dir, config_file
):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.yaml"),
        ("ahab_certificate384.yaml"),
        ("ahab_certificate521.yaml"),
        ("ahab_certificate256_uuid.yaml"),
        ("ahab_certificate384_uuid.yaml"),
        ("ahab_certificate521_uuid.yaml"),
    ],
)
def test_nxpimage_ahab_cert_export(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(data_dir):
        ref_binary = os.path.join(data_dir, "ahab", os.path.splitext(config_file)[0] + ".bin")
        new_binary = os.path.join(tmpdir, os.path.splitext(config_file)[0] + ".bin")
        cmd = f"ahab certificate export -c ahab/{config_file} -o {new_binary}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.bin"),
        ("ahab_certificate384.bin"),
        ("ahab_certificate521.bin"),
        ("ahab_certificate256_uuid.bin"),
        ("ahab_certificate384_uuid.bin"),
        ("ahab_certificate521_uuid.bin"),
    ],
)
def test_nxpimage_ahab_cert_parse(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(tmpdir):
        input_binary = os.path.join(data_dir, "ahab", config_file)
        cmd = f"ahab certificate parse -b {input_binary} -o {tmpdir} -s oem"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile("certificate_config.yaml")


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "config_file",
    [
        ("ctcm_cm33_signed_img_sm2.yaml"),
    ],
)
def test_nxpimage_ahab_export_signed_encrypted_sm2(
    cli_runner: CliRunner, tmpdir, data_dir, config_file
):
    test_nxpimage_ahab_export_signed_encrypted(cli_runner, tmpdir, data_dir, config_file)


def test_nxpimage_ahab_parse_cli(cli_runner: CliRunner, tmpdir, data_dir):
    def is_subpart(new_file, orig_file):
        new = load_binary(new_file)
        orig = load_binary(orig_file)
        return new[: len(orig)] == orig

    with use_working_directory(data_dir):
        cmd = f"ahab parse -f rt118x -b ahab/test_parse_ahab.bin -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container0_image0_executable.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image0_executable.bin"),
            os.path.join(data_dir, "ahab", "inc1024.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image1_executable.bin"),
            os.path.join(data_dir, "ahab", "inc1026.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image2_executable.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )


@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33.bin", "rt118x", "nor"),
        ("cntr_signed_ctcm_cm33_nx.bin", "rt118x", "nor"),
        ("cntr_signed_ctcm_cm33_sb.bin", "rt118x", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_nand.bin", "rt118x", "nand_2k"),
        ("cntr_encrypted_ctcm_cm33.bin", "rt118x", "nor"),
    ],
)
def test_nxpimage_ahab_parse(data_dir, binary, family, target_memory):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/{binary}")
        ahab = AHABImage(family, "a0", target_memory)
        ahab.parse(original_file)
        ahab.update_fields()
        ahab.validate()
        exported_ahab = ahab.export()
        assert original_file == exported_ahab
        assert ahab.target_memory == target_memory


@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33_cert_wrong_signature.bin", "rt118x", "nor"),
    ],
)
def test_nxpimage_ahab_wrong_signature(data_dir, binary, family, target_memory):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/{binary}")
        ahab = AHABImage(family, "a0", target_memory)
        ahab.parse(original_file)
        ahab.update_fields()
        with pytest.raises(SPSDKValueError, match="Signature cannot be verified"):
            ahab.validate()


@pytest.mark.parametrize(
    "binary,family",
    [
        ("cntr_signed_ctcm_cm33.bin", "rt118x"),
        ("cntr_signed_ctcm_cm33_nx.bin", "rt118x"),
        ("cntr_signed_ctcm_cm33_sb.bin", "rt118x"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93"),
        ("cntr_signed_ctcm_cm33_nand.bin", "rt118x"),
        ("cntr_encrypted_ctcm_cm33.bin", "rt118x"),
    ],
)
def test_nxpimage_ahab_parse_cli2(cli_runner: CliRunner, data_dir, binary, family, tmpdir):
    with use_working_directory(data_dir):
        cmd = f"ahab parse -f {family} -b ahab/{binary} -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33_img_sm2.bin", "rt118x", "nor"),
    ],
)
def test_nxpimage_ahab_parse_sm2(data_dir, binary, family, target_memory):
    test_nxpimage_ahab_parse(data_dir, binary, family, target_memory)


@pytest.mark.parametrize(
    "config_file",
    [
        ("return_lc.yaml"),
    ],
)
def test_nxpimage_signed_message_export(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"signed-msg export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        new_bin = load_binary(new_binary)
        ref_bin = load_binary(ref_binary)
        # Check content up to signature
        assert new_bin[:408] == ref_bin[:408]


def test_nxpimage_signed_message_parse_cli(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        cmd = f"signed-msg parse -b ahab/signed_msg_oem_field_return.bin -o {tmpdir}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed_config.yaml"))


@pytest.mark.parametrize(
    "family",
    ["mx8ulp", "mx93", "mx95", "rt118x"],
)
def test_nxpimage_fcb_template_cli(cli_runner: CliRunner, tmpdir, family):
    cmd = f"signed-msg get-template -f {family} --output {tmpdir}/signed_msg.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/signed_msg.yml")


def test_nxpimage_signed_message_parse(data_dir):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/signed_msg_oem_field_return.bin")
        signed_msg = SignedMessage().parse(original_file)
        signed_msg.update_fields()
        signed_msg.validate({})
        exported_signed_msg = signed_msg.export()
        assert original_file == exported_signed_msg


def test_nxpimage_ahab_update_keyblob(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/cntr_encrypted_ctcm_cm33.bin"
        ref_bin_path = "ahab/cntr_encrypted_ctcm_cm33.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = f"ahab update-keyblob -b {new_bin_path} -i 1 -k ahab/keyblobs/container1_dek_keyblob.bin"
        cli_runner.invoke(nxpimage.main, cmd.split())

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_bootable(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        ref_bin_path = "ahab/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = f"ahab update-keyblob -f rt118x -m flexspi_nand -b {new_bin_path} -i 1 -k ahab/keyblobs/dek_keyblob.bin"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_invalid(cli_runner: CliRunner, data_dir):
    with use_working_directory(data_dir):
        cmd = f"ahab update-keyblob -b ahab/cntr_encrypted_ctcm_cm33.bin -i 0 -k ahab/keyblobs/container1_dek_keyblob.bin"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize(
    "family",
    [
        "mx8ulp",
        "mx93",
        "mx95",
        "rt118x",
    ],
)
def test_nxpimage_ahab_get_template(cli_runner: CliRunner, tmpdir, family):
    cmd = f"ahab get-template -f {family} -o {tmpdir}/tmp.yaml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")

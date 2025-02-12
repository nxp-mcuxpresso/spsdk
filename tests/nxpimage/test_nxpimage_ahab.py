#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""
import filecmp
import os
import shutil

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.keys import IS_OSCCA_SUPPORTED
from spsdk.image.ahab.ahab_data import FlagsSrkSet
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.signed_msg import MessageCommands, SignedMessage
from spsdk.utils.misc import (
    load_binary,
    load_configuration,
    load_hex_string,
    load_text,
    reverse_bytes_in_longs,
    use_working_directory,
    value_to_bytes,
    value_to_int,
)
from tests.cli_runner import CliRunner
from tests.nxpimage.test_nxpimage_cert_block import process_config_file


@pytest.mark.parametrize(
    "config_file",
    [
        ("config_ctcm.yaml"),
        ("config_ctcm_gdet.yaml"),
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
        ("ctcm_cm33_encrypted_img.yaml"),
        pytest.param(
            "ahab_mx95_pqc.yaml",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_pqc_cert.yaml",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
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
        pytest.param(
            ("ahab_certificate256_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            ("ahab_certificate384_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            ("ahab_certificate521_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
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
        pytest.param(
            "ahab_certificate256_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate384_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate521_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_cert_parse(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(tmpdir):
        input_binary = os.path.join(data_dir, "ahab", config_file)
        cmd = f"ahab certificate parse -f mx95 -b {input_binary} -o {tmpdir} -s oem"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile("certificate_config.yaml")


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.bin"),
        ("ahab_certificate384.bin"),
        ("ahab_certificate521.bin"),
        pytest.param(
            "ahab_certificate256_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate384_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate521_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_cert_verify(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(tmpdir):
        input_binary = os.path.join(data_dir, "ahab", config_file)
        cmd = f"ahab certificate verify -f mx95 -b {input_binary}"
        cli_runner.invoke(nxpimage.main, cmd.split())


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
        cmd = f"ahab parse -f mimxrt1189 -b ahab/test_parse_ahab.bin -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container0_image0_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image0_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc1024.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image1_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc1026.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image2_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )


@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189", "nor"),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189", "nor"),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189", "nand_2k"),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189", "nor"),
        pytest.param(
            "ahab_mx95_dilithium3.bin",
            "mx95",
            "standard",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_dilithium3_cert.bin",
            "mx95",
            "standard",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_parse(data_dir, binary, family, target_memory):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/{binary}")
        ahab = AHABImage(family, "a0", target_memory)
        ahab.parse(original_file)
        ahab.verify().validate()
        exported_ahab = ahab.export()
        # if original_file != exported_ahab:
        #     write_file(exported_ahab, f"{data_dir}/ahab/{binary}.created", mode="wb")
        assert original_file == exported_ahab
        assert ahab.chip_config.target_memory.label == target_memory


@pytest.mark.parametrize(
    "config_file,new_key,container_id,succeeded",
    [
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk0_ecc256.pem", 1, True),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk0_ecc256.pem", 0, False),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk1_ecc256.pem", 1, False),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc384/srk0_ecc384.pem", 1, False),
        ("ctcm_cm33_signed.yaml", "srk0_ecc256.pem", 1, False),
    ],
)
def test_nxpimage_ahab_re_signs(
    cli_runner: CliRunner, tmpdir, data_dir, config_file, new_key, container_id, succeeded
):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        # we have now a reference binary - is not needed to run export
        shutil.copyfile(ref_binary, new_binary)
        cmd = f"ahab re-sign -f mimxrt1189 -b {new_binary} -k {new_key} -i {container_id}"
        if succeeded:
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert os.path.isfile(new_binary)
            assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)
            ahab = AHABImage("mimxrt1189")
            new_binary_data = load_binary(new_binary)
            ahab.parse(new_binary_data)
            ahab.verify().validate()
            assert ahab.export() == new_binary_data
        else:
            cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize(
    "binary,family",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93"),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189"),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189"),
    ],
)
def test_nxpimage_ahab_parse_cli2(cli_runner: CliRunner, data_dir, binary, family, tmpdir):
    with use_working_directory(data_dir):
        cmd = f"ahab parse -f {family} -b ahab/{binary} -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))


@pytest.mark.parametrize(
    "binary,family,succeeded",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93", True),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189", True),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189", True),
        ("test_parse_ahab.bin", "mimxrt1189", True),
        ("test_parse_ahab_err.bin", "mimxrt1189", False),
        pytest.param(
            "ahab_mx95_dilithium3.bin",
            "mx95",
            True,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_dilithium3_cert.bin",
            "mx95",
            True,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_verify(cli_runner: CliRunner, data_dir, binary, family, succeeded):
    with use_working_directory(data_dir):
        cmd = f"ahab verify -f {family} -b ahab/{binary} -p"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if succeeded else 1)


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33_img_sm2.bin", "mimxrt1189", "nor"),
    ],
)
def test_nxpimage_ahab_parse_sm2(data_dir, binary, family, target_memory):
    test_nxpimage_ahab_parse(data_dir, binary, family, target_memory)


@pytest.mark.parametrize(
    "config_file",
    [
        ("sm_return_lc.yaml"),
        ("sm_key_import.yaml"),
        ("sm_key_exchange.yaml"),
    ],
)
def test_nxpimage_signed_message_export(cli_runner: CliRunner, tmpdir, data_dir, config_file):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/signed_msg/{config_file}"
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
        cmd = f"signed-msg parse -f mimxrt1189 -b ahab/signed_msg/signed_msg_oem_field_return.bin -o {tmpdir}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed_config.yaml"))


@pytest.mark.parametrize(
    "family",
    AHABImage.get_supported_families(),
)
@pytest.mark.parametrize(
    "message",
    MessageCommands.labels() + [None],
)
def test_nxpimage_signed_msg_template_cli(cli_runner: CliRunner, tmpdir, family, message):
    cmd = f"signed-msg get-template -f {family} {f'-m {message}' if message else ''} --output {tmpdir}/signed_msg.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/signed_msg.yml")


def test_nxpimage_signed_message_parse(data_dir):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/signed_msg/signed_msg_oem_field_return.bin")
        signed_msg = SignedMessage(family="mimxrt1189")
        signed_msg.parse(original_file)
        signed_msg.verify().validate()
        exported_signed_msg = signed_msg.export()
        assert original_file == exported_signed_msg


def test_nxpimage_signed_message_key_exchange(data_dir):
    with use_working_directory(data_dir):
        config = load_configuration(
            os.path.join(data_dir, "ahab", "signed_msg", "sm_key_exchange.yaml")
        )
        signed_msg = SignedMessage.load_from_config(config)
        signed_msg.update_fields()
        signed_msg.verify().validate()


def test_nxpimage_ahab_update_keyblob(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/cntr_encrypted_ctcm_cm33.bin"
        ref_bin_path = "ahab/cntr_encrypted_ctcm_cm33.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = f"ahab update-keyblob -f mimxrt1189 -b {new_bin_path} -i 1 -k ahab/keyblobs/container1_dek_keyblob.bin"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_bootable(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        ref_bin_path = "ahab/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = f"ahab update-keyblob -f mimxrt1189 -m flexspi_nand -b {new_bin_path} -i 1 -k ahab/keyblobs/dek_keyblob.bin"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_invalid(cli_runner: CliRunner, data_dir):
    with use_working_directory(data_dir):
        cmd = f"ahab update-keyblob -f mimxrt1189 -b ahab/cntr_encrypted_ctcm_cm33.bin -i 2 -k ahab/keyblobs/container1_dek_keyblob.bin"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize(
    "family",
    [
        "mx8ulp",
        "mx93",
        "mx95",
        "mimxrt1189",
    ],
)
def test_nxpimage_ahab_get_template(cli_runner: CliRunner, tmpdir, family):
    cmd = f"ahab get-template -f {family} -o {tmpdir}/tmp.yaml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")


@pytest.mark.parametrize(
    "family",
    [
        "mx8ulp",
        "mx93",
        "mx95",
        "mimxrt1189",
    ],
)
def test_nxpimage_ahab_sign_get_template(cli_runner: CliRunner, tmpdir, family):
    cmd = f"ahab get-template -f {family} -o {tmpdir}/tmp.yaml --sign"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")


def test_nxpimage_ahab__invalid_encrypt_flag(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/config_ctcm_invalid_encrypt_flag.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        res = cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)
        assert res.exit_code == 1
        assert not os.path.isfile(new_binary)


def test_nxpimage_ahab_fuses(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/ctcm_cm33_signed_img.yaml"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        bcf_file = os.path.join(
            os.path.dirname(new_binary),
            "cntr_signed_ctcm_cm33_img_oem1_srk0_hash_blhost.bcf",
        )
        assert os.path.isfile(bcf_file)

        fuses = load_text(bcf_file)
        srk_hash = 0xCB2CC774B2DCEC92C840ECA0646B78F8D3661D3A43ED265A490A13ACA75E190A
        srk_rev = reverse_bytes_in_longs(value_to_bytes(srk_hash))

        fuse_start = 128

        for fuse_ix in range(8):
            value = srk_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            assert f"efuse-program-once {fuse_start+fuse_ix} 0x{value_to_int(value):X}" in fuses

        # Change family to mx93
        with open(new_config, "r") as f:
            config_mx93 = f.read().replace("mimxrt1189", "mx93")

        with open(new_config, "w") as f:
            f.write(config_mx93)
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        bcf_file = os.path.join(
            os.path.dirname(new_binary),
            "cntr_signed_ctcm_cm33_img_oem1_srk0_hash_nxpele.bcf",
        )
        assert os.path.isfile(bcf_file)
        fuses = load_text(bcf_file)

        for fuse_ix in range(8):
            value = srk_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            assert (
                f"write-fuse --index {fuse_start+fuse_ix} --data 0x{value_to_int(value):X}" in fuses
            )


@pytest.mark.parametrize(
    "config_file",
    [
        ("container_sign_config.yaml"),
        ("container_sign_encrypted_config.yaml"),
    ],
)
@pytest.mark.parametrize(
    "input_binary",
    [
        ("test_img_for_sign.bin"),
        ("ctcm_cm33_signed_img.bin"),
    ],
)
def test_nxpimage_ahab_sign(cli_runner: CliRunner, tmpdir, data_dir, config_file, input_binary):
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        binary_for_sign = f"{data_dir}/ahab/test_img_for_sign.bin"
        output_file = f"{tmpdir}/signed.bin"
        cmd = f"ahab sign -c {config_file} -b {binary_for_sign} -o {output_file}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0)
        assert os.path.exists(output_file)
        signed_image = load_binary(output_file)
        ahab = AHABImage("mx93")
        ahab.parse(signed_image)
        dek = "000102030405060708090a0b0c0d0e0f"
        if "encrypted" in config_file:
            for container in ahab.ahab_containers:
                if container.flag_srk_set != FlagsSrkSet.NXP:
                    if container.signature_block and container.signature_block.blob:
                        container.signature_block.blob.dek = load_hex_string(
                            dek, container.signature_block.blob._size // 8
                        )
                        container.decrypt_data()
        ahab.verify().validate()
